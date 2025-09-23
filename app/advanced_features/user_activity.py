# app/advanced_features/user_activity.py
# COMBINED VIEW:
#  - Tab 1: System Logs (Kali/Linux) via journalctl JSON, fallback /var/log/auth.log
#  - Tab 2: App Log (your AppConfig.ACTIVITY_LOG_FILE): refresh, export, clear
#
# Requirements/Notes:
#  - For "System Logs" to show entries, run as root OR add user to 'adm' group:
#      sudo usermod -aG adm $USER
#      newgrp adm
#  - No extra third-party deps required.

from __future__ import annotations
import asyncio
import contextlib
import csv
import datetime as dt
import json
import os
import re
import shutil
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QHeaderView,
    QPushButton, QMessageBox, QFileDialog, QLineEdit, QComboBox,
    QTableView, QTabWidget, QTableWidget, QTableWidgetItem
)

from app.config import AppConfig
from app.widgets.base_widget import BaseToolWidget


# ----------------------------- System activity engine -----------------------------

EVENT_LOGIN_SUCCESS = "login_success"
EVENT_LOGIN_FAILURE = "login_failure"
EVENT_PRIV_ESC      = "privilege_escalation"
EVENT_PROCESS       = "process_start"
EVENT_OTHER         = "other"


@dataclass
class ActivityEvent:
    when: dt.datetime
    user: str
    host: str
    event_type: str
    source: str
    extra: Dict[str, str]

    def to_row(self) -> List[str]:
        return [
            self.when.isoformat(sep=" ", timespec="seconds"),
            self.user or "N/A",
            self.host or "N/A",
            self.event_type,
            self.source,
            json.dumps(self.extra, ensure_ascii=False),
        ]


class _UserActivityEngine:
    """Linux activity engine with journalctl JSON + /var/log/auth.log fallback."""

    def __init__(self, logger: Optional[Callable[[str], None]] = None):
        self._log = logger or (lambda s: None)
        self._stop = False

    def stop(self): self._stop = True

    async def fetch_recent(self, limit: int = 600) -> List[ActivityEvent]:
        events: List[ActivityEvent] = []
        if shutil.which("journalctl"):
            try:
                cmd = "journalctl -n 2000 -o json --no-pager"
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                out, err = await proc.communicate()
                if proc.returncode == 0:
                    for line in out.decode(errors="ignore").splitlines():
                        evt = self._parse_journal_json(line)
                        if evt:
                            events.append(evt)
                else:
                    self._log(f"journalctl error: {err.decode(errors='ignore')}")
                    events.extend(self._parse_authlog_tail())
            except Exception as e:
                self._log(f"journalctl exception: {e}")
                events.extend(self._parse_authlog_tail())
        else:
            events.extend(self._parse_authlog_tail())

        events.sort(key=lambda e: e.when, reverse=True)
        return events[:limit]

    async def stream_live(self):
        """Async generator of ActivityEvent."""
        self._stop = False
        if shutil.which("journalctl"):
            proc = await asyncio.create_subprocess_shell(
                "journalctl -f -o json --no-pager",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            try:
                while not self._stop:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    evt = self._parse_journal_json(line.decode(errors="ignore"))
                    if evt:
                        yield evt
            finally:
                with _silent(): proc.terminate()
        else:
            path = "/var/log/auth.log"
            if not os.path.exists(path):
                return
            proc = await asyncio.create_subprocess_shell(
                f"tail -F {path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            try:
                while not self._stop:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    evt = self._parse_auth_line(line.decode(errors="ignore"))
                    if evt:
                        yield evt
            finally:
                with _silent(): proc.terminate()

    # ---------- Parsers ----------
    def _parse_journal_json(self, line: str) -> Optional[ActivityEvent]:
        try:
            obj = json.loads(line)
        except Exception:
            return None

        msg  = (obj.get("MESSAGE") or "").strip()
        host = (obj.get("_HOSTNAME") or obj.get("HOSTNAME") or os.uname().nodename or "").strip()
        src  = (obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM") or "").strip()

        # Timestamp
        when = dt.datetime.now()
        for k in ("_SOURCE_REALTIME_TIMESTAMP", "__REALTIME_TIMESTAMP"):
            if k in obj:
                try:
                    val = int(obj[k])
                    # journalctl uses usec; some builds nanosec; handle both
                    when = dt.datetime.fromtimestamp(val / (1_000_000 if val > 10**13 else 1_000))
                except Exception:
                    pass
                break

        # SSH accepted
        m = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+)", msg)
        if m:
            user, ip = m.group(1), m.group(2)
            return ActivityEvent(when, user, host, EVENT_LOGIN_SUCCESS, src or "sshd", {"from": ip})

        # SSH failed
        m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", msg)
        if m:
            user, ip = m.group(1), m.group(2)
            return ActivityEvent(when, user, host, EVENT_LOGIN_FAILURE, src or "sshd", {"from": ip})

        # sudo privilege escalation
        if "sudo:" in msg and "USER=root" in msg:
            m = re.search(r"sudo:\s+(\S+)\s*:", msg)
            user = m.group(1) if m else "N/A"
            return ActivityEvent(when, user, host, EVENT_PRIV_ESC, src or "sudo", {"details": msg})

        # sudo/cron commands
        if src in ("sudo", "cron") and "COMMAND=" in msg:
            m = re.search(r"COMMAND=([^;]+)$", msg)
            cmd = m.group(1) if m else msg
            return ActivityEvent(when, "N/A", host, EVENT_PROCESS, src, {"cmd": cmd})

        # systemd-logind sessions
        if "SESSION_START" in msg or "New session" in msg:
            m = re.search(r"for user (\S+)", msg)
            if m:
                user = m.group(1)
                return ActivityEvent(when, user, host, EVENT_LOGIN_SUCCESS, src or "systemd-logind", {})

        return None

    def _parse_authlog_tail(self) -> List[ActivityEvent]:
        path = "/var/log/auth.log"
        if not os.path.exists(path):
            return []
        out: List[ActivityEvent] = []
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f.readlines()[-4000:]:
                    evt = self._parse_auth_line(line)
                    if evt:
                        out.append(evt)
        except Exception as e:
            self._log(f"auth.log read error: {e}")
        out.sort(key=lambda e: e.when, reverse=True)
        return out

    def _parse_auth_line(self, line: str) -> Optional[ActivityEvent]:
        m = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[\d+\]:\s*(.*)$", line)
        if not m:
            return None
        ts_s, host, src, msg = m.groups()
        try:
            when = dt.datetime.strptime(f"{ts_s} {dt.datetime.now().year}", "%b %d %H:%M:%S %Y")
        except Exception:
            when = dt.datetime.now()

        m2 = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+)", msg)
        if m2:
            user, ip = m2.group(1), m2.group(2)
            return ActivityEvent(when, user, host, EVENT_LOGIN_SUCCESS, "sshd", {"from": ip})

        m2 = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", msg)
        if m2:
            user, ip = m2.group(1), m2.group(2)
            return ActivityEvent(when, user, host, EVENT_LOGIN_FAILURE, "sshd", {"from": ip})

        if "sudo:" in msg and "USER=root" in msg:
            m2 = re.search(r"sudo:\s+(\S+)\s*:", msg)
            user = m2.group(1) if m2 else "N/A"
            return ActivityEvent(when, user, host, EVENT_PRIV_ESC, "sudo", {"details": msg})

        if "sudo:" in msg and "COMMAND=" in msg:
            m2 = re.search(r"COMMAND=([^;]+)$", msg)
            cmd = m2.group(1) if m2 else msg
            return ActivityEvent(when, "N/A", host, EVENT_PROCESS, "sudo", {"cmd": cmd})

        m2 = re.search(r"session opened for user (\S+)", msg)
        if m2:
            return ActivityEvent(when, m2.group(1), host, EVENT_LOGIN_SUCCESS, src, {})

        return None


@contextlib.contextmanager
def _silent():
    try:
        yield
    except Exception:
        pass


# ----------------------------- Models -----------------------------

class _SystemModel(QAbstractTableModel):
    HEADERS = ["Time", "User", "Host", "Type", "Source", "Details"]

    def __init__(self):
        super().__init__()
        self._rows: List[ActivityEvent] = []
        self._filtered: List[ActivityEvent] = []
        self._user_q = ""
        self._type_q = "All"

    def set_rows(self, rows: List[ActivityEvent]):
        self.beginResetModel()
        self._rows = list(rows)
        self._apply()
        self.endResetModel()

    def prepend(self, rows: List[ActivityEvent]):
        if not rows: return
        self.beginResetModel()
        self._rows = list(rows) + self._rows
        self._apply()
        self.endResetModel()

    def set_filter(self, user: str, etype: str):
        self.beginResetModel()
        self._user_q = (user or "").strip().lower()
        self._type_q = etype
        self._apply()
        self.endResetModel()

    def _apply(self):
        def ok(e: ActivityEvent):
            if self._user_q and self._user_q not in (e.user or "").lower(): return False
            if self._type_q not in ("All", "", None) and e.event_type != self._type_q: return False
            return True
        self._filtered = [e for e in self._rows if ok(e)]

    def rowCount(self, parent=QModelIndex()) -> int: return len(self._filtered)
    def columnCount(self, parent=QModelIndex()) -> int: return len(self.HEADERS)
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole: return None
        return self.HEADERS[section] if orientation == Qt.Horizontal else section + 1
    def data(self, idx: QModelIndex, role=Qt.DisplayRole):
        if not idx.isValid() or role not in (Qt.DisplayRole, Qt.ToolTipRole): return None
        return self._filtered[idx.row()].to_row()[idx.column()]
    def current_rows(self) -> List[ActivityEvent]: return self._filtered


# ----------------------------- Widget -----------------------------

class UserActivityWidget(BaseToolWidget):
    """
    Combined user activity viewer:
      - System Logs (journalctl/auth.log) with live tail + filters
      - App Log (AppConfig.ACTIVITY_LOG_FILE) with refresh/export/clear
    """
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)

        self.engine = _UserActivityEngine(logger=self._log)
        self._live_task: Optional[asyncio.Task] = None
        self._live = False

        tabs = QTabWidget(self)
        root = QVBoxLayout(self)
        root.addWidget(tabs)

        # -------- Tab 1: System Logs --------
        sys_tab = QWidget()
        tabs.addTab(sys_tab, "System Logs")

        sys_layout = QVBoxLayout(sys_tab)
        sys_bar = QHBoxLayout()
        sys_bar.addWidget(_lbl("User filter:"))
        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("e.g., root, kali, ubuntu")
        sys_bar.addWidget(self.user_edit)

        sys_bar.addWidget(_lbl("Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All", EVENT_LOGIN_SUCCESS, EVENT_LOGIN_FAILURE, EVENT_PRIV_ESC, EVENT_PROCESS, EVENT_OTHER])
        sys_bar.addWidget(self.type_combo)
        sys_bar.addStretch()

        self.refresh_btn = QPushButton("Refresh")
        self.live_btn = QPushButton("Start Live")
        self.export_sys_btn = QPushButton("Export CSV")
        sys_bar.addWidget(self.refresh_btn)
        sys_bar.addWidget(self.live_btn)
        sys_bar.addWidget(self.export_sys_btn)
        sys_layout.addLayout(sys_bar)

        self.sys_table = QTableView()
        self.sys_table.setAlternatingRowColors(True)
        self.sys_table.horizontalHeader().setStretchLastSection(True)
        self.sys_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.sys_model = _SystemModel()
        self.sys_table.setModel(self.sys_model)
        sys_layout.addWidget(self.sys_table)

        self.refresh_btn.clicked.connect(self._on_refresh_system)
        self.live_btn.clicked.connect(self._on_toggle_live)
        self.export_sys_btn.clicked.connect(self._export_system)
        self.user_edit.textChanged.connect(self._apply_filters)
        self.type_combo.currentTextChanged.connect(self._apply_filters)

        # -------- Tab 2: App Log --------
        app_tab = QWidget()
        tabs.addTab(app_tab, "App Log")

        app_layout = QVBoxLayout(app_tab)
        self.app_table = QTableWidget()
        self.app_table.setColumnCount(3)
        self.app_table.setHorizontalHeaderLabels(["Timestamp", "Action", "Details"])
        app_header = self.app_table.horizontalHeader()
        app_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        app_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        app_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.app_table.setAlternatingRowColors(True)
        self.app_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        app_layout.addWidget(self.app_table)

        app_bar = QHBoxLayout()
        self.app_refresh_btn = QPushButton("Refresh")
        self.app_export_btn = QPushButton("Export to CSV")
        self.app_clear_btn = QPushButton("Clear Log")
        app_bar.addWidget(self.app_refresh_btn)
        app_bar.addStretch()
        app_bar.addWidget(self.app_export_btn)
        app_bar.addWidget(self.app_clear_btn)
        app_layout.addLayout(app_bar)

        self.app_refresh_btn.clicked.connect(self._load_app_logs)
        self.app_export_btn.clicked.connect(self._export_app_logs)
        self.app_clear_btn.clicked.connect(self._clear_app_logs)

        # Initial loads
        self._on_refresh_system()
        self._load_app_logs()

    # ---------------- Base helpers ----------------
    def _log(self, s: str):  # attach to external log if needed
        pass

    # ---------------- System tab actions ----------------
    def _apply_filters(self):
        self.sys_model.set_filter(self.user_edit.text(), self.type_combo.currentText())

    def _on_refresh_system(self):
        async def job():
            rows = await self.engine.fetch_recent(limit=600)
            self.sys_model.set_rows(rows)
            if not rows:
                QMessageBox.information(
                    self, "No Activity",
                    "No system events found.\n\nOn Kali, run the app as root OR add your user to the 'adm' group to read logs:\n"
                    "  sudo usermod -aG adm $USER\n  newgrp adm\nThen restart the application."
                )
        self.task_manager.create_task(job())

    def _on_toggle_live(self):
        if self._live:
            self.engine.stop()
            if self._live_task:
                self._live_task.cancel()
            self._live = False
            self.live_btn.setText("Start Live")
            return

        self._live = True
        self.live_btn.setText("Stop Live")

        async def tail():
            try:
                async for evt in self.engine.stream_live():
                    self.sys_model.prepend([evt])
            except asyncio.CancelledError:
                pass
            finally:
                self._live = False
                self.live_btn.setText("Start Live")

        self._live_task = self.task_manager.create_task(tail())

    def _export_system(self):
        rows = self.sys_model.current_rows()
        if not rows:
            QMessageBox.information(self, "Export", "No rows to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export System Log", "system_user_activity.csv", "CSV (*.csv)")
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(_SystemModel.HEADERS)
                for e in rows:
                    w.writerow(e.to_row())
            QMessageBox.information(self, "Export", f"Saved {len(rows)} rows to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    # ---------------- App log tab actions ----------------
    def _load_app_logs(self):
        self.app_table.setRowCount(0)
        if not AppConfig.ACTIVITY_LOG_FILE.exists():
            return
        try:
            with open(AppConfig.ACTIVITY_LOG_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in reversed(lines):
                    parts = line.strip().split(" - ", 2)
                    if len(parts) == 3:
                        row_pos = self.app_table.rowCount()
                        self.app_table.insertRow(row_pos)
                        self.app_table.setItem(row_pos, 0, QTableWidgetItem(parts[0]))
                        self.app_table.setItem(row_pos, 1, QTableWidgetItem(parts[1]))
                        self.app_table.setItem(row_pos, 2, QTableWidgetItem(parts[2]))
        except Exception as e:
            QMessageBox.critical(self, "Read Error", f"Failed to read activity log: {e}")

    def _export_app_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export App Log", "user_activity.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                header = [self.app_table.horizontalHeaderItem(i).text() for i in range(self.app_table.columnCount())]
                writer.writerow(header)
                for row in range(self.app_table.rowCount()):
                    row_data = [self.app_table.item(row, col).text() if self.app_table.item(row, col) else "" for col in range(self.app_table.columnCount())]
                    writer.writerow(row_data)
            QMessageBox.information(self, "Export", f"Log exported to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export log: {e}")

    def _clear_app_logs(self):
        reply = QMessageBox.question(self, "Confirm Clear",
                                     "Are you sure you want to permanently delete the app user activity log?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                if AppConfig.ACTIVITY_LOG_FILE.exists():
                    open(AppConfig.ACTIVITY_LOG_FILE, 'w').close()
                self._load_app_logs()
            except Exception as e:
                QMessageBox.critical(self, "Clear Error", f"Could not clear log file: {e}")


def _lbl(text: str):
    from PySide6.QtWidgets import QLabel
    l = QLabel(text)
    return l

