# app/core/user_activity_engine.py
# Linux-only user activity collector (Kali friendly).
# Prefers `journalctl -o json`, falls back to parsing /var/log/auth.log.
from __future__ import annotations
import asyncio
import json
import os
import re
import datetime as dt
from dataclasses import dataclass
from typing import AsyncIterator, Callable, Dict, List, Optional, Tuple
import shutil
import contextlib

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

class UserActivityEngine:
    """
    Minimal, robust Linux activity engine:
      - `journalctl -n 1000 -o json --no-pager`
      - fallback: /var/log/auth.log
    Events normalized to: login_success, login_failure, privilege_escalation, process_start, other
    """
    def __init__(self, logger: Optional[Callable[[str], None]] = None):
        self._log = logger or (lambda s: None)
        self._stop = False

    def stop(self):
        self._stop = True

    # ----------------- Public API -----------------
    async def fetch_recent(self, limit: int = 400) -> List[ActivityEvent]:
        evts: List[ActivityEvent] = []
        if shutil.which("journalctl"):
            try:
                cmd = "journalctl -n 1000 -o json --no-pager"
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                out, err = await proc.communicate()
                if proc.returncode == 0:
                    for line in out.decode(errors="ignore").splitlines():
                        evt = self._parse_journal_json(line)
                        if evt:
                            evts.append(evt)
                else:
                    self._log(f"journalctl error: {err.decode(errors='ignore')}")
                    evts.extend(self._parse_authlog_tail())
            except Exception as e:
                self._log(f"journalctl exception: {e}")
                evts.extend(self._parse_authlog_tail())
        else:
            evts.extend(self._parse_authlog_tail())

        evts.sort(key=lambda e: e.when, reverse=True)
        return evts[:limit]

    async def stream_live(self) -> AsyncIterator[ActivityEvent]:
        """
        Live streaming:
          - `journalctl -f -o json --no-pager`
          - fallback `tail -F /var/log/auth.log`
        """
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
                with _silent():
                    proc.terminate()
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
                with _silent():
                    proc.terminate()

    # ----------------- Parsers -----------------
    def _parse_journal_json(self, line: str) -> Optional[ActivityEvent]:
        try:
            obj = json.loads(line)
        except Exception:
            return None

        msg  = (obj.get("MESSAGE") or "").strip()
        host = (obj.get("_HOSTNAME") or obj.get("HOSTNAME") or os.uname().nodename or "").strip()
        src  = (obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM") or "").strip()

        # Timestamp (prefer REALTIME ns)
        when = dt.datetime.now()
        for k in ("_SOURCE_REALTIME_TIMESTAMP", "__REALTIME_TIMESTAMP"):
            if k in obj:
                try:
                    ns = int(obj[k])
                    when = dt.datetime.fromtimestamp(ns / 1_000_000)
                except Exception:
                    pass
                break

        # Classify
        etype = EVENT_OTHER
        user  = "N/A"
        extra: Dict[str, str] = {}

        # SSH logins
        # Accepted password/publickey for <user> from <ip>
        m = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+)", msg)
        if m:
            user, ip = m.group(1), m.group(2)
            etype = EVENT_LOGIN_SUCCESS
            extra["from"] = ip
            return ActivityEvent(when, user, host, etype, src or "sshd", extra)

        # Failed password for (invalid user )?<user> from <ip>
        m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", msg)
        if m:
            user, ip = m.group(1), m.group(2)
            etype = EVENT_LOGIN_FAILURE
            extra["from"] = ip
            return ActivityEvent(when, user, host, etype, src or "sshd", extra)

        # sudo privilege escalation
        # e.g. "sudo: username : TTY=pts/0 ; PWD=/home/username ; USER=root ; COMMAND=/usr/bin/apt update"
        if "sudo:" in msg and "USER=root" in msg:
            m = re.search(r"sudo:\s+(\S+)\s*:", msg)
            if m:
                user = m.group(1)
            etype = EVENT_PRIV_ESC
            extra["details"] = msg
            return ActivityEvent(when, user, host, etype, src or "sudo", extra)

        # Process execution (best effort; many daemons)
        if src in ("sudo", "cron") and "COMMAND=" in msg:
            m = re.search(r"COMMAND=([^;]+)$", msg)
            cmd = m.group(1) if m else msg
            etype = EVENT_PROCESS
            return ActivityEvent(when, user, host, etype, src, {"cmd": cmd})

        # systemd-logind sessions
        if "SESSION_START" in msg or "New session" in msg:
            m = re.search(r"for user (\S+)", msg)
            if m:
                user = m.group(1)
                etype = EVENT_LOGIN_SUCCESS
                return ActivityEvent(when, user, host, etype, src or "systemd-logind", {})

        return None

    def _parse_authlog_tail(self) -> List[ActivityEvent]:
        path = "/var/log/auth.log"
        if not os.path.exists(path):
            return []
        out: List[ActivityEvent] = []
        with open(path, "r", errors="ignore") as f:
            for line in f.readlines()[-4000:]:
                evt = self._parse_auth_line(line)
                if evt:
                    out.append(evt)
        out.sort(key=lambda e: e.when, reverse=True)
        return out

    def _parse_auth_line(self, line: str) -> Optional[ActivityEvent]:
        # "Aug 24 10:12:33 host sshd[1234]: <message>"
        m = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[\d+\]:\s*(.*)$", line)
        if not m:
            return None
        ts_s, host, src, msg = m.groups()
        # Ts has no year; assume current year (OK for "recent")
        try:
            when = dt.datetime.strptime(f"{ts_s} {dt.datetime.now().year}", "%b %d %H:%M:%S %Y")
        except Exception:
            when = dt.datetime.now()

        # Same classifiers as journal
        # success
        m2 = re.search(r"Accepted (?:password|publickey) for (\S+) from (\S+)", msg)
        if m2:
            user, ip = m2.group(1), m2.group(2)
            return ActivityEvent(when, user, host, EVENT_LOGIN_SUCCESS, "sshd", {"from": ip})

        # failure
        m2 = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", msg)
        if m2:
            user, ip = m2.group(1), m2.group(2)
            return ActivityEvent(when, user, host, EVENT_LOGIN_FAILURE, "sshd", {"from": ip})

        # sudo
        if "sudo:" in msg and "USER=root" in msg:
            m2 = re.search(r"sudo:\s+(\S+)\s*:", msg)
            user = m2.group(1) if m2 else "N/A"
            return ActivityEvent(when, user, host, EVENT_PRIV_ESC, "sudo", {"details": msg})

        # process (best effort)
        if "sudo:" in msg and "COMMAND=" in msg:
            m2 = re.search(r"COMMAND=([^;]+)$", msg)
            cmd = m2.group(1) if m2 else msg
            return ActivityEvent(when, "N/A", host, EVENT_PROCESS, "sudo", {"cmd": cmd})

        # PAM/session opened
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

