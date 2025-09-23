# app/advanced_features/topology.py
# REFACTORED & POLISHED:
# - Guarantees nodes have a details dict (hostname, subnet_mask, technology, username).
# - Normalizes legacy nodes (if details missing, build it from top-level keys).
# - Better card rendering with auto text wrapping and dynamic height.
# - Same public UI and behaviors, just nicer + reliable.

import json
import os
import getpass
import platform as py_platform
from typing import Dict, List, Tuple

import networkx as nx
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QGraphicsView, QGraphicsScene,
    QMessageBox, QTextEdit, QGraphicsObject, QGraphicsItem,
    QHBoxLayout, QFileDialog, QSplitter, QLineEdit, QMenu,
    QInputDialog
)
from PySide6.QtGui import (
    QPainter, QPen, QBrush, QColor, QFont, QPainterPath, QImage, QFontMetricsF
)
from PySide6.QtCore import Qt, QPointF, QRectF, QSizeF, QMarginsF
from PySide6.QtWebEngineWidgets import QWebEngineView

from app.config import AppConfig
from app.widgets.base_widget import BaseToolWidget
from app.core.task_manager import TaskManager
from app.core.credentials_manager import CredentialsManager
from app.core.device_connector import DeviceConnector
from app.core.topology_discoverer import TopologyDiscoverer
from app.core.nac_engine import NacEngine
from app.core.system_tools import SystemTools

DEVICES_FILE = AppConfig.PROJECT_ROOT / "device_configs" / "devices.json"


# --------------------------
# Card / Edge Graphics Items
# --------------------------

class DeviceNode(QGraphicsObject):
    """
    A clean, auto-wrapping device card. Content determines height, so text never overflows.
    """
    CARD_WIDTH = 260.0
    PADDING = QMarginsF(14, 12, 14, 12)
    RADIUS = 14.0
    GAP = 6.0

    def __init__(self, name: str, device_type: str = "Host",
                 ip: str = "N/A", mac: str = "N/A", vendor: str = "N/A",
                 details: Dict = None):
        super().__init__()
        self.name = name or "Host"
        self.device_type = device_type or "Host"
        self.ip = ip or "N/A"
        self.mac = mac or "N/A"
        self.vendor = vendor or "N/A"
        self.details = details or {}

        # Interactivity
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setCacheMode(QGraphicsItem.CacheMode.DeviceCoordinateCache)

        # Fonts
        self.font_title = QFont("Inter, Segoe UI, Ubuntu, DejaVu Sans, Arial", 11, QFont.Weight.Bold)
        self.font_subtitle = QFont("Inter, Segoe UI, Ubuntu, DejaVu Sans, Arial", 9, QFont.Weight.DemiBold)
        self.font_body = QFont("Inter, Segoe UI, Ubuntu, DejaVu Sans, Arial", 9)

        self._edges: List["Edge"] = []

        # Precompute layout metrics
        self._lines_title: List[str] = []
        self._lines: List[Tuple[QFont, str]] = []
        self._bounding = QRectF(0, 0, self.CARD_WIDTH, 120)
        self._rebuild_layout()

        # Tooltip
        tooltip = f"{self.device_type}\nIP: {self.ip}\nMAC: {self.mac}\nVendor: {self.vendor}"
        for k in ("subnet_mask", "hostname", "technology", "username"):
            if k in self.details and self.details[k]:
                tooltip += f"\n{k.replace('_',' ').title()}: {self.details[k]}"
        self.setToolTip(tooltip)

    # ---- public helpers ----
    def add_edge(self, edge: "Edge"):
        self._edges.append(edge)

    # ---- layout + rendering ----
    def _wrap_text(self, painter: QPainter, text: str, font: QFont, width: float) -> List[str]:
        fm = QFontMetricsF(font)
        wrapped: List[str] = []
        line = ""
        for word in text.split():
            probe = f"{line} {word}".strip()
            if fm.horizontalAdvance(probe) <= width:
                line = probe
            else:
                if line:
                    wrapped.append(line)
                line = word
        if line:
            wrapped.append(line)
        # ensure at least one line
        return wrapped or [""]

    def _rebuild_layout(self):
        # Recompute bounding rect based on content
        w = self.CARD_WIDTH
        content_width = w - self.PADDING.left() - self.PADDING.right()

        # Title / header lines
        self._lines_title = [self.name]

        # The detail stack in drawing order
        body_pairs: List[Tuple[str, str]] = [
            ("Type", self.device_type),
            ("IP", self.ip),
            ("MAC", self.mac),
            ("Vendor", self.vendor),
        ]

        for key in ("subnet_mask", "hostname", "technology", "username"):
            val = self.details.get(key, None)
            if val:
                body_pairs.append((key.replace("_", " ").title(), str(val)))

        # Build wrapped lines with fonts attached
        self._lines = []
        # Title
        for ln in self._lines_title:
            self._lines.append((self.font_title, ln))
        # Small gap
        self._lines.append((self.font_body, ""))

        # Body: "Label: value"
        for label, value in body_pairs:
            line = f"{label}: {value}"
            for wrapped in self._wrap_text(None, line, self.font_body, content_width):
                self._lines.append((self.font_body, wrapped))

        # Compute height
        y = self.PADDING.top()
        fm_title = QFontMetricsF(self.font_title)
        fm_body = QFontMetricsF(self.font_body)

        line_height_title = fm_title.height()
        line_height_body = fm_body.height()

        # Title (1 line)
        y += line_height_title
        # Gap
        y += self.GAP

        # Count body lines
        body_count = sum(1 for f, _ in self._lines if f is self.font_body)
        y += body_count * line_height_body

        y += self.PADDING.bottom()

        # include top padding for first line
        y += 2.0

        # finalize bounding
        self.prepareGeometryChange()
        self._bounding = QRectF(-w / 2.0, -y / 2.0, w, y)

    def boundingRect(self) -> QRectF:
        return self._bounding

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Colors
        base_bg = QColor("#ffffff")
        base_border = QColor("#D0D5DD")
        title_color = QColor("#111827")
        text_color = QColor("#111827")
        if self.isSelected():
            base_bg = QColor("#E8F3FF")
            base_border = QColor("#3B82F6")

        # Card
        painter.setBrush(QBrush(base_bg))
        painter.setPen(QPen(base_border, 1.8))
        r = self.boundingRect()
        path = QPainterPath()
        path.addRoundedRect(r, self.RADIUS, self.RADIUS)
        painter.drawPath(path)

        # Content rect
        content = r.marginsRemoved(self.PADDING)

        # Draw Title
        painter.setFont(self.font_title)
        painter.setPen(title_color)
        fm_title = QFontMetricsF(self.font_title)
        y = content.top() + fm_title.ascent()

        painter.drawText(QRectF(content.left(), y - fm_title.ascent(), content.width(), fm_title.height()),
                         Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter,
                         self._lines_title[0])

        # Gap
        y += self.GAP + fm_title.descent()

        # Body
        painter.setFont(self.font_body)
        painter.setPen(text_color)
        fm_body = QFontMetricsF(self.font_body)
        # Skip the first body placeholder line (we used a gap already)
        started = False
        for fnt, txt in self._lines:
            if fnt is self.font_title:
                # already drawn
                continue
            if not started:
                started = True
                continue  # skip placeholder

            painter.setFont(fnt)
            fm = QFontMetricsF(fnt)
            painter.drawText(QRectF(content.left(), y, content.width(), fm.height()),
                             Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                             txt)
            y += fm.height()

    # Keep edges stuck to node while moving
    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._edges:
                edge.adjust()
        return super().itemChange(change, value)

    def contextMenuEvent(self, event):
        menu = QMenu()
        open_web_action = menu.addAction("Open Web Admin")
        action = menu.exec(event.screenPos())
        if action == open_web_action:
            parent_widget = self.scene().views()[0]
            while parent_widget and not isinstance(parent_widget, TopologyWidget):
                parent_widget = parent_widget.parent()
            if isinstance(parent_widget, TopologyWidget):
                parent_widget.load_in_browser(self.ip)


class Edge(QGraphicsItem):
    def __init__(self, source_node: DeviceNode, dest_node: DeviceNode):
        super().__init__()
        self.source = source_node
        self.dest = dest_node
        self.source.add_edge(self)
        self.dest.add_edge(self)
        self.setZValue(-1)

    def adjust(self):
        self.prepareGeometryChange()
        self.update()

    def boundingRect(self) -> QRectF:
        return QRectF(self.source.pos(), self.dest.pos()).normalized().adjusted(-4, -4, 4, 4)

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#9CA3AF"), 2))
        path = QPainterPath(self.source.pos())
        path.lineTo(self.dest.pos())
        painter.drawPath(path)


# --------------------------
# Main Widget
# --------------------------

class TopologyWidget(BaseToolWidget):
    def __init__(self, settings, task_manager):
        super().__init__(settings, task_manager)

        self.devices = self._load_devices()
        self.connector = DeviceConnector()
        self.cred_manager = CredentialsManager()
        self.scan_engine = NacEngine()
        self.system_tools = SystemTools()

        main_layout = QVBoxLayout(self)

        # Controls
        control_bar = QHBoxLayout()
        self.discover_ssh_btn = QPushButton("Discover from SSH/CDP")
        self.discover_scan_btn = QPushButton("Discover from Network Scan")
        self.recalc_layout_btn = QPushButton("Recalculate Layout")
        self.fit_view_btn = QPushButton("Fit to View")
        self.zoom_in_btn = QPushButton("+")
        self.zoom_out_btn = QPushButton("-")
        self.export_btn = QPushButton("Export as PNG")
        for w in (self.discover_ssh_btn, self.discover_scan_btn, self.recalc_layout_btn,
                  self.fit_view_btn, self.zoom_in_btn, self.zoom_out_btn, self.export_btn):
            control_bar.addWidget(w)
        control_bar.addStretch()
        main_layout.addLayout(control_bar)

        # Splitter: graph + log / browser
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        # Top: Graph + log
        topology_widget = QWidget()
        topology_layout = QHBoxLayout(topology_widget)
        topology_layout.setContentsMargins(0, 0, 0, 0)

        self.scene = QGraphicsScene()
        self.scene.setBackgroundBrush(QColor("#F8FAFC"))
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        topology_layout.addWidget(self.view)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumWidth(340)
        topology_layout.addWidget(self.log_output)

        main_splitter.addWidget(topology_widget)

        # Bottom: embedded browser
        browser_widget = QWidget()
        browser_layout = QVBoxLayout(browser_widget)
        browser_address_bar = QHBoxLayout()
        self.url_input = QLineEdit()
        self.go_btn = QPushButton("Go")
        browser_address_bar.addWidget(self.url_input)
        browser_address_bar.addWidget(self.go_btn)
        self.browser = QWebEngineView()
        self.browser.setUrl("about:blank")
        browser_layout.addLayout(browser_address_bar)
        browser_layout.addWidget(self.browser)

        main_splitter.addWidget(browser_widget)
        main_splitter.setSizes([720, 260])
        main_layout.addWidget(main_splitter)

        # Signals
        self.discover_ssh_btn.clicked.connect(self.start_ssh_discovery)
        self.discover_scan_btn.clicked.connect(self.start_scan_discovery)
        self.recalc_layout_btn.clicked.connect(self.recalculate_layout)
        self.fit_view_btn.clicked.connect(self.fit_to_view)
        self.export_btn.clicked.connect(self.export_as_png)
        self.zoom_in_btn.clicked.connect(lambda: self.view.scale(1.18, 1.18))
        self.zoom_out_btn.clicked.connect(lambda: self.view.scale(0.85, 0.85))
        self.go_btn.clicked.connect(lambda: self.load_in_browser(self.url_input.text()))
        self.url_input.returnPressed.connect(self.go_btn.click)

        self.current_graph: nx.Graph = nx.Graph()

    # -------------
    # Utilities
    # -------------
    def log(self, message: str):
        self.log_output.append(message)
        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())

    def _load_devices(self):
        if not DEVICES_FILE.exists():
            return []
        try:
            with open(DEVICES_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []

    def _normalize_node_attrs(self, data: Dict) -> Dict:
        """
        Make sure every node has .details with hostname / subnet_mask / technology / username.
        Accepts legacy nodes that may have put hostname etc. at the top level.
        """
        details = data.get("details") or {}
        # pull legacy keys if details missing
        for k in ("hostname", "subnet_mask", "technology", "username"):
            if k not in details:
                v = data.get(k, None)
                if v:
                    details[k] = v

        data["details"] = {
            "hostname": details.get("hostname", "N/A"),
            "subnet_mask": details.get("subnet_mask", "N/A"),
            "technology": details.get("technology", "N/A"),
            "username": details.get("username", "N/A"),
        }
        data["ip"] = data.get("ip", "N/A") or "N/A"
        data["mac"] = data.get("mac", "N/A") or "N/A"
        data["vendor"] = data.get("vendor", "Unknown") or "Unknown"
        data["device_type"] = data.get("device_type", data.get("type", "Host")) or "Host"
        return data

    # ---------------------------
    # SSH/CDP discovery
    # ---------------------------
    def start_ssh_discovery(self):
        if not self.devices:
            self.show_error("No devices found. Please add devices in 'Config Management' first.")
            return
        self.log_output.clear()
        self.scene.clear()
        self.set_controls_enabled(False)
        self.log("Starting topology discovery from SSH/CDP...")
        self.task_manager.create_task(self.run_ssh_and_draw())

    async def run_ssh_and_draw(self):
        discoverer = TopologyDiscoverer(self.connector, self.cred_manager, self.log)
        graph, status = await discoverer.discover_from_seeds(self.devices)
        self.log(status)

        # Normalize attributes for rendering
        for n, data in list(graph.nodes(data=True)):
            graph.nodes[n].update(self._normalize_node_attrs(data))

        if not graph.nodes:
            self.log("No topology information could be discovered.")
        else:
            self.draw_graph(graph)
        self.set_controls_enabled(True)

    # ---------------------------
    # Passive scan discovery
    # ---------------------------
    def start_scan_discovery(self):
        lan_info = self.system_tools.get_default_lan_info()
        default_target = lan_info.get('cidr', "192.168.1.0/24") if lan_info else "192.168.1.0/24"

        target_cidr, ok = QInputDialog.getText(
            self, "Network Scan Discovery", "Enter Target Network (CIDR format):", text=default_target
        )
        if ok and target_cidr:
            self.log_output.clear()
            self.scene.clear()
            self.set_controls_enabled(False)
            self.log(f"Starting discovery by scanning {target_cidr}...")
            self.task_manager.create_task(self.run_scan_and_draw(target_cidr))

    async def run_scan_and_draw(self, target_cidr: str):
        graph = nx.Graph()
        local_info = self.system_tools.get_default_lan_info()
        if not local_info:
            self.log("ERROR: Could not get local machine network details to start the scan.")
            self.set_controls_enabled(True)
            return

        # Local machine node enriched
        local_ip = local_info.get('ip', 'localhost')
        interface = local_info.get('adapter')
        if not interface:
            self.log("ERROR: Could not determine a network interface to scan with.")
            self.set_controls_enabled(True)
            return

        try:
            username = getpass.getuser()
        except Exception:
            username = "N/A"

        local_details = {
            "subnet_mask": local_info.get('subnet_mask', 'N/A'),
            "hostname": py_platform.node() or "N/A",
            "technology": f"{py_platform.system()} {py_platform.release()}",
            "username": username,
        }

        graph.add_node(local_ip, ip=local_ip, mac="N/A", vendor="Local Machine",
                       device_type="Linux", details=local_details)

        self.log(f"Scanning for live hosts on interface {interface}...")
        async for device in self.scan_engine.discover_devices(target_cidr, interface):
            ip = device.get('ip')
            mac = device.get('mac', 'N/A')
            vendor = device.get('vendor', 'Unknown')
            hostname = device.get('hostname', 'N/A')

            node_name = hostname if hostname and hostname != 'N/A' else ip

            node_details = {
                "subnet_mask": device.get('subnet_mask', 'N/A'),
                "hostname": hostname,
                "technology": device.get('technology', 'N/A'),
                "username": device.get('username', 'N/A'),
            }

            self.log(f"Found: {ip} ({mac} - {vendor})")
            graph.add_node(node_name, ip=ip, mac=mac, vendor=vendor,
                           device_type=device.get('device_type', 'Host'),
                           details=node_details)
            graph.add_edge(local_ip, node_name)

        self.log("Scan finished.")

        # Normalize (in case any missing fields slipped in)
        for n, data in list(graph.nodes(data=True)):
            graph.nodes[n].update(self._normalize_node_attrs(data))

        self.draw_graph(graph)
        self.set_controls_enabled(True)

    # ---------------------------
    # Rendering
    # ---------------------------
    def draw_graph(self, graph: nx.Graph):
        self.scene.clear()
        self.current_graph = graph

        # Stable layout
        positions = nx.spring_layout(self.current_graph, scale=520, iterations=180, seed=7)

        # Create nodes
        node_items: Dict[str, DeviceNode] = {}
        for node_name, data in self.current_graph.nodes(data=True):
            data = self._normalize_node_attrs(data)
            ip = data["ip"]
            mac = data["mac"]
            vendor = data["vendor"]
            details = data["details"]
            device_type = data.get("device_type", "Host")

            item = DeviceNode(node_name, device_type, ip, mac, vendor, details)
            self.scene.addItem(item)
            x, y = positions.get(node_name, (0.0, 0.0))
            item.setPos(QPointF(x, y))
            node_items[node_name] = item

        # Create edges
        for src, dst in self.current_graph.edges():
            s = node_items.get(src)
            d = node_items.get(dst)
            if s and d:
                edge = Edge(s, d)
                self.scene.addItem(edge)

        self.fit_to_view()

    def recalculate_layout(self):
        if hasattr(self, 'current_graph') and self.current_graph and len(self.current_graph.nodes) > 0:
            self.draw_graph(self.current_graph)

    def fit_to_view(self):
        rect = self.scene.itemsBoundingRect()
        if not rect.isEmpty():
            self.view.fitInView(rect.adjusted(-36, -36, 36, 36), Qt.AspectRatioMode.KeepAspectRatio)

    def export_as_png(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export as PNG", "topology.png", "PNG Image (*.png)")
        if not path:
            return
        # Compute scene bounds tightly
        rect = self.scene.itemsBoundingRect().adjusted(-24, -24, 24, 24)
        image = QImage(rect.size().toSize(), QImage.Format.Format_ARGB32)
        image.fill(Qt.GlobalColor.white)
        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.scene.render(painter, target=QRectF(image.rect()), source=rect)
        painter.end()
        image.save(path)
        self.log(f"Topology exported to {path}")

    def set_controls_enabled(self, enabled: bool):
        self.discover_ssh_btn.setEnabled(enabled)
        self.discover_scan_btn.setEnabled(enabled)
        self.recalc_layout_btn.setEnabled(enabled)
        self.fit_view_btn.setEnabled(enabled)
        self.export_btn.setEnabled(enabled)
        self.zoom_in_btn.setEnabled(enabled)
        self.zoom_out_btn.setEnabled(enabled)

    def load_in_browser(self, url_or_ip: str):
        if not url_or_ip or url_or_ip == 'N/A':
            return
        url = str(url_or_ip)
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        from PySide6.QtCore import QUrl
        self.browser.setUrl(QUrl(url))
        self.url_input.setText(url)

