# -*- coding: utf-8 -*-
import json
import networkx as nx
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QPushButton, QGraphicsView, QGraphicsScene,
    QMessageBox, QTextEdit, QSizePolicy, QGraphicsObject, QGraphicsItem,
    QHBoxLayout, QFileDialog, QWidget, QSplitter, QLineEdit, QMenu,
    QInputDialog
)
from PySide6.QtGui import QPainter, QPen, QBrush, QColor, QFont, QPainterPath, QImage
from PySide6.QtCore import Qt, QPointF, QRectF
from PySide6.QtWebEngineWidgets import QWebEngineView

from app.advanced_features.config_management import DEVICES_FILE
from app.core.task_manager import TaskManager
from app.core.credentials_manager import CredentialsManager
from app.core.device_connector import DeviceConnector
from app.core.topology_discoverer import TopologyDiscoverer
# --- NEW: Import the network scanning engine ---
from app.core.nac_engine import NacEngine
from app.core.system_tools import SystemTools

class DeviceNode(QGraphicsObject):
    """A custom, interactive graphics item representing a network device."""
    def __init__(self, name, device_type="unknown", ip="N/A", vendor="N/A"):
        super().__init__()
        self.name = name
        self.device_type = device_type
        self.ip = ip
        self.vendor = vendor
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setCacheMode(QGraphicsItem.CacheMode.DeviceCoordinateCache)
        self.setToolTip(f"Host: {self.name}\nIP: {self.ip}\nType: {self.device_type}\nVendor: {self.vendor}")
        
        self.edges = []

    def boundingRect(self):
        return QRectF(-60, -30, 120, 60)

    def paint(self, painter, option, widget):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        body_color = QColor("#e9e9e9")
        border_color = QColor("#333333")
        if self.isSelected():
            body_color = QColor("#a6d8ff")
            border_color = QColor("#0078d4")
            
        painter.setBrush(QBrush(body_color))
        painter.setPen(QPen(border_color, 2))
        path = QPainterPath()
        path.addRoundedRect(self.boundingRect(), 10, 10)
        painter.drawPath(path)

        font = QFont("Consolas", 10, QFont.Weight.Bold)
        painter.setFont(font)
        painter.setPen(Qt.GlobalColor.black)
        
        name_rect = QRectF(-60, -30, 120, 30)
        painter.drawText(name_rect, Qt.AlignmentFlag.AlignCenter, self.name)
        
        font.setBold(False)
        painter.setFont(font)
        ip_rect = QRectF(-60, -5, 120, 30)
        painter.drawText(ip_rect, Qt.AlignmentFlag.AlignCenter, self.ip)
        
    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self.edges:
                edge.adjust()
        return super().itemChange(change, value)

    def contextMenuEvent(self, event):
        menu = QMenu()
        open_web_action = menu.addAction("Open Web Admin")
        action = menu.exec(event.screenPos())
        if action == open_web_action:
            parent_dialog = self.scene().views()[0].parent().parent()
            if isinstance(parent_dialog, TopologyDialog):
                parent_dialog.load_in_browser(self.ip)

class Edge(QGraphicsItem):
    def __init__(self, source_node, dest_node):
        super().__init__()
        self.source = source_node
        self.dest = dest_node
        self.source.edges.append(self)
        self.dest.edges.append(self)
        self.setZValue(-1)

    def adjust(self):
        self.prepareGeometryChange()
        self.update()

    def boundingRect(self):
        return QRectF(self.source.pos(), self.dest.pos()).normalized()

    def paint(self, painter, option, widget):
        line = QPainterPath(self.source.pos())
        line.lineTo(self.dest.pos())
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#555555"), 2, Qt.PenStyle.SolidLine))
        painter.drawPath(line)

class TopologyDialog(QDialog):
    def __init__(self, settings, task_manager: TaskManager, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.settings = settings
        self.task_manager = task_manager
        self.devices = self._load_devices()
        self.connector = DeviceConnector()
        self.cred_manager = CredentialsManager()
        # --- NEW: Initialize scan engines ---
        self.scan_engine = NacEngine()
        self.system_tools = SystemTools()
        
        self.setWindowTitle("Network Topology Discovery & Management")
        self.setMinimumSize(1200, 800)
        
        main_layout = QVBoxLayout(self)
        
        control_bar = QHBoxLayout()
        self.discover_ssh_btn = QPushButton("Discover from SSH/CDP")
        # --- NEW: Scan Button ---
        self.discover_scan_btn = QPushButton("Discover from Network Scan")
        self.recalc_layout_btn = QPushButton("Recalculate Layout")
        self.fit_view_btn = QPushButton("Fit to View")
        self.zoom_in_btn = QPushButton("+"); self.zoom_out_btn = QPushButton("-")
        self.export_btn = QPushButton("Export as PNG")
        control_bar.addWidget(self.discover_ssh_btn)
        control_bar.addWidget(self.discover_scan_btn)
        control_bar.addWidget(self.recalc_layout_btn)
        control_bar.addWidget(self.fit_view_btn)
        control_bar.addWidget(self.zoom_in_btn); control_bar.addWidget(self.zoom_out_btn)
        control_bar.addStretch()
        control_bar.addWidget(self.export_btn)
        main_layout.addLayout(control_bar)
        
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        
        topology_widget = QWidget()
        topology_layout = QHBoxLayout(topology_widget)
        topology_layout.setContentsMargins(0,0,0,0)
        self.scene = QGraphicsScene()
        self.scene.setBackgroundBrush(QColor("#F0F0F0"))
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        topology_layout.addWidget(self.view)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumWidth(300)
        topology_layout.addWidget(self.log_output)
        main_splitter.addWidget(topology_widget)
        
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
        
        main_splitter.setSizes([600, 200])
        main_layout.addWidget(main_splitter)
        
        self.discover_ssh_btn.clicked.connect(self.start_ssh_discovery)
        self.discover_scan_btn.clicked.connect(self.start_scan_discovery)
        self.recalc_layout_btn.clicked.connect(self.recalculate_layout)
        self.fit_view_btn.clicked.connect(self.fit_to_view)
        self.export_btn.clicked.connect(self.export_as_png)
        self.zoom_in_btn.clicked.connect(lambda: self.view.scale(1.2, 1.2))
        self.zoom_out_btn.clicked.connect(lambda: self.view.scale(0.8, 0.8))
        self.go_btn.clicked.connect(lambda: self.load_in_browser(self.url_input.text()))
        self.url_input.returnPressed.connect(self.go_btn.click)
        
    def log(self, message):
        self.log_output.append(message)
        self.log_output.verticalScrollBar().setValue(self.log_output.verticalScrollBar().maximum())

    def _load_devices(self):
        if not DEVICES_FILE.exists(): return []
        try:
            with open(DEVICES_FILE, 'r') as f: return json.load(f)
        except (json.JSONDecodeError, IOError): return []

    def start_ssh_discovery(self):
        if not self.devices:
            QMessageBox.warning(self, "No Devices", "No devices found. Please add devices in 'Config Management' first.")
            return
        self.log_output.clear(); self.scene.clear()
        self.set_controls_enabled(False)
        self.log("Starting topology discovery from SSH/CDP...")
        self.task_manager.create_task(self.run_ssh_and_draw())

    async def run_ssh_and_draw(self):
        discoverer = TopologyDiscoverer(self.connector, self.cred_manager, self.log)
        graph, status = await discoverer.discover_from_seeds(self.devices)
        self.log(status)
        if not graph.nodes:
            self.log("No topology information could be discovered.")
        else:
            self.draw_graph(graph)
        self.set_controls_enabled(True)

    def start_scan_discovery(self):
        default_target = self.system_tools.get_default_lan_info().get('cidr', "192.168.1.0/24")
        target_cidr, ok = QInputDialog.getText(self, "Network Scan Discovery", "Enter Target Network (CIDR format):", text=default_target)
        if ok and target_cidr:
            self.log_output.clear(); self.scene.clear()
            self.set_controls_enabled(False)
            self.log(f"Starting discovery by scanning {target_cidr}...")
            self.task_manager.create_task(self.run_scan_and_draw(target_cidr))

    async def run_scan_and_draw(self, target_cidr):
        graph = nx.Graph()
        local_info = self.system_tools.get_default_lan_info()
        local_host = local_info.get('ip', 'localhost')
        # --- FIX: Determine which interface to use for the scan ---
        interface = local_info.get('adapter')
        if not interface:
            self.log("ERROR: Could not determine a network interface to scan with.")
            self.set_controls_enabled(True)
            return

        graph.add_node(local_host, ip=local_host, vendor="Local Machine")

        self.log(f"Scanning for live hosts on interface {interface}...")
        # --- FIX: Pass the required 'interface' argument to the scanner ---
        async for device in self.scan_engine.discover_devices(target_cidr, interface):
            ip = device.get('ip')
            vendor = device.get('vendor', 'Unknown')
            self.log(f"Found: {ip} ({vendor})")
            graph.add_node(ip, ip=ip, vendor=vendor)
            graph.add_edge(local_host, ip)
        
        self.log("Scan finished.")
        self.draw_graph(graph)
        self.set_controls_enabled(True)

    def draw_graph(self, graph):
        self.scene.clear()
        self.current_graph = graph
        positions = nx.spring_layout(self.current_graph, scale=400, iterations=150)
        nodes = {}
        for node_name, data in self.current_graph.nodes(data=True):
            ip = data.get('ip', 'N/A')
            vendor = data.get('vendor', 'N/A')
            device_info = next((d for d in self.devices if d["host"] == node_name), {})
            device_type = device_info.get("device_type", "Scanned Host")
            node = DeviceNode(node_name, device_type, ip, vendor)
            self.scene.addItem(node)
            node.setPos(QPointF(positions[node_name][0], positions[node_name][1]))
            nodes[node_name] = node
        for edge in self.current_graph.edges():
            source_node = nodes.get(edge[0])
            dest_node = nodes.get(edge[1])
            if source_node and dest_node:
                self.scene.addItem(Edge(source_node, dest_node))
        self.fit_to_view()

    def recalculate_layout(self):
        if hasattr(self, 'current_graph') and self.current_graph:
            self.draw_graph(self.current_graph)
    
    def fit_to_view(self):
        if not self.scene.itemsBoundingRect().isEmpty():
            self.view.fitInView(self.scene.itemsBoundingRect().adjusted(-20, -20, 20, 20), Qt.AspectRatioMode.KeepAspectRatio)

    def export_as_png(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export as PNG", "topology.png", "PNG Image (*.png)")
        if not path: return
        image = QImage(self.scene.sceneRect().size().toSize(), QImage.Format.Format_ARGB32)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        self.scene.render(painter)
        painter.end()
        image.save(path)
        self.log(f"Topology exported to {path}")

    def set_controls_enabled(self, enabled: bool):
        self.discover_ssh_btn.setEnabled(enabled)
        self.discover_scan_btn.setEnabled(enabled)
        self.recalc_layout_btn.setEnabled(enabled)
        self.fit_view_btn.setEnabled(enabled)
        self.export_btn.setEnabled(enabled)

    def load_in_browser(self, url_or_ip):
        if not url_or_ip or url_or_ip == 'N/A': return
        if not url_or_ip.startswith(('http://', 'https://')):
            url = f"http://{url_or_ip}"
        else:
            url = url_or_ip
        from PySide6.QtCore import QUrl
        self.browser.setUrl(QUrl(url))
        self.url_input.setText(url)