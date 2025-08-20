# -*- coding: utf-8 -*-
import datetime
import logging
import psutil
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QComboBox, QPushButton, QLineEdit,
    QLabel, QGroupBox, QTableWidget, QTableWidgetItem, QMessageBox,
    QHeaderView, QSplitter, QTextEdit, QFileDialog
)
from PySide6.QtCore import Qt, QThread, Signal
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, wrpcap, Packet
from app.core.system_tools import SystemTools

class CaptureWorker(QThread):
    packet_captured = Signal(object)
    def __init__(self, interface, filter_exp, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.filter_exp = filter_exp
        self.is_running = True

    def run(self):
        try:
            sniff(iface=self.interface, prn=self.emit_packet,
                  filter=self.filter_exp, stop_filter=lambda p: not self.is_running)
        except Exception as e:
            logging.error(f"Scapy sniff error: {e}")

    def emit_packet(self, packet):
        self.packet_captured.emit(packet)

    def stop(self):
        self.is_running = False

class PacketCaptureDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Window | Qt.WindowType.WindowMinimizeButtonHint |
            Qt.WindowType.WindowMaximizeButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.setWindowTitle("Incident Response - Packet Capture")
        self.setMinimumSize(1000, 800)
        self.resize(1000, 800)
        self.capture_thread = None
        self.captured_packets = []
        self.system_tools = SystemTools() # Instance of SystemTools
        main_layout = QVBoxLayout(self)
        controls_group = QGroupBox("Capture Controls")
        controls_layout = QHBoxLayout(controls_group)
        self.iface_combo = QComboBox()
        
        # FIX: Populate with usable interfaces only
        self.iface_combo.addItems(self.system_tools.get_usable_interfaces())
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText('BPF Filter (e.g., "tcp port 443")')
        self.start_btn = QPushButton("Start Capture")
        self.stop_btn = QPushButton("Stop Capture")
        self.clear_btn = QPushButton("Clear")
        self.save_btn = QPushButton("Save to PCAP")
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(QLabel("Interface:"))
        controls_layout.addWidget(self.iface_combo)
        controls_layout.addWidget(QLabel("Filter:"))
        controls_layout.addWidget(self.filter_input)
        controls_layout.addWidget(self.start_btn)
        controls_layout.addWidget(self.stop_btn)
        controls_layout.addWidget(self.clear_btn)
        controls_layout.addWidget(self.save_btn)
        main_layout.addWidget(controls_group)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        splitter.addWidget(self.packet_table)
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setFontFamily("Consolas")
        splitter.addWidget(self.detail_view)
        splitter.setSizes([500, 300])
        main_layout.addWidget(splitter)
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.clear_btn.clicked.connect(self.clear_capture)
        self.save_btn.clicked.connect(self.save_capture)
        self.packet_table.itemSelectionChanged.connect(self.display_packet_details)
        self.check_permissions()

    def check_permissions(self):
        import os
        if os.name == 'posix' and os.geteuid() != 0:
            QMessageBox.warning(self, "Permissions Warning",
                "On Linux and macOS, this tool may need to be run with root privileges (sudo) to capture packets.")

    def start_capture(self):
        interface = self.iface_combo.currentText()
        if not interface:
            QMessageBox.critical(self, "Error", "No usable network interface found or selected.")
            return
        filter_exp = self.filter_input.text()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.capture_thread = CaptureWorker(interface, filter_exp)
        self.capture_thread.packet_captured.connect(self.add_packet_to_table)
        self.capture_thread.start()

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait(1000)
            self.capture_thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.iface_combo.setEnabled(True)

    def add_packet_to_table(self, packet: Packet):
        self.captured_packets.append(packet)
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        proto, src, dst, info = "Unknown", "N/A", "N/A", packet.summary()
        if packet.haslayer("IP"):
            src, dst, proto = packet["IP"].src, packet["IP"].dst, packet["IP"].sprintf("%IP.proto%")
        elif packet.haslayer("ARP"):
            src, dst, proto = packet["ARP"].psrc, packet["ARP"].pdst, "ARP"
        if "TCP" in proto: proto = "TCP"
        if "UDP" in proto: proto = "UDP"
        if "ICMP" in proto: proto = "ICMP"
        timestamp = datetime.datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')
        self.packet_table.setItem(row_position, 0, QTableWidgetItem(str(row_position + 1)))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(timestamp))
        self.packet_table.setItem(row_position, 2, QTableWidgetItem(src))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(dst))
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(proto))
        self.packet_table.setItem(row_position, 5, QTableWidgetItem(str(len(packet))))
        self.packet_table.setItem(row_position, 6, QTableWidgetItem(info))
        scrollbar = self.packet_table.verticalScrollBar()
        if scrollbar.value() == scrollbar.maximum():
            scrollbar.setValue(scrollbar.maximum())

    def display_packet_details(self):
        selected_rows = self.packet_table.selectionModel().selectedRows()
        if not selected_rows: return
        row_index = selected_rows[0].row()
        packet = self.captured_packets[row_index]
        self.detail_view.setText(packet.show(dump=True))

    def clear_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            QMessageBox.warning(self, "Warning", "Please stop the capture before clearing.")
            return
        self.captured_packets.clear()
        self.packet_table.setRowCount(0)
        self.detail_view.clear()

    def save_capture(self):
        if not self.captured_packets:
            QMessageBox.warning(self, "No Data", "There are no captured packets to save.")
            return
        if self.capture_thread and self.capture_thread.isRunning():
            self.stop_capture()
        filename = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path, _ = QFileDialog.getSaveFileName(self, "Save PCAP File", filename, "PCAP Files (*.pcap *.pcapng)")
        if path:
            try:
                wrpcap(path, self.captured_packets)
                QMessageBox.information(self, "Success", f"Capture saved to {path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {e}")

    def closeEvent(self, event):
        self.stop_capture()
        super().closeEvent(event)