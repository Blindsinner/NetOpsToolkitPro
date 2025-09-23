# app/advanced_features/incident_response.py
# REFACTORED: Fixed the stop_capture method to prevent crashes.

import datetime
import logging
import queue
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QPushButton, QLineEdit,
    QLabel, QGroupBox, QTableWidget, QTableWidgetItem, QMessageBox,
    QHeaderView, QSplitter, QTextEdit, QFileDialog
)
from PySide6.QtCore import Qt, QTimer

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import wrpcap, Packet
from scapy.config import conf
from scapy.sendrecv import AsyncSniffer

from app.core.task_manager import TaskManager
from app.widgets.base_widget import BaseToolWidget

class PacketCaptureWidget(BaseToolWidget):
    def __init__(self, settings, task_manager): # Standardized constructor
        super().__init__(settings, task_manager)
        
        self.sniffer = None
        self.captured_packets = []
        self.packet_queue = queue.Queue()
        
        self.ui_update_timer = QTimer(self)
        self.ui_update_timer.setInterval(100)
        self.ui_update_timer.timeout.connect(self.process_packet_queue)
        
        main_layout = QVBoxLayout(self)
        controls_group = QGroupBox("Capture Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        self.iface_combo = QComboBox()
        
        try:
            interface_names = list(conf.ifaces.keys())
            self.iface_combo.addItems(interface_names)
        except Exception as e:
            logging.error(f"Could not list interfaces using scapy: {e}")
            self.iface_combo.addItem("Error: Could not list interfaces")

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
    
    def shutdown(self):
        """Gracefully stop the packet sniffer."""
        print("Shutting down packet sniffer...")
        self.stop_capture()

    def check_permissions(self):
        import os
        if os.name == 'posix' and os.geteuid() != 0:
            QMessageBox.warning(self, "Permissions Warning",
                "On Linux and macOS, this tool may need to be run with root privileges (sudo) to capture packets.")

    def start_capture(self):
        interface = self.iface_combo.currentText()
        if not interface or "Error" in interface:
            self.show_error("No usable network interface found or selected.")
            return
            
        filter_exp = self.filter_input.text()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        
        self.sniffer = AsyncSniffer(
            iface=interface,
            prn=lambda pkt: self.packet_queue.put(pkt),
            filter=filter_exp,
            store=False
        )
        self.sniffer.start()
        self.ui_update_timer.start()

    def stop_capture(self):
        # FIX: This robustly stops the sniffer thread and prevents crashes.
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop(join=True) # Tell the thread to stop and wait for it
        
        self.ui_update_timer.stop()
        # Drain the queue of any remaining packets after stopping
        self.process_packet_queue()
        
        self.sniffer = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.iface_combo.setEnabled(True)

    def process_packet_queue(self):
        while not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get_nowait()
                self.add_packet_to_table(packet)
            except queue.Empty:
                break

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
        if self.sniffer:
            QMessageBox.warning(self, "Warning", "Please stop the capture before clearing.")
            return
            
        self.captured_packets.clear()
        self.packet_table.setRowCount(0)
        self.detail_view.clear()

    def save_capture(self):
        if not self.captured_packets:
            self.show_error("There are no captured packets to save.")
            return
            
        if self.sniffer:
            self.stop_capture()
            
        filename = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        path, _ = QFileDialog.getSaveFileName(self, "Save PCAP File", filename, "PCAP Files (*.pcap *.pcapng)")
        
        if path:
            try:
                wrpcap(path, self.captured_packets)
                self.show_info(f"Capture saved to {path}")
            except Exception as e:
                self.show_error(f"Failed to save file: {e}")
