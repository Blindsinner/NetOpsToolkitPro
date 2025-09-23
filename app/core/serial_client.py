# -*- coding: utf-8 -*-
import serial
from PySide6.QtCore import QThread, Signal

class SerialClient(QThread):
    """
    A QThread-based client for handling serial port communication
    in a non-blocking way for a Qt application.
    """
    # Signal to emit when data is received from the serial port
    received = Signal(str)
    # Signal to emit when the connection is lost or closed
    connection_lost = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._serial = None
        self._is_running = False
        self._port = None
        self._baudrate = None

    def connect(self, port: str, baudrate: int):
        """
        Attempts to connect to the specified serial port and start the reading thread.
        """
        if self._is_running:
            return

        self._port = port
        self._baudrate = baudrate
        try:
            self._serial = serial.Serial(
                port=self._port,
                baudrate=self._baudrate,
                timeout=0.1  # Timeout for read operations
            )
            self._is_running = True
            self.start()  # Start the QThread's run() method
        except serial.SerialException as e:
            self._is_running = False
            # We can't emit a signal here because the thread isn't running
            # The calling widget should check is_running()
            print(f"Error opening serial port: {e}")
            
    def disconnect(self):
        """
        Stops the thread and closes the serial port connection.
        """
        if not self._is_running:
            return
            
        self._is_running = False
        self.wait(500) # Wait up to 500ms for the thread to finish
        if self._serial and self._serial.is_open:
            self._serial.close()
        self._serial = None

    def send(self, data: str):
        """
        Sends data to the connected serial port.
        """
        if self._serial and self._serial.is_open:
            try:
                self._serial.write(data.encode('utf-8', 'replace'))
            except serial.SerialException as e:
                print(f"Error writing to serial port: {e}")
                self.disconnect()

    def is_running(self) -> bool:
        """
        Returns the connection status.
        """
        return self._is_running

    def run(self):
        """
        The main loop of the thread. Reads from the serial port and emits signals.
        """
        if not self._serial:
            return

        while self._is_running:
            try:
                if self._serial.in_waiting > 0:
                    # Read all available bytes
                    data = self._serial.read(self._serial.in_waiting)
                    # Decode assuming utf-8, replace errors
                    text = data.decode('utf-8', 'replace')
                    self.received.emit(text)
            except serial.SerialException:
                # This can happen if the device is unplugged
                break
            except Exception as e:
                print(f"An unexpected error occurred in serial reader thread: {e}")
                break
        
        # Cleanup after the loop finishes
        self._is_running = False
        self.connection_lost.emit()