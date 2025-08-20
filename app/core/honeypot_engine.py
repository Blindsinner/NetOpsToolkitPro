# -*- coding: utf-8 -*-
import asyncio
import string
from PySide6.QtCore import QObject, Signal

class HoneypotEngine(QObject):
    """Manages the lifecycle of multiple honeypot listeners."""
    connection_trapped = Signal(dict)
    listener_status_changed = Signal(int, str) # port, status

    def __init__(self, task_manager):
        super().__init__()
        self.task_manager = task_manager
        self.listeners = {} # {port: asyncio.Server}

        self.personas = {
            "FTP": b"220 ProFTPD 1.3.5a Server (Debian)\r\n",
            "Telnet": b"\xFF\xFB\x01\xFF\xFB\x03\xFF\xFD\x18\xFF\xFD\x1F", # Telnet negotiation
            "HTTP": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Ubuntu)\r\nContent-Length: 0\r\n\r\n"
        }

    def _sanitize_input(self, data: bytes) -> str:
        """FIX: Removes non-printable characters from captured data."""
        # Decode ignoring errors, then filter for printable characters
        decoded = data.decode('utf-8', errors='ignore')
        printable_chars = set(string.printable)
        sanitized = "".join(filter(lambda x: x in printable_chars, decoded))
        return sanitized.strip()

    async def handle_connection(self, reader, writer, port, persona):
        """Callback for when a client connects to a honeypot port."""
        addr = writer.get_extra_info('peername')
        source_ip, source_port = addr[0], addr[1]
        
        event = {
            "source_ip": source_ip, "source_port": source_port,
            "dest_port": port, "data_sent": "", "persona": persona
        }
        
        try:
            if persona in self.personas:
                writer.write(self.personas[persona])
                await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            # Use the new sanitize function
            event["data_sent"] = self._sanitize_input(data)
        
        except asyncio.TimeoutError:
            pass # No data sent
        except Exception as e:
            print(f"Honeypot connection error on port {port}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            # Only log the event if actual data was sent or it's not a noisy protocol
            if event["data_sent"] or persona != "Telnet":
                self.connection_trapped.emit(event)

    def start_listener(self, port, persona, host='0.0.0.0'):
        if port in self.listeners:
            return
        
        async def _start():
            try:
                handler = lambda r, w: self.handle_connection(r, w, port, persona)
                server = await asyncio.start_server(handler, host, port)
                self.listeners[port] = server
                self.listener_status_changed.emit(port, "Running")
            except Exception as e:
                self.listener_status_changed.emit(port, f"Error: {e}")

        self.task_manager.create_task(_start())

    def stop_listener(self, port):
        if port in self.listeners:
            server = self.listeners.pop(port)
            server.close()
            self.listener_status_changed.emit(port, "Stopped")