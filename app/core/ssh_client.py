# -*- coding: utf-8 -*-
import asyncio
import asyncssh
from PySide6.QtCore import QObject, Signal

class SshClient(QObject):
    """An asynchronous SSH client that streams output."""
    received = Signal(str)
    connection_lost = Signal(str)
    connection_made = Signal()

    def __init__(self):
        super().__init__()
        self.conn = None
        self.process = None

    async def connect(self, host, port, username, password):
        try:
            self.conn = await asyncssh.connect(
                host, port=port, username=username, password=password,
                known_hosts=None # Disables host key checking for simplicity
            )
            self.process = await self.conn.create_process(term_type='xterm-color')
            self.connection_made.emit()
            
            # Start a reader task to stream output
            asyncio.create_task(self._reader())
        except Exception as e:
            self.connection_lost.emit(str(e))

    async def _reader(self):
        try:
            async for data in self.process.stdout:
                self.received.emit(data)
        except Exception as e:
            self.connection_lost.emit(f"Connection lost: {e}")
    
    async def send(self, data):
        if self.process and self.process.stdin:
            await self.process.stdin.write(data)

    def disconnect(self):
        if self.conn:
            self.conn.close()
        self.conn = None
        self.process = None