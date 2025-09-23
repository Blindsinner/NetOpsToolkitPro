# -*- coding: utf-8 -*-
"""
TaskManager — GUI-thread asyncio scheduler (qasync friendly)

- Schedules coroutines onto the *current running* (qasync) loop so Qt widgets are only touched on the GUI thread.
- For blocking CPU/I/O use:
      await asyncio.to_thread(func, *args)      # Python 3.9+
  or  await loop.run_in_executor(None, func, *args)
"""

from __future__ import annotations
import asyncio
import logging
from typing import Coroutine, Set

class TaskManager:
    def __init__(self) -> None:
        # Track live tasks so we can cancel them on shutdown.
        self.tasks: Set[asyncio.Task] = set()

    def create_task(self, coro: Coroutine) -> asyncio.Task:
        """
        Schedule a coroutine onto the *current* running asyncio loop (qasync on GUI thread).

        Returns:
            asyncio.Task — supports .add_done_callback(), .cancel(), .done(), etc.
        """
        try:
            loop = asyncio.get_running_loop()  # qasync loop on the GUI thread
        except RuntimeError:
            # If no loop yet (very early startup), fall back to default loop;
            # once qasync is running, subsequent calls will use the GUI loop.
            loop = asyncio.get_event_loop()

        async def _runner():
            try:
                return await coro
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.exception("Unhandled exception in scheduled task")
                raise

        task = loop.create_task(_runner())

        def _cleanup(t: asyncio.Task):
            self.tasks.discard(t)

        self.tasks.add(task)
        task.add_done_callback(_cleanup)
        return task

    def cancel_all(self) -> None:
        """Cancel all outstanding tasks."""
        logging.info("Cancelling %d outstanding tasks.", len(self.tasks))
        for t in list(self.tasks):
            try:
                t.cancel()
            except Exception:
                pass
        self.tasks.clear()

