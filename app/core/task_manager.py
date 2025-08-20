# -*- coding: utf-8 -*-
import asyncio
import logging

class TaskManager:
    """A central manager to track and cancel all running asyncio tasks on shutdown."""
    def __init__(self):
        self.tasks = set()

    def create_task(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def cancel_all(self):
        logging.info(f"Cancelling {len(self.tasks)} outstanding tasks.")
        for task in list(self.tasks):
            task.cancel()