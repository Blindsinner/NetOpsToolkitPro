# app/core/recon/screenshot_engine.py
import asyncio, json
from pathlib import Path
from typing import List, Dict
from PySide6.QtCore import QObject, Signal
from contextlib import asynccontextmanager

class ScreenshotEngine(QObject):
    progress = Signal(str)
    error = Signal(str)
    finished = Signal(list)  # list of dict manifest

    def __init__(self, task_manager, timeout: float = 12.0, concurrency: int = 4):
        super().__init__()
        self.task_manager = task_manager
        self.timeout = timeout
        self.concurrency = concurrency
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self, urls: List[str], out_dir: str):
        self._cancel = False
        coro = self._run(urls, out_dir)
        self.task_manager.create_task(coro)

    async def _run(self, urls: List[str], out_dir: str):
        try:
            out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
            manifest: List[Dict] = []
            sem = asyncio.Semaphore(self.concurrency)

            async with self._playwright() as pw:
                browser = await pw.chromium.launch()
                async def snap(url: str, idx: int):
                    if self._cancel: return
                    async with sem:
                        page = await browser.new_page()
                        try:
                            resp = await page.goto(url, timeout=int(self.timeout*1000), wait_until="domcontentloaded")
                            title = await page.title()
                            file = out / f"{idx:04d}.png"
                            await page.screenshot(path=str(file), full_page=True)
                            manifest.append({
                                "url": url,
                                "final_url": page.url,
                                "status": resp.status if resp else None,
                                "title": title,
                                "file": str(file)
                            })
                            self.progress.emit(f"Captured {url}")
                        except Exception as e:
                            self.progress.emit(f"Failed {url}: {e}")
                        finally:
                            await page.close()

                await asyncio.gather(*(snap(u, i) for i, u in enumerate(urls, 1)))
                await browser.close()

            # Write manifest
            (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            if not self._cancel:
                self.finished.emit(manifest)
        except Exception as e:
            self.error.emit(f"ScreenshotEngine failed: {e!r}")

    @asynccontextmanager
    async def _playwright(self):
        # Lazy import to avoid hard dependency at import time
        try:
            from playwright.async_api import async_playwright
        except Exception as e:
            raise RuntimeError("Playwright is not installed. Please ensure 'playwright' is installed and browsers are set up.") from e
        async with async_playwright() as pw:
            yield pw

