"""GUI 的后台资源监控。"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

try:  # pragma: no cover - psutil might not be available in the execution environment
    import psutil
except Exception:  # pragma: no cover
    psutil = None  # type: ignore


@dataclass
class ResourceSample:
    timestamp: datetime
    cpu_percent: float
    memory_mb: float


class ResourceMonitor:
    """按间隔轮询 CPU 和内存使用情况，并发出 :class:`ResourceSample`。"""

    def __init__(self, callback: Callable[[ResourceSample], None], interval: float = 1.0) -> None:
        self.callback = callback
        self.interval = interval
        self.start_time: Optional[datetime] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    @staticmethod
    def is_available() -> bool:
        return psutil is not None

    def start(self) -> None:
        if not self.is_available():
            return
        if self._thread and self._thread.is_alive():
            return

        self.start_time = datetime.now()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._thread and self._thread.is_alive():
            self._stop_event.set()
            self._thread.join(timeout=self.interval * 2)
        self._thread = None
        self.start_time = None

    def _run(self) -> None:
        assert psutil is not None
        process = psutil.Process()
        process.cpu_percent(interval=None)
        while not self._stop_event.wait(self.interval):
            cpu = process.cpu_percent(interval=None) / psutil.cpu_count() if psutil.cpu_count() else 0.0
            mem_info = process.memory_info()
            sample = ResourceSample(
                timestamp=datetime.now(),
                cpu_percent=cpu,
                memory_mb=mem_info.rss / (1024 * 1024),
            )
            try:
                self.callback(sample)
            except Exception:  # pragma: no cover - defensive
                pass

