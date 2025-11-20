"""数据包捕获工具的管理工具。"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

try:
    from scapy.all import AsyncSniffer  # type: ignore
except Exception:  # pragma: no cover - scapy may be unavailable in CI environments
    AsyncSniffer = None  # type: ignore


class CaptureUnavailableError(RuntimeError):
    """当请求数据包捕获但 scapy/tshark 不可用时抛出。"""


class CaptureManager:
    """封装 :class:`scapy.all.AsyncSniffer` 以实现安全的启动/停止管理。"""

    def __init__(self, packet_callback: Callable[[object], None]):
        self._packet_callback = packet_callback # 回调
        self._sniffer: Optional[AsyncSniffer] = None # 嗅探器
        self._filter_expr: Optional[str] = None # 过滤器
        self._iface: Optional[str] = None # 接口

    @property
    def is_running(self) -> bool:
        return bool(self._sniffer and getattr(self._sniffer, "running", False))

    @staticmethod
    def is_available() -> bool:
        return AsyncSniffer is not None

    def start(self, filter_expr: Optional[str] = None, iface: Optional[str] = None, promisc: bool = True) -> None:
        if not self.is_available():
            raise CaptureUnavailableError(
                "Scapy 不可用。请安装 scapy 并确保已授予必要的权限。"
            )

        if self.is_running:
            logging.info("捕获已在运行")
            return

        self._filter_expr = filter_expr
        self._iface = iface

        def _safe_callback(packet: object) -> None:
            try:
                self._packet_callback(packet)
            except Exception:  # pragma: no cover - defensive logging
                logging.exception("处理捕获的数据包失败")

        try:
            self._sniffer = AsyncSniffer(
                filter=filter_expr,
                prn=_safe_callback,
                store=False,
                iface=iface,
                promisc=promisc,
            )
            self._sniffer.start()
            logging.info("数据包捕获已启动，过滤器=%s 接口=%s", filter_expr, iface)
        except Exception as e:
            # 捕获可能因为网络接口问题失败
            logging.error(f"启动数据包捕获失败: {e}")
            self._sniffer = None
            raise

    def stop(self) -> None:
        if self._sniffer is not None:
            def stop_sniffer():
                try:
                    self._sniffer.stop()
                finally:
                    self._sniffer = None
                    self._filter_expr = None
                    self._iface = None
            
            # 在后台线程中停止嗅探器，避免阻塞主线程
            stop_thread = threading.Thread(target=stop_sniffer, daemon=True)
            stop_thread.daemon = True
            stop_thread.start()
            # 不阻塞等待，立即返回
            self._sniffer = None
            self._filter_expr = None
            self._iface = None

    def restart(self, filter_expr: Optional[str] = None, iface: Optional[str] = None) -> None:
        self.stop()
        self.start(filter_expr=filter_expr, iface=iface)

    def current_filter(self) -> Optional[str]:
        return self._filter_expr

    def current_interface(self) -> Optional[str]:
        return self._iface

