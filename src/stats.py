"""流量统计辅助函数。"""
from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, List, Tuple

from .packet_parser import ParsedPacket


class TrafficStats:
    """聚合每个协议的计数器和 IPv6 占比时间线。"""

    def __init__(self, window: timedelta = timedelta(days=1)) -> None:
        self.window = window
        self._protocol_counts: Counter[str] = Counter()
        self._timeline: Deque[Tuple[datetime, int, int]] = deque()
        self.total_packets = 0

    def reset(self) -> None:
        self._protocol_counts.clear()
        self._timeline.clear()
        self.total_packets = 0

    def register(self, packet: ParsedPacket) -> None:
        self.total_packets += 1
        
        # 统一协议名称为大写，避免重复
        for protocol in packet.protocols:
            # 跳过 Ethernet，只统计有意义的协议
            if protocol.upper() == "ETHERNET":
                continue
            self._protocol_counts[protocol.upper()] += 1
        
        # DNS 已经在 protocols 中了，不需要重复计数
        if "DNS" in packet.protocols:
            self._protocol_counts["DNS"] -= 1

        timestamp = packet.timestamp.replace(second=0, microsecond=0)
        ipv6_present = 1 if packet.network_layer.get("version") == "IPv6" else 0

        if self._timeline and self._timeline[-1][0] == timestamp:
            ts, total, ipv6 = self._timeline[-1]
            self._timeline[-1] = (ts, total + 1, ipv6 + ipv6_present)
        else:
            self._timeline.append((timestamp, 1, ipv6_present))

        self._trim()

    def _trim(self) -> None:
        cutoff = datetime.now() - self.window
        while self._timeline and self._timeline[0][0] < cutoff:
            self._timeline.popleft()

    def ipv6_ratio_series(self) -> List[Tuple[datetime, float]]:
        """返回用于绘图的 (时间戳, 占比) 元组列表。"""
        self._trim()
        series: List[Tuple[datetime, float]] = []
        total_packets = 0
        ipv6_packets = 0
        for ts, total, ipv6 in self._timeline:
            total_packets += total
            ipv6_packets += ipv6
            ratio = (ipv6_packets / total_packets * 100.0) if total_packets else 0.0
            series.append((ts, ratio))
        return series

    def protocol_counters(self) -> Dict[str, int]:
        keys = ["IPv4", "IPv6", "TCP", "UDP", "ARP", "DNS"]
        return {key: self._protocol_counts.get(key, 0) for key in keys}

    def table_rows(self) -> List[Tuple[str, int]]:
        """ 返回所有非零计数的协议，按数量排序 """
        # 过滤掉零计数，按数量降序
        return sorted(
            [(name, count) for name, count in self._protocol_counts.items() if count > 0],
            key=lambda x: x[1],
            reverse=True
        )

    def merge_from(self, packets: Iterable[ParsedPacket]) -> None:
        for packet in packets:
            self.register(packet)

