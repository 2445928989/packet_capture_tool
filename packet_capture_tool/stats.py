"""Traffic statistics helpers."""
from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, List, Tuple

from .packet_parser import ParsedPacket


class TrafficStats:
    """Aggregates per-protocol counters and IPv6 ratio timeline."""

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
        for protocol in packet.protocols:
            self._protocol_counts[protocol.upper()] += 1
        if "DNS" in packet.protocols:
            self._protocol_counts["DNS"] -= 1

        # Add specific counting for IPv4 and IPv6
        if "IPv4" in packet.network_layer.get("version", ""):
            self._protocol_counts["IPv4"] += 1
        elif "IPv6" in packet.network_layer.get("version", ""):
            self._protocol_counts["IPv6"] += 1

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
        """Return a list of (timestamp, ratio) tuples for plotting."""
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
        counters = self.protocol_counters()
        return [(name, counters[name]) for name in counters]

    def merge_from(self, packets: Iterable[ParsedPacket]) -> None:
        for packet in packets:
            self.register(packet)

