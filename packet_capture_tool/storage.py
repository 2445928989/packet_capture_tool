"""用于持久化捕获数据包的实用工具。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .packet_parser import ParsedPacket


def save_packets(path: Path, packets: Iterable[ParsedPacket]) -> None:
    payload = [packet.to_json() for packet in packets]
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_packets(path: Path) -> List[ParsedPacket]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [ParsedPacket.from_json(item) for item in data]

