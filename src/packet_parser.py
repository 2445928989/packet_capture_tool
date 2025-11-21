"""GUI 应用程序使用的数据包解析辅助函数。"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

try:  # pragma: no cover - the test environment may not have scapy installed
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS
except Exception:  # pragma: no cover
    IP = IPv6 = TCP = UDP = ICMP = ARP = Ether = DNS = None  # type: ignore


@dataclass
class ParsedPacket:
    timestamp: datetime
    summary: str
    protocols: List[str]
    network_layer: Dict[str, str] = field(default_factory=dict)
    transport_layer: Dict[str, str] = field(default_factory=dict)
    dns_info: Dict[str, str] = field(default_factory=dict)
    # 可选：原始字节（base64 编码），用于精确导出 PCAP
    raw_b64: Optional[str] = None
    # 可选：原始时间戳（浮点秒）
    orig_ts: Optional[float] = None

    def to_json(self) -> Dict[str, object]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "summary": self.summary,
            "protocols": self.protocols,
            "network_layer": self.network_layer,
            "transport_layer": self.transport_layer,
            "dns_info": self.dns_info,
            "raw_b64": self.raw_b64,
            "orig_ts": self.orig_ts,
        }

    @classmethod
    def from_json(cls, payload: Dict[str, object]) -> "ParsedPacket":
        return cls(
            timestamp=datetime.fromisoformat(str(payload["timestamp"])),
            summary=str(payload["summary"]),
            protocols=list(payload.get("protocols", [])),
            network_layer=dict(payload.get("network_layer", {})),
            transport_layer=dict(payload.get("transport_layer", {})),
            dns_info=dict(payload.get("dns_info", {})),
            raw_b64=payload.get("raw_b64"),
            orig_ts=payload.get("orig_ts"),
        )


def _populate_network_layer(packet: object) -> (Dict[str, str], List[str]):
    fields: Dict[str, str] = {}
    protocols: List[str] = []

    if Ether is not None and packet.haslayer(Ether):  # type: ignore[attr-defined]
        ether = packet[Ether]
        fields.update({
            "src_mac": ether.src,
            "dst_mac": ether.dst,
            "type": hex(ether.type),
        })
        protocols.append("Ethernet")

    if IP is not None and packet.haslayer(IP):  # type: ignore[attr-defined]
        layer = packet[IP]
        fields.update(
            {
                "version": "IPv4",
                "src": layer.src,
                "dst": layer.dst,
                "ttl": str(layer.ttl),
                "ihl": str(layer.ihl),
                "len": str(layer.len),
                "flags": str(layer.flags),
                "proto": str(layer.proto),
            }
        )
        protocols.append("IPv4")
    elif IPv6 is not None and packet.haslayer(IPv6):  # type: ignore[attr-defined]
        layer6 = packet[IPv6]
        fields.update(
            {
                "version": "IPv6",
                "src": layer6.src,
                "dst": layer6.dst,
                "tc": str(layer6.tc),
                "fl": str(layer6.fl),
                "hlim": str(layer6.hlim),
                "plen": str(layer6.plen),
                "nh": str(layer6.nh),
            }
        )
        protocols.append("IPv6")
    elif ARP is not None and packet.haslayer(ARP):  # type: ignore[attr-defined]
        arp = packet[ARP]
        fields.update(
            {
                "op": str(arp.op),
                "psrc": arp.psrc,
                "pdst": arp.pdst,
                "hwsrc": arp.hwsrc,
                "hwdst": arp.hwdst,
            }
        )
        protocols.append("ARP")

    return fields, protocols


def _populate_transport_layer(packet: object) -> (Dict[str, str], List[str], Dict[str, str]):
    transport: Dict[str, str] = {}
    protocols: List[str] = []
    dns_info: Dict[str, str] = {}

    if TCP is not None and packet.haslayer(TCP):  # type: ignore[attr-defined]
        tcp = packet[TCP]
        transport.update(
            {
                "type": "TCP",
                "sport": str(tcp.sport),
                "dport": str(tcp.dport),
                "seq": str(tcp.seq),
                "ack": str(tcp.ack),
                "flags": tcp.flags.flagrepr() if hasattr(tcp.flags, "flagrepr") else str(tcp.flags),
                "window": str(tcp.window),
            }
        )
        protocols.append("TCP")
    elif UDP is not None and packet.haslayer(UDP):  # type: ignore[attr-defined]
        udp = packet[UDP]
        transport.update(
            {
                "type": "UDP",
                "sport": str(udp.sport),
                "dport": str(udp.dport),
                "len": str(udp.len),
            }
        )
        protocols.append("UDP")
    elif ICMP is not None and packet.haslayer(ICMP):  # type: ignore[attr-defined]
        icmp = packet[ICMP]
        transport.update(
            {
                "type": "ICMP",
                "type_field": str(icmp.type),
                "code": str(icmp.code),
            }
        )
        protocols.append("ICMP")

    if DNS is not None and packet.haslayer(DNS):  # type: ignore[attr-defined]
        dns = packet[DNS]
        dns_info = {
            "qr": "response" if dns.qr else "query",
            "opcode": str(dns.opcode),
            "qname": dns.qd.qname.decode(errors="ignore") if dns.qd and dns.qd.qname else "",
            "ancount": str(dns.ancount),
            "nscount": str(dns.nscount),
            "arcount": str(dns.arcount),
        }
        protocols.append("DNS")

    return transport, protocols, dns_info


def parse_packet(packet: object, extract_raw: bool = True) -> ParsedPacket:
    """将 scapy 数据包转换为 :class:`ParsedPacket` 结构。"""
    # 优先使用 scapy 提供的时间戳（如果存在），否则使用当前时间
    ts = None
    try:
        ts = float(getattr(packet, "time", None))
    except Exception:
        ts = None
    timestamp = datetime.fromtimestamp(ts) if ts else datetime.now()
    summary = getattr(packet, "summary", lambda: repr(packet))()

    network_layer, network_protocols = _populate_network_layer(packet)
    transport_layer, transport_protocols, dns_info = _populate_transport_layer(packet)

    protocols = list(dict.fromkeys(network_protocols + transport_protocols))  # 保持顺序
    if dns_info:
        protocols.append("DNS")

    raw_b64 = None
    if extract_raw:
        # 尝试提取原始 bytes（用于精确导出）
        try:
            raw_bytes = bytes(packet)
            import base64

            raw_b64 = base64.b64encode(raw_bytes).decode()
        except Exception:
            raw_b64 = None

    return ParsedPacket(
        timestamp=timestamp,
        summary=summary,
        protocols=protocols,
        network_layer=network_layer,
        transport_layer=transport_layer,
        dns_info=dns_info,
        raw_b64=raw_b64,
        orig_ts=ts,
    )

