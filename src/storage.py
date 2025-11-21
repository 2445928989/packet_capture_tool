"""用于持久化捕获数据包的实用工具。"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Iterable, List, Optional, TextIO
import base64

from .packet_parser import ParsedPacket
try:
    # Scapy 在 requirements 中已声明；导出 PCAP 依赖 scapy
    from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, wrpcap  # type: ignore
    from scapy.utils import PcapWriter  # type: ignore
    from scapy.utils import PcapReader  # type: ignore
except Exception:  # pragma: no cover - scapy may be missing in some envs
    Ether = IP = IPv6 = TCP = UDP = Raw = wrpcap = PcapWriter = None  # type: ignore
    PcapReader = None  # type: ignore


# 默认最大文件大小（字节）：50MB
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024


class RotatingJSONLWriter:
    """轮转式 JSONL 文件写入器"""
    
    def __init__(self, base_dir: Path, session_name: str, max_file_size: int = DEFAULT_MAX_FILE_SIZE):
        """
        初始化轮转写入器
        
        Args:
            base_dir: 存储目录
            session_name: 会话名称（用于生成文件名前缀）
            max_file_size: 单个文件的最大字节数
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.session_name = session_name
        self.max_file_size = max_file_size
        
        self._current_file: Optional[TextIO] = None
        self._current_file_path: Optional[Path] = None
        self._current_file_index = 0
        self._current_file_size = 0
        
        self._rotate_file()
    
    def _rotate_file(self) -> None:
        """轮转到新文件"""
        # 关闭当前文件
        if self._current_file:
            try:
                self._current_file.close()
            except:
                pass
        
        # 生成新文件名
        self._current_file_index += 1
        filename = f"{self.session_name}_{self._current_file_index:04d}.jsonl"
        self._current_file_path = self.base_dir / filename
        
        # 打开新文件
        try:
            self._current_file = open(self._current_file_path, "w", encoding="utf-8")
            self._current_file_size = 0
            logging.info(f"创建新 JSONL 文件: {self._current_file_path}")
        except Exception as e:
            logging.error(f"无法创建 JSONL 文件: {e}")
            self._current_file = None
    
    def write(self, data: dict) -> bool:
        """
        写入一条 JSON 记录
        
        Args:
            data: 要写入的字典数据
            
        Returns:
            是否写入成功
        """
        if not self._current_file:
            return False
        
        try:
            # 序列化数据
            line = json.dumps(data, ensure_ascii=False) + "\n"
            line_size = len(line.encode("utf-8"))
            
            # 检查是否需要轮转
            if self._current_file_size + line_size > self.max_file_size:
                self._rotate_file()
                if not self._current_file:
                    return False
            
            # 写入数据
            self._current_file.write(line)
            self._current_file.flush()
            self._current_file_size += line_size
            
            return True
        except Exception as e:
            logging.error(f"写入 JSONL 失败: {e}")
            return False
    
    def close(self) -> None:
        """关闭写入器"""
        if self._current_file:
            try:
                self._current_file.close()
            except:
                pass
            self._current_file = None
    
    def get_all_files(self) -> List[Path]:
        """获取此会话的所有 JSONL 文件（按顺序）"""
        pattern = f"{self.session_name}_*.jsonl"
        files = sorted(self.base_dir.glob(pattern))
        return files


def read_all_jsonl_packets(base_dir: Path, session_name: str) -> List[tuple[int, ParsedPacket]]:
    """
    读取会话的所有 JSONL 文件中的数据包
    
    Args:
        base_dir: 存储目录
        session_name: 会话名称
        
    Returns:
        [(index, packet), ...] 列表
    """
    results = []
    pattern = f"{session_name}_*.jsonl"
    files = sorted(Path(base_dir).glob(pattern))
    
    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                        idx = obj.get("index")
                        data = obj.get("data")
                        if idx is None or data is None:
                            continue
                        pkt = ParsedPacket.from_json(data)
                        results.append((idx, pkt))
                    except Exception as e:
                        logging.warning(f"解析 JSONL 行失败: {e}")
                        continue
        except Exception as e:
            logging.error(f"读取文件 {filepath} 失败: {e}")
            continue
    
    results.sort(key=lambda x: x[0])
    return results


def save_packets(path: Path, packets: Iterable[ParsedPacket]) -> None:
    """保存数据包到单个 JSON 文件（用于导出功能）"""
    payload = [packet.to_json() for packet in packets]
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_packets(path: Path) -> List[ParsedPacket]:
    """从单个 JSON 文件加载数据包（用于导入功能）"""
    data = json.loads(path.read_text(encoding="utf-8"))
    return [ParsedPacket.from_json(item) for item in data]


def export_to_pcap(path: Path, packets: Iterable[ParsedPacket]) -> None:
    """将给定的 ParsedPacket 列表导出为 PCAP 文件（基于字段重建 Scapy 包）。

    说明：此方法采用轻量方案（方案 A），通过 ParsedPacket 中的
    `network_layer`/`transport_layer` 字段重建最小的 Scapy 包并写入 pcap。
    该方式无法恢复捕获时的原始裸字节（payload/选项/时间戳等可能丢失），
    但足以用于课程演示与 Wireshark 打开查看协议字段。
    """
    if wrpcap is None:
        raise RuntimeError("Scapy 未安装，无法导出 PCAP。请安装 scapy>=2.5")

    # 如果 packets 中包含原始 bytes（raw_b64），优先使用原始字节和时间戳写入
    raw_entries_exist = any(getattr(pkt, "raw_b64", None) for pkt in packets)

    if raw_entries_exist:
        if PcapWriter is None:
            raise RuntimeError("Scapy 未安装，无法导出 PCAP（需要写入原始字节）。请安装 scapy>=2.5")
        try:
            writer = PcapWriter(str(path), append=False, sync=True)
        except Exception as e:
            logging.error(f"创建 PcapWriter 失败: {e}")
            raise

        for pkt in packets:
            try:
                raw_b64 = getattr(pkt, "raw_b64", None)
                if raw_b64:
                    raw_bytes = base64.b64decode(raw_b64)
                    # 尝试用 Ether 解析原始字节为 Scapy Packet
                    try:
                        scapy_pkt = Ether(raw_bytes)
                    except Exception:
                        # 无法解析为以太网帧，则写入原始负载为 Raw
                        scapy_pkt = Raw(raw_bytes)

                    # 使用原始时间戳（若存在）
                    ts = getattr(pkt, "orig_ts", None)
                    if ts:
                        writer.write(scapy_pkt, ts=float(ts))
                    else:
                        writer.write(scapy_pkt)
                else:
                    # 回退到字段重建（兼容旧数据）
                    # 构建最小 scapy 包（复用下方重建逻辑）
                    net = pkt.network_layer
                    trans = pkt.transport_layer
                    sc = None
                    if net and isinstance(net, dict) and net.get("src_mac") and net.get("dst_mac"):
                        try:
                            sc = Ether(src=net.get("src_mac"), dst=net.get("dst_mac"))
                        except Exception:
                            sc = Ether()

                    ip_layer = None
                    if net and net.get("version") == "IPv4":
                        try:
                            ip_kwargs = {}
                            if net.get("src"):
                                ip_kwargs["src"] = net.get("src")
                            if net.get("dst"):
                                ip_kwargs["dst"] = net.get("dst")
                            ip_layer = IP(**ip_kwargs)
                        except Exception:
                            ip_layer = IP()
                    elif net and net.get("version") == "IPv6":
                        try:
                            ipv6_kwargs = {}
                            if net.get("src"):
                                ipv6_kwargs["src"] = net.get("src")
                            if net.get("dst"):
                                ipv6_kwargs["dst"] = net.get("dst")
                            ip_layer = IPv6(**ipv6_kwargs)
                        except Exception:
                            ip_layer = IPv6()

                    trans_layer = None
                    if trans and trans.get("type") == "TCP":
                        try:
                            tcp_kwargs = {}
                            if trans.get("sport"):
                                tcp_kwargs["sport"] = int(trans.get("sport"))
                            if trans.get("dport"):
                                tcp_kwargs["dport"] = int(trans.get("dport"))
                            trans_layer = TCP(**tcp_kwargs)
                        except Exception:
                            trans_layer = TCP()
                    elif trans and trans.get("type") == "UDP":
                        try:
                            udp_kwargs = {}
                            if trans.get("sport"):
                                udp_kwargs["sport"] = int(trans.get("sport"))
                            if trans.get("dport"):
                                udp_kwargs["dport"] = int(trans.get("dport"))
                            trans_layer = UDP(**udp_kwargs)
                        except Exception:
                            trans_layer = UDP()

                    composed = None
                    if sc is not None:
                        composed = sc
                        if ip_layer is not None:
                            composed = composed / ip_layer
                    else:
                        if ip_layer is not None:
                            composed = ip_layer
                    if composed is None:
                        composed = Raw(b"")
                    if trans_layer is not None:
                        composed = composed / trans_layer

                    writer.write(composed)
            except Exception:
                logging.exception("写入 PcapWriter 时失败，跳过此包")
                continue

        # 关闭 writer
        try:
            writer.close()
        except Exception:
            pass
        return

    # 否则回退到字段重建并一次性写入（原先逻辑）
    scapy_pkts = []
    for pkt in packets:
        try:
            net = pkt.network_layer
            trans = pkt.transport_layer

            sc = None
            # 以太网层
            if net and isinstance(net, dict) and net.get("src_mac") and net.get("dst_mac"):
                try:
                    eth_type = None
                    if "type" in net:
                        try:
                            eth_type = int(net.get("type"), 16)
                        except Exception:
                            eth_type = None
                    sc = Ether(src=net.get("src_mac"), dst=net.get("dst_mac"))
                    if eth_type is not None:
                        sc.type = eth_type
                except Exception:
                    sc = Ether()

            # 网络层
            ip_layer = None
            if net and net.get("version") == "IPv4":
                try:
                    ip_kwargs = {}
                    if net.get("src"):
                        ip_kwargs["src"] = net.get("src")
                    if net.get("dst"):
                        ip_kwargs["dst"] = net.get("dst")
                    if net.get("ttl"):
                        try:
                            ip_kwargs["ttl"] = int(net.get("ttl"))
                        except Exception:
                            pass
                    ip_layer = IP(**ip_kwargs)
                except Exception:
                    ip_layer = IP()
            elif net and net.get("version") == "IPv6":
                try:
                    ipv6_kwargs = {}
                    if net.get("src"):
                        ipv6_kwargs["src"] = net.get("src")
                    if net.get("dst"):
                        ipv6_kwargs["dst"] = net.get("dst")
                    ip_layer = IPv6(**ipv6_kwargs)
                except Exception:
                    ip_layer = IPv6()

            # 传输层
            trans_layer = None
            if trans and trans.get("type") == "TCP":
                try:
                    tcp_kwargs = {}
                    if trans.get("sport"):
                        tcp_kwargs["sport"] = int(trans.get("sport"))
                    if trans.get("dport"):
                        tcp_kwargs["dport"] = int(trans.get("dport"))
                    if trans.get("seq"):
                        try:
                            tcp_kwargs["seq"] = int(trans.get("seq"))
                        except Exception:
                            pass
                    if trans.get("ack"):
                        try:
                            tcp_kwargs["ack"] = int(trans.get("ack"))
                        except Exception:
                            pass
                    if trans.get("flags"):
                        tcp_kwargs["flags"] = str(trans.get("flags"))
                    trans_layer = TCP(**tcp_kwargs)
                except Exception:
                    trans_layer = TCP()
            elif trans and trans.get("type") == "UDP":
                try:
                    udp_kwargs = {}
                    if trans.get("sport"):
                        udp_kwargs["sport"] = int(trans.get("sport"))
                    if trans.get("dport"):
                        udp_kwargs["dport"] = int(trans.get("dport"))
                    trans_layer = UDP(**udp_kwargs)
                except Exception:
                    trans_layer = UDP()

            # 组合层次
            composed = None
            if sc is not None:
                composed = sc
                if ip_layer is not None:
                    composed = composed / ip_layer
            else:
                if ip_layer is not None:
                    composed = ip_layer

            if composed is None:
                # 无法构建分层，写入空的 Raw 包
                composed = Raw(b"")

            if trans_layer is not None:
                composed = composed / trans_layer

            scapy_pkts.append(composed)
        except Exception:
            logging.exception("重建 Scapy 包失败，跳过此包")
            continue

    # 使用 wrpcap 写 pcap（会覆盖同名文件）
    try:
        wrpcap(str(path), scapy_pkts)
    except Exception as e:
        logging.error(f"写入 PCAP 失败: {e}")
        raise


def import_from_pcap(path: Path, extract_raw: bool = True) -> List[ParsedPacket]:
    """从 PCAP 文件导入数据包并返回 ParsedPacket 列表。

    Args:
        path: PCAP 文件路径
        extract_raw: 是否在返回的 ParsedPacket 中保留原始 bytes (base64)

    Returns:
        ParsedPacket 列表
    """
    if PcapReader is None:
        raise RuntimeError("Scapy 未安装，无法导入 PCAP。请安装 scapy>=2.5")

    results: List[ParsedPacket] = []
    try:
        # PcapReader 按流读取，避免一次性加载大量数据
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                try:
                    # parse_packet 会尝试从 scapy packet 中读取时间戳与原始 bytes
                    from .packet_parser import parse_packet

                    parsed = parse_packet(pkt, extract_raw=extract_raw)
                    results.append(parsed)
                except Exception:
                    logging.exception("解析 pcap 中的单个包失败，跳过")
                    continue
    except Exception as e:
        logging.error(f"读取 PCAP 失败: {e}")
        raise

    return results

