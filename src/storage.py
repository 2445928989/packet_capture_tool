"""用于持久化捕获数据包的实用工具。"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Iterable, List, Optional, TextIO

from .packet_parser import ParsedPacket


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

