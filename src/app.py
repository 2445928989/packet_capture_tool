"""基于 PyQt6 的数据包捕获与分析应用程序。"""
from __future__ import annotations

import json
import logging
import queue
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Deque, Tuple, Dict
from collections import deque

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QPushButton, QLineEdit, QLabel,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QFileDialog, QMessageBox,
    QHeaderView, QSplitter, QFrame, QCheckBox, QSpinBox, QGroupBox,
    QDialog, QDialogButtonBox, QRadioButton, QButtonGroup
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QSettings
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure
import matplotlib

# 配置 matplotlib 支持中文字符
try:
    import platform
    if platform.system() == 'Windows':
        matplotlib.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'SimSun', 'KaiTi']
    else:
        matplotlib.rcParams['font.sans-serif'] = ['WenQuanYi Micro Hei', 'DejaVu Sans', 'Arial Unicode MS']
    matplotlib.rcParams['axes.unicode_minus'] = False
except Exception:
    pass

from .capture import CaptureManager, CaptureUnavailableError
from .packet_parser import ParsedPacket, parse_packet
from .resource_monitor import ResourceMonitor, ResourceSample
from .stats import TrafficStats
from .storage import load_packets, save_packets, RotatingJSONLWriter, read_all_jsonl_packets


class SettingsDialog(QDialog):
    """设置对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置")
        self.setModal(True)
        self.resize(500, 400)
        
        # 加载设置
        self.settings = QSettings("NekoShark", "Settings")
        
        layout = QVBoxLayout(self)
        
        # 自动滚动设置
        scroll_group = QGroupBox("自动滚动")
        scroll_layout = QVBoxLayout()
        
        self.auto_scroll_checkbox = QCheckBox("在最新页且滚动条在底部时自动滚动到底部")
        self.auto_scroll_checkbox.setChecked(self.settings.value("auto_scroll", True, type=bool))
        scroll_layout.addWidget(self.auto_scroll_checkbox)
        
        scroll_group.setLayout(scroll_layout)
        layout.addWidget(scroll_group)
        
        # 自动换页设置
        page_group = QGroupBox("自动换页")
        page_layout = QVBoxLayout()
        
        self.auto_page_checkbox = QCheckBox("在最新页时，新数据导致页数增加时自动跳转到新页")
        self.auto_page_checkbox.setChecked(self.settings.value("auto_page", True, type=bool))
        page_layout.addWidget(self.auto_page_checkbox)
        
        page_group.setLayout(page_layout)
        layout.addWidget(page_group)
        
        # 批处理大小设置
        batch_group = QGroupBox("性能设置")
        batch_layout = QVBoxLayout()
        
        batch_label_layout = QHBoxLayout()
        batch_label_layout.addWidget(QLabel("每次处理的数据包批量大小:"))
        self.batch_size_spinbox = QSpinBox()
        self.batch_size_spinbox.setRange(10, 1000)
        self.batch_size_spinbox.setValue(self.settings.value("batch_size", 100, type=int))
        self.batch_size_spinbox.setSuffix(" 个")
        batch_label_layout.addWidget(self.batch_size_spinbox)
        batch_label_layout.addStretch()
        batch_layout.addLayout(batch_label_layout)
        
        batch_help = QLabel("较大的批量可以提高性能，但可能导致界面更新延迟")
        batch_help.setStyleSheet("color: gray; font-size: 11px;")
        batch_layout.addWidget(batch_help)
        
        batch_group.setLayout(batch_layout)
        layout.addWidget(batch_group)
        
        # 缓存设置
        cache_group = QGroupBox("缓存设置")
        cache_layout = QVBoxLayout()
        
        cache_label_layout = QHBoxLayout()
        cache_label_layout.addWidget(QLabel("内存缓存数据包数量:"))
        self.cache_size_spinbox = QSpinBox()
        self.cache_size_spinbox.setRange(100, 50000)
        self.cache_size_spinbox.setValue(self.settings.value("cache_size", 5000, type=int))
        self.cache_size_spinbox.setSuffix(" 个")
        cache_label_layout.addWidget(self.cache_size_spinbox)
        cache_label_layout.addStretch()
        cache_layout.addLayout(cache_label_layout)
        
        cache_help = QLabel("较大的缓存可以减少磁盘读取，但会占用更多内存")
        cache_help.setStyleSheet("color: gray; font-size: 11px;")
        cache_layout.addWidget(cache_help)
        
        cache_group.setLayout(cache_layout)
        layout.addWidget(cache_group)

        # 保存选项
        save_group = QGroupBox("保存选项")
        save_layout = QVBoxLayout()

        self.save_raw_checkbox = QCheckBox("保存原始包字节（raw bytes，增大文件大小）")
        self.save_raw_checkbox.setChecked(self.settings.value("save_raw_packets", False, type=bool))
        save_help = QLabel("开启后会在 JSON/JSONL 中保存 base64 编码的原始包，用于精确导出 PCAP。")
        save_help.setStyleSheet("color: gray; font-size: 11px;")
        save_layout.addWidget(self.save_raw_checkbox)
        save_layout.addWidget(save_help)

        save_group.setLayout(save_layout)
        layout.addWidget(save_group)
        
        # 主题设置
        theme_group = QGroupBox("界面主题")
        theme_layout = QVBoxLayout()
        
        self.light_theme_radio = QRadioButton("明色主题")
        self.dark_theme_radio = QRadioButton("暗色主题")
        
        self.theme_button_group = QButtonGroup()
        self.theme_button_group.addButton(self.light_theme_radio)
        self.theme_button_group.addButton(self.dark_theme_radio)
        
        current_theme = self.settings.value("theme", "dark", type=str)
        if current_theme == "dark":
            self.dark_theme_radio.setChecked(True)
        else:
            self.light_theme_radio.setChecked(True)
        
        theme_layout.addWidget(self.light_theme_radio)
        theme_layout.addWidget(self.dark_theme_radio)
        
        theme_help = QLabel("更改主题将在应用设置后立即生效")
        theme_help.setStyleSheet("color: gray; font-size: 11px;")
        theme_layout.addWidget(theme_help)
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        layout.addStretch()
        
        # 按钮
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel |
            QDialogButtonBox.StandardButton.RestoreDefaults
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        button_box.button(QDialogButtonBox.StandardButton.RestoreDefaults).clicked.connect(self.restore_defaults)
        layout.addWidget(button_box)
    
    def restore_defaults(self):
        """恢复默认设置"""
        self.auto_scroll_checkbox.setChecked(True)
        self.auto_page_checkbox.setChecked(True)
        self.batch_size_spinbox.setValue(100)
        self.cache_size_spinbox.setValue(5000)
        self.dark_theme_radio.setChecked(True)
        self.save_raw_checkbox.setChecked(False)
    
    def save_settings(self):
        """保存设置"""
        self.settings.setValue("auto_scroll", self.auto_scroll_checkbox.isChecked())
        self.settings.setValue("auto_page", self.auto_page_checkbox.isChecked())
        self.settings.setValue("batch_size", self.batch_size_spinbox.value())
        self.settings.setValue("cache_size", self.cache_size_spinbox.value())
        theme = "dark" if self.dark_theme_radio.isChecked() else "light"
        self.settings.setValue("theme", theme)
        self.settings.setValue("save_raw_packets", self.save_raw_checkbox.isChecked())
    
    def get_settings(self):
        """获取设置"""
        theme = "dark" if self.dark_theme_radio.isChecked() else "light"
        return {
            "auto_scroll": self.auto_scroll_checkbox.isChecked(),
            "auto_page": self.auto_page_checkbox.isChecked(),
            "batch_size": self.batch_size_spinbox.value(),
            "cache_size": self.cache_size_spinbox.value(),
            "theme": theme
            ,"save_raw_packets": self.save_raw_checkbox.isChecked()
        }


class PacketSignals(QObject):
    """信号类，用于线程间通信"""
    packet_captured = pyqtSignal(object)
    resource_sample = pyqtSignal(object)


class PacketCaptureApp(QMainWindow):
    """主图形界面应用程序。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NekoShark")
        self.resize(1400, 900)
        
        # 设置窗口图标（兼容开发环境和打包后的 exe）
        import sys
        import os
        
        def get_resource_path(relative_path):
            """获取资源文件的绝对路径，兼容开发环境和打包后的exe"""
            if getattr(sys, 'frozen', False):
                # 打包后的exe，PyInstaller会解压到临时目录
                base_path = sys._MEIPASS
            else:
                # 开发环境
                base_path = Path(__file__).parent.parent
            return os.path.join(base_path, relative_path)
        
        icon_path = get_resource_path("icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # 加载设置
        self.settings = QSettings("NekoShark", "Settings")
        self._auto_scroll_enabled = self.settings.value("auto_scroll", True, type=bool)
        self._auto_page_enabled = self.settings.value("auto_page", True, type=bool)
        self._batch_size_setting = self.settings.value("batch_size", 100, type=int)
        self._ui_cache_size = self.settings.value("cache_size", 5000, type=int)
        self._save_raw_packets = self.settings.value("save_raw_packets", False, type=bool)

        # 信号
        self.signals = PacketSignals()
        self.signals.packet_captured.connect(self._on_packet_captured_slot)
        self.signals.resource_sample.connect(self._on_resource_sample_slot)

        self.packet_queue: "queue.Queue[ParsedPacket]" = queue.Queue()
        self.captured_packets: Deque[Tuple[int, ParsedPacket]] = deque(maxlen=self._ui_cache_size)
        self._packet_cache: Dict[int, ParsedPacket] = {}
        self._packet_global_index = 0
        self._capture_session_name: Optional[str] = None
        self._jsonl_writer: Optional[RotatingJSONLWriter] = None
        self._resource_jsonl_writer: Optional[RotatingJSONLWriter] = None
        self._new_packets_since_page = 0
        self._pending_page_reload = False
        self.resource_samples: List[ResourceSample] = []
        self.stats = TrafficStats(window=timedelta(days=1))
        self.capture_start: Optional[datetime] = None

        self.capture_manager = CaptureManager(self._on_packet_captured)
        self.resource_monitor = ResourceMonitor(self._on_resource_sample, interval=2.0)

        self._stats_update_counter = 0
        self._stats_update_interval = 10
        self._pending_ui_update = False

        # 分页参数
        self._page_size = 100
        self._current_page = 1
        
        # 网络监控
        self._last_packet_time = None
        self._network_check_enabled = False
        self._last_packet_count = 0
        
        # 显示过滤器
        self._display_filter_pattern = None
        self._display_filter_enabled = False

        self._build_ui()

        # 应用主题
        self._apply_theme(self.settings.value("theme", "dark", type=str))

        # 定时器
        self.uptime_timer = QTimer()
        self.uptime_timer.timeout.connect(self._update_uptime)
        self.uptime_timer.start(1000)

        self.queue_timer = QTimer()
        self.queue_timer.timeout.connect(self._drain_packet_queue)
        self.queue_timer.start(50)
        
        # 网络状态检测定时器，每30秒检查一次
        self.network_check_timer = QTimer()
        self.network_check_timer.timeout.connect(self._check_network_status)
        self.network_check_timer.start(30000)  # 30秒

    def _build_ui(self) -> None:
        """构建UI"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 顶部控制面板
        control_frame = QFrame()
        control_layout = QVBoxLayout(control_frame)
        
        # 过滤器行
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("BPF 过滤器:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("例如: tcp port 80")
        filter_layout.addWidget(self.filter_input)
        
        # 按钮
        self.start_button = QPushButton("▶ 开始捕获")
        self.start_button.clicked.connect(self.start_capture)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #2fa572;
                color: white;
                font-weight: bold;
                padding: 6px 12px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #278d5f;
            }
            QPushButton:pressed {
                background-color: #1e6b47;
            }
            QPushButton:disabled {
                background-color: #9e9e9e;
                color: #e0e0e0;
            }
        """)
        filter_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("⏹ 停止")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                font-weight: bold;
                padding: 6px 12px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #b71c1c;
            }
            QPushButton:pressed {
                background-color: #8b0000;
            }
            QPushButton:disabled {
                background-color: #9e9e9e;
                color: #e0e0e0;
            }
        """)
        filter_layout.addWidget(self.stop_button)
        
        control_layout.addLayout(filter_layout)
        
        # 显示过滤器行（正则表达式）
        display_filter_layout = QHBoxLayout()
        display_filter_layout.addWidget(QLabel("显示过滤器:"))
        self.display_filter_input = QLineEdit()
        self.display_filter_input.setPlaceholderText(r"正则表达式，例如: 192\.168\..*|tcp.*80")
        self.display_filter_input.textChanged.connect(self._on_display_filter_changed)
        display_filter_layout.addWidget(self.display_filter_input)
        
        clear_filter_button = QPushButton("✖ 清除")
        clear_filter_button.clicked.connect(lambda: self.display_filter_input.clear())
        clear_filter_button.setMaximumWidth(60)
        display_filter_layout.addWidget(clear_filter_button)
        
        self.filter_status_label = QLabel("")
        self.filter_status_label.setStyleSheet("color: green; font-size: 11px;")
        display_filter_layout.addWidget(self.filter_status_label)
        
        control_layout.addLayout(display_filter_layout)
        
        # 按钮行2
        button_layout = QHBoxLayout()
        save_button = QPushButton("💾 保存捕获")
        save_button.clicked.connect(self.save_capture)
        button_layout.addWidget(save_button)
        
        export_pcap_button = QPushButton("📥 导出为 PCAP")
        export_pcap_button.clicked.connect(self.export_capture_pcap)
        button_layout.addWidget(export_pcap_button)
        
        load_button = QPushButton("📂 加载捕获")
        load_button.clicked.connect(self.load_capture)
        button_layout.addWidget(load_button)
        
        settings_button = QPushButton("⚙️ 设置")
        settings_button.clicked.connect(self.open_settings)
        button_layout.addWidget(settings_button)
        
        about_button = QPushButton("ℹ️ 关于")
        about_button.clicked.connect(self.show_about)
        button_layout.addWidget(about_button)
        
        # 网络状态指示器
        self.network_status_label = QLabel("● 未开始")
        self.network_status_label.setStyleSheet("""
            QLabel {
                color: gray;
                font-weight: bold;
                padding: 6px 12px;
                border-radius: 4px;
                background-color: rgba(128, 128, 128, 0.1);
            }
        """)
        button_layout.addWidget(self.network_status_label)
        
        button_layout.addStretch()
        
        control_layout.addLayout(button_layout)
        main_layout.addWidget(control_frame)

        # 主分割器
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #555;
                width: 2px;
            }
            QSplitter::handle:hover {
                background-color: #777;
            }
        """)
        
        # 左侧：数据包列表
        left_widget = QWidget()
        left_widget.setStyleSheet("""
            QWidget {
                border: 1px solid #444;
                border-radius: 4px;
                background-color: palette(window);
            }
        """)
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(8, 8, 8, 8)
        
        left_layout.addWidget(QLabel("📦 捕获的数据包"))
        
        # 数据包表格
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(3)
        self.packet_table.setHorizontalHeaderLabels(["时间", "摘要", "协议"])
        # 固定列宽，防止抖动
        self.packet_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.packet_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.packet_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.packet_table.setColumnWidth(0, 160)
        self.packet_table.setColumnWidth(2, 150)
        # 优化性能
        self.packet_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.packet_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)  # 禁止编辑
        self.packet_table.verticalHeader().setVisible(False)  # 隐藏行号
        self.packet_table.setShowGrid(True)  # 显示网格
        # 强制垂直滚动条始终显示，防止宽度变化
        self.packet_table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.packet_table.itemSelectionChanged.connect(self._on_packet_selected)
        left_layout.addWidget(self.packet_table)
        
        # 分页控件
        pagination_layout = QHBoxLayout()
        pagination_layout.addWidget(QLabel("每页记录:"))
        self.page_size_input = QLineEdit("100")
        self.page_size_input.setMaximumWidth(60)
        pagination_layout.addWidget(self.page_size_input)
        
        self.prev_button = QPushButton("◀ 上一页")
        self.prev_button.setMinimumWidth(80)
        self.prev_button.clicked.connect(self._on_prev_page)
        pagination_layout.addWidget(self.prev_button)
        
        self.load_page_button = QPushButton("🔄 回到最新")
        self.load_page_button.setMinimumWidth(100)
        self.load_page_button.clicked.connect(self._on_load_page)
        pagination_layout.addWidget(self.load_page_button)
        
        self.next_button = QPushButton("下一页 ▶")
        self.next_button.setMinimumWidth(80)
        self.next_button.clicked.connect(self._on_next_page)
        pagination_layout.addWidget(self.next_button)
        
        self.page_label = QLabel("记录: -")
        pagination_layout.addWidget(self.page_label)
        pagination_layout.addStretch()
        
        left_layout.addLayout(pagination_layout)
        
        # 右侧：标签页
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #444;
                border-radius: 4px;
                background-color: palette(window);
                padding: 4px;
            }
            QTabBar::tab {
                background-color: #353535;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #505050;
                border-bottom: 2px solid #4a9eff;
            }
            QTabBar::tab:hover {
                background-color: #454545;
            }
        """)
        
        # 详情标签页
        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["字段", "内容"])
        self.details_tree.setColumnWidth(0, 220)
        self.tab_widget.addTab(self.details_tree, "📋 数据包详情")
        
        # 统计标签页
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(2)
        self.stats_table.setHorizontalHeaderLabels(["协议", "数据包数"])
        self.stats_table.setMinimumHeight(140)
        self.stats_table.setMaximumHeight(300)
        stats_layout.addWidget(self.stats_table)
        
        # 图表
        self.figure = Figure(figsize=(8, 6))
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.figure.subplots_adjust(hspace=0.4, top=0.95, bottom=0.08, left=0.1, right=0.95)
        self.ax_ipv6 = self.figure.add_subplot(211)
        self.ax_bar = self.figure.add_subplot(212)
        stats_layout.addWidget(self.canvas)
        
        self.tab_widget.addTab(stats_widget, "📊 统计信息")
        
        # 资源监控标签页
        resource_widget = QWidget()
        resource_layout = QVBoxLayout(resource_widget)
        
        # 顶部信息栏
        info_layout = QHBoxLayout()
        self.start_time_label = QLabel("开始时间: -")
        self.uptime_label = QLabel("运行时长: 0秒")
        info_layout.addWidget(self.start_time_label)
        info_layout.addWidget(self.uptime_label)
        info_layout.addStretch()
        
        export_resource_button = QPushButton("📥 导出资源日志")
        export_resource_button.clicked.connect(self.export_resource_log)
        info_layout.addWidget(export_resource_button)
        
        resource_layout.addLayout(info_layout)
        
        # 资源图表
        self.resource_figure = Figure(figsize=(8, 6))
        self.resource_canvas = FigureCanvasQTAgg(self.resource_figure)
        self.resource_figure.subplots_adjust(hspace=0.4, top=0.95, bottom=0.1, left=0.1, right=0.95)
        self.ax_cpu = self.resource_figure.add_subplot(211)
        self.ax_memory = self.resource_figure.add_subplot(212)
        resource_layout.addWidget(self.resource_canvas)
        
        self.tab_widget.addTab(resource_widget, "💻 资源监控")
        
        # 添加到分割器
        splitter.addWidget(left_widget)
        splitter.addWidget(self.tab_widget)
        splitter.setSizes([600, 800])
        
        main_layout.addWidget(splitter)

    def open_settings(self):
        """打开设置对话框"""
        dialog = SettingsDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            dialog.save_settings()
            # 应用新设置
            new_settings = dialog.get_settings()
            self._auto_scroll_enabled = new_settings["auto_scroll"]
            self._auto_page_enabled = new_settings["auto_page"]
            old_batch_size = self._batch_size_setting
            self._batch_size_setting = new_settings["batch_size"]
            
            # 如果缓存大小改变，需要重新创建 deque
            if new_settings["cache_size"] != self._ui_cache_size:
                self._ui_cache_size = new_settings["cache_size"]
                # 保留现有数据，只改变最大长度
                old_packets = list(self.captured_packets)
                self.captured_packets = deque(old_packets, maxlen=self._ui_cache_size)
            
            # 应用主题设置
            self._apply_theme(new_settings["theme"])
            
            QMessageBox.information(self, "设置已保存", "设置已成功保存并应用！")
    
    def show_about(self):
        """显示关于对话框"""
        about_text = """
        <div style='text-align: center;'>
            <h2>🐱🦈 NekoShark</h2>
            <p style='font-size: 14px; color: #666;'>🐱🦈 A network packet capture and analysis tool inspired by Wireshark</p>
            <hr style='border: 1px solid #ddd; margin: 15px 0;'>
            
            <p><b>版本:</b> 1.0.0</p>
            
            <p><b>制作人:</b>2组 Dual-Core：蔡兆元 王思哲</p>
            
            <p><b>项目主页:</b><br>
            <a href='https://github.com/2445928989/NekoShark'>
            https://github.com/2445928989/NekoShark
            </a></p>
            
            <hr style='border: 1px solid #ddd; margin: 15px 0;'>
            
            <p style='font-size: 12px; color: #888;'>
            基于 PyQt6 + Scapy + Matplotlib 构建<br>
            开源协议: MIT License
            </p>
            
            <p style='font-size: 11px; color: #aaa; margin-top: 10px;'>
            © 2024 NekoShark - All rights reserved
            </p>
        </div>
        """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("关于 NekoShark")
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setText(about_text)
        msg.setIconPixmap(self.windowIcon().pixmap(64, 64))
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

    def _on_display_filter_changed(self, text: str):
        """显示过滤器文本变化"""
        import re
        if not text.strip():
            self._display_filter_pattern = None
            self._display_filter_enabled = False
            self.filter_status_label.setText("✓ 过滤器已禁用")
            self.filter_status_label.setStyleSheet("color: gray; font-size: 11px;")
            self._on_load_page()  # 重新加载页面
            return
        
        try:
            self._display_filter_pattern = re.compile(text, re.IGNORECASE)
            self._display_filter_enabled = True
            self.filter_status_label.setText("✓ 过滤器有效")
            self.filter_status_label.setStyleSheet("color: green; font-size: 11px;")
            self._on_load_page()  # 重新加载页面
        except re.error as e:
            self._display_filter_pattern = None
            self._display_filter_enabled = False
            self.filter_status_label.setText(f"✖ 正则错误: {str(e)}")
            self.filter_status_label.setStyleSheet("color: red; font-size: 11px;")
    
    def _packet_matches_filter(self, packet: ParsedPacket) -> bool:
        """检查数据包是否匹配显示过滤器"""
        if not self._display_filter_enabled or not self._display_filter_pattern:
            return True
        
        # 搜索范围：摘要、协议、网络层、传输层
        search_text = packet.summary + " " + " ".join(packet.protocols)
        for value in packet.network_layer.values():
            search_text += " " + str(value)
        for value in packet.transport_layer.values():
            search_text += " " + str(value)
        
        return bool(self._display_filter_pattern.search(search_text))

    def _apply_theme(self, theme: str):
        """应用明色或暗色主题"""
        palette = QPalette()
        
        if theme == "dark":
            # 暗色主题
            palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
        else:
            # 明色主题 (系统默认)
            palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.WindowText, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
            palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 220))
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.ColorRole.Link, QColor(0, 0, 255))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 120, 215))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        QApplication.instance().setPalette(palette)

    def _apply_theme(self, theme: str):
        """应用明色或暗色主题"""
        palette = QPalette()
        
        if theme == "dark":
            # 暗色主题
            palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
        else:
            # 明色主题 (系统默认)
            palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.WindowText, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
            palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 220))
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.ColorRole.Link, QColor(0, 0, 255))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 120, 215))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        QApplication.instance().setPalette(palette)


    # ------------------------------------------------------------------ 分页逻辑
    def _update_page_label(self, start_idx: int = None, end_idx: int = None) -> None:
        last_index = max(-1, self._packet_global_index - 1)
        if last_index < 0:
            self.page_label.setText("记录: -")
            return
        total = last_index + 1
        total_pages = (total + self._page_size - 1) // self._page_size
        if start_idx is None or end_idx is None:
            start = (self._current_page - 1) * self._page_size
            end = min(start + self._page_size - 1, last_index)
        else:
            start, end = start_idx, end_idx
        label = f"记录: {start} → {end} (页 {self._current_page}/{total_pages})"
        if self._new_packets_since_page and self._current_page < total_pages:
            label += f"  新: {self._new_packets_since_page}"
        self.page_label.setText(label)

    def _on_load_page(self) -> None:
        try:
            self._page_size = max(1, int(self.page_size_input.text()))
        except:
            self._page_size = 100
        
        last_index = self._packet_global_index - 1
        if last_index < 0:
            self.packet_table.setRowCount(0)
            self._current_page = 1
            self._update_page_label()
            return
        
        total = last_index + 1
        total_pages = (total + self._page_size - 1) // self._page_size
        self._current_page = total_pages
        
        start = (self._current_page - 1) * self._page_size
        end = min(start + self._page_size - 1, last_index)
        self._new_packets_since_page = 0
        self._load_page_by_index(start, end)

    def _on_prev_page(self) -> None:
        if self._current_page > 1:
            self._current_page -= 1
            last_index = self._packet_global_index - 1
            if last_index < 0:
                return
            start = (self._current_page - 1) * self._page_size
            end = min(start + self._page_size - 1, last_index)
            total = last_index + 1
            total_pages = (total + self._page_size - 1) // self._page_size
            if self._current_page == total_pages:
                self._new_packets_since_page = 0
            self._load_page_by_index(start, end)

    def _on_next_page(self) -> None:
        last_index = self._packet_global_index - 1
        if last_index < 0:
            return
        total = last_index + 1
        total_pages = (total + self._page_size - 1) // self._page_size
        if self._current_page < total_pages:
            self._current_page += 1
            start = (self._current_page - 1) * self._page_size
            end = min(start + self._page_size - 1, last_index)
            if self._current_page == total_pages:
                self._new_packets_since_page = 0
            self._load_page_by_index(start, end)

    def _load_page_by_index(self, start_idx: int, end_idx: int) -> None:
        """按索引范围加载页面"""
        # 检查是否在底部（用于自动滚动）
        scrollbar = self.packet_table.verticalScrollBar()
        was_at_bottom = scrollbar.value() >= scrollbar.maximum() - 10  # 留10像素容差
        
        results = []

        try:
            if self._capture_session_name:
                # 从所有轮转文件中读取指定范围的数据包
                captures_dir = Path.cwd() / "captures"
                all_packets = read_all_jsonl_packets(captures_dir, self._capture_session_name)
                for idx, pkt in all_packets:
                    if start_idx <= idx <= end_idx:
                        results.append((idx, pkt))
            else:
                # 从内存缓存读取
                for idx, pkt in self.captured_packets:
                    if start_idx <= idx <= end_idx:
                        results.append((idx, pkt))
        except:
            logging.exception("按索引加载页面失败")

        results.sort(key=lambda x: x[0])
        
        # 应用显示过滤器
        if self._display_filter_enabled:
            filtered_results = [(idx, pkt) for idx, pkt in results if self._packet_matches_filter(pkt)]
            results = filtered_results
        
        # 完全禁用更新以避免任何视觉闪烁
        self.packet_table.setUpdatesEnabled(False)
        self.packet_table.blockSignals(True)
        
        # 直接设置行数（一次性操作）
        self.packet_table.setRowCount(len(results))
        
        # 更新所有单元格
        for row, (idx, packet) in enumerate(results):
            # 时间列
            time_item = QTableWidgetItem(packet.timestamp.strftime("%H:%M:%S"))
            time_item.setData(Qt.ItemDataRole.UserRole, idx)
            time_item.setFlags(time_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.packet_table.setItem(row, 0, time_item)
            
            # 摘要列
            summary_item = QTableWidgetItem(packet.summary)
            summary_item.setFlags(summary_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.packet_table.setItem(row, 1, summary_item)
            
            # 协议列
            protocol_item = QTableWidgetItem(",".join(packet.protocols))
            protocol_item.setFlags(protocol_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.packet_table.setItem(row, 2, protocol_item)
        
        # 重新启用更新（一次性刷新）
        self.packet_table.blockSignals(False)
        self.packet_table.setUpdatesEnabled(True)

        self._update_page_label(start_idx, end_idx)
        
        # 如果启用了自动滚动且之前在底部且在最新页，自动滚动到底部
        if self._auto_scroll_enabled:
            last_index = self._packet_global_index - 1
            if last_index >= 0:
                total = last_index + 1
                total_pages = (total + self._page_size - 1) // self._page_size
                if was_at_bottom and self._current_page == total_pages:
                    self.packet_table.scrollToBottom()

    # ------------------------------------------------------------------ 数据包处理
    def _on_packet_captured(self, packet: object) -> None:
        """在捕获线程中调用"""
        try:
            parsed = parse_packet(packet, extract_raw=getattr(self, "_save_raw_packets", False))
            self.signals.packet_captured.emit(parsed)
        except:
            logging.exception("解析数据包失败")

    def _on_packet_captured_slot(self, packet: ParsedPacket) -> None:
        """在主线程中调用"""
        self.packet_queue.put(packet)

    def _drain_packet_queue(self) -> None:
        batch_count = 0
        max_batch_size = self._batch_size_setting

        while batch_count < max_batch_size:
            try:
                packet = self.packet_queue.get_nowait()
            except queue.Empty:
                break

            index = self._packet_global_index
            
            # 更新最后收到包的时间
            self._last_packet_time = datetime.now()
            self._last_packet_count = index + 1

            # 写入 JSONL（轮转式）
            try:
                if self._jsonl_writer:
                    data = packet.to_json()
                    if not getattr(self, "_save_raw_packets", False):
                        # 移除可能的原始字段以节省空间
                        data.pop("raw_b64", None)
                        data.pop("orig_ts", None)
                    payload = {"index": index, "data": data}
                    self._jsonl_writer.write(payload)
            except:
                logging.exception("写入 JSONL 失败")

            self.stats.register(packet)
            self._stats_update_counter += 1
            batch_count += 1

            # 内存缓存管理
            try:
                if self.captured_packets.maxlen and len(self.captured_packets) >= self.captured_packets.maxlen:
                    oldest_index, _ = self.captured_packets.popleft()
                    if oldest_index in self._packet_cache:
                        del self._packet_cache[oldest_index]
            except:
                pass

            self.captured_packets.append((index, packet))
            self._packet_cache[index] = packet

            # 判断是否需要刷新页面
            try:
                last_index = index
                total = last_index + 1
                prev_total = last_index
                prev_total_pages = (prev_total + self._page_size - 1) // self._page_size if prev_total > 0 else 1
                total_pages = (total + self._page_size - 1) // self._page_size

                # 使用设置中的自动换页选项
                if self._auto_page_enabled and self._current_page == prev_total_pages and total_pages > prev_total_pages:
                    self._current_page = total_pages
                    self._pending_page_reload = True
                elif self._current_page == total_pages:
                    current_page_start = (self._current_page - 1) * self._page_size
                    current_page_end = min(current_page_start + self._page_size - 1, last_index)
                    if current_page_start <= index <= current_page_end:
                        self._pending_page_reload = True
                else:
                    if self._current_page < total_pages:
                        self._new_packets_since_page += 1
                        self._update_page_label()
            except:
                pass

            self._packet_global_index += 1

        # 统计更新
        if self._stats_update_counter >= self._stats_update_interval:
            self._stats_update_counter = 0
            self._refresh_statistics()

        # 刷新页面
        if self._pending_page_reload:
            self._pending_page_reload = False
            self._on_load_page()

    def _on_packet_selected(self) -> None:
        selection = self.packet_table.selectedItems()
        if not selection:
            return
        row = self.packet_table.currentRow()
        if row < 0:
            return
        
        idx = self.packet_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        packet = self._get_packet_by_global_index(idx)
        
        if packet:
            self._display_packet_details(packet)

    def _display_packet_details(self, packet: ParsedPacket) -> None:
        self.details_tree.clear()
        
        general = QTreeWidgetItem(self.details_tree, ["概览", ""])
        QTreeWidgetItem(general, ["捕获时间", str(packet.timestamp)])
        QTreeWidgetItem(general, ["摘要", packet.summary])
        QTreeWidgetItem(general, ["协议链路", ", ".join(packet.protocols)])
        general.setExpanded(True)
        
        network = QTreeWidgetItem(self.details_tree, ["网络层", ""])
        if packet.network_layer:
            for key, value in packet.network_layer.items():
                QTreeWidgetItem(network, [key, str(value)])
        else:
            QTreeWidgetItem(network, ["无", ""])
        network.setExpanded(True)
        
        transport = QTreeWidgetItem(self.details_tree, ["传输层", ""])
        if packet.transport_layer:
            for key, value in packet.transport_layer.items():
                QTreeWidgetItem(transport, [key, str(value)])
        else:
            QTreeWidgetItem(transport, ["无", ""])
        transport.setExpanded(True)
        
        if packet.dns_info:
            dns = QTreeWidgetItem(self.details_tree, ["DNS", ""])
            for key, value in packet.dns_info.items():
                QTreeWidgetItem(dns, [key, str(value)])
            dns.setExpanded(True)

    def _get_packet_by_global_index(self, index: int) -> Optional[ParsedPacket]:
        if index in self._packet_cache:
            return self._packet_cache[index]

        try:
            if self._capture_session_name:
                # 从所有轮转文件中查找
                captures_dir = Path.cwd() / "captures"
                all_packets = read_all_jsonl_packets(captures_dir, self._capture_session_name)
                for idx, pkt in all_packets:
                    if idx == index:
                        return pkt
        except:
            logging.exception("从 JSONL 加载包失败")

        return None

    # ------------------------------------------------------------------ 捕获控制
    def start_capture(self) -> None:
        self.start_button.setEnabled(False)
        self.start_button.setText("⏳ 启动中...")

        filter_expr = self.filter_input.text().strip() or None

        def _start_capture_thread():
            try:
                self.capture_manager.start(filter_expr=filter_expr)
                QTimer.singleShot(0, self._on_capture_started)
            except CaptureUnavailableError as exc:
                QTimer.singleShot(0, lambda: self._on_capture_error("捕获不可用", str(exc)))
            except Exception as exc:
                QTimer.singleShot(0, lambda: self._on_capture_error("捕获错误", str(exc)))

        thread = threading.Thread(target=_start_capture_thread, daemon=True)
        thread.start()

    def _on_capture_started(self) -> None:
        self.capture_start = datetime.now()
        self.start_button.setText("▶ 开始捕获")
        self.stop_button.setEnabled(True)
        self.start_time_label.setText(f"开始时间: {self.capture_start.strftime('%Y-%m-%d %H:%M:%S')}")
        self.resource_monitor.start()
        
        # 启用网络监控
        self._network_check_enabled = True
        self._last_packet_time = datetime.now()
        self._last_packet_count = 0
        self._update_network_status("normal")
        
        try:
            captures_dir = Path.cwd() / "captures"
            captures_dir.mkdir(parents=True, exist_ok=True)
            self._capture_session_name = self.capture_start.strftime("capture_%Y%m%d_%H%M%S")
            # 创建数据包轮转式写入器，单文件最大 50MB
            self._jsonl_writer = RotatingJSONLWriter(
                base_dir=captures_dir,
                session_name=self._capture_session_name,
                max_file_size=50 * 1024 * 1024  # 50MB
            )
            # 创建资源监控轮转式写入器，单文件最大 10MB
            self._resource_jsonl_writer = RotatingJSONLWriter(
                base_dir=captures_dir,
                session_name=f"resource_{self._capture_session_name}",
                max_file_size=10 * 1024 * 1024  # 10MB
            )
        except:
            logging.exception("无法创建轮转式 JSONL 写入器")

    def _on_capture_error(self, title: str, message: str) -> None:
        QMessageBox.critical(self, title, message)
        self.start_button.setEnabled(True)
        self.start_button.setText("▶ 开始捕获")

    def stop_capture(self) -> None:
        logging.info("停止抓包")
        self.capture_manager.stop()
        self.resource_monitor.stop()
        self.capture_start = None
        self._network_check_enabled = False
        self._update_network_status("stopped")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.uptime_label.setText("运行时长: 0秒")
        
        try:
            if self._jsonl_writer:
                self._jsonl_writer.close()
                self._jsonl_writer = None
            if self._resource_jsonl_writer:
                self._resource_jsonl_writer.close()
                self._resource_jsonl_writer = None
        except:
            pass
        finally:
            self._capture_jsonl_file = None
            self._capture_jsonl_path = None

    # ------------------------------------------------------------------ 统计
    def _refresh_statistics(self) -> None:
        # 更新表格 - 显示所有有数据的协议
        stats_data = list(self.stats.table_rows())
        # 添加总数
        stats_data.insert(0, ("总计", self.stats.total_packets))
        self.stats_table.setRowCount(len(stats_data))
        for row, (protocol, count) in enumerate(stats_data):
            protocol_item = QTableWidgetItem(protocol)
            if protocol == "总计":
                protocol_item.setData(Qt.ItemDataRole.FontRole, QFont("", -1, QFont.Weight.Bold))
            self.stats_table.setItem(row, 0, protocol_item)
            
            count_item = QTableWidgetItem(str(count))
            if protocol == "总计":
                count_item.setData(Qt.ItemDataRole.FontRole, QFont("", -1, QFont.Weight.Bold))
            self.stats_table.setItem(row, 1, count_item)

        # 更新图表
        ipv6_series = self.stats.ipv6_ratio_series()
        if ipv6_series:
            self.ax_ipv6.clear()
            self.ax_ipv6.set_title("IPv6 流量占比（最近24小时）")
            self.ax_ipv6.set_ylabel("IPv6 %")
            x = [ts for ts, _ in ipv6_series]
            y = [ratio for _, ratio in ipv6_series]
            self.ax_ipv6.plot_date(x, y, "-")
            self.ax_ipv6.set_ylim(0, 100)
            self.ax_ipv6.grid(True)

        counters = self.stats.protocol_counters()
        self.ax_bar.clear()
        self.ax_bar.set_title("TCP/UDP/ARP 分布")
        self.ax_bar.set_ylabel("数据包数")
        labels = ["TCP", "UDP", "ARP"]
        values = [counters.get(label, 0) for label in labels]
        self.ax_bar.bar(labels, values)
        self.ax_bar.grid(axis="y")

        self.canvas.draw()

    # ------------------------------------------------------------------ 持久化
    def save_capture(self) -> None:
        has_any = bool(self.captured_packets) or (self._capture_jsonl_path and self._capture_jsonl_path.exists())
        if not has_any:
            QMessageBox.information(self, "无数据", "暂无数据包可保存。")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "保存捕获的数据包", "", "JSON Files (*.json)")
        if not file_path:
            return

        try:
            all_packets: List[ParsedPacket] = []
            if self._capture_session_name:
                # 从所有轮转文件中读取
                captures_dir = Path.cwd() / "captures"
                indexed_packets = read_all_jsonl_packets(captures_dir, self._capture_session_name)
                all_packets = [pkt for _, pkt in indexed_packets]
            else:
                # 从内存缓存读取
                for _, pkt in sorted(self.captured_packets, key=lambda x: x[0]):
                    all_packets.append(pkt)

            # 根据设置决定是否在导出 JSON 中包含 raw 字段
            if not getattr(self, "_save_raw_packets", False):
                # 生成仅包含非 raw 字段的字典列表
                payload = [
                    (lambda p: (lambda d: (d.pop("raw_b64", None), d.pop("orig_ts", None), d)[2])(p.to_json()))(p)
                    for p in all_packets
                ]
                Path(file_path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                save_packets(Path(file_path), all_packets)
            QMessageBox.information(self, "已保存", f"捕获数据已保存到 {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "保存错误", str(exc))

    def load_capture(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "打开捕获文件", "", "JSON Files (*.json);;PCAP Files (*.pcap)")
        if not file_path:
            return
        try:
            p = Path(file_path)
            if p.suffix.lower() == ".pcap":
                # 导入 pcap 并解析为 ParsedPacket
                from .storage import import_from_pcap

                packets = import_from_pcap(p, extract_raw=True)
            else:
                packets = load_packets(p)
        except Exception as exc:
            QMessageBox.critical(self, "加载错误", str(exc))
            return

        self.stats.reset()
        self.packet_table.setRowCount(0)
        self.captured_packets = deque(maxlen=self._ui_cache_size)
        self._packet_cache.clear()
        self._packet_global_index = 0

        for idx, packet in enumerate(packets):
            try:
                self.stats.register(packet)
            except Exception:
                # 忽略统计错误，仍然加载包
                logging.exception("统计注册失败")
            self.captured_packets.append((idx, packet))
            self._packet_cache[idx] = packet
            self._packet_global_index = idx + 1

        self._refresh_statistics()
        QMessageBox.information(self, "已加载", f"已加载 {len(packets)} 个数据包")

    def export_capture_pcap(self) -> None:
        """在 GUI 中导出当前捕获为 PCAP 文件（优先使用原始 bytes）。"""
        has_any = bool(self.captured_packets) or (self._capture_jsonl_path and self._capture_jsonl_path.exists())
        if not has_any:
            QMessageBox.information(self, "无数据", "暂无数据包可导出。")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "导出为 PCAP", "", "PCAP Files (*.pcap)")
        if not file_path:
            return

        try:
            all_packets: List[ParsedPacket] = []
            if self._capture_session_name:
                captures_dir = Path.cwd() / "captures"
                indexed_packets = read_all_jsonl_packets(captures_dir, self._capture_session_name)
                all_packets = [pkt for _, pkt in indexed_packets]
            else:
                for _, pkt in sorted(self.captured_packets, key=lambda x: x[0]):
                    all_packets.append(pkt)

            # 如果用户选择不保存 raw，那么内存中的 ParsedPacket 也不会包含 raw，export_to_pcap 会回退到字段重建
            from .storage import export_to_pcap
            export_to_pcap(Path(file_path), all_packets)
            QMessageBox.information(self, "已导出", f"PCAP 已保存到 {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "导出错误", str(exc))

    # ------------------------------------------------------------------ 资源监控
    def _on_resource_sample(self, sample: ResourceSample) -> None:
        self.signals.resource_sample.emit(sample)

    def _on_resource_sample_slot(self, sample: ResourceSample) -> None:
        # 写入 JSONL 轮转文件
        try:
            if self._resource_jsonl_writer:
                payload = {
                    "timestamp": sample.timestamp.isoformat(),
                    "cpu_percent": sample.cpu_percent,
                    "memory_mb": sample.memory_mb,
                }
                self._resource_jsonl_writer.write(payload)
        except:
            logging.exception("写入资源监控 JSONL 失败")
        
        # 保持最近 200 条在内存中（用于图表显示）
        self.resource_samples.append(sample)
        if len(self.resource_samples) > 200:
            self.resource_samples.pop(0)
        
        # 更新资源图表
        self._update_resource_charts()

    def export_resource_log(self) -> None:
        if not self._capture_session_name:
            QMessageBox.information(self, "无样本", "尚未开始资源监控。")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "导出资源使用情况", "", "JSON Files (*.json)")
        if not file_path:
            return
        
        try:
            # 从所有轮转文件中读取资源数据
            captures_dir = Path.cwd() / "captures"
            pattern = f"resource_{self._capture_session_name}_*.jsonl"
            files = sorted(captures_dir.glob(pattern))
            
            payload = []
            for filepath in files:
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        for line in f:
                            if not line.strip():
                                continue
                            try:
                                obj = json.loads(line)
                                payload.append(obj)
                            except:
                                continue
                except:
                    continue
            
            if not payload:
                QMessageBox.information(self, "无样本", "未找到资源监控数据。")
                return
            
            Path(file_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            QMessageBox.information(self, "已导出", f"资源日志已保存到 {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "导出错误", str(exc))
    
    def _update_resource_charts(self) -> None:
        """更新资源监控图表"""
        if len(self.resource_samples) < 2:
            return
        
        try:
            # 提取数据
            timestamps = [sample.timestamp for sample in self.resource_samples]
            cpu_values = [sample.cpu_percent for sample in self.resource_samples]
            memory_values = [sample.memory_mb for sample in self.resource_samples]
            
            # CPU 图表
            self.ax_cpu.clear()
            self.ax_cpu.set_title("CPU 使用率（最近 200 个样本）")
            self.ax_cpu.set_ylabel("CPU %")
            self.ax_cpu.plot(timestamps, cpu_values, "-", color="#2196F3", linewidth=1.5)
            self.ax_cpu.grid(True, alpha=0.3)
            self.ax_cpu.set_ylim(0, max(cpu_values) * 1.2 if cpu_values else 10)
            
            # 内存图表
            self.ax_memory.clear()
            self.ax_memory.set_title("内存使用量（最近 200 个样本）")
            self.ax_memory.set_ylabel("内存 (MB)")
            self.ax_memory.set_xlabel("时间")
            self.ax_memory.plot(timestamps, memory_values, "-", color="#4CAF50", linewidth=1.5)
            self.ax_memory.grid(True, alpha=0.3)
            self.ax_memory.set_ylim(0, max(memory_values) * 1.2 if memory_values else 100)
            
            # 旋转 x 轴标签
            self.ax_memory.tick_params(axis='x', rotation=45)
            
            self.resource_canvas.draw()
        except Exception as e:
            logging.warning(f"更新资源图表失败: {e}")

    def _update_uptime(self) -> None:
        if self.capture_start:
            delta = datetime.now() - self.capture_start
            self.uptime_label.setText(f"运行时长: {str(delta).split('.')[0]}")
    
    def _update_network_status(self, status: str):
        """更新网络状态指示器"""
        if status == "normal":
            self.network_status_label.setText("● 正常")
            self.network_status_label.setStyleSheet("""
                QLabel {
                    color: #2fa572;
                    font-weight: bold;
                    padding: 6px 12px;
                    border-radius: 4px;
                    background-color: rgba(47, 165, 114, 0.1);
                }
            """)
        elif status == "warning":
            self.network_status_label.setText("● 可能断网")
            self.network_status_label.setStyleSheet("""
                QLabel {
                    color: #ff9800;
                    font-weight: bold;
                    padding: 6px 12px;
                    border-radius: 4px;
                    background-color: rgba(255, 152, 0, 0.1);
                }
            """)
        else:  # stopped
            self.network_status_label.setText("● 未开始")
            self.network_status_label.setStyleSheet("""
                QLabel {
                    color: gray;
                    font-weight: bold;
                    padding: 6px 12px;
                    border-radius: 4px;
                    background-color: rgba(128, 128, 128, 0.1);
                }
            """)
    
    def _check_network_status(self) -> None:
        """检查网络状态，如果超过60秒没有收到包，可能是断网了"""
        if not self._network_check_enabled or not self.capture_start:
            return
        
        if self._last_packet_time is None:
            return
        
        time_since_last_packet = (datetime.now() - self._last_packet_time).total_seconds()
        
        # 如果超过60秒没有收到新包，且总包数大于0，可能是网络问题
        if time_since_last_packet > 60 and self._last_packet_count > 0:
            current_count = self._packet_global_index
            # 检查是否真的没有新包
            if current_count == self._last_packet_count:
                logging.warning(f"检测到可能的网络问题：{time_since_last_packet:.0f}秒未收到新数据包")
                self._update_network_status("warning")
            else:
                # 有新包，恢复正常
                self._update_network_status("normal")
        else:
            # 正常状态
            if time_since_last_packet <= 60:
                self._update_network_status("normal")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = QApplication([])
    window = PacketCaptureApp()
    window.showMaximized()  # 默认最大化显示
    app.exec()


if __name__ == "__main__":
    main()
