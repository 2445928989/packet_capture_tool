"""基于 CustomTkinter 的数据包捕获与分析应用程序。"""
from __future__ import annotations


import json
import logging
import queue
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import matplotlib

# 配置 matplotlib 支持中文字符
try:
    # Windows 系统常用中文字体
    import platform
    if platform.system() == 'Windows':
        matplotlib.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'SimSun', 'KaiTi']
    else:
        # Linux/Mac 系统常用中文字体
        matplotlib.rcParams['font.sans-serif'] = ['WenQuanYi Micro Hei', 'DejaVu Sans', 'Arial Unicode MS']
    matplotlib.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题
except Exception:
    pass

from .capture import CaptureManager, CaptureUnavailableError
from .packet_parser import ParsedPacket, parse_packet
from .resource_monitor import ResourceMonitor, ResourceSample
from .stats import TrafficStats
from .storage import load_packets, save_packets

# 设置 CustomTkinter 外观
ctk.set_appearance_mode("light")  # 可选: "light", "dark", "system"
ctk.set_default_color_theme("green")  # 可选: "blue", "green", "dark-blue"
ctk.set_window_scaling(1.15)
ctk.set_widget_scaling(1.25)

ACCENT_COLOR = "#1f538d"
LIGHT_PANEL_BG = "#f7f7f7"
LIGHT_TEXT_COLOR = "#1f1f1f"
TREE_BG_COLOR = "#ffffff"
TREE_SELECTION_BG = "#cfe2ff"
TREE_HEADER_BG = "#1f538d"
TREE_HEADER_FG = "#ffffff"


class PacketCaptureApp(ctk.CTk):
    """主图形界面应用程序。"""

    def __init__(self) -> None:
        super().__init__()
        self.title("数据包捕获与分析工具")
        self.geometry("1400x900")

        self.packet_queue: "queue.Queue[ParsedPacket]" = queue.Queue()
        self.captured_packets: List[ParsedPacket] = []
        self.resource_samples: List[ResourceSample] = []
        self.stats = TrafficStats(window=timedelta(days=1))
        self.capture_start: Optional[datetime] = None

        self.capture_manager = CaptureManager(self._on_packet_captured)
        self.resource_monitor = ResourceMonitor(self._on_resource_sample, interval=2.0)

        # 优化参数：限制UI显示、批处理、限流
        self._max_packets_display = 5000
        self._stats_update_counter = 0
        self._stats_update_interval = 10
        self._pending_ui_update = False
        self._display_offset = 0 

        self._build_ui()
        self.after(1000, self._update_uptime)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 主容器使用 CTkFrame
        main_container = ctk.CTkFrame(self, fg_color=LIGHT_PANEL_BG)
        main_container.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        main_container.grid_columnconfigure(0, weight=3)
        main_container.grid_columnconfigure(1, weight=5)
        main_container.grid_rowconfigure(1, weight=1)

        # 顶部控制面板（跨两列）
        control_frame = ctk.CTkFrame(main_container)
        control_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        control_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(control_frame, text="BPF 过滤器:", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.filter_var = tk.StringVar()
        filter_entry = ctk.CTkEntry(control_frame, textvariable=self.filter_var, placeholder_text="例如: tcp port 80", font=ctk.CTkFont(size=14))
        filter_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=3)

        # 按钮行1
        button_frame1 = ctk.CTkFrame(control_frame)
        button_frame1.grid(row=0, column=2, padx=3, pady=3)
        self.start_button = ctk.CTkButton(button_frame1, text="▶ 开始捕获", command=self.start_capture, 
                                          fg_color="#2fa572", hover_color="#228B22", width=140, 
                                          font=ctk.CTkFont(size=14, weight="bold"))
        self.start_button.pack(side=tk.LEFT, padx=2)
        self.stop_button = ctk.CTkButton(button_frame1, text="⏹ 停止", command=self.stop_capture, 
                                        state=tk.DISABLED, fg_color="#d32f2f", hover_color="#b71c1c", width=120,
                                        font=ctk.CTkFont(size=14, weight="bold"))
        self.stop_button.pack(side=tk.LEFT, padx=2)

        # 按钮行2
        button_frame2 = ctk.CTkFrame(control_frame)
        button_frame2.grid(row=1, column=0, columnspan=3, pady=3)
        self.save_button = ctk.CTkButton(button_frame2, text="💾 保存捕获", command=self.save_capture, 
                                        width=140, font=ctk.CTkFont(size=14))
        self.save_button.pack(side=tk.LEFT, padx=3)
        self.load_button = ctk.CTkButton(button_frame2, text="📂 加载捕获", command=self.load_capture, 
                                        width=140, font=ctk.CTkFont(size=14))
        self.load_button.pack(side=tk.LEFT, padx=3)

        # 左侧面板
        left_frame = ctk.CTkFrame(main_container, fg_color=LIGHT_PANEL_BG)
        left_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5), pady=(0, 5))
        left_frame.grid_rowconfigure(0, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        # 右侧面板
        right_frame = ctk.CTkFrame(main_container, fg_color=LIGHT_PANEL_BG)
        right_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 0), pady=(0, 5))
        right_frame.grid_columnconfigure(0, weight=1)
        right_frame.grid_rowconfigure(0, weight=1)

        # 数据包列表
        packet_frame = ctk.CTkFrame(left_frame, fg_color=LIGHT_PANEL_BG)
        packet_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=(0, 5))
        packet_frame.grid_rowconfigure(1, weight=1)
        packet_frame.grid_columnconfigure(0, weight=1)

        # 列表标题
        list_header = ctk.CTkFrame(packet_frame)
        list_header.grid(row=0, column=0, sticky="ew", padx=3, pady=3)
        list_header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(list_header, text="📦 捕获的数据包", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, sticky="w", padx=8, pady=3)

        # Treeview 容器
        tree_container = ctk.CTkFrame(packet_frame, fg_color=LIGHT_PANEL_BG)
        tree_container.grid(row=1, column=0, sticky="nsew", padx=3, pady=3)
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

        columns = ("time", "summary", "protocols")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Capture.Treeview",
            background=TREE_BG_COLOR,
            foreground=LIGHT_TEXT_COLOR,
            fieldbackground=TREE_BG_COLOR,
            font=("Microsoft YaHei", 19),
            rowheight=48,
        )
        style.configure(
            "Capture.Treeview.Heading",
            background=TREE_HEADER_BG,
            foreground=TREE_HEADER_FG,
            font=("Microsoft YaHei", 22, "bold"),
        )
        style.map(
            "Capture.Treeview",
            background=[("selected", TREE_SELECTION_BG)],
            foreground=[("selected", LIGHT_TEXT_COLOR)],
        )

        self.packet_tree = ttk.Treeview(tree_container, columns=columns, show="headings", height=20, style="Capture.Treeview")
        self.packet_tree.heading("time", text="时间")
        self.packet_tree.heading("summary", text="摘要")
        self.packet_tree.heading("protocols", text="协议")
        self.packet_tree.column("time", width=140, anchor=tk.W)
        self.packet_tree.column("summary", width=400)
        self.packet_tree.column("protocols", width=120)
        self.packet_tree.bind("<<TreeviewSelect>>", self._on_packet_selected)

        scroll = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scroll.set)
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        # 右侧标签页
        notebook_style = ttk.Style()
        notebook_style.theme_use("clam")
        notebook_style.configure(
            "RightNotebook.TNotebook",
            background=LIGHT_PANEL_BG,
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
        )
        notebook_style.configure(
            "RightNotebook.TNotebook.Tab",
            font=("Microsoft YaHei", 16, "bold"),
            padding=(18, 10),
            background=LIGHT_PANEL_BG,
            foreground=LIGHT_TEXT_COLOR,
        )
        notebook_style.map(
            "RightNotebook.TNotebook.Tab",
            background=[("selected", ACCENT_COLOR), ("!selected", LIGHT_PANEL_BG)],
            foreground=[("selected", "#ffffff"), ("!selected", LIGHT_TEXT_COLOR)],
        )

        notebook = ttk.Notebook(right_frame, style="RightNotebook.TNotebook")
        notebook.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        self.details_tab = ctk.CTkFrame(notebook, fg_color=LIGHT_PANEL_BG)
        self.stats_tab = ctk.CTkFrame(notebook, fg_color=LIGHT_PANEL_BG)
        self.resource_tab = ctk.CTkFrame(notebook, fg_color=LIGHT_PANEL_BG)
        notebook.add(self.details_tab, text="📋 数据包详情")
        notebook.add(self.stats_tab, text="📊 统计信息")
        notebook.add(self.resource_tab, text="💻 资源监控")

        self._build_details_tab()
        self._build_stats_tab()
        self._build_resource_tab()

    def _build_details_tab(self) -> None:
        self.details_tab.grid_columnconfigure(0, weight=1)
        self.details_tab.grid_rowconfigure(0, weight=1)
        
        tree_frame = ctk.CTkFrame(self.details_tab, fg_color=LIGHT_PANEL_BG)
        tree_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        tree_style = ttk.Style()
        tree_style.configure(
            "Details.Treeview",
            background=TREE_BG_COLOR,
            foreground=LIGHT_TEXT_COLOR,
            fieldbackground=TREE_BG_COLOR,
            font=("Microsoft YaHei", 16),
            rowheight=32,
        )
        tree_style.configure(
            "Details.Treeview.Heading",
            font=("Microsoft YaHei", 17, "bold"),
            background=TREE_HEADER_BG,
            foreground=TREE_HEADER_FG,
        )
        tree_style.map(
            "Details.Treeview",
            background=[("selected", TREE_SELECTION_BG)],
            foreground=[("selected", LIGHT_TEXT_COLOR)],
        )

        self.details_tree = ttk.Treeview(
            tree_frame,
            columns=("value",),
            show="tree headings",
            style="Details.Treeview",
        )
        self.details_tree.heading("#0", text="字段")
        self.details_tree.heading("value", text="内容")
        self.details_tree.column("#0", width=220, anchor=tk.W, stretch=True)
        self.details_tree.column("value", width=400, anchor=tk.W, stretch=True)
        self.details_tree.grid(row=0, column=0, sticky="nsew", padx=3, pady=3)

        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.details_tree.yview)
        self.details_tree.configure(yscrollcommand=tree_scroll_y.set)
        tree_scroll_y.grid(row=0, column=1, sticky="ns", pady=3)

    def _build_stats_tab(self) -> None:
        self.stats_tab.grid_columnconfigure(0, weight=1)
        self.stats_tab.grid_rowconfigure(0, weight=0)
        self.stats_tab.grid_rowconfigure(1, weight=1)
        
        stats_top = ctk.CTkFrame(self.stats_tab, fg_color=LIGHT_PANEL_BG)
        stats_top.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        stats_top.grid_columnconfigure(0, weight=1)

        # 统计表格容器
        table_container = ctk.CTkFrame(stats_top, fg_color=LIGHT_PANEL_BG)
        table_container.grid(row=0, column=0, sticky="ew", padx=3, pady=3)
        table_container.grid_columnconfigure(0, weight=1)

        columns = ("protocol", "count")
        self.stats_tree = ttk.Treeview(table_container, columns=columns, show="headings", height=4, style="Capture.Treeview")
        self.stats_tree.heading("protocol", text="协议")
        self.stats_tree.heading("count", text="数据包数")
        self.stats_tree.column("protocol", width=120)
        self.stats_tree.column("count", width=100, anchor=tk.E)
        self.stats_tree.grid(row=0, column=0, sticky="ew")

        stats_scroll = ttk.Scrollbar(table_container, orient=tk.VERTICAL, command=self.stats_tree.yview)
        self.stats_tree.configure(yscrollcommand=stats_scroll.set)
        stats_scroll.grid(row=0, column=1, sticky="ns")

        # 图表容器
        chart_frame = ctk.CTkFrame(self.stats_tab, fg_color=LIGHT_PANEL_BG)
        chart_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 5))
        chart_frame.grid_columnconfigure(0, weight=1)
        chart_frame.grid_rowconfigure(0, weight=1)

        figure = Figure(figsize=(8, 5), dpi=100, facecolor="#ffffff")
        self.ax_ipv6 = figure.add_subplot(211)
        self.ax_ipv6.set_title("IPv6 流量占比（最近24小时）", color=LIGHT_TEXT_COLOR, fontsize=14, fontweight='bold')
        self.ax_ipv6.set_ylabel("IPv6 %", color=LIGHT_TEXT_COLOR, fontsize=13)
        self.ax_ipv6.set_facecolor("#ffffff")
        self.ax_ipv6.tick_params(colors=LIGHT_TEXT_COLOR, labelsize=11)
        for spine in self.ax_ipv6.spines.values():
            spine.set_color(LIGHT_TEXT_COLOR)

        self.ax_bar = figure.add_subplot(212)
        self.ax_bar.set_title("TCP/UDP/ARP 分布", color=LIGHT_TEXT_COLOR, fontsize=14, fontweight='bold')
        self.ax_bar.set_ylabel("数据包数", color=LIGHT_TEXT_COLOR, fontsize=13)
        self.ax_bar.set_facecolor("#ffffff")
        self.ax_bar.tick_params(colors=LIGHT_TEXT_COLOR, labelsize=11)
        for spine in self.ax_bar.spines.values():
            spine.set_color(LIGHT_TEXT_COLOR)

        self.canvas = FigureCanvasTkAgg(figure, master=chart_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew")

    def _build_resource_tab(self) -> None:
        self.resource_tab.grid_columnconfigure(0, weight=1)
        self.resource_tab.grid_rowconfigure(1, weight=1)
        
        info_frame = ctk.CTkFrame(self.resource_tab, fg_color=LIGHT_PANEL_BG)
        info_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        info_frame.grid_columnconfigure(0, weight=1)

        self.start_time_var = tk.StringVar(value="开始时间: -")
        self.uptime_var = tk.StringVar(value="运行时长: 0秒")
        ctk.CTkLabel(info_frame, textvariable=self.start_time_var, 
                    font=ctk.CTkFont(size=14)).grid(row=0, column=0, sticky="w", padx=8, pady=3)
        ctk.CTkLabel(info_frame, textvariable=self.uptime_var, 
                    font=ctk.CTkFont(size=14)).grid(row=1, column=0, sticky="w", padx=8, pady=3)

        # 资源表格容器
        resource_table_frame = ctk.CTkFrame(self.resource_tab, fg_color=LIGHT_PANEL_BG)
        resource_table_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 5))
        resource_table_frame.grid_columnconfigure(0, weight=1)
        resource_table_frame.grid_rowconfigure(0, weight=1)

        self.resource_tree = ttk.Treeview(
            resource_table_frame,
            columns=("time", "cpu", "memory"),
            show="headings",
            height=12,
            style="Capture.Treeview",
        )
        self.resource_tree.heading("time", text="时间戳")
        self.resource_tree.heading("cpu", text="CPU %")
        self.resource_tree.heading("memory", text="内存 (MB)")
        self.resource_tree.column("time", width=180)
        self.resource_tree.column("cpu", width=100, anchor=tk.E)
        self.resource_tree.column("memory", width=130, anchor=tk.E)
        self.resource_tree.grid(row=0, column=0, sticky="nsew", padx=3, pady=3)

        resource_scroll = ttk.Scrollbar(resource_table_frame, orient=tk.VERTICAL, command=self.resource_tree.yview)
        self.resource_tree.configure(yscrollcommand=resource_scroll.set)
        resource_scroll.grid(row=0, column=1, sticky="ns")

        button_frame = ctk.CTkFrame(self.resource_tab, fg_color=LIGHT_PANEL_BG)
        button_frame.grid(row=2, column=0, pady=5)
        export_button = ctk.CTkButton(button_frame, text="📥 导出资源日志", command=self.export_resource_log, 
                                     width=160, font=ctk.CTkFont(size=14))
        export_button.pack(pady=3)

        if not ResourceMonitor.is_available():
            ctk.CTkLabel(
                self.resource_tab,
                text="⚠️ psutil 未安装，资源监控不可用",
                text_color="red",
                font=ctk.CTkFont(size=14, weight="bold")
            ).grid(row=3, column=0, pady=5)

    # ------------------------------------------------------------------ Packet handling
    def _on_packet_captured(self, packet: object) -> None:
        try:
            parsed = parse_packet(packet)
            self.packet_queue.put(parsed)
            if not self._pending_ui_update:
                self._pending_ui_update = True
                self.after(50, self._drain_packet_queue)
        except Exception:
            logging.exception("解析数据包失败")

    def _drain_packet_queue(self) -> None:
        self._pending_ui_update = False
        updated = False
        batch_count = 0
        max_batch_size = 100
        
        while batch_count < max_batch_size:
            try:
                packet = self.packet_queue.get_nowait()
            except queue.Empty:
                break
            else:
                self.captured_packets.append(packet)
                self.stats.register(packet)
                self._stats_update_counter += 1
                batch_count += 1
                
                index = len(self.captured_packets) - 1
                # 当前UI中显示的条目数
                display_count = len(self.packet_tree.get_children())

                # 始终使用捕获包的全局索引作为 iid，这样 selection 可以直接映射到 captured_packets
                if display_count < self._max_packets_display:
                    self.packet_tree.insert(
                        "",
                        tk.END,
                        iid=str(index),
                        values=(packet.timestamp.strftime("%H:%M:%S"), packet.summary, ",".join(packet.protocols)),
                    )
                    updated = True
                else:
                    # 超过显示上限：删除最旧的显示项（Treeview 中的第一项），然后插入新项（iid 为全局索引）
                    children = self.packet_tree.get_children()
                    if children:
                        self.packet_tree.delete(children[0])
                    self.packet_tree.insert(
                        "",
                        tk.END,
                        iid=str(index),
                        values=(packet.timestamp.strftime("%H:%M:%S"), packet.summary, ",".join(packet.protocols)),
                    )
                    updated = True
        
        # 限制图表更新频率，避免频繁重绘
        if self._stats_update_counter >= self._stats_update_interval:
            self._stats_update_counter = 0
            if updated:
                self._refresh_statistics()
        
        # 如果队列中还有数据，继续处理
        if not self.packet_queue.empty():
            self._pending_ui_update = True
            self.after(50, self._drain_packet_queue)

    def _on_packet_selected(self, _event: object) -> None:
        selection = self.packet_tree.selection()
        if not selection:
            return
        idx = int(selection[0])
        packet = self.captured_packets[idx]
        self._display_packet_details(packet)

    def _display_packet_details(self, packet: ParsedPacket) -> None:
        # 更新树形视图
        self.details_tree.delete(*self.details_tree.get_children())
        general = self.details_tree.insert("", tk.END, text="概览", open=True)
        self.details_tree.insert(general, tk.END, text="捕获时间", values=(packet.timestamp,))
        self.details_tree.insert(general, tk.END, text="摘要", values=(packet.summary,))
        self.details_tree.insert(general, tk.END, text="协议链路", values=(", ".join(packet.protocols)))

        network_node = self.details_tree.insert("", tk.END, text="网络层", open=True)
        if packet.network_layer:
            for key, value in packet.network_layer.items():
                self.details_tree.insert(network_node, tk.END, text=key, values=(value,))
        else:
            self.details_tree.insert(network_node, tk.END, text="无", values=("",))

        transport_node = self.details_tree.insert("", tk.END, text="传输层", open=True)
        if packet.transport_layer:
            for key, value in packet.transport_layer.items():
                self.details_tree.insert(transport_node, tk.END, text=key, values=(value,))
        else:
            self.details_tree.insert(transport_node, tk.END, text="无", values=("",))

        if packet.dns_info:
            dns_node = self.details_tree.insert("", tk.END, text="DNS", open=True)
            for key, value in packet.dns_info.items():
                self.details_tree.insert(dns_node, tk.END, text=key, values=(value,))


    # ------------------------------------------------------------------ Capture controls
    def start_capture(self) -> None:
        filter_expr = self.filter_var.get().strip() or None
        try:
            self.capture_manager.start(filter_expr=filter_expr)
        except CaptureUnavailableError as exc:
            messagebox.showerror("捕获不可用", str(exc))
            return
        except Exception as exc:  # pragma: no cover - safety
            messagebox.showerror("捕获错误", str(exc))
            return

        self.capture_start = datetime.now()
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL, fg_color="#d32f2f", hover_color="#b71c1c")
        self.start_time_var.set(f"开始时间: {self.capture_start.strftime('%Y-%m-%d %H:%M:%S')}")
        self.resource_monitor.start()

    def stop_capture(self) -> None:
        logging.info("停止抓包")
        self.capture_manager.stop()
        self.resource_monitor.stop()
        self.capture_start = None
        self.start_button.configure(state=tk.NORMAL, fg_color="#2fa572", hover_color="#228B22")
        self.stop_button.configure(state=tk.DISABLED)
        self.uptime_var.set("运行时长: 0秒")

    # ------------------------------------------------------------------ Statistics & charts
    def _refresh_statistics(self) -> None:
        # 更新表格（增量更新，避免闪烁）
        current_items = {item: self.stats_tree.item(item) for item in self.stats_tree.get_children()}
        for protocol, count in self.stats.table_rows():
            found = False
            for item_id, item_data in current_items.items():
                if item_data['values'][0] == protocol:
                    self.stats_tree.item(item_id, values=(protocol, count))
                    found = True
                    break
            if not found:
                self.stats_tree.insert("", tk.END, values=(protocol, count))

        # 更新图表
        ipv6_series = self.stats.ipv6_ratio_series()
        if ipv6_series:
            self.ax_ipv6.clear()
            self.ax_ipv6.set_facecolor("#ffffff")
            self.ax_ipv6.set_title("IPv6 流量占比（最近24小时）", color=LIGHT_TEXT_COLOR, fontsize=14, fontweight='bold')
            self.ax_ipv6.set_ylabel("IPv6 %", color=LIGHT_TEXT_COLOR, fontsize=13)
            self.ax_ipv6.tick_params(colors=LIGHT_TEXT_COLOR, labelsize=11)
            for spine in self.ax_ipv6.spines.values():
                spine.set_color(LIGHT_TEXT_COLOR)
            x = [ts for ts, _ in ipv6_series]
            y = [ratio for _, ratio in ipv6_series]
            self.ax_ipv6.plot_date(x, y, linestyle="solid", marker=None, color="#4A9EFF")
            self.ax_ipv6.set_ylim(0, 100)
            self.ax_ipv6.grid(True, which="both", linestyle="--", alpha=0.3, color="#c0c0c0")

        counters = self.stats.protocol_counters()
        self.ax_bar.clear()
        self.ax_bar.set_facecolor("#ffffff")
        self.ax_bar.set_title("TCP/UDP/ARP 分布", color=LIGHT_TEXT_COLOR, fontsize=14, fontweight='bold')
        self.ax_bar.set_ylabel("数据包数", color=LIGHT_TEXT_COLOR, fontsize=13)
        self.ax_bar.tick_params(colors=LIGHT_TEXT_COLOR, labelsize=11)
        for spine in self.ax_bar.spines.values():
            spine.set_color(LIGHT_TEXT_COLOR)
        labels = ["TCP", "UDP", "ARP"]
        values = [counters.get(label, 0) for label in labels]
        self.ax_bar.bar(labels, values, color=["#4A9EFF", "#FF9500", "#2ECC71"])
        self.ax_bar.grid(axis="y", linestyle="--", alpha=0.3, color="#c0c0c0")

        self.canvas.draw_idle()

    # ------------------------------------------------------------------ Persistence
    def save_capture(self) -> None:
        if not self.captured_packets:
            messagebox.showinfo("无数据", "暂无数据包可保存。")
            return
        file_path = filedialog.asksaveasfilename(
            title="保存捕获的数据包",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not file_path:
            return
        try:
            save_packets(Path(file_path), self.captured_packets)
        except Exception as exc:
            messagebox.showerror("保存错误", str(exc))
        else:
            messagebox.showinfo("已保存", f"捕获数据已保存到 {file_path}")

    def load_capture(self) -> None:
        file_path = filedialog.askopenfilename(
            title="打开捕获文件",
            filetypes=[("JSON", "*.json"), ("所有文件", "*.*")],
        )
        if not file_path:
            return
        try:
            packets = load_packets(Path(file_path))
        except Exception as exc:
            messagebox.showerror("加载错误", str(exc))
            return

        self.captured_packets = packets
        self.stats.reset()
        self.packet_tree.delete(*self.packet_tree.get_children())
        # 只在UI中加载最后N个数据包
        start_idx = max(0, len(packets) - self._max_packets_display)
        for idx, packet in enumerate(packets):
            self.stats.register(packet)
            if idx >= start_idx:
                self.packet_tree.insert(
                    "",
                    tk.END,
                    iid=str(idx),
                    values=(packet.timestamp.strftime("%H:%M:%S"), packet.summary, ",".join(packet.protocols)),
                )
        self._refresh_statistics()
        messagebox.showinfo("已加载", f"已加载 {len(packets)} 个数据包（显示最后 {min(len(packets), self._max_packets_display)} 个）")

    # ------------------------------------------------------------------ Resource monitoring
    def _on_resource_sample(self, sample: ResourceSample) -> None:
        self.resource_samples.append(sample)
        self.after(0, lambda: self._append_resource_sample(sample))

    def _append_resource_sample(self, sample: ResourceSample) -> None:
        timestamp = sample.timestamp.strftime("%H:%M:%S")
        self.resource_tree.insert("", tk.END, values=(timestamp, f"{sample.cpu_percent:.2f}", f"{sample.memory_mb:.2f}"))
        # 限制UI中只显示最后200个样本
        children = self.resource_tree.get_children()
        if len(children) > 200:
            self.resource_tree.delete(children[0])

    def export_resource_log(self) -> None:
        if not self.resource_samples:
            messagebox.showinfo("无样本", "尚未捕获资源样本。")
            return
        file_path = filedialog.asksaveasfilename(
            title="导出资源使用情况",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not file_path:
            return
        try:
            payload = [
                {
                    "timestamp": sample.timestamp.isoformat(),
                    "cpu_percent": sample.cpu_percent,
                    "memory_mb": sample.memory_mb,
                }
                for sample in self.resource_samples
            ]
            Path(file_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as exc:
            messagebox.showerror("导出错误", str(exc))
        else:
            messagebox.showinfo("已导出", f"资源日志已保存到 {file_path}")

    def _update_uptime(self) -> None:
        if self.capture_start:
            delta = datetime.now() - self.capture_start
            self.uptime_var.set(f"运行时长: {str(delta).split('.')[0]}")
        self.after(1000, self._update_uptime)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = PacketCaptureApp()
    app.mainloop()


if __name__ == "__main__":
    main()

