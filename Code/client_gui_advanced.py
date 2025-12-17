import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import time
from datetime import datetime
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters

class AdvancedVPNClient:
    """Professional VPN Client with enhanced UI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SecureVPN")
        self.root.geometry("1100x750")
        self.root.configure(bg='#0a0e27')
        
        # Default server
        self.selected_server = {
            "name": "Custom Server",
            "host": "192.168.1.100",
            "port": 5555,
            "location": "Local Network"
        }
        
        # Setup styling
        self.setup_styles()
        
        # Connection state
        self.sock = None
        self.shared_key = None
        self.connected = False
        self.receive_thread = None
        self.BUF = 65536
        
        # Statistics
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connection_start_time = None
        self.last_bytes_sent = 0
        self.last_bytes_received = 0
        self.last_speed_update = None
        self.upload_speed = 0
        self.download_speed = 0
        self.ping_ms = 0
        self.messages_sent = 0
        self.messages_received = 0
        
        self.setup_ui()
        
    def setup_styles(self):
        """Modern dark theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Color palette
        self.bg_primary = '#0a0e27'
        self.bg_secondary = '#151b3d'
        self.bg_tertiary = '#1e2749'
        self.accent_blue = '#3b82f6'
        self.accent_green = '#10b981'
        self.accent_red = '#ef4444'
        self.accent_yellow = '#f59e0b'
        self.text_white = '#ffffff'
        self.text_gray = '#94a3b8'
        self.text_dark = '#64748b'
        
    def create_panel(self, parent, **kwargs):
        """Create styled panel"""
        panel = tk.Frame(parent, bg=self.bg_secondary, **kwargs)
        return panel
    
    def setup_ui(self):
        """Build main interface"""
        # Header
        header = tk.Frame(self.root, bg=self.bg_secondary, height=80)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        tk.Label(header, text="SecureVPN", font=('Arial', 24, 'bold'),
                fg=self.text_white, bg=self.bg_secondary).pack(side=tk.LEFT, padx=30, pady=20)
        
        version = tk.Label(header, text="Pro v2.1", font=('Arial', 10),
                          fg=self.text_dark, bg=self.bg_secondary)
        version.pack(side=tk.LEFT, pady=20)
        
        # Main content
        content = tk.Frame(self.root, bg=self.bg_primary)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Left sidebar
        sidebar = tk.Frame(content, bg=self.bg_primary, width=320)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 20))
        sidebar.pack_propagate(False)
        
        self._build_connection_card(sidebar)
        self._build_server_card(sidebar)
        
        # Right content area
        main_area = tk.Frame(content, bg=self.bg_primary)
        main_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        self._build_stats_panel(main_area)
        self._build_activity_panel(main_area)
        
    def _build_connection_card(self, parent):
        """Connection status and control"""
        card = self.create_panel(parent)
        card.pack(fill=tk.X, pady=(0, 20))
        
        # Status section
        status_frame = tk.Frame(card, bg=self.bg_secondary)
        status_frame.pack(fill=tk.X, padx=25, pady=25)
        
        tk.Label(status_frame, text="Status", font=('Arial', 11, 'bold'),
                fg=self.text_gray, bg=self.bg_secondary).pack(anchor='w')
        
        status_display = tk.Frame(status_frame, bg=self.bg_secondary)
        status_display.pack(fill=tk.X, pady=(10, 0))
        
        self.status_indicator = tk.Canvas(status_display, width=12, height=12, 
                                         bg=self.bg_secondary, highlightthickness=0)
        self.status_indicator.pack(side=tk.LEFT, padx=(0, 10))
        self.status_circle = self.status_indicator.create_oval(2, 2, 10, 10, 
                                                               fill=self.accent_red, outline='')
        
        self.status_text = tk.Label(status_display, text="Disconnected", 
                                   font=('Arial', 16, 'bold'),
                                   fg=self.text_white, bg=self.bg_secondary)
        self.status_text.pack(side=tk.LEFT)
        
        self.connection_info = tk.Label(status_frame, text="Not connected", 
                                       font=('Arial', 9),
                                       fg=self.text_dark, bg=self.bg_secondary)
        self.connection_info.pack(anchor='w', pady=(8, 0))
        
        # Connect button
        btn_frame = tk.Frame(card, bg=self.bg_secondary)
        btn_frame.pack(fill=tk.X, padx=25, pady=(0, 25))
        
        self.connect_btn = tk.Button(btn_frame, text="Connect",
                                     command=self.toggle_connection,
                                     font=('Arial', 13, 'bold'),
                                     bg=self.accent_green, fg=self.text_white,
                                     activebackground='#059669',
                                     relief='flat', cursor='hand2',
                                     padx=40, pady=15)
        self.connect_btn.pack(fill=tk.X)
        
    def _build_server_card(self, parent):
        """Server configuration"""
        card = self.create_panel(parent)
        card.pack(fill=tk.X, pady=(0, 20))
        
        # Title
        title_frame = tk.Frame(card, bg=self.bg_secondary)
        title_frame.pack(fill=tk.X, padx=25, pady=(20, 15))
        
        tk.Label(title_frame, text="Server", font=('Arial', 11, 'bold'),
                fg=self.text_gray, bg=self.bg_secondary).pack(side=tk.LEFT)
        
        # Server display
        server_display = tk.Frame(card, bg=self.bg_tertiary)
        server_display.pack(fill=tk.X, padx=25, pady=(0, 20))
        
        info_frame = tk.Frame(server_display, bg=self.bg_tertiary)
        info_frame.pack(fill=tk.X, padx=20, pady=15)
        
        self.server_name = tk.Label(info_frame, text=self.selected_server['name'],
                                    font=('Arial', 12, 'bold'),
                                    fg=self.text_white, bg=self.bg_tertiary)
        self.server_name.pack(anchor='w')
        
        self.server_details = tk.Label(info_frame, 
                                      text=f"{self.selected_server['host']}:{self.selected_server['port']}",
                                      font=('Arial', 10),
                                      fg=self.text_gray, bg=self.bg_tertiary)
        self.server_details.pack(anchor='w', pady=(5, 0))
        
        # Configure button
        config_btn = tk.Button(card, text="Configure Server",
                              command=self.open_server_config,
                              font=('Arial', 10),
                              bg=self.bg_tertiary, fg=self.text_white,
                              activebackground=self.bg_primary,
                              relief='flat', cursor='hand2',
                              padx=20, pady=12)
        config_btn.pack(fill=tk.X, padx=25, pady=(0, 20))
        
        # Quick info
        tk.Label(card, text="Configure your VPN server address",
                font=('Arial', 9), fg=self.text_dark,
                bg=self.bg_secondary).pack(padx=25, pady=(0, 20))
        
    def _build_stats_panel(self, parent):
        """Connection statistics"""
        panel = self.create_panel(parent)
        panel.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(panel, text="Statistics", font=('Arial', 11, 'bold'),
                fg=self.text_gray, bg=self.bg_secondary).pack(anchor='w', padx=25, pady=(20, 15))
        
        stats_grid = tk.Frame(panel, bg=self.bg_secondary)
        stats_grid.pack(fill=tk.X, padx=15, pady=(0, 20))
        
        self.stat_widgets = {}
        stats_data = [
            ('upload_speed', 'Upload Speed', '0 KB/s'),
            ('download_speed', 'Download Speed', '0 KB/s'),
            ('ping', 'Latency', '0 ms'),
            ('duration', 'Duration', '00:00:00')
        ]
        
        for i, (key, label, value) in enumerate(stats_data):
            stat_box = tk.Frame(stats_grid, bg=self.bg_tertiary)
            stat_box.grid(row=0, column=i, padx=10, sticky='nsew')
            
            tk.Label(stat_box, text=label, font=('Arial', 9),
                    fg=self.text_dark, bg=self.bg_tertiary).pack(pady=(12, 5))
            
            value_label = tk.Label(stat_box, text=value, font=('Arial', 12, 'bold'),
                                  fg=self.text_white, bg=self.bg_tertiary)
            value_label.pack(pady=(0, 12))
            
            self.stat_widgets[key] = value_label
        
        for i in range(4):
            stats_grid.columnconfigure(i, weight=1)
        
        # Secondary stats row
        stats_grid2 = tk.Frame(panel, bg=self.bg_secondary)
        stats_grid2.pack(fill=tk.X, padx=15, pady=(0, 20))
        
        stats_data2 = [
            ('upload_total', 'Total Upload', '0 KB'),
            ('download_total', 'Total Download', '0 KB'),
            ('messages', 'Messages', '0 sent / 0 received')
        ]
        
        for i, (key, label, value) in enumerate(stats_data2):
            stat_box = tk.Frame(stats_grid2, bg=self.bg_tertiary)
            stat_box.grid(row=0, column=i, padx=10, sticky='nsew')
            
            tk.Label(stat_box, text=label, font=('Arial', 9),
                    fg=self.text_dark, bg=self.bg_tertiary).pack(pady=(12, 5))
            
            value_label = tk.Label(stat_box, text=value, font=('Arial', 11, 'bold'),
                                  fg=self.text_white, bg=self.bg_tertiary)
            value_label.pack(pady=(0, 12))
            
            self.stat_widgets[key] = value_label
        
        for i in range(3):
            stats_grid2.columnconfigure(i, weight=1)
    
    def _build_activity_panel(self, parent):
        """Logs and messages"""
        panel = self.create_panel(parent)
        panel.pack(fill=tk.BOTH, expand=True)
        
        # Tabs
        tab_frame = tk.Frame(panel, bg=self.bg_secondary)
        tab_frame.pack(fill=tk.X, padx=25, pady=(20, 0))
        
        self.active_tab = 'logs'
        
        logs_tab = tk.Button(tab_frame, text="Activity Log",
                            command=lambda: self.switch_tab('logs'),
                            font=('Arial', 10, 'bold'),
                            bg=self.bg_tertiary, fg=self.text_white,
                            relief='flat', padx=20, pady=10, cursor='hand2')
        logs_tab.pack(side=tk.LEFT, padx=(0, 5))
        
        chat_tab = tk.Button(tab_frame, text="Messages",
                            command=lambda: self.switch_tab('chat'),
                            font=('Arial', 10),
                            bg=self.bg_secondary, fg=self.text_gray,
                            relief='flat', padx=20, pady=10, cursor='hand2')
        chat_tab.pack(side=tk.LEFT)
        
        self.tab_buttons = {'logs': logs_tab, 'chat': chat_tab}
        
        # Content area
        content_frame = tk.Frame(panel, bg=self.bg_secondary)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=15)
        
        # Logs
        self.logs_display = scrolledtext.ScrolledText(content_frame,
                                                      wrap=tk.WORD,
                                                      font=('Consolas', 9),
                                                      bg=self.bg_primary,
                                                      fg="#22c5b2",
                                                      insertbackground="#22c5c2",
                                                      relief='flat',
                                                      padx=15, pady=15,
                                                      state='disabled')
        self.logs_display.pack(fill=tk.BOTH, expand=True)
        
        self.logs_display.tag_config('info', foreground='#22c55e')
        self.logs_display.tag_config('success', foreground='#3b82f6')
        self.logs_display.tag_config('error', foreground='#ef4444')
        self.logs_display.tag_config('warning', foreground='#f59e0b')
        
        # Chat (hidden initially)
        self.chat_frame = tk.Frame(content_frame, bg=self.bg_secondary)
        
        self.messages_display = scrolledtext.ScrolledText(self.chat_frame,
                                                          wrap=tk.WORD,
                                                          font=('Arial', 10),
                                                          bg=self.bg_primary,
                                                          fg=self.text_white,
                                                          relief='flat',
                                                          padx=15, pady=15,
                                                          state='disabled')
        self.messages_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.messages_display.tag_config('you', foreground='#3b82f6', font=('Arial', 10, 'bold'))
        self.messages_display.tag_config('server', foreground='#10b981', font=('Arial', 10, 'bold'))
        
        # Message input
        input_frame = tk.Frame(self.chat_frame, bg=self.bg_secondary)
        input_frame.pack(fill=tk.X)
        
        self.message_input = tk.Entry(input_frame, font=('Arial', 10),
                                     bg=self.bg_tertiary, fg=self.text_white,
                                     insertbackground=self.accent_blue,
                                     relief='flat', state='disabled')
        self.message_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, ipady=8, padx=(0, 10))
        self.message_input.bind('<Return>', lambda e: self.send_message())
        
        self.send_button = tk.Button(input_frame, text="Send",
                                     command=self.send_message,
                                     bg=self.accent_blue, fg=self.text_white,
                                     font=('Arial', 10, 'bold'),
                                     relief='flat', padx=25, pady=8,
                                     cursor='hand2', state='disabled')
        self.send_button.pack(side=tk.RIGHT)
        
        self.log("VPN client initialized. Configure server to begin.", 'info')
    
    def switch_tab(self, tab_name):
        """Switch between tabs"""
        self.active_tab = tab_name
        
        for name, btn in self.tab_buttons.items():
            if name == tab_name:
                btn.config(bg=self.bg_tertiary, fg=self.text_white, font=('Arial', 10, 'bold'))
            else:
                btn.config(bg=self.bg_secondary, fg=self.text_gray, font=('Arial', 10))
        
        if tab_name == 'logs':
            self.chat_frame.pack_forget()
            self.logs_display.pack(fill=tk.BOTH, expand=True)
        else:
            self.logs_display.pack_forget()
            self.chat_frame.pack(fill=tk.BOTH, expand=True)
    
    def open_server_config(self):
        """Server configuration dialog"""
        if self.connected:
            messagebox.showwarning("Active Connection", 
                                 "Please disconnect before changing server settings.")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Server Configuration")
        dialog.geometry("450x300")
        dialog.configure(bg=self.bg_secondary)
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - 225
        y = (dialog.winfo_screenheight() // 2) - 150
        dialog.geometry(f"450x300+{x}+{y}")
        
        tk.Label(dialog, text="Configure Server", font=('Arial', 16, 'bold'),
                fg=self.text_white, bg=self.bg_secondary).pack(pady=20)
        
        tk.Label(dialog, text="Enter your VPN server details",
                font=('Arial', 10), fg=self.text_gray,
                bg=self.bg_secondary).pack()
        
        # IP input
        tk.Label(dialog, text="IP Address", font=('Arial', 10, 'bold'),
                fg=self.text_white, bg=self.bg_secondary).pack(anchor='w', padx=40, pady=(20, 5))
        
        ip_input = tk.Entry(dialog, font=('Arial', 11),
                           bg=self.bg_tertiary, fg=self.text_white,
                           insertbackground=self.accent_blue,
                           relief='flat', width=35)
        ip_input.pack(padx=40, ipady=8)
        ip_input.insert(0, self.selected_server['host'])
        ip_input.focus()
        
        # Port input
        tk.Label(dialog, text="Port", font=('Arial', 10, 'bold'),
                fg=self.text_white, bg=self.bg_secondary).pack(anchor='w', padx=40, pady=(15, 5))
        
        port_input = tk.Entry(dialog, font=('Arial', 11),
                             bg=self.bg_tertiary, fg=self.text_white,
                             insertbackground=self.accent_blue,
                             relief='flat', width=35)
        port_input.pack(padx=40, ipady=8)
        port_input.insert(0, str(self.selected_server['port']))
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg=self.bg_secondary)
        btn_frame.pack(pady=25)
        
        def save_config():
            ip = ip_input.get().strip()
            port_str = port_input.get().strip()
            
            if not ip or not port_str:
                messagebox.showerror("Invalid Input", "Please fill all fields.", parent=dialog)
                return
            
            try:
                port = int(port_str)
                if not (1 <= port <= 65535):
                    raise ValueError("Port out of range")
            except ValueError:
                messagebox.showerror("Invalid Port", "Port must be between 1-65535.", parent=dialog)
                return
            
            self.selected_server = {
                "name": "Custom Server",
                "host": ip,
                "port": port,
                "location": "Local Network"
            }
            
            self.server_name.config(text=self.selected_server['name'])
            self.server_details.config(text=f"{ip}:{port}")
            
            self.log(f"Server configured: {ip}:{port}", 'success')
            messagebox.showinfo("Configuration Saved", 
                              f"Server: {ip}:{port}\n\nReady to connect!",
                              parent=dialog)
            dialog.destroy()
        
        tk.Button(btn_frame, text="Save", command=save_config,
                 bg=self.accent_green, fg=self.text_white,
                 font=('Arial', 10, 'bold'), relief='flat',
                 padx=30, pady=10, cursor='hand2').pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy,
                 bg=self.bg_tertiary, fg=self.text_white,
                 font=('Arial', 10), relief='flat',
                 padx=30, pady=10, cursor='hand2').pack(side=tk.LEFT, padx=5)
        
        ip_input.bind('<Return>', lambda e: port_input.focus())
        port_input.bind('<Return>', lambda e: save_config())
    
    def log(self, message, level='info'):
        """Add log entry"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logs_display.config(state='normal')
        self.logs_display.insert(tk.END, f"[{timestamp}] {message}\n", level)
        self.logs_display.see(tk.END)
        self.logs_display.config(state='disabled')
    
    def add_chat_message(self, text, sender='server'):
        """Add chat message"""
        self.messages_display.config(state='normal')
        if sender == 'you':
            self.messages_display.insert(tk.END, "You: ", 'you')
            self.messages_sent += 1
        else:
            self.messages_display.insert(tk.END, "Server: ", 'server')
            self.messages_received += 1
        self.messages_display.insert(tk.END, f"{text}\n")
        self.messages_display.see(tk.END)
        self.messages_display.config(state='disabled')
    
    def measure_ping(self):
        """Measure latency to server"""
        if not self.connected or not self.sock:
            return
        
        try:
            start = time.time()
            # Send a small ping packet
            ping_msg = b"PING"
            enc_ping = encrypt_data(self.shared_key, ping_msg)
            self.send_data(enc_ping)
            
            # Calculate round-trip time (simplified - actual pong comes in receive loop)
            # This is an approximation
            elapsed = (time.time() - start) * 1000
            self.ping_ms = int(elapsed)
        except:
            pass
    
    def update_stats(self):
        """Update statistics display"""
        if self.connected and self.connection_start_time:
            # Duration
            elapsed = int(time.time() - self.connection_start_time)
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            self.stat_widgets['duration'].config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Calculate speeds
            current_time = time.time()
            if self.last_speed_update:
                time_diff = current_time - self.last_speed_update
                if time_diff >= 1.0:  # Update every second
                    bytes_sent_diff = self.bytes_sent - self.last_bytes_sent
                    bytes_recv_diff = self.bytes_received - self.last_bytes_received
                    
                    self.upload_speed = int(bytes_sent_diff / time_diff)
                    self.download_speed = int(bytes_recv_diff / time_diff)
                    
                    self.last_bytes_sent = self.bytes_sent
                    self.last_bytes_received = self.bytes_received
                    self.last_speed_update = current_time
            else:
                self.last_speed_update = current_time
                self.last_bytes_sent = self.bytes_sent
                self.last_bytes_received = self.bytes_received
            
            # Update display
            if self.upload_speed < 1024:
                upload_text = f"{self.upload_speed} B/s"
            else:
                upload_text = f"{self.upload_speed // 1024} KB/s"
            
            if self.download_speed < 1024:
                download_text = f"{self.download_speed} B/s"
            else:
                download_text = f"{self.download_speed // 1024} KB/s"
            
            self.stat_widgets['upload_speed'].config(text=upload_text)
            self.stat_widgets['download_speed'].config(text=download_text)
            
            # Total data
            self.stat_widgets['upload_total'].config(text=f"{self.bytes_sent // 1024} KB")
            self.stat_widgets['download_total'].config(text=f"{self.bytes_received // 1024} KB")
            
            # Messages
            self.stat_widgets['messages'].config(text=f"{self.messages_sent} sent / {self.messages_received} received")
            
            # Ping (measure periodically)
            if elapsed % 5 == 0:  # Measure every 5 seconds
                threading.Thread(target=self.measure_ping, daemon=True).start()
            
            self.stat_widgets['ping'].config(text=f"{self.ping_ms} ms")
    
    def toggle_connection(self):
        """Toggle VPN connection"""
        if self.connected:
            self.disconnect()
        else:
            self.connect()
    
    def connect(self):
        """Establish VPN connection"""
        self.connect_btn.config(state='disabled', text="Connecting...")
        self.log(f"Connecting to {self.selected_server['host']}:{self.selected_server['port']}...", 'info')
        
        threading.Thread(target=self._connection_worker, daemon=True).start()
    
    def _connection_worker(self):
        """Connection background worker"""
        try:
            host = self.selected_server['host']
            port = self.selected_server['port']
            
            # Connect
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            
            ping_start = time.time()
            self.sock.connect((host, port))
            self.ping_ms = int((time.time() - ping_start) * 1000)
            
            self.log("TCP connection established", 'success')
            
            # DH key exchange
            params_data = self.recv_data()
            client_params = load_pem_parameters(params_data)
            self.log("Received DH parameters", 'info')
            
            server_pub = self.recv_data()
            self.log("Received server public key", 'info')
            
            client_priv, client_pub = generate_dh_keypair(client_params)
            self.send_data(client_pub)
            self.log("Sent client public key", 'info')
            
            self.shared_key = compute_shared_key(client_priv, server_pub)
            self.log("Encryption established (AES-128)", 'success')
            
            # Update state
            self.connected = True
            self.connection_start_time = time.time()
            self.bytes_sent = 0
            self.bytes_received = 0
            self.last_bytes_sent = 0
            self.last_bytes_received = 0
            self.last_speed_update = time.time()
            self.upload_speed = 0
            self.download_speed = 0
            self.messages_sent = 0
            self.messages_received = 0
            
            self.root.after(0, self._update_connected_ui)
            
            # Start receive loop
            threading.Thread(target=self._receive_worker, daemon=True).start()
            self.root.after(1000, self._stats_updater)
            
            self.add_chat_message(f"Connected to {host}:{port}", 'server')
            
        except socket.timeout:
            self.log(f"Connection timeout: {self.selected_server['host']}:{self.selected_server['port']}", 'error')
            self.root.after(0, self._update_disconnected_ui)
        except ConnectionRefusedError:
            self.log(f"Connection refused: {self.selected_server['host']}:{self.selected_server['port']}", 'error')
            self.root.after(0, self._update_disconnected_ui)
        except Exception as e:
            self.log(f"Connection failed: {e}", 'error')
            self.root.after(0, self._update_disconnected_ui)
    
    def _update_connected_ui(self):
        """Update UI for connected state"""
        self.status_indicator.itemconfig(self.status_circle, fill=self.accent_green)
        self.status_text.config(text="Connected")
        self.connection_info.config(text=f"{self.selected_server['host']}:{self.selected_server['port']}")
        self.connect_btn.config(state='normal', text="Disconnect", 
                               bg=self.accent_red, activebackground='#dc2626')
        self.message_input.config(state='normal')
        self.send_button.config(state='normal')
    
    def _update_disconnected_ui(self):
        """Update UI for disconnected state"""
        self.status_indicator.itemconfig(self.status_circle, fill=self.accent_red)
        self.status_text.config(text="Disconnected")
        self.connection_info.config(text="Not connected")
        self.connect_btn.config(state='normal', text="Connect",
                               bg=self.accent_green, activebackground='#059669')
        self.message_input.config(state='disabled')
        self.send_button.config(state='disabled')
        self.stat_widgets['duration'].config(text='00:00:00')
        self.stat_widgets['upload_speed'].config(text='0 KB/s')
        self.stat_widgets['download_speed'].config(text='0 KB/s')
        self.stat_widgets['upload_total'].config(text='0 KB')
        self.stat_widgets['download_total'].config(text='0 KB')
        self.stat_widgets['messages'].config(text='0 sent / 0 received')
        self.stat_widgets['ping'].config(text='0 ms')
    
    def _stats_updater(self):
        """Periodic stats update"""
        if self.connected:
            self.update_stats()
            self.root.after(1000, self._stats_updater)
    
    def _receive_worker(self):
        """Background message receiver"""
        while self.connected:
            try:
                enc_data = self.recv_data()
                self.bytes_received += len(enc_data)
                plaintext = decrypt_data(self.shared_key, enc_data)
                message = plaintext.decode('utf-8')
                
                self.root.after(0, lambda m=message: self.add_chat_message(m, 'server'))
            except Exception as e:
                if self.connected:
                    self.log(f"Receive error: {e}", 'error')
                break
        
        if self.connected:
            self.disconnect()
    
    def send_data(self, data):
        """Send length-prefixed data"""
        self.sock.sendall(len(data).to_bytes(4, 'big'))
        self.sock.sendall(data)
    
    def recv_data(self):
        """Receive length-prefixed data"""
        length_bytes = self.sock.recv(4)
        if not length_bytes:
            raise ConnectionError("Connection closed")
        
        data_len = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < data_len:
            chunk = self.sock.recv(min(self.BUF, data_len - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data
    
    def send_message(self):
        """Send chat message"""
        if not self.connected:
            return
        
        message = self.message_input.get().strip()
        if not message:
            return
        
        try:
            enc_msg = encrypt_data(self.shared_key, message.encode('utf-8'))
            self.bytes_sent += len(enc_msg)
            self.send_data(enc_msg)
            
            self.add_chat_message(message, 'you')
            self.log("Message sent", 'info')
            self.message_input.delete(0, tk.END)
        except Exception as e:
            self.log(f"Send failed: {e}", 'error')
    
    def disconnect(self):
        """Close VPN connection"""
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        self.sock = None
        self.shared_key = None
        
        self.log("Disconnected", 'warning')
        self.add_chat_message("Connection closed", 'server')
        self.root.after(0, self._update_disconnected_ui)
    
    def on_closing(self):
        """Handle window close"""
        if self.connected:
            if messagebox.askokcancel("Confirm Exit", 
                                     "You are currently connected. Disconnect and exit?"):
                self.disconnect()
                self.root.destroy()
        else:
            self.root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = AdvancedVPNClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()