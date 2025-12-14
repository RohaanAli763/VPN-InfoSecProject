import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import struct
import itertools
import sys
import time
from datetime import datetime
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters

# Configure these
SERVER_HOST = "myfirstvpnnust.duckdns.org"  # DuckDNS domain for remote access
SERVER_PORT = 5555
BUF = 131072  # 128KB to match server buffer size

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 1080

# Frame types (must match server)
TYPE_CONNECT_REQ  = 1
TYPE_CONNECT_RESP = 2
TYPE_DATA         = 3
TYPE_CLOSE        = 4
TYPE_UDP          = 5

def send_blob(sock, b):
    # Send as single atomic write to prevent interleaving
    msg = len(b).to_bytes(4, "big") + b
    sock.sendall(msg)

def recv_blob(sock):
    raw = sock.recv(4)
    if not raw:
        return None
    ln = int.from_bytes(raw, "big")
    
    # Sanity check: reject unreasonably large blobs
    if ln > 10 * 1024 * 1024:
        raise ValueError(f"blob size too large: {ln} bytes")
    
    data = b''
    while len(data) < ln:
        chunk = sock.recv(min(BUF, ln - len(data)))
        if not chunk:
            raise ConnectionError(f"unexpected EOF (got {len(data)}/{ln} bytes)")
        data += chunk
    return data

def build_frame(ftype, conn_id, payload=b''):
    return struct.pack("!BII", ftype, conn_id, len(payload)) + payload

def parse_frame(b):
    if len(b) < 9:
        raise ValueError("frame too short")
    ftype = b[0]
    conn_id = struct.unpack("!I", b[1:5])[0]
    payload_len = struct.unpack("!I", b[5:9])[0]
    payload = b[9:9+payload_len]
    return ftype, conn_id, payload

class EncryptedTunnel:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.sock = None
        self.shared_key = None
        self.conn_id_iter = itertools.count(1)
        # maps conn_id -> (local_socket, ready_event, optional_resp)
        self.local_map = {}
        self.map_lock = threading.Lock()
        # UDP handling: we will create a local UDP socket that browser/app will send to (after UDP ASSOCIATE). Key: conn_id -> local_udp_src (ip,port)
        self.udp_map = {}  # conn_id -> (local_udp_ip, local_udp_port)
        self.udp_map_lock = threading.Lock()

    def connect_and_handshake(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] connecting to VPN server {self.server_host}:{self.server_port} ...")
        s.connect((self.server_host, self.server_port))
        # receive params and server pub
        params_bytes = recv_blob(s)
        server_pub = recv_blob(s)
        params = load_pem_parameters(params_bytes)
        client_priv, client_pub_bytes = generate_dh_keypair(params)
        send_blob(s, client_pub_bytes)
        self.shared_key = compute_shared_key(client_priv, server_pub)
        self.sock = s
        print("[+] shared key established.")
        t = threading.Thread(target=self.reader, daemon=True)
        t.start()

    def reader(self):
        try:
            while True:
                enc = recv_blob(self.sock)
                if enc is None:
                    break
                frame = decrypt_data(self.shared_key, enc)
                ftype, cid, payload = parse_frame(frame)
                if ftype == TYPE_CONNECT_RESP:
                    with self.map_lock:
                        entry = self.local_map.get(cid)
                        if entry:
                            # append response bytes and signal
                            entry.append(payload)
                            entry[1].set()
                elif ftype == TYPE_DATA:
                    with self.map_lock:
                        entry = self.local_map.get(cid)
                    if entry:
                        localsock, ready_event = entry[0], entry[1]
                        try:
                            localsock.sendall(payload)
                        except Exception:
                            try:
                                localsock.close()
                            except:
                                pass
                            # notify server we closed
                            frame = build_frame(TYPE_CLOSE, cid, b'')
                            encf = encrypt_data(self.shared_key, frame)
                            send_blob(self.sock, encf)
                            with self.map_lock:
                                if cid in self.local_map: del self.local_map[cid]
                elif ftype == TYPE_CLOSE:
                    with self.map_lock:
                        entry = self.local_map.pop(cid, None)
                    if entry:
                        localsock, _ = entry[:2]
                        try:
                            localsock.close()
                        except:
                            pass
                elif ftype == TYPE_UDP:
                    # payload: client_src_ip + \x00 + client_src_port + \x00 + dest_host + \x00 + dest_port + \x00 + udp_payload
                    try:
                        parts = payload.split(b'\x00', 4)
                        if len(parts) < 5:
                            continue
                        client_src_ip = parts[0].decode()
                        client_src_port = int(parts[1].decode())
                        dest_host = parts[2].decode()
                        dest_port = int(parts[3].decode())
                        udp_payload = parts[4]
                    except Exception:
                        continue
                    # find local udp socket for this conn_id and send the response to the local UDP source
                    with self.udp_map_lock:
                        tup = self.udp_map.get(cid)
                    if tup:
                        local_udp_sock = tup[2]
                        try:
                            local_udp_sock.sendto(udp_payload, (client_src_ip, client_src_port))
                        except Exception:
                            pass
                else:
                    pass
        except Exception as e:
            print("tunnel reader error:", e)
        finally:
            print("[*] Tunnel reader exiting")
            try:
                self.sock.close()
            except:
                pass

    def open_proxy_connection(self, localsock, dest_host, dest_port):
        cid = next(self.conn_id_iter)
        ready_event = threading.Event()
        entry = [localsock, ready_event]  # later append resp
        with self.map_lock:
            self.local_map[cid] = entry
        payload = f"{dest_host}:{dest_port}".encode()
        frame = build_frame(TYPE_CONNECT_REQ, cid, payload)
        enc = encrypt_data(self.shared_key, frame)
        send_blob(self.sock, enc)
        waited = ready_event.wait(timeout=15)
        if not waited:
            with self.map_lock:
                if cid in self.local_map: del self.local_map[cid]
            raise ConnectionError("no response from server")
        with self.map_lock:
            entry = self.local_map.get(cid)
        resp = entry[2] if len(entry) >= 3 else b"ERR"
        if not resp.startswith(b"OK"):
            with self.map_lock:
                if cid in self.local_map: del self.local_map[cid]
            raise ConnectionError(resp.decode(errors='ignore'))
        # start writer
        t = threading.Thread(target=self._local_to_tunnel_writer, args=(cid, localsock), daemon=True)
        t.start()
        return cid

    def _local_to_tunnel_writer(self, cid, localsock):
        try:
            while True:
                data = localsock.recv(BUF)
                if not data:
                    break
                frame = build_frame(TYPE_DATA, cid, data)
                enc = encrypt_data(self.shared_key, frame)
                send_blob(self.sock, enc)
        except Exception:
            pass
        finally:
            try:
                frame = build_frame(TYPE_CLOSE, cid, b'')
                enc = encrypt_data(self.shared_key, frame)
                send_blob(self.sock, enc)
            except:
                pass
            with self.map_lock:
                if cid in self.local_map: del self.local_map[cid]
            try:
                localsock.close()
            except:
                pass

    def open_udp_associate(self):
        """
        Called when SOCKS5 client requests UDP ASSOCIATE.
        Create a local UDP socket bound to 127.0.0.1:0 and return whichever port.
        We'll associate a special conn_id for UDP relay.
        """
        cid = next(self.conn_id_iter)
        local_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        local_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        local_udp.bind(("127.0.0.1", 0))
        local_ip, local_port = local_udp.getsockname()
        # store it to udp_map so reader thread can route responses
        with self.udp_map_lock:
            self.udp_map[cid] = (local_ip, local_port, local_udp)
        # start local listener to read from browser and forward to server encapsulated
        t = threading.Thread(target=self._udp_local_reader, args=(cid, local_udp), daemon=True)
        t.start()
        return cid, local_ip, local_port, local_udp

    def _udp_local_reader(self, cid, local_udp_sock):
        """
        Read UDP datagrams from local socket (browser/app) and send them encapsulated to server.
        Payload format to server: client_src_ip \x00 client_src_port \x00 dest_host \x00 dest_port \x00 udp_payload
        We need to parse the SOCKS5 UDP request format which the browser will send:
        SOCKS5 UDP request: [RSV(2)][FRAG(1)][ATYP(1)][DST.ADDR][DST.PORT(2)][DATA]
        We'll receive these datagrams, extract dest, then send encapsulated version to server.
        """
        try:
            while True:
                data, src = local_udp_sock.recvfrom(65535)
                # parse SOCKS5 UDP request header
                if len(data) < 4:
                    continue
                # RSV (2 bytes) FRAG (1) ATYP (1)
                rsv = data[0:2]
                frag = data[2]
                atyp = data[3]
                idx = 4
                if atyp == 0x01:  # IPv4
                    if len(data) < idx+4+2: continue
                    dest_addr = socket.inet_ntoa(data[idx:idx+4])
                    idx += 4
                elif atyp == 0x03:  # domain
                    domain_len = data[idx]
                    idx += 1
                    dest_addr = data[idx:idx+domain_len].decode()
                    idx += domain_len
                elif atyp == 0x04:
                    # IPv6 not supported here
                    continue
                else:
                    continue
                dest_port = struct.unpack("!H", data[idx:idx+2])[0]
                idx += 2
                udp_payload = data[idx:]
                # build encapsulated payload
                client_src_ip = src[0]
                client_src_port = src[1]
                payload = client_src_ip.encode() + b"\x00" + str(client_src_port).encode() + b"\x00" + dest_addr.encode() + b"\x00" + str(dest_port).encode() + b"\x00" + udp_payload
                frame = build_frame(TYPE_UDP, cid, payload)
                enc = encrypt_data(self.shared_key, frame)
                send_blob(self.sock, enc)
        except Exception:
            pass
        finally:
            with self.udp_map_lock:
                ent = self.udp_map.pop(cid, None)
            try:
                local_udp_sock.close()
            except:
                pass

def handle_socks5_connection(tunnel, localsock, addr):
    try:
        # Initial greeting
        data = localsock.recv(262)
        if not data:
            localsock.close(); return
        if data[0] != 0x05:
            localsock.close(); return
        # respond: version 5, no auth
        localsock.sendall(b"\x05\x00")
        # request: VER CMD RSV ATYP ...
        req = localsock.recv(4)
        if len(req) < 4:
            localsock.close(); return
        ver, cmd, rsv, atyp = req[0], req[1], req[2], req[3]
        if ver != 0x05:
            localsock.close(); return
        if cmd == 0x01:  # CONNECT
            # parse target
            if atyp == 0x01:  # IPv4
                addr_bytes = localsock.recv(4)
                dest = socket.inet_ntoa(addr_bytes)
            elif atyp == 0x03:  # domain
                ln = localsock.recv(1)[0]
                dest = localsock.recv(ln).decode()
            elif atyp == 0x04:  # IPv6 not supported
                localsock.close(); return
            else:
                localsock.close(); return
            port_bytes = localsock.recv(2)
            dest_port = struct.unpack("!H", port_bytes)[0]

            # open connection via encrypted tunnel
            try:
                cid = tunnel.open_proxy_connection(localsock, dest, dest_port)
            except Exception as e:
                # reply failure
                localsock.sendall(b"\x05\x01\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
                localsock.close()
                return

            # reply success (bound addr = 0.0.0.0:0)
            localsock.sendall(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")

            # After this, tunnel writer & reader handle forwarding.
            # Just wait for socket close
            try:
                while True:
                    # busy wait with small sleep so thread doesn't die
                    if localsock.fileno() == -1:
                        break
                    # peek to detect closure
                    try:
                        data = localsock.recv(1, socket.MSG_PEEK)
                        if not data:
                            break
                    except Exception:
                        pass
                    time.sleep(0.2)
            except Exception:
                pass
            try:
                localsock.close()
            except:
                pass

        elif cmd == 0x03:  # UDP ASSOCIATE
            # per RFC, client sends UDP ASSOCIATE to tell proxy it wants to send UDP datagrams
            # We'll create a local UDP socket and return its address as BND.ADDR so the client (browser) will send UDP to it.
            cid, local_ip, local_port, local_udp_sock = tunnel.open_udp_associate()
            # reply with success and BND.ADDR/BND.PORT = local_ip:local_port
            # Build reply: VER(5) REP(0) RSV(0) ATYP + ADDR + PORT
            try:
                # IPv4 only
                ip_bytes = socket.inet_aton(local_ip)
                port_bytes = struct.pack("!H", local_port)
                localsock.sendall(b"\x05\x00\x00\x01" + ip_bytes + port_bytes)
            except Exception:
                localsock.sendall(b"\x05\x01\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
                localsock.close()
                return

            # Keep TCP connection open; UDP reading/encapsulation happens in separate thread.
            try:
                while True:
                    time.sleep(1)
                    # keep alive while localsock exists
                    if localsock.fileno() == -1:
                        break
            except Exception:
                pass
            finally:
                try:
                    localsock.close()
                except:
                    pass

        else:
            # unsupported command
            localsock.sendall(b"\x05\x07\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
            localsock.close()
            return

    except Exception:
        pass
    finally:
        try:
            localsock.close()
        except:
            pass

class AdvancedVPNClient:
    """Professional VPN Client with enhanced UI and full SOCKS5 functionality"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SecureVPN Pro - SOCKS5 Proxy")
        self.root.geometry("1100x750")
        self.root.configure(bg='#0a0e27')
        
        # Default server
        self.selected_server = {
            "name": "Custom Server",
            "host": SERVER_HOST,
            "port": SERVER_PORT,
            "location": "Local Network"
        }
        
        # Setup styling
        self.setup_styles()
        
        # Connection state
        self.tunnel = None
        self.socks_server = None
        self.connected = False
        self.socks_listening = False
        
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
        self.active_connections = 0
        
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
        
        version = tk.Label(header, text="Pro v2.1 - SOCKS5", font=('Arial', 10),
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
        
        # SOCKS5 info
        socks_info = tk.Label(info_frame,
                             text=f"SOCKS5: {SOCKS_HOST}:{SOCKS_PORT}",
                             font=('Arial', 9),
                             fg=self.accent_blue, bg=self.bg_tertiary)
        socks_info.pack(anchor='w', pady=(5, 0))
        
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
            ('connections', 'Active Connections', '0')
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
        """Logs and activity"""
        panel = self.create_panel(parent)
        panel.pack(fill=tk.BOTH, expand=True)
        
        # Title
        tk.Label(panel, text="Activity Log", font=('Arial', 11, 'bold'),
                fg=self.text_gray, bg=self.bg_secondary).pack(anchor='w', padx=25, pady=(20, 15))
        
        # Content area
        content_frame = tk.Frame(panel, bg=self.bg_secondary)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=(0, 15))
        
        # Logs
        self.logs_display = scrolledtext.ScrolledText(content_frame,
                                                      wrap=tk.WORD,
                                                      font=('Consolas', 9),
                                                      bg=self.bg_primary,
                                                      fg="#22c55e",
                                                      insertbackground="#22c55e",
                                                      relief='flat',
                                                      padx=15, pady=15,
                                                      state='disabled')
        self.logs_display.pack(fill=tk.BOTH, expand=True)
        
        self.logs_display.tag_config('info', foreground='#22c55e')
        self.logs_display.tag_config('success', foreground='#3b82f6')
        self.logs_display.tag_config('error', foreground='#ef4444')
        self.logs_display.tag_config('warning', foreground='#f59e0b')
        
        self.log(f"VPN client initialized. SOCKS5 proxy will run on {SOCKS_HOST}:{SOCKS_PORT}", 'info')
    
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
                    if self.tunnel:
                        # Get stats from tunnel
                        with self.tunnel.map_lock:
                            conn_count = len(self.tunnel.local_map)
                        self.active_connections = conn_count
                    
                    self.last_speed_update = current_time
            else:
                self.last_speed_update = current_time
            
            # Update display (placeholder speeds for now)
            self.stat_widgets['upload_speed'].config(text=f"{self.upload_speed // 1024} KB/s")
            self.stat_widgets['download_speed'].config(text=f"{self.download_speed // 1024} KB/s")
            
            # Total data
            self.stat_widgets['upload_total'].config(text=f"{self.bytes_sent // 1024} KB")
            self.stat_widgets['download_total'].config(text=f"{self.bytes_received // 1024} KB")
            
            # Active connections
            self.stat_widgets['connections'].config(text=f"{self.active_connections}")
            
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
            
            # Create tunnel
            self.tunnel = EncryptedTunnel(host, port)
            
            ping_start = time.time()
            self.tunnel.connect_and_handshake()
            self.ping_ms = int((time.time() - ping_start) * 1000)
            
            self.log("VPN tunnel established", 'success')
            
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
            self.active_connections = 0
            
            self.root.after(0, self._update_connected_ui)
            
            # Start stats updater
            self.root.after(1000, self._stats_updater)
            
            # Start SOCKS5 server
            threading.Thread(target=self._start_socks_server, daemon=True).start()
            
        except socket.timeout:
            self.log(f"Connection timeout: {self.selected_server['host']}:{self.selected_server['port']}", 'error')
            self.root.after(0, self._update_disconnected_ui)
        except ConnectionRefusedError:
            self.log(f"Connection refused: {self.selected_server['host']}:{self.selected_server['port']}", 'error')
            self.root.after(0, self._update_disconnected_ui)
        except Exception as e:
            self.log(f"Connection failed: {e}", 'error')
            self.root.after(0, self._update_disconnected_ui)
    
    def _start_socks_server(self):
        """Start local SOCKS5 server"""
        try:
            self.socks_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socks_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socks_server.bind((SOCKS_HOST, SOCKS_PORT))
            self.socks_server.listen(128)
            self.socks_listening = True
            
            self.log(f"SOCKS5 proxy listening on {SOCKS_HOST}:{SOCKS_PORT}", 'success')
            self.log("Configure your browser to use this SOCKS5 proxy", 'info')
            
            while self.connected and self.socks_listening:
                try:
                    self.socks_server.settimeout(1.0)
                    c, a = self.socks_server.accept()
                    t = threading.Thread(target=handle_socks5_connection, 
                                       args=(self.tunnel, c, a), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.connected:
                        self.log(f"SOCKS5 accept error: {e}", 'error')
                    break
        except Exception as e:
            self.log(f"SOCKS5 server error: {e}", 'error')
        finally:
            if self.socks_server:
                try:
                    self.socks_server.close()
                except:
                    pass
            self.socks_listening = False
    
    def _update_connected_ui(self):
        """Update UI for connected state"""
        self.status_indicator.itemconfig(self.status_circle, fill=self.accent_green)
        self.status_text.config(text="Connected")
        self.connection_info.config(text=f"{self.selected_server['host']}:{self.selected_server['port']}")
        self.connect_btn.config(state='normal', text="Disconnect", 
                               bg=self.accent_red, activebackground='#dc2626')
    
    def _update_disconnected_ui(self):
        """Update UI for disconnected state"""
        self.status_indicator.itemconfig(self.status_circle, fill=self.accent_red)
        self.status_text.config(text="Disconnected")
        self.connection_info.config(text="Not connected")
        self.connect_btn.config(state='normal', text="Connect",
                               bg=self.accent_green, activebackground='#059669')
        self.stat_widgets['duration'].config(text='00:00:00')
        self.stat_widgets['upload_speed'].config(text='0 KB/s')
        self.stat_widgets['download_speed'].config(text='0 KB/s')
        self.stat_widgets['upload_total'].config(text='0 KB')
        self.stat_widgets['download_total'].config(text='0 KB')
        self.stat_widgets['connections'].config(text='0')
        self.stat_widgets['ping'].config(text='0 ms')
    
    def _stats_updater(self):
        """Periodic stats update"""
        if self.connected:
            self.update_stats()
            self.root.after(1000, self._stats_updater)
    
    def disconnect(self):
        """Close VPN connection"""
        self.connected = False
        self.socks_listening = False
        
        if self.socks_server:
            try:
                self.socks_server.close()
            except:
                pass
            self.socks_server = None
        
        if self.tunnel and self.tunnel.sock:
            try:
                self.tunnel.sock.close()
            except:
                pass
        
        self.tunnel = None
        
        self.log("Disconnected from VPN", 'warning')
        self.log("SOCKS5 proxy stopped", 'warning')
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

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedVPNClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
