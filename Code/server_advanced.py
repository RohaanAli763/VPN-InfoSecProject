"""
VPN Server with Clean Terminal Interface
"""

import socket
import threading
import time
import os
import struct
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding, ParameterFormat, load_pem_parameters
)

# Frame protocol constants (must match client)
TYPE_CONNECT_REQ  = 1
TYPE_CONNECT_RESP = 2
TYPE_DATA         = 3
TYPE_CLOSE        = 4
TYPE_UDP          = 5

# Configuration
HOST = '0.0.0.0'
PORT = 5555
BUF = 65536

# Frame protocol helpers
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

def send_blob(sock, b):
    sock.sendall(len(b).to_bytes(4, "big"))
    sock.sendall(b)

def recv_blob(sock):
    raw = sock.recv(4)
    if not raw:
        return None
    ln = int.from_bytes(raw, "big")
    data = b''
    while len(data) < ln:
        chunk = sock.recv(min(BUF, ln - len(data)))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data

# Stats tracking
class Stats:
    def __init__(self):
        self.connections = 0
        self.active = 0
        self.sent = 0
        self.received = 0
        self.start = time.time()
        self.clients = {}
        self.lock = threading.Lock()
        self.errors = []  # Track recent errors
        self.error_lock = threading.Lock()
    
    def add_error(self, msg):
        with self.error_lock:
            self.errors.append(f"{time.strftime('%H:%M:%S')} {msg}")
            if len(self.errors) > 10:  # Keep last 10 errors
                self.errors.pop(0)

stats = Stats()

class Client:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.connected = time.time()
        self.sent = 0
        self.received = 0
        self.active = time.time()
    
    def uptime(self):
        t = int(time.time() - self.connected)
        h = t // 3600
        m = (t % 3600) // 60
        s = t % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def log(msg, prefix="INFO"):
    t = time.strftime("%H:%M:%S")
    symbols = {
        "INFO": "[*]",
        "OK": "[+]",
        "ERR": "[-]",
        "WARN": "[!]",
        "CONN": "[>]",
        "DISC": "[<]"
    }
    log_msg = f"{t} {symbols.get(prefix, '[*]')} {msg}"
    print(log_msg)
    
    # Track errors persistently
    if prefix == "ERR":
        stats.add_error(msg)

def show_header():
    print("\n" + "="*60)
    print("  VPN SERVER")
    print("  Encrypted proxy | DH-2048 + AES-128 | SOCKS5 tunnel")
    print("="*60 + "\n")

def show_stats():
    uptime = int(time.time() - stats.start)
    h = uptime // 3600
    m = (uptime % 3600) // 60
    s = uptime % 60
    
    print(f"Server: {HOST}:{PORT}")
    print(f"Uptime: {h:02d}:{m:02d}:{s:02d}")
    print(f"Active clients: {stats.active}")
    print(f"Total connections: {stats.connections}")
    print(f"Data sent: {stats.sent // 1024} KB")
    print(f"Data received: {stats.received // 1024} KB")
    print()

def show_clients():
    if not stats.clients:
        print("No active connections\n")
    else:
        print("Connected Clients:")
        print("-" * 60)
        print(f"{'IP Address':<20} {'Uptime':<12} {'Sent':<10} {'Recv':<10}")
        print("-" * 60)
        
        with stats.lock:
            for ip, client in list(stats.clients.items()):
                print(f"{ip:<20} {client.uptime():<12} {client.sent//1024:<10} {client.received//1024:<10}")
        print()
    
    # Show recent errors
    with stats.error_lock:
        if stats.errors:
            print("Recent Errors:")
            print("-" * 60)
            for err in stats.errors[-5:]:  # Show last 5
                print(f"  {err}")
            print()

def refresh_display():
    while True:
        time.sleep(10)
        clear()
        show_header()
        show_stats()
        show_clients()
        print("Press Ctrl+C to stop\n")

def generate_params():
    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)

def handle_remote_connection(conn_id, remote_sock, client_sock, key, ip, client_stats, send_lock, active_flag):
    """Forward data from remote destination back to client"""
    try:
        while active_flag[0]:  # Check if main connection is still active
            try:
                remote_sock.settimeout(1.0)  # Allow periodic checks
                data = remote_sock.recv(BUF)
                if not data:
                    break
                
                if not active_flag[0]:  # Double-check before sending
                    break
                
                # Build DATA frame
                frame = build_frame(TYPE_DATA, conn_id, data)
                enc_frame = encrypt_data(key, frame)
                
                client_stats.sent += len(enc_frame)
                stats.sent += len(enc_frame)
                
                # Thread-safe send
                with send_lock:
                    if not active_flag[0]:  # Check again while holding lock
                        break
                    send_blob(client_sock, enc_frame)
                    
            except socket.timeout:
                continue  # Keep checking if connection is active
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                # Remote server closed connection - this is normal
                break
            except OSError as e:
                if e.winerror in [10038, 10053, 10054]:  # Not a socket / Connection aborted/reset on Windows
                    # Main tunnel closed, exit silently
                    break
                if active_flag[0]:  # Only log if main connection is still active
                    log(f"[{ip}] Remote #{conn_id} OS error: {e}", "ERR")
                break
            except Exception as e:
                if active_flag[0]:  # Only log if main connection is still active
                    log(f"[{ip}] Remote #{conn_id} error: {e}", "ERR")
                break
                
    except Exception as e:
        if active_flag[0]:
            log(f"[{ip}] Remote #{conn_id} fatal: {e}", "ERR")
    finally:
        # Send CLOSE frame only if main connection is still active
        if active_flag[0]:
            try:
                frame = build_frame(TYPE_CLOSE, conn_id, b'')
                enc_frame = encrypt_data(key, frame)
                with send_lock:
                    if active_flag[0]:
                        send_blob(client_sock, enc_frame)
            except:
                pass
        try:
            remote_sock.close()
        except:
            pass

def handle_client(sock, addr):
    ip = addr[0]
    port = addr[1]
    
    client = Client(ip, port)
    
    with stats.lock:
        stats.clients[ip] = client
        stats.connections += 1
        stats.active += 1
    
    log(f"Client connected: {ip}:{port}", "CONN")
    
    # Map conn_id -> remote_socket for proxy connections
    remote_connections = {}
    remote_lock = threading.Lock()
    send_lock = threading.Lock()  # Lock for sending to client socket
    active_flag = [True]  # Mutable flag to signal threads when main connection closes
    
    try:
        # Send DH parameters
        params = generate_params()
        send_blob(sock, params)
        log(f"[{ip}] DH parameters sent", "INFO")
        
        # Generate keypair
        dh_params = load_pem_parameters(params)
        priv, pub = generate_dh_keypair(dh_params)
        
        # Send public key
        send_blob(sock, pub)
        log(f"[{ip}] Public key sent", "INFO")
        
        # Receive client public key
        client_pub = recv_blob(sock)
        log(f"[{ip}] Client public key received", "INFO")
        
        # Compute shared key
        key = compute_shared_key(priv, client_pub)
        log(f"[{ip}] Encryption active - VPN mode", "OK")
        
        # Frame processing loop
        while True:
            try:
                # Receive encrypted frame
                enc_frame = recv_blob(sock)
                if enc_frame is None:
                    break
                
                client.received += len(enc_frame)
                stats.received += len(enc_frame)
                client.active = time.time()
                
                # Decrypt and parse frame
                try:
                    frame_data = decrypt_data(key, enc_frame)
                    ftype, conn_id, payload = parse_frame(frame_data)
                except Exception as decrypt_err:
                    # Decryption or parsing failed - connection likely interrupted
                    log(f"[{ip}] Data corruption or connection interrupted", "WARN")
                    break
                    
            except ConnectionError as e:
                log(f"[{ip}] Connection lost", "WARN")
                break
            except OSError as e:
                if e.winerror in [10053, 10054]:
                    log(f"[{ip}] Connection closed by client", "WARN")
                else:
                    log(f"[{ip}] Network error: {e}", "ERR")
                break
            except Exception as e:
                log(f"[{ip}] Unexpected error: {type(e).__name__}: {e}", "ERR")
                break
            
            
            if ftype == TYPE_CONNECT_REQ:
                # Client wants to connect to a destination
                dest_str = payload.decode('utf-8')
                try:
                    dest_host, dest_port = dest_str.rsplit(':', 1)
                    dest_port = int(dest_port)
                    
                    log(f"[{ip}] Connect request #{conn_id}: {dest_host}:{dest_port}", "INFO")
                    
                    # Connect to destination
                    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_sock.settimeout(10)
                    remote_sock.connect((dest_host, dest_port))
                    remote_sock.settimeout(None)
                    
                    with remote_lock:
                        remote_connections[conn_id] = remote_sock
                    
                    # Send success response
                    resp_frame = build_frame(TYPE_CONNECT_RESP, conn_id, b"OK")
                    enc_resp = encrypt_data(key, resp_frame)
                    
                    with send_lock:
                        send_blob(sock, enc_resp)
                    
                    client.sent += len(enc_resp)
                    stats.sent += len(enc_resp)
                    
                    log(f"[{ip}] Connected #{conn_id} to {dest_host}:{dest_port}", "OK")
                    
                    # Start reader thread for this connection
                    threading.Thread(target=handle_remote_connection, 
                                   args=(conn_id, remote_sock, sock, key, ip, client, send_lock, active_flag),
                                   daemon=True).start()
                    
                except Exception as e:
                    log(f"[{ip}] Connect failed #{conn_id}: {e}", "ERR")
                    resp_frame = build_frame(TYPE_CONNECT_RESP, conn_id, f"ERR: {e}".encode())
                    enc_resp = encrypt_data(key, resp_frame)
                    with send_lock:
                        send_blob(sock, enc_resp)
                    
            elif ftype == TYPE_DATA:
                # Forward data to remote destination
                with remote_lock:
                    remote_sock = remote_connections.get(conn_id)
                
                if remote_sock:
                    try:
                        remote_sock.sendall(payload)
                    except Exception:
                        # Connection broken, send CLOSE
                        with remote_lock:
                            if conn_id in remote_connections:
                                del remote_connections[conn_id]
                        try:
                            remote_sock.close()
                        except:
                            pass
                        frame = build_frame(TYPE_CLOSE, conn_id, b'')
                        enc_frame = encrypt_data(key, frame)
                        with send_lock:
                            send_blob(sock, enc_frame)
                        
            elif ftype == TYPE_CLOSE:
                # Client closed connection
                with remote_lock:
                    remote_sock = remote_connections.pop(conn_id, None)
                
                if remote_sock:
                    try:
                        remote_sock.close()
                    except:
                        pass
                    log(f"[{ip}] Connection #{conn_id} closed by client", "INFO")
                    
            elif ftype == TYPE_UDP:
                # UDP relay - parse and forward
                try:
                    parts = payload.split(b'\x00', 4)
                    if len(parts) < 5:
                        continue
                    client_src_ip = parts[0].decode()
                    client_src_port = int(parts[1].decode())
                    dest_host = parts[2].decode()
                    dest_port = int(parts[3].decode())
                    udp_payload = parts[4]
                    
                    # Forward UDP packet
                    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_sock.sendto(udp_payload, (dest_host, dest_port))
                    
                    # Wait for response (with timeout)
                    udp_sock.settimeout(2)
                    try:
                        response, _ = udp_sock.recvfrom(BUF)
                        
                        # Send back to client
                        resp_payload = client_src_ip.encode() + b"\x00" + str(client_src_port).encode() + b"\x00" + dest_host.encode() + b"\x00" + str(dest_port).encode() + b"\x00" + response
                        frame = build_frame(TYPE_UDP, conn_id, resp_payload)
                        enc_frame = encrypt_data(key, frame)
                        with send_lock:
                            send_blob(sock, enc_frame)
                    except socket.timeout:
                        pass
                    finally:
                        udp_sock.close()
                        
                except Exception as e:
                    log(f"[{ip}] UDP relay error: {e}", "ERR")
    
    except Exception as e:
        log(f"[{ip}] Fatal error: {type(e).__name__}: {e}", "ERR")
        import traceback
        traceback.print_exc()
    
    finally:
        # Signal all threads to stop
        active_flag[0] = False
        
        # Clean up all remote connections
        with remote_lock:
            for conn_id, remote_sock in list(remote_connections.items()):
                try:
                    remote_sock.close()
                except:
                    pass
            remote_connections.clear()
        
        try:
            sock.close()
        except:
            pass
        
        with stats.lock:
            if ip in stats.clients:
                del stats.clients[ip]
            stats.active -= 1
        
        log(f"Client disconnected: {ip}:{port} (uptime: {client.uptime()})", "DISC")

def run():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(10)
        
        clear()
        show_header()
        log(f"Server starting on {HOST}:{PORT}", "INFO")
        log("Encryption: DH-2048 + AES-128", "INFO")
        log("Server ready", "OK")
        time.sleep(2)
        
        # Start display refresh
        threading.Thread(target=refresh_display, daemon=True).start()
        
        # Accept connections
        while True:
            sock, addr = server.accept()
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
    
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        log("Server stopped", "WARN")
    
    except Exception as e:
        log(f"Server error: {e}", "ERR")
    
    finally:
        server.close()

if __name__ == '__main__':
    run()