"""
VPN Server with Clean Terminal Interface
"""

import socket
import threading
import time
import os
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding, ParameterFormat, load_pem_parameters
)

# Configuration
HOST = '0.0.0.0'
PORT = 5555

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
    print(f"{t} {symbols.get(prefix, '[*]')} {msg}")

def show_header():
    print("\n" + "="*60)
    print("  VPN SERVER")
    print("  Encrypted connections | DH-2048 + AES-128")
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
        return
    
    print("Connected Clients:")
    print("-" * 60)
    print(f"{'IP Address':<20} {'Uptime':<12} {'Sent':<10} {'Recv':<10}")
    print("-" * 60)
    
    with stats.lock:
        for ip, client in list(stats.clients.items()):
            print(f"{ip:<20} {client.uptime():<12} {client.sent//1024:<10} {client.received//1024:<10}")
    print()

def refresh_display():
    while True:
        time.sleep(3)
        clear()
        show_header()
        show_stats()
        show_clients()
        print("Press Ctrl+C to stop\n")

def generate_params():
    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)

def handle_client(sock, addr):
    ip = addr[0]
    port = addr[1]
    
    client = Client(ip, port)
    
    with stats.lock:
        stats.clients[ip] = client
        stats.connections += 1
        stats.active += 1
    
    log(f"Client connected: {ip}:{port}", "CONN")
    
    try:
        # Send DH parameters
        params = generate_params()
        sock.sendall(len(params).to_bytes(4, 'big'))
        sock.sendall(params)
        log(f"[{ip}] DH parameters sent", "INFO")
        
        # Generate keypair
        dh_params = load_pem_parameters(params)
        priv, pub = generate_dh_keypair(dh_params)
        
        # Send public key
        sock.sendall(len(pub).to_bytes(4, 'big'))
        sock.sendall(pub)
        log(f"[{ip}] Public key sent", "INFO")
        
        # Receive client public key
        client_pub_len = int.from_bytes(sock.recv(4), 'big')
        client_pub = b''
        while len(client_pub) < client_pub_len:
            chunk = sock.recv(min(65536, client_pub_len - len(client_pub)))
            if not chunk:
                raise ConnectionError("Connection lost")
            client_pub += chunk
        
        log(f"[{ip}] Client public key received", "INFO")
        
        # Compute shared key
        key = compute_shared_key(priv, client_pub)
        log(f"[{ip}] Encryption active", "OK")
        
        # Message loop
        while True:
            # Receive message
            msg_len_bytes = sock.recv(4)
            if not msg_len_bytes:
                break
            
            msg_len = int.from_bytes(msg_len_bytes, 'big')
            enc_msg = b''
            
            while len(enc_msg) < msg_len:
                chunk = sock.recv(min(65536, msg_len - len(enc_msg)))
                if not chunk:
                    raise ConnectionError("Connection lost")
                enc_msg += chunk
            
            client.received += len(enc_msg)
            stats.received += len(enc_msg)
            client.active = time.time()
            
            # Decrypt
            plaintext = decrypt_data(key, enc_msg)
            msg = plaintext.decode('utf-8')
            
            log(f"[{ip}] Message: {msg[:40]}{'...' if len(msg) > 40 else ''}", "INFO")
            
            # Echo back
            response = f"Server received: {msg}".encode('utf-8')
            enc_response = encrypt_data(key, response)
            
            client.sent += len(enc_response)
            stats.sent += len(enc_response)
            
            sock.sendall(len(enc_response).to_bytes(4, 'big'))
            sock.sendall(enc_response)
    
    except Exception as e:
        log(f"[{ip}] Error: {e}", "ERR")
    
    finally:
        sock.close()
        
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