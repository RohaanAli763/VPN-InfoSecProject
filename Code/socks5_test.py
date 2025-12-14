import socket
import threading
import struct
import time

HOST = "127.0.0.1"
PORT = 1080
BUF = 65536


def forward(src, dst):
    try:
        while True:
            data = src.recv(BUF)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass


def handle_client(client):
    try:
        # SOCKS5 Greeting
        data = client.recv(262)
        if not data or data[0] != 0x05:
            client.close()
            return

        # Send "no authentication"
        client.sendall(b"\x05\x00")

        # Request details
        hdr = client.recv(4)
        if len(hdr) < 4:
            client.close()
            return

        ver, cmd, rsv, atyp = hdr

        if cmd != 1:  # Only CONNECT supported
            client.sendall(b"\x05\x07\x00\x01" + b"\x00"*6)
            client.close()
            return

        # Parse address
        if atyp == 1:  # IPv4
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 3:  # Domain
            ln = client.recv(1)[0]
            addr = client.recv(ln).decode()
        else:
            client.close()
            return

        port = struct.unpack(">H", client.recv(2))[0]

        # Try connecting
        try:
            remote = socket.create_connection((addr, port))
        except Exception:
            client.sendall(b"\x05\x05\x00\x01" + b"\x00"*6)
            client.close()
            return

        # Send success
        client.sendall(b"\x05\x00\x00\x01" + b"\x00"*4 + b"\x00\x00")

        # Start bidirectional forwarding
        threading.Thread(target=forward, args=(client, remote), daemon=True).start()
        threading.Thread(target=forward, args=(remote, client), daemon=True).start()

    except Exception:
        pass


def main():
    print(f"[+] Simple SOCKS5 listening at {HOST}:{PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(50)

    while True:
        c, a = s.accept()
        threading.Thread(target=handle_client, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
