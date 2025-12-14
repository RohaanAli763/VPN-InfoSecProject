# client.py (ADVANCED). Local SOCKS5 server at 127.0.0.1:1080, encrypted tunnel to remote VPN server.
import socket
import threading
import struct
import itertools
import sys
import time
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters

# Configure these
SERVER_HOST = "127.0.0.1"  # localhost for local testing
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

def main():
    tunnel = EncryptedTunnel(SERVER_HOST, SERVER_PORT)
    tunnel.connect_and_handshake()

    # start local SOCKS5 server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((SOCKS_HOST, SOCKS_PORT))
    s.listen(128)
    print(f"SOCKS5 listening on {SOCKS_HOST}:{SOCKS_PORT} (use this in your browser)")
    try:
        while True:
            c, a = s.accept()
            t = threading.Thread(target=handle_socks5_connection, args=(tunnel, c, a), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Shutting down")
    finally:
        s.close()

if __name__ == "__main__":
    main()
