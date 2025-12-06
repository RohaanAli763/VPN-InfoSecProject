# server.py (ADVANCED SOCKS5-capable server with UDP relay)
import socket
import threading
import struct
import time
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters, Encoding, ParameterFormat

HOST = "0.0.0.0"
PORT = 5555
BUF = 65536

# Frame types
TYPE_CONNECT_REQ  = 1
TYPE_CONNECT_RESP = 2
TYPE_DATA         = 3
TYPE_CLOSE        = 4
TYPE_UDP          = 5   # used to carry UDP datagrams (encapsulated)

# load DH params
with open("dh_params.pem", "rb") as f:
    params_bytes = f.read()
    server_params = load_pem_parameters(params_bytes)

def send_blob(conn, b):
    conn.sendall(len(b).to_bytes(4, "big"))
    conn.sendall(b)

def recv_blob(conn):
    raw = conn.recv(4)
    if not raw:
        return None
    ln = int.from_bytes(raw, "big")
    data = b''
    while len(data) < ln:
        chunk = conn.recv(min(BUF, ln - len(data)))
        if not chunk:
            raise ConnectionError("unexpected EOF")
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

def handle_remote_to_client(conn, shared_key, remote_sock, conn_id):
    """
    Forward bytes from remote (TCP) -> client via encrypted frames.
    """
    try:
        while True:
            data = remote_sock.recv(BUF)
            if not data:
                break
            frame = build_frame(TYPE_DATA, conn_id, data)
            enc = encrypt_data(shared_key, frame)
            send_blob(conn, enc)
    except Exception:
        pass
    finally:
        try:
            frame = build_frame(TYPE_CLOSE, conn_id, b'')
            enc = encrypt_data(shared_key, frame)
            send_blob(conn, enc)
        except Exception:
            pass
        try:
            remote_sock.close()
        except:
            pass

def handle_udp_relay_from_client(conn, shared_key, udp_sock, peer_map_lock, peer_map):
    """
    This function isn't used as a separate thread on the server side because
    UDP relay is driven by receiving TYPE_UDP frames inside the main reader loop.
    Kept for clarity.
    """
    pass

def handle_client_session(conn, addr):
    print("[+] connection from", addr)
    try:
        # DH handshake
        server_priv, server_pub_bytes = generate_dh_keypair(server_params)
        params_pem = server_params.parameter_bytes(encoding=Encoding.PEM, format=ParameterFormat.PKCS3)
        send_blob(conn, params_pem)
        send_blob(conn, server_pub_bytes)

        client_pub = recv_blob(conn)
        if client_pub is None:
            return
        shared_key = compute_shared_key(server_priv, client_pub)
        print("[*] shared key established with", addr)

        # mappings
        tcp_connections = {}   # conn_id -> remote_tcp_socket
        tcp_lock = threading.Lock()

        # For UDP: server will send/receive via a single server UDP socket, and map client-side ephemeral ids to client's UDP info
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind ephemeral port on all interfaces; OS will pick a free port
        udp_sock.bind(("0.0.0.0", 0))
        server_udp_ip, server_udp_port = udp_sock.getsockname()
        # Map to route responses back: key = (client_conn_id, client_udp_src_addr, client_udp_src_port) => last seen
        udp_map = {}  # maps (conn_id, src_addr, src_port) -> True (presence)
        udp_map_lock = threading.Lock()

        # thread to listen for UDP responses from internet and send them back to client
        def udp_listen_loop():
            try:
                while True:
                    try:
                        data, src = udp_sock.recvfrom(65535)
                    except Exception:
                        break
                    # `src` is (dst_ip, dst_port) of the remote server that responded.
                    # We do not have an explicit mapping to the requesting client except by inspecting the UDP packet's payloads.
                    # To handle this correctly, client will include the original client_src (IP:port) and conn_id in the TYPE_UDP frame payload.
                    # Server should echo back to the correct client using that conn_id and client_src that came in the request.
                    # But here we need to store the data handling in the main loop when a request arrived.
                    # To simplify, when server receives a TYPE_UDP request we will immediately send the datagram and expect the response,
                    # but UDP is asynchronous. So we will instead let server remember the last request map in udp_map via conn_id -> (client_addr, client_port).
                    # On receipt, search for an entry where remote dest matches src for any conn_id and forward back.
                    forwarded = False
                    with udp_map_lock:
                        # search for matching remote dest in mapping values:
                        for (cid, client_src_ip, client_src_port), remote_info in list(udp_map.items()):
                            rem_ip, rem_port = remote_info.get("remote_dest", (None, None))
                            if rem_ip == src[0] and rem_port == src[1]:
                                # forward back to client over tunnel
                                # Build payload: first: original client_src ip len + ip (utf-8) + port(2 bytes) + udp payload
                                # But we already stored client_src in the key
                                # We will build a payload that includes the original client source info so client can send to local socket
                                payload = client_src_ip.encode() + b"\x00" + str(client_src_port).encode() + b"\x00" + data
                                frame = build_frame(TYPE_UDP, cid, payload)
                                enc = encrypt_data(shared_key, frame)
                                send_blob(conn, enc)
                                forwarded = True
                                break
                    if not forwarded:
                        # no known mapping: drop
                        pass
            except Exception:
                pass

        udp_thread = threading.Thread(target=udp_listen_loop, daemon=True)
        udp_thread.start()

        # reader loop: read encrypted frames from client, act accordingly
        while True:
            enc = recv_blob(conn)
            if enc is None:
                break
            try:
                frame = decrypt_data(shared_key, enc)
            except Exception as e:
                print("decrypt error:", e)
                break
            try:
                ftype, cid, payload = parse_frame(frame)
            except Exception as e:
                print("frame parse error:", e)
                break

            if ftype == TYPE_CONNECT_REQ:
                # payload is "host:port"
                try:
                    s = payload.decode()
                    host, port_s = s.rsplit(":", 1)
                    port_num = int(port_s)
                except Exception as e:
                    resp = build_frame(TYPE_CONNECT_RESP, cid, b"ERR:bad-target")
                    enc_resp = encrypt_data(shared_key, resp)
                    send_blob(conn, enc_resp)
                    continue
                try:
                    remote = socket.create_connection((host, port_num), timeout=10)
                    with tcp_lock:
                        tcp_connections[cid] = remote
                    t = threading.Thread(target=handle_remote_to_client, args=(conn, shared_key, remote, cid), daemon=True)
                    t.start()
                    resp = build_frame(TYPE_CONNECT_RESP, cid, b"OK")
                except Exception as e:
                    resp = build_frame(TYPE_CONNECT_RESP, cid, f"ERR:{e}".encode())
                send_blob(conn, encrypt_data(shared_key, resp))

            elif ftype == TYPE_DATA:
                with tcp_lock:
                    remote = tcp_connections.get(cid)
                if remote:
                    try:
                        remote.sendall(payload)
                    except Exception:
                        try:
                            remote.close()
                        except:
                            pass
                        with tcp_lock:
                            if cid in tcp_connections: del tcp_connections[cid]

            elif ftype == TYPE_CLOSE:
                with tcp_lock:
                    remote = tcp_connections.pop(cid, None)
                try:
                    if remote: remote.close()
                except:
                    pass

            elif ftype == TYPE_UDP:
                # payload format we expect: client_src_ip + b'\x00' + client_src_port + b'\x00' + dest_host + b'\x00' + dest_port + b'\x00' + udp_payload
                try:
                    parts = payload.split(b'\x00', 4)
                    if len(parts) < 5:
                        continue
                    client_src_ip = parts[0].decode()
                    client_src_port = int(parts[1].decode())
                    dest_host = parts[2].decode()
                    dest_port = int(parts[3].decode())
                    udp_payload = parts[4]
                except Exception as e:
                    continue

                try:
                    # send UDP to target
                    udp_sock.sendto(udp_payload, (dest_host, dest_port))
                    # remember mapping so response can be forwarded back:
                    with udp_map_lock:
                        udp_map[(cid, client_src_ip, client_src_port)] = {"remote_dest": (dest_host, dest_port), "ts": time.time()}
                    # we don't send an immediate ack; responses will be forwarded by udp_listen_loop
                except Exception:
                    # ignore send errors
                    pass

            else:
                # unknown type
                pass

    except Exception as e:
        print("session error:", e)
    finally:
        try:
            conn.close()
        except:
            pass
        print("[-] closed", addr)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(100)
    print("Server listening on", HOST, PORT)
    try:
        while True:
            c, a = s.accept()
            t = threading.Thread(target=handle_client_session, args=(c, a), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Shutting down")
    finally:
        s.close()

if __name__ == "__main__":
    main()
