import socket
import threading
import struct
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters, ParameterFormat, Encoding

HOST = '0.0.0.0'  # listen on all interfaces
PORT = 5555      # tcp port to bind to
BACKLOG = 50     # max queued connections
BUF = 131072     # recv buffer size for blobs (128KB for video streams)

# Frame protocol constants (must match client)
TYPE_CONNECT_REQ  = 1
TYPE_CONNECT_RESP = 2
TYPE_DATA         = 3
TYPE_CLOSE        = 4
TYPE_UDP          = 5

# load dh parameters from a file so server and client use the same group
with open("dh_params.pem", "rb") as f:
    server_params = load_pem_parameters(f.read())

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

def handle_remote_connection(conn_id, remote_sock, client_conn, shared_key, addr, send_lock, active_flag, send_blob):
    """Forward data from remote destination back to client"""
    try:
        while active_flag[0]:
            try:
                remote_sock.settimeout(1.0)
                data = remote_sock.recv(BUF)
                if not data:
                    break
                
                if not active_flag[0]:
                    break
                
                # Build DATA frame
                frame = build_frame(TYPE_DATA, conn_id, data)
                enc_frame = encrypt_data(shared_key, frame)
                
                # Thread-safe send
                with send_lock:
                    if not active_flag[0]:
                        break
                    send_blob(enc_frame)
                    
            except socket.timeout:
                continue
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                break
            except OSError as e:
                if hasattr(e, 'winerror') and e.winerror in [10038, 10053, 10054]:
                    break
                if active_flag[0]:
                    print(f"[!] Remote #{conn_id} error: {e}")
                break
            except Exception as e:
                if active_flag[0]:
                    print(f"[!] Remote #{conn_id} error: {e}")
                break
                
    except Exception as e:
        if active_flag[0]:
            print(f"[!] Remote #{conn_id} fatal: {e}")
    finally:
        if active_flag[0]:
            try:
                frame = build_frame(TYPE_CLOSE, conn_id, b'')
                enc_frame = encrypt_data(shared_key, frame)
                with send_lock:
                    if active_flag[0]:
                        send_blob(enc_frame)
            except:
                pass
        try:
            remote_sock.close()
        except:
            pass

def handle_client(conn, addr):
    try:
        print(f"[+] connection from {addr}")

        # generate a fresh dh keypair for this client session
        server_priv, server_pub_bytes = generate_dh_keypair(server_params)

        # serialize the dh parameters to pem so we can send them to the client
        params_bytes = server_params.parameter_bytes(
            encoding=Encoding.PEM,
            format=ParameterFormat.PKCS3
        )

        # helper to send a length-prefixed blob
        def send_blob(b):
            # Send as single atomic write to prevent interleaving
            msg = len(b).to_bytes(4, 'big') + b
            conn.sendall(msg)

        # helper to receive a length-prefixed blob
        def recv_blob():
            raw_len = conn.recv(4)
            if not raw_len:
                raise ConnectionError("no length header")
            ln = int.from_bytes(raw_len, 'big')
            
            # Sanity check: reject unreasonably large blobs (over 10MB)
            if ln > 10 * 1024 * 1024:
                raise ValueError(f"blob size too large: {ln} bytes")
            
            data = b''
            # keep receiving until we have the declared length
            while len(data) < ln:
                chunk = conn.recv(min(BUF, ln - len(data)))
                if not chunk:
                    raise ConnectionError(f"unexpected EOF (got {len(data)}/{ln} bytes)")
                data += chunk
            return data

        # first send dh parameters and our public key to the client
        send_blob(params_bytes)
        send_blob(server_pub_bytes)

        # then receive the client's public key
        client_pub_bytes = recv_blob()

        # compute the shared secret from our private key and client's public key
        shared_key = compute_shared_key(server_priv, client_pub_bytes)
        print(f"[+] shared key established for {addr} - VPN mode")

        # Map conn_id -> remote_socket for proxy connections
        remote_connections = {}
        remote_lock = threading.Lock()
        send_lock = threading.Lock()
        active_flag = [True]

        # Frame processing loop
        while True:
            try:
                try:
                    enc = recv_blob()
                except ConnectionError:
                    break
                
                # Validate encrypted data is not empty
                if not enc or len(enc) == 0:
                    print(f"[!] {addr} received empty encrypted blob")
                    break

                try:
                    frame_data = decrypt_data(shared_key, enc)
                    ftype, conn_id, payload = parse_frame(frame_data)
                except ValueError as e:
                    print(f"[!] {addr} frame parse error: {e}")
                    break
                except Exception as e:
                    import traceback
                    print(f"[!] {addr} decryption failed: {type(e).__name__}: {str(e) or 'no message'}")
                    print(f"[!] Encrypted blob size: {len(enc)} bytes")
                    # Show first and last bytes for diagnosis
                    if len(enc) > 0:
                        preview = enc[:32].hex() if len(enc) >= 32 else enc.hex()
                        print(f"[!] First bytes (hex): {preview}...")
                        # Check if it starts with valid base64url chars (Fernet format)
                        try:
                            first_char = chr(enc[0])
                            if first_char not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_':
                                print(f"[!] Warning: Data doesn't look like Fernet token (first byte: {enc[0]:02x})")
                        except:
                            pass
                    if len(enc) > 100000:
                        print(f"[!] Warning: Large encrypted payload may exceed Fernet limits")
                    break

            except OSError as e:
                if hasattr(e, 'winerror') and e.winerror in [10053, 10054]:
                    print(f"[!] {addr} connection closed by client")
                else:
                    print(f"[!] {addr} network error: {e}")
                break
            except Exception as e:
                print(f"[!] {addr} unexpected error: {e}")
                break

            if ftype == TYPE_CONNECT_REQ:
                # Client wants to connect to a destination
                dest_str = payload.decode('utf-8')
                try:
                    dest_host, dest_port = dest_str.rsplit(':', 1)
                    dest_port = int(dest_port)
                    
                    print(f"[*] {addr} connect #{conn_id}: {dest_host}:{dest_port}")
                    
                    # Connect to destination
                    remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote_sock.settimeout(30)  # Increased timeout for video CDN servers
                    remote_sock.connect((dest_host, dest_port))
                    remote_sock.settimeout(None)
                    
                    with remote_lock:
                        remote_connections[conn_id] = remote_sock
                    
                    # Send success response
                    resp_frame = build_frame(TYPE_CONNECT_RESP, conn_id, b"OK")
                    enc_resp = encrypt_data(shared_key, resp_frame)
                    with send_lock:
                        send_blob(enc_resp)
                    
                    print(f"[+] {addr} connected #{conn_id} to {dest_host}:{dest_port}")
                    
                    # Start reader thread for this connection
                    threading.Thread(target=handle_remote_connection, 
                                   args=(conn_id, remote_sock, conn, shared_key, addr, send_lock, active_flag, send_blob),
                                   daemon=True).start()
                    
                except Exception as e:
                    print(f"[-] {addr} connect failed #{conn_id}: {e}")
                    resp_frame = build_frame(TYPE_CONNECT_RESP, conn_id, f"ERR: {e}".encode())
                    enc_resp = encrypt_data(shared_key, resp_frame)
                    with send_lock:
                        send_blob(enc_resp)
                    
            elif ftype == TYPE_DATA:
                # Forward data to remote destination
                with remote_lock:
                    remote_sock = remote_connections.get(conn_id)
                
                if remote_sock:
                    try:
                        remote_sock.sendall(payload)
                    except Exception:
                        with remote_lock:
                            if conn_id in remote_connections:
                                del remote_connections[conn_id]
                        try:
                            remote_sock.close()
                        except:
                            pass
                        frame = build_frame(TYPE_CLOSE, conn_id, b'')
                        enc_frame = encrypt_data(shared_key, frame)
                        with send_lock:
                            send_blob(enc_frame)
                        
            elif ftype == TYPE_CLOSE:
                # Client closed connection
                with remote_lock:
                    remote_sock = remote_connections.pop(conn_id, None)
                
                if remote_sock:
                    try:
                        remote_sock.close()
                    except:
                        pass
                    print(f"[*] {addr} connection #{conn_id} closed by client")
                    
            elif ftype == TYPE_UDP:
                # UDP relay
                try:
                    parts = payload.split(b'\x00', 4)
                    if len(parts) < 5:
                        continue
                    client_src_ip = parts[0].decode()
                    client_src_port = int(parts[1].decode())
                    dest_host = parts[2].decode()
                    dest_port = int(parts[3].decode())
                    udp_payload = parts[4]
                    
                    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_sock.sendto(udp_payload, (dest_host, dest_port))
                    
                    udp_sock.settimeout(2)
                    try:
                        response, _ = udp_sock.recvfrom(BUF)
                        resp_payload = client_src_ip.encode() + b"\x00" + str(client_src_port).encode() + b"\x00" + dest_host.encode() + b"\x00" + str(dest_port).encode() + b"\x00" + response
                        frame = build_frame(TYPE_UDP, conn_id, resp_payload)
                        enc_frame = encrypt_data(shared_key, frame)
                        with send_lock:
                            send_blob(enc_frame)
                    except socket.timeout:
                        pass
                    finally:
                        udp_sock.close()
                except Exception as e:
                    print(f"[!] {addr} UDP relay error: {e}")

    except Exception as e:
        # catch-all so one client error doesn't take the server down
        print(f"[!] client handler error ({addr}):", e)
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
            conn.close()
        except:
            pass
        print(f"[-] closed {addr}")

def main():
    # create and bind the listening socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(BACKLOG)
    print(f"[+] VPN server listening on {HOST}:{PORT}")
    print(f"[*] Encryption: DH-2048 + AES-128")
    print(f"[*] Mode: SOCKS5 proxy tunnel\n")

    try:
        # accept loop, spawn a new thread per client
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("shutting down")
    finally:
        sock.close()

if __name__ == '__main__':
    main()