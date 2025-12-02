import socket
import threading
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters, ParameterFormat, Encoding
from routing import get_next_hop, is_blocked

HOST = '0.0.0.0'
PORT = 5555
BACKLOG = 50
BUF = 65536

# load DH parameters
with open("dh_params.pem", "rb") as f:
    server_params = load_pem_parameters(f.read())


def handle_client(conn, addr):

    try:
        print(f"[+] connection from {addr}")

        # perform DH handshake
        server_priv, server_pub_bytes = generate_dh_keypair(server_params)

        params_bytes = server_params.parameter_bytes(
            encoding=Encoding.PEM,
            format=ParameterFormat.PKCS3
        )

        # helper functions
        def send_blob(b):
            conn.sendall(len(b).to_bytes(4, 'big'))
            conn.sendall(b)

        def recv_blob():
            raw_len = conn.recv(4)
            if not raw_len:
                raise ConnectionError("no length header")
            ln = int.from_bytes(raw_len, 'big')
            data = b''
            while len(data) < ln:
                chunk = conn.recv(min(BUF, ln - len(data)))
                if not chunk:
                    raise ConnectionError("unexpected EOF")
                data += chunk
            return data

        # send DH params and server public key
        send_blob(params_bytes)
        send_blob(server_pub_bytes)

        # receive client public key
        client_pub_bytes = recv_blob()

        # derive shared symmetric key
        shared_key = compute_shared_key(server_priv, client_pub_bytes)
        print(f"[*] shared key established for {addr}")

        # main loop to receive encrypted requests and forward them
        while True:
            enc_request = recv_blob()   # Encrypted packet from client
            plaintext = decrypt_data(shared_key, enc_request)

            try:
                # incoming format: host|port|message
                decoded = plaintext.decode("utf-8")
                host, port, message = decoded.split("|", 2)
                port = int(port)
            except:
                print(f"[!] bad packet format from {addr}")
                break

            print(f"[REQ] {addr} → {host}:{port}")

            # check blocklist
            if is_blocked(host):
                response = f"[VPN SERVER] BLOCKED DOMAIN: {host}".encode()
                send_blob(encrypt_data(shared_key, response))
                continue

            # routing step (resolve DNS, get next hop)
            next_ip, next_port = get_next_hop(host, port)
            if not next_ip:
                response = f"[VPN SERVER] Could not resolve hostname {host}".encode()
                send_blob(encrypt_data(shared_key, response))
                continue

            # packet forwarding
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fw:
                    fw.settimeout(5)
                    fw.connect((next_ip, next_port))
                    fw.sendall(message.encode())
                    reply = fw.recv(BUF)
            except Exception as e:
                reply = f"[VPN SERVER] forwarding error: {e}".encode()

            # encrypt and return response to client
            enc_reply = encrypt_data(shared_key, reply)
            send_blob(enc_reply)

    except Exception as e:
        print(f"client handler error ({addr}):", e)

    finally:
        conn.close()
        print(f"[-] closed {addr}")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(BACKLOG)
    print(f"[VPN] listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("[VPN] shutting down")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
