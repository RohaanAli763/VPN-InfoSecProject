import socket
import threading
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters, ParameterFormat, Encoding

HOST = '0.0.0.0'
PORT = 5555
BACKLOG = 50
BUF = 65536

# Load DH parameters from file
with open("dh_params.pem", "rb") as f:
    server_params = load_pem_parameters(f.read())

def handle_client(conn, addr):
    try:
        print(f"[+] connection from {addr}")

        # Generate server keypair for this client
        server_priv, server_pub_bytes = generate_dh_keypair(server_params)

        # Serialize parameters to send to client
        params_bytes = server_params.parameter_bytes(
            encoding=Encoding.PEM,
            format=ParameterFormat.PKCS3
        )

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

        # Send DH parameters + server public key
        send_blob(params_bytes)
        send_blob(server_pub_bytes)

        # Receive client's public key
        client_pub_bytes = recv_blob()

        # Compute shared key
        shared_key = compute_shared_key(server_priv, client_pub_bytes)
        print(f"[*] shared key established for {addr}")

        # Encrypted communication loop
        while True:
            try:
                enc = recv_blob()
            except ConnectionError:
                break

            try:
                plaintext = decrypt_data(shared_key, enc)
            except Exception as e:
                print(f"decryption error from {addr}: {e}")
                break

            print(f"<{addr}>", plaintext[:200])

            reply = b"server received: " + plaintext
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
    print(f"listening on {HOST}:{PORT}")

    try:
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
