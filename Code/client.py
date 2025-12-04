import socket
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters

SERVER_HOST = '127.0.0.1'   # need to change this when using actual server
SERVER_PORT = 5555
BUF = 65536

def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] connecting to {SERVER_HOST}:{SERVER_PORT}")
        sock.connect((SERVER_HOST, SERVER_PORT))
        print("[+] connected!\n")

        # helpers
        def send_blob(b):
            sock.sendall(len(b).to_bytes(4, 'big'))
            sock.sendall(b)

        def recv_blob():
            raw_len = sock.recv(4)
            if not raw_len:
                raise ConnectionError("no length header")
            ln = int.from_bytes(raw_len, 'big')
            data = b''
            while len(data) < ln:
                chunk = sock.recv(min(BUF, ln - len(data)))
                if not chunk:
                    raise ConnectionError("unexpected EOF")
                data += chunk
            return data

        # dh handshake
        print("[*] receiving DH parameters...")
        params_bytes = recv_blob()
        client_params = load_pem_parameters(params_bytes)

        print("[*] receiving server public key...")
        server_pub_bytes = recv_blob()

        print("[*] generating client keypair...")
        client_priv, client_pub_bytes = generate_dh_keypair(client_params)

        print("[*] sending client public key...")
        send_blob(client_pub_bytes)

        shared_key = compute_shared_key(client_priv, server_pub_bytes)
        print("[+] shared key established. Encryption active.\n")

        # vpn mode
        print("You can now send requests through the VPN.")
        print("Format:  host  port  message")
        print("Example: google.com 80 GET / HTTP/1.1")
        print("Type quit to exit.\n")

        while True:
            user_in = input("Enter host:port message → ")

            if user_in.lower() == "quit":
                break

            try:
                # user input format
                parts = user_in.split(" ", 2)
                host = parts[0]
                port = parts[1]
                message = parts[2]
            except:
                print("Invalid format. Use: host port message")
                continue

            # format: host|port|payload
            payload = f"{host}|{port}|{message}"
            enc = encrypt_data(shared_key, payload.encode())
            send_blob(enc)

            # receive encrypted reply from server
            enc_reply = recv_blob()
            reply = decrypt_data(shared_key, enc_reply)
            print("\n[Server Reply]:")
            print(reply.decode("utf-8"))
            print()

    except Exception as e:
        print(f"[!] error: {e}")

    finally:
        sock.close()
        print("[*] connection closed")


if __name__ == "__main__":
    main()
