import socket
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters

SERVER_HOST = '127.0.0.1'  # localhost for testing change to server IP for real use
SERVER_PORT = 5555
BUF = 65536

def main():
    try:
        # connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] connecting to {SERVER_HOST}:{SERVER_PORT}")
        sock.connect((SERVER_HOST, SERVER_PORT))
        print("[+] connected!")

        # helper to send length-prefixed blob
        def send_blob(b):
            sock.sendall(len(b).to_bytes(4, 'big'))
            sock.sendall(b)

        # helper to receive length-prefixed blob
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

        # receive dh parameters from server
        print("[*] receiving DH parameters..")
        params_bytes = recv_blob()
        client_params = load_pem_parameters(params_bytes)

        # receive server's public key
        print("[*] receiving server public key..")
        server_pub_bytes = recv_blob()

        # generate client's own keypair using the received parameters
        print("[*] generating client keypair...")
        client_priv, client_pub_bytes = generate_dh_keypair(client_params)

        # send client's public key to server
        print("[*] sending client public key...")
        send_blob(client_pub_bytes)

        # compute shared secret
        shared_key = compute_shared_key(client_priv, server_pub_bytes)
        print("[+] shared key established! encryption active.")
        print()

        # now we can send encrypted messages
        print("You can now send messages to the server.")
        print("Type your message and press Enter.")
        print("Type 'quit' to exit.")
        print()

        while True:
            # get message from user
            msg = input("You: ").strip()
            
            if msg.lower() == 'quit':
                print("closing connection...")
                break

            if not msg:
                continue

            # encrypt and send
            enc_msg = encrypt_data(shared_key, msg.encode('utf-8'))
            send_blob(enc_msg)
            print("message sent (encrypted)")

            # receive encrypted reply
            enc_reply = recv_blob()
            plaintext_reply = decrypt_data(shared_key, enc_reply)
            print(f"Server: {plaintext_reply.decode('utf-8')}")
            print()

    except ConnectionRefusedError:
        print("[!] connection refused - is the server running?")
    except KeyboardInterrupt:
        print("\n[*] interrupted by user")
    except Exception as e:
        print(f"[!] error: {e}")
    finally:
        sock.close()
        print("[*] connection closed")

if __name__ == '__main__':
    main()