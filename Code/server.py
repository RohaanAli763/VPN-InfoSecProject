import socket
import threading
from encryption import generate_dh_keypair, compute_shared_key, encrypt_data, decrypt_data
from cryptography.hazmat.primitives.serialization import load_pem_parameters, ParameterFormat, Encoding

HOST = '0.0.0.0'  # listen on all interfaces
PORT = 5555      # tcp port to bind to
BACKLOG = 50     # max queued connections
BUF = 65536      # recv buffer size for blobs

# load dh parameters from a file so server and client use the same group
with open("dh_params.pem", "rb") as f:
    server_params = load_pem_parameters(f.read())

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
            conn.sendall(len(b).to_bytes(4, 'big'))
            conn.sendall(b)

        # helper to receive a length-prefixed blob
        def recv_blob():
            raw_len = conn.recv(4)
            if not raw_len:
                raise ConnectionError("no length header")
            ln = int.from_bytes(raw_len, 'big')
            data = b''
            # keep receiving until we have the declared length
            while len(data) < ln:
                chunk = conn.recv(min(BUF, ln - len(data)))
                if not chunk:
                    raise ConnectionError("unexpected EOF")
                data += chunk
            return data

        # first send dh parameters and our public key to the client
        send_blob(params_bytes)
        send_blob(server_pub_bytes)

        # then receive the client's public key
        client_pub_bytes = recv_blob()

        # compute the shared secret from our private key and client's public key
        shared_key = compute_shared_key(server_priv, client_pub_bytes)
        print(f"[*] shared key established for {addr}")

        # now we can exchange encrypted messages in a loop
        while True:
            try:
                enc = recv_blob()
            except ConnectionError:
                # client closed connection or protocol error
                break

            try:
                plaintext = decrypt_data(shared_key, enc)
            except Exception as e:
                # decryption failed
                print(f"decryption error from {addr}: {e}")
                break

            # show a short preview of the message for logging
            print(f"<{addr}>", plaintext[:200])

            # prepare and send an encrypted reply
            reply = b"server received: " + plaintext
            enc_reply = encrypt_data(shared_key, reply)
            send_blob(enc_reply)

    except Exception as e:
        # catch-all so one client error doesn't take the server down
        print(f"client handler error ({addr}):", e)
    finally:
        conn.close()
        print(f"[-] closed {addr}")

def main():
    # create and bind the listening socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(BACKLOG)
    print(f"listening on {HOST}:{PORT}")

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