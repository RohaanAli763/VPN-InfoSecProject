# encryption.py
import base64
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

#before any communication first key exchange will be done then encryption/decryption will be performed
#First server will generate the parameters of diffie-hellman(p and g) using the first function and generate
#its public and private key using the second function and finally send parameters and public key of server to client
#then client will generate its private and public key using the second function and send its public key to server
#then both server and client will generate derived key using 3rd function (boht of them have same key now)(its exactly same as what we did in IS lectures)
#now simply both server and client can encrypt and decrypt data by using the encrypt and decrypt functions in last


#function to create large prime p and generator (public)
def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048)  # g=2 and p is very large coz 2048 bits


#generatin of public and private keys 
def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_bytes


#function to create shared common key
def compute_shared_key(private_key, peer_public_bytes):
    peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)

    # Derive 32-byte symmetric key using HKDF coz fernet requires 32 byte key not the one we generated (shared key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"vpn-handshake"
    ).derive(shared_secret)

    # Convert to Fernet-compatible base64 key
    fernet_key = base64.urlsafe_b64encode(derived_key)
    return fernet_key


#encryption and decryption functions 
# Fernet(internally uses AES-123) is used for encryption and decryption with HMAC for authentication
def encrypt_data(shared_key, plaintext_bytes):
    cipher = Fernet(shared_key)
    return cipher.encrypt(plaintext_bytes)


def decrypt_data(shared_key, encrypted_bytes):
    cipher = Fernet(shared_key)
    # Disable timestamp validation (ttl=None) to prevent time-based token rejection
    # This is safe for VPN use case where we control both endpoints
    return cipher.decrypt(encrypted_bytes, ttl=None)
