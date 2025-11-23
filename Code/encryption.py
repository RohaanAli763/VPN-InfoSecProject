# encryption.py
import base64
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

# ---------------------------------------------------------
# PART 1: Diffie–Hellman Key Exchange
# ---------------------------------------------------------

def generate_dh_parameters():
    """
    Generates Diffie–Hellman parameters (shared by both parties).
    Should be done once on server; client receives parameters.
    """
    return dh.generate_parameters(generator=2, key_size=2048)


def generate_dh_keypair(parameters):
    """
    Generate a DH private/public key pair.
    Returns: (private_key, public_key_bytes)
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key, public_bytes


def compute_shared_key(private_key, peer_public_bytes):
    """
    Given our private key and peer's public bytes,
    compute the shared secret and derive a Fernet-compatible key.
    """
    peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public_key)

    # Derive 32-byte symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"vpn-handshake"
    ).derive(shared_secret)

    # Convert to Fernet-compatible base64 key
    fernet_key = base64.urlsafe_b64encode(derived_key)
    return fernet_key

# ---------------------------------------------------------
# PART 2: AES + HMAC Encryption (Fernet)
# ---------------------------------------------------------

def encrypt_data(shared_key, plaintext_bytes):
    """
    Encrypt data using AES-128 + HMAC-SHA256 (Fernet).
    shared_key: Fernet-compatible 32-byte base64 key
    plaintext_bytes: bytes
    """
    cipher = Fernet(shared_key)
    return cipher.encrypt(plaintext_bytes)


def decrypt_data(shared_key, encrypted_bytes):
    """
    Decrypt data using AES-128 + HMAC-SHA256 (Fernet).
    shared_key: Fernet-compatible 32-byte base64 key
    encrypted_bytes: bytes
    """
    cipher = Fernet(shared_key)
    return cipher.decrypt(encrypted_bytes)
