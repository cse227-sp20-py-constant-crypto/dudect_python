from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes, hmac, poly1305
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# import os
# import base64


def generate_aes_cbc(key, nonce_or_iv):
    backend = default_backend()
    iv = nonce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()
        

    return do_computation


def generate_aes_cfb(key, nonce_or_iv):
    backend = default_backend()
    iv = nonce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_aes_ofb(key, nonce_or_iv):
    backend = default_backend()
    iv = nonce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_aes_ctr(key, nonce_or_iv):
    backend = default_backend()
    iv = nonce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation




def generate_aes_gcm(key, nonce_or_iv):
    backend = default_backend()
    iv = nonce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_chacha20(key, nonce_or_iv):
    backend = default_backend()
    nonce = nonce_or_iv
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


generate_tls_chacha20 = generate_chacha20


def generate_rsa(key, nonce_or_iv):
    private_key = serialization.load_pem_private_key(key, password=None, backend=default_backend())
    public_key = private_key.public_key()
    
    def do_computation(msg: bytes):
        ciphertext = public_key.encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),label=None))
        # ciphertext = str(base64.b64encode(ciphertext), encoding='utf-8')
        signer = private_key.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        # signature = str(base64.b64encode(signer), encoding='utf-8')
        # ct=(ciphertext, signature)

    return do_computation


def generate_dsa(key, nonce_or_iv):
    private_key = serialization.load_pem_private_key(key, password=None, backend=default_backend())
    
    def do_computation(msg: bytes):
        signature = private_key.sign(
            msg,
            hashes.SHA256()
        )

    return do_computation


def generate_ecdsa(key, nonce_or_iv):
    private_key = serialization.load_pem_private_key(key, password=None, backend=default_backend())

    def do_computation(msg: bytes):
        signature = private_key.sign(
            msg,
            ec.ECDSA(hashes.SHA256())
        )

    return do_computation


def generate_sha256(key, nonce_or_iv):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    
    def do_computation(msg: bytes):
        digest.update(msg)
        # digest.finalize()

    return do_computation


def generate_sha3_256(key, nonce_or_iv):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    
    def do_computation(msg: bytes):
        digest.update(msg)
        # digest.finalize()

    return do_computation


# HMAC
def generate_hmac(key, nonce_or_iv):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    
    def do_computation(msg: bytes):
        h.update(msg)
        # h.finalize()

    return do_computation


def generate_poly1305(key, nonce_or_iv):
    p = poly1305.Poly1305(key)
    
    def do_computation(msg: bytes):
        p.update(msg)
        # p.finalize()

    return do_computation

