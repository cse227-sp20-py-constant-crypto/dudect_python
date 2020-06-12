from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes, hmac, poly1305
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

import os
import base64


with open("testcases/private.pem", "rb") as key_file:
    rsaKey_preload = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend())


def generate_aes_cbc(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()
        

    return do_computation


def generate_aes_cfb(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_aes_ofb(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_aes_ctr(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation




def generate_aes_gcm(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation




def generate_chacha20(key, nounce_or_iv):
    backend = default_backend()
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_rsa(key_info, nounce_or_iv):
    if key_info.mode == key_info.constant:
        private_key = rsaKey_preload
    elif key_info.mode == key_info.random:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    else:
        raise Exception("key info ERROR: %s" % key_info)

    public_key = private_key.public_key()
    
    def do_computation(msg: bytes):
        ciphertext = public_key.encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),label=None))
        ciphertext = str(base64.b64encode(ciphertext), encoding='utf-8')
        signer = private_key.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        signature = str(base64.b64encode(signer),encoding='utf-8')
        ct=(ciphertext, signature)
    return do_computation


def generate_dsa(key_info, nounce_or_iv):
    if key_info.mode == key_info.constant:
        p, q, g, x, y = key_info.args
        para_num = dsa.DSAParameterNumbers(p, q, g)
        pub_num = dsa.DSAPublicNumbers(y, para_num)
        pri_num = dsa.DSAPrivateNumbers(x, pub_num)
        private_key = pri_num.private_key(default_backend())
    elif key_info.mode == key_info.random:
        n = key_info.args
        private_key = dsa.generate_private_key(key_size=n, backend=default_backend())
    else:
        raise Exception("key info ERROR: %s" % key_info)
    
    def do_computation(msg: bytes):
        signature = private_key.sign(
            msg,
            hashes.SHA256()
        )
    return do_computation


def generate_ecdsa(key_info, nounce_or_iv):
    if key_info.mode == key_info.constant:
        prival = key_info.args
        private_key = ec.derive_private_key(prival,ec.SECP384R1(), backend=default_backend())
    elif key_info.mode == key_info.random:
        private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
    else:
        raise Exception("key info ERROR: %s" % key_info)

    def do_computation(msg: bytes):
        signature = private_key.sign(
            msg,
            ec.ECDSA(hashes.SHA256())
        )
    return do_computation


def generate_sha256(key, nounce_or_iv):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    
    def do_computation(msg: bytes):
        digest.update(msg)
        digest.finalize()

    return do_computation


def generate_sha3_256(key, nounce_or_iv):
    digest = hashes.Hash(hashes.SHA3_256, backend=default_backend())
    
    def do_computation(msg: bytes):
        digest.update(msg)
        digest.finalize()

    return do_computation


# HMAC
def generate_hmac(key, nounce_or_iv):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    
    def do_computation(msg: bytes):
        h.update(msg)
        h.finalize()

    return do_computation


def generate_poly1305(key, nounce_or_iv):
    p = poly1305.Poly1305(key)
    
    def do_computation(msg: bytes):
        p.update(msg)
        p.finalize()

    return do_computation

