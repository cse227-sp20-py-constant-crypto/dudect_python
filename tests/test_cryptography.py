from test_lib import TestLib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os


def init_aes():
    # AES
    backend = default_backend()
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    return cipher


def init_3des():
    # 3DES
    backend = default_backend()
    key = os.urandom(16)
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.OFB(iv), backend=backend)
    return cipher


def init_chacha20():
    # ChaCha20
    backend = default_backend()
    key = os.urandom(32)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
    return cipher


def do_computation(cipher, in_msg: bytes):
    encryptor = cipher.encryptor()
    ct = encryptor.update(in_msg)


cryptography_aes_test = TestLib(init_aes, do_computation, name="cryptography-AES")
cryptography_3des_test = TestLib(init_3des, do_computation, name="cryptography-3DES")
cryptography_chacha20_test = TestLib(init_chacha20, do_computation, name="cryptography-ChaCha20")
