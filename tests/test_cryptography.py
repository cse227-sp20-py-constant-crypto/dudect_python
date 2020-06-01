from test_lib import TestLib
from test_lib import fixed_inputs_info
from test_lib import constant_key_32, random_key_32, mixed_key_32

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os


def init_aes(**kwargs):
    # AES
    backend = default_backend()
    if 'key' in kwargs and kwargs['key'] is not None:
        f, p = kwargs['key'][:2]
        key = f(*p)
    else:
        key = os.urandom(32)
    if 'iv' in kwargs and kwargs['iv'] is not None:
        f, p = kwargs['iv'][:2]
        iv = f(*p)
    else:
        iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    return cipher


def init_3des(**kwargs):
    # 3DES
    backend = default_backend()
    if 'key' in kwargs and kwargs['key'] is not None:
        f, p = kwargs['key'][:2]
        key = f(*p)
    else:
        key = os.urandom(16)
    if 'iv' in kwargs and kwargs['iv'] is not None:
        f, p = kwargs['iv'][:2]
        iv = f(*p)
    else:
        iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.OFB(iv), backend=backend)
    return cipher


def init_chacha20(**kwargs):
    # ChaCha20
    backend = default_backend()
    if 'key' in kwargs and kwargs['key'] is not None:
        f, p = kwargs['key'][:2]
        key = f(*p)
    else:
        key = os.urandom(32)
    if 'nonce' in kwargs and kwargs['nonce'] is not None:
        f, p = kwargs['nonce'][:2]
        nonce = f(*p)
    else:
        nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
    return cipher


def do_computation(cipher, in_msg: bytes):
    encryptor = cipher.encryptor()
    ct = encryptor.update(in_msg)


cryptography_aes_test_const = TestLib(init_aes, do_computation, name="cryptography-AES-const-key", key=constant_key_32)
cryptography_aes_test_random = TestLib(init_aes, do_computation, name="cryptography-AES-random-key", key=random_key_32)
cryptography_aes_test_mixed = TestLib(init_aes, do_computation, name="cryptography-AES-mixed-key",
                                      key=mixed_key_32, inputs_info_pairs=fixed_inputs_info, multi_init=True)

cryptography_3des_test_const = TestLib(init_3des, do_computation, name="cryptography-3DES-const-key", key=constant_key_32)
cryptography_3des_test_random = TestLib(init_3des, do_computation, name="cryptography-3DES-random-key", key=random_key_32)
cryptography_3des_test_mixed = TestLib(init_3des, do_computation, name="cryptography-3DES-mixed-key",
                                       key=mixed_key_32, inputs_info_pairs=fixed_inputs_info, multi_init=True)

cryptography_chacha20_test_const = TestLib(init_chacha20, do_computation, name="cryptography-ChaCha20-const-key", key=constant_key_32)
cryptography_chacha20_test_random = TestLib(init_chacha20, do_computation, name="cryptography-ChaCha20-random-key", key=random_key_32)
cryptography_chacha20_test_mixed = TestLib(init_chacha20, do_computation, name="cryptography-ChaCha20-mixed-key",
                                           key=mixed_key_32, inputs_info_pairs=fixed_inputs_info, multi_init=True)
