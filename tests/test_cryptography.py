from test_lib import TestLib
from test_lib import different_inputs_infos, fixed_inputs_infos
from test_lib import different_key_infos_16, fixed_key_infos_16, different_key_infos_32, fixed_key_infos_32, \
    different_key_infos_64, fixed_key_infos_64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os


def generate_aes(key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg)

    return do_computation


def generate_des3(key):
    backend = default_backend()
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.OFB(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg)

    return do_computation


def generate_chacha20(key):
    backend = default_backend()
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg)

    return do_computation


cryptography_aes_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
                                       generate_aes, name="cryptography-AES-inputs")
cryptography_aes_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
                                    generate_aes, name="cryptography-AES-key", multi_init=True)

cryptography_des3_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
                                        generate_des3, name="cryptography-DES3-inputs")
cryptography_des3_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
                                     generate_des3, name="cryptography-DES3-key", multi_init=True)

cryptography_chacha20_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_32,
                                        generate_chacha20, name="cryptography-ChaCha20-inputs")
cryptography_chacha20_test_key = TestLib(fixed_inputs_infos, different_key_infos_32,
                                     generate_chacha20, name="cryptography-ChaCha20-key", multi_init=True)
