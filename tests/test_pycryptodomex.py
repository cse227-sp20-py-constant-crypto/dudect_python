from test_lib import TestLib
from test_lib import fixed_inputs_info
from test_lib import constant_key, random_key, mixed_key

from Cryptodome.Cipher import AES, DES3
from Cryptodome import Random
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Hash import SHA


def init_aes(**kwargs):
    if 'key' in kwargs and kwargs['key'] is not None:
        f, p = kwargs['key'][:2]
        key = f(*p)
    else:
        key = b'Sixteen byte key'
    if 'iv' in kwargs and kwargs['iv'] is not None:
        f, p = kwargs['iv'][:2]
        iv = f(*p)
    else:
        iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher


def init_des3(**kwargs):
    if 'key' in kwargs and kwargs['key'] is not None:
        f, p = kwargs['key'][:2]
        key = f(*p)
    else:
        key = b'Sixteen byte key'
    if 'iv' in kwargs and kwargs['iv'] is not None:
        f, p = kwargs['iv'][:2]
        iv = f(*p)
    else:
        iv = Random.new().read(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    return cipher


def do_computation(cipher, in_msg: bytes):
    cipher.encrypt(in_msg)


pycryptodomex_aes_test_const = TestLib(init_aes, do_computation, name="pycryptodomex-AES-const-key", key=constant_key)
pycryptodomex_aes_test_random = TestLib(init_aes, do_computation, name="pycryptodomex-AES-random-key", key=random_key)
pycryptodomex_aes_test_mixed = TestLib(init_aes, do_computation, name="pycryptodomex-AES-mixed-key",
                                       key=mixed_key, inputs_info_pairs=fixed_inputs_info)

pycryptodomex_des3_test_const = TestLib(init_des3, do_computation, name="pycryptodomex-3DES-const-key", key=constant_key)
pycryptodomex_des3_test_random = TestLib(init_des3, do_computation, name="pycryptodomex-3DES-random-key", key=random_key)
pycryptodomex_des3_test_mixed = TestLib(init_des3, do_computation, name="pycryptodomex-3DES-mixed-key",
                                        key=mixed_key, inputs_info_pairs=fixed_inputs_info)
