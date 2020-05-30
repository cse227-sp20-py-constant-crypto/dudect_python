from test_lib import TestLib

from Cryptodome.Cipher import AES, DES3
from Cryptodome import Random
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Hash import SHA


def init_aes():
    key = b'Sixteen byte key'
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher


def init_des3():
    key = b'Sixteen byte key'
    iv = Random.new().read(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    return cipher


def do_computation(cipher, in_msg: bytes):
    cipher.encrypt(in_msg)


pycryptodomex_aes_test = TestLib(init_aes, do_computation, name="pycryptodomex-AES")
