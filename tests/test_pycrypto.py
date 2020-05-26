from test_lib import TestLib

from Crypto.Cipher import AES, DES3
from Crypto import Random
from Crypto.Cipher.blockalgo import BlockAlgo
from Crypto.PublicKey import ElGamal
from Crypto.Hash import SHA


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


def do_computation(cipher: BlockAlgo, in_msg: bytes):
    cipher.encrypt(in_msg)


pycrypto_aes_test = TestLib(init_aes, do_computation, name="pycrypto-AES")
pycrypto_des3_test = TestLib(init_des3, do_computation, name="pycrypto-DES3")
