from test_lib import TestLib
from test_lib import different_inputs_infos, fixed_inputs_infos
from test_lib import different_key_infos_16, fixed_key_infos_16, different_key_infos_64, fixed_key_infos_64

from Crypto.Cipher import AES, DES3
from Crypto import Random
from Crypto.Cipher.blockalgo import BlockAlgo
from Crypto.PublicKey import ElGamal
from Crypto.Hash import SHA


def generate_aes(key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_des3(key):
    iv = Random.new().read(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_OFB, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


pycrypto_aes_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
                                   generate_aes, name="pycrypto-AES-inputs")
pycrypto_aes_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
                                generate_aes, name="pycrypto-AES-key", multi_init=True)

pycrypto_des3_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
                                   generate_des3, name="pycrypto-DES3-inputs")
pycrypto_des3_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
                                generate_des3, name="pycrypto-DES3-key", multi_init=True)
