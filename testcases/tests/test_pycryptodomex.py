from testcases.test_lib import TestLib
from testcases.test_lib import different_inputs_infos, fixed_inputs_infos
from testcases.test_lib import different_key_infos_16, fixed_key_infos_16, different_key_infos_64, fixed_key_infos_64

from Cryptodome.Cipher import AES, DES3, ChaCha20
from Cryptodome import Random
from Cryptodome.PublicKey import RSA, ElGamal
from Cryptodome.Hash import SHA
import os
import base64


def generate_aes_cbc(key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_cfb(key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ofb(key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_OFB, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ctr(key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CTR, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_chacha20(key):
    nonce = os.urandom(16)
    cipher = ChaCha20.new(key=key, nonce=nonce)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_rsa(key_info):
    pass


def generate_dsa(key_info):
    pass


def generate_ecdsa(key_info):
    pass


pycryptodomex_aes_cbc_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
                                        generate_aes_cbc, name="pycryptodomex-AES-cbc-inputs")
pycryptodomex_aes_cbc_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
                                     generate_aes_cbc, name="pycryptodomex-AES-cbc-key", multi_init=True)

pycryptodomex_aes_cfb_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
                                        generate_aes_cfb, name="pycryptodomex-AES-cfb-inputs")
pycryptodomex_aes_cfb_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
                                     generate_aes_cfb, name="pycryptodomex-AES-cfb-key", multi_init=True)

pycryptodomex_aes_ofb_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
                                        generate_aes_ofb, name="pycryptodomex-AES-ofb-inputs")
pycryptodomex_aes_ofb_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
                                     generate_aes_ofb, name="pycryptodomex-AES-ofb-key", multi_init=True)

pycryptodomex_aes_ctr_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
                                        generate_aes_cbc, name="pycryptodomex-AES-cbc-inputs")
pycryptodomex_aes_cbc_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
                                     generate_aes_cbc, name="pycryptodomex-AES-cbc-key", multi_init=True)
