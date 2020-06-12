from testcases.test_lib import TestLib
from testcases.test_lib import different_inputs_infos, fixed_inputs_infos
from testcases.test_lib import different_key_infos_16, fixed_key_infos_16, different_key_infos_64, fixed_key_infos_64

from Cryptodome.Cipher import AES, ChaCha20
from Cryptodome import Random
from Cryptodome.PublicKey import RSA, ElGamal
from Cryptodome.Hash import SHA
import os
import base64


# AES
def generate_aes_cbc(key, nounce_or_iv):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_cfb(key, nounce_or_iv):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ofb(key, nounce_or_iv):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_OFB, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ctr(key, nounce_or_iv):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CTR, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ccm(key, nounce_or_iv):
    pass


def generate_aes_eax(key, nounce_or_iv):
    pass


def generate_aes_gcm(key, nounce_or_iv):
    pass


def generate_aes_siv(key, nounce_or_iv):
    pass


def generate_aes_ocb(key, nounce_or_iv):
    pass


# ChaCha20
def generate_chacha20(key, nounce_or_iv):
    nonce = nounce_or_iv
    cipher = ChaCha20.new(key=key, nonce=nonce)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_tls_chacha20(key, nounce_or_iv):
    pass


# Salsa20
def generate_salsa20(key, nounce_or_iv):
    pass


# RSA DSA
def generate_rsa(key_info, nounce_or_iv):
    if key_info.mode == key_info.constant:
        pass
    elif key_info.mode == key_info.random:
        pass
    else:
        raise Exception("key info error: %s")

    pass


def generate_dsa(key_info, nounce_or_iv):
    if key_info.mode == key_info.constant:
        pass
    elif key_info.mode == key_info.random:
        pass
    else:
        raise Exception("key info error: %s")

    pass


def generate_ecdsa(key_info, nounce_or_iv):
    if key_info.mode == key_info.constant:
        pass
    elif key_info.mode == key_info.random:
        pass
    else:
        raise Exception("key info error: %s")

    pass


# HASH
def generate_sha256(key, nounce_or_iv):
    pass


def generate_sha3_256(key, nounce_or_iv):
    pass


# MAC
def generate_hmac(key, nounce_or_iv):
    pass


def generate_poly1305(key, nounce_or_iv):
    pass

