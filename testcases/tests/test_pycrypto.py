from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import random
from Crypto.PublicKey import RSA, ElGamal, DSA
from Crypto.Hash import SHA, SHA256, HMAC

# import os
# import base64


# AES
def generate_aes_cbc(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_CBC, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_cfb(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_CFB, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ofb(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_OFB, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


# RSA DSA
def generate_rsa(key, nonce_or_iv):
    rsa_key = RSA.importKey(key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    def do_computation(msg: bytes):
        cipher_rsa.encrypt(msg)

    return do_computation


# HASH
def generate_sha256(key, nonce_or_iv):
    h = SHA256.new()

    def do_computation(msg: bytes):
        h.update(msg)
        # h.hexdigest()
    return do_computation


# MAC
def generate_hmac(key, nonce_or_iv):
    h = HMAC.new(key, digestmod=SHA256)
    def do_computation(msg: bytes):
        h.update(msg)
        # h.hexdigest()
    return do_computation

