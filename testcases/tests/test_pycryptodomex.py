import OpenSSL
import Cryptodome
from Cryptodome.Cipher import AES, ChaCha20, Salsa20, PKCS1_OAEP
from Cryptodome import Random
from Cryptodome.PublicKey import RSA, ElGamal, DSA, ECC
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA, SHA256, SHA3_256, HMAC, Poly1305
import os
import base64


# AES
def generate_aes_cbc(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_cfb(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ofb(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ctr(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ccm(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_CCM, nonce=iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_eax(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_EAX, nonce=iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_gcm(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_siv(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_SIV, nonce=iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_aes_ocb(key, nonce_or_iv):
    iv = nonce_or_iv
    cipher = AES.new(key, AES.MODE_OCB, nonce=iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


# ChaCha20
def generate_chacha20(key, nonce_or_iv):
    nonce = nonce_or_iv
    cipher = ChaCha20.new(key=key, nonce=nonce)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


def generate_tls_chacha20(key, nonce_or_iv):
    nonce = nonce_or_iv
    cipher = ChaCha20.new(key=key, nonce=nonce)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


# Salsa20
def generate_salsa20(key, nonce_or_iv):
    key = key
    nonce = nonce_or_iv
    cipher = Salsa20.new(key=key, nonce=nonce)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)
    return do_computation


# RSA DSA
with open("testcases/private.pem", "rb") as key_file:
    rsaKey_preload = RSA.import_key(key_file.read())


def generate_rsa(key_info, nonce_or_iv):
    if key_info.mode == key_info.constant:
        public_key = rsaKey_preload
    elif key_info.mode == key_info.random:
        public_key = RSA.generate(bits=2048)
    else:
        raise Exception("key info ERROR: %s" % key_info)

    def do_computation(msg: bytes):
        ciphertext = str(base64.b64encode(msg), encoding='utf-8')
        cipher_rsa = PKCS1_OAEP.new(public_key)
    return do_computation


def generate_dsa(key_info, nonce_or_iv):
    if key_info.mode == key_info.constant:
        p, q, g, x, y = key_info.args
        key = DSA.construct(tup=(y,g,p,q,x))
    elif key_info.mode == key_info.random:
        n = key_info.args
        key = DSA.generate(randfunc=Random.get_random_bytes(n),bits=2048)
    else:
        raise Exception("key info ERROR: %s" % key_info)

    def do_computation(msg: bytes):
        hash_obj = SHA256.new(msg)
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(hash_obj)
    return do_computation


def generate_ecdsa(key_info, nonce_or_iv):
    if key_info.mode == key_info.constant:
        # signer = DSS.new(eccKey_preload, 'deterministic-rfc6979')
        p, q, g, x, y = key_info.args
        key = ECC.construct(tup=(y,g,p,q,x))
    elif key_info.mode == key_info.random:
        n = key_info.args
        key = ECC.generate(randfunc=Random.get_random_bytes(n),bits=2048)
        # signer = DSS.new(eccKey_preload, 'fips-186-3', randfunc=Random.get_random_bytes(n))
    else:
        raise Exception("key info ERROR: %s" % key_info)
    def do_computation(msg: bytes):
        h = SHA256.new(msg)
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
    return do_computation


# HASH
def generate_sha256(key, nonce_or_iv):
    h = SHA256.new()
    def do_computation(msg: bytes):
        h.update(msg)
        h.hexdigest()
    return do_computation

def generate_sha3_256(key, nonce_or_iv):
    h = SHA3_256.new()
    def do_computation(msg: bytes):
        h.update(msg)
        h.hexdigest()
    return do_computation


# MAC
def generate_hmac(key, nonce_or_iv):
    h = HMAC.new(key, digestmod=SHA256)
    def do_computation(msg: bytes):
        h.update(msg)
        h.hexdigest()
    return do_computation


def generate_poly1305(key, nonce_or_iv):
    mac = Poly1305.new(key=key, cipher=AES)
    def do_computation(msg: bytes):
        mac.update(msg)
        mac.nonce.hex()
        mac.hexdigest()
    return do_computation

