from Cryptodome.Cipher import AES, ChaCha20, Salsa20, PKCS1_OAEP
from Cryptodome.PublicKey import RSA, ElGamal, DSA, ECC
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA, SHA256, SHA3_256, HMAC, Poly1305

# import os
# import base64


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
def generate_rsa(key, nonce_or_iv):
    rsa_key = RSA.import_key(key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)

    def do_computation(msg: bytes):
        cipher_rsa.encrypt(msg)

    return do_computation


def generate_dsa(key, nonce_or_iv):
    dsa_key = DSA.import_key(key)
    signer = DSS.new(dsa_key, 'fips-186-3')

    def do_computation(msg: bytes):
        h = SHA256.new(msg)
        signature = signer.sign(h)

    return do_computation


def generate_ecdsa(key, nonce_or_iv):
    ec_key = ECC.import_key(key)
    signer = DSS.new(ec_key, 'deterministic-rfc6979')

    def do_computation(msg: bytes):
        h = SHA256.new(msg)
        signature = signer.sign(h)

    return do_computation


# HASH
def generate_sha256(key, nonce_or_iv):
    h = SHA256.new()

    def do_computation(msg: bytes):
        h.update(msg)
        # h.hexdigest()
    return do_computation

def generate_sha3_256(key, nonce_or_iv):
    h = SHA3_256.new()

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


def generate_poly1305(key, nonce_or_iv):
    mac = Poly1305.new(key=key, cipher=AES)
    def do_computation(msg: bytes):
        mac.update(msg)
        # mac.nonce.hex()
        # mac.hexdigest()
    return do_computation

