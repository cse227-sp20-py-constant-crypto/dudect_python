from testcases.test_lib import TestLib
from testcases.test_lib import different_inputs_infos, fixed_inputs_infos
from testcases.test_lib import different_key_infos_16, fixed_key_infos_16, different_key_infos_32, fixed_key_infos_32, \
    different_key_infos_64, fixed_key_infos_64, fixed_key_infos_rsa, different_key_infos_rsa,fixed_key_infos_dsa, different_key_infos_dsa,\
        fixed_key_infos_ecdsa, different_key_infos_ecdsa

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import base64

def generate_aes(key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()
        

    return do_computation


def generate_des3(key):
    backend = default_backend()
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.OFB(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_chacha20(key):
    backend = default_backend()
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_rsa(PrivateKey):
    PublicKey=PrivateKey.public_key()
    def do_computation(msg: bytes):
        ciphertext = PublicKey.encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),label=None))
        ciphertext = str(base64.b64encode(ciphertext), encoding='utf-8')
        signer = PrivateKey.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        signature = str(base64.b64encode(signer),encoding='utf-8')
        ct=(ciphertext, signature)
    return do_computation


def generate_dsa(PrivateKey):
    def do_computation(msg: bytes):
        signature = PrivateKey.sign(
            msg,
            hashes.SHA256()
        )
    return do_computation

def generate_ecdsa(PrivateKey):
    def do_computation(msg: bytes):
        signature = PrivateKey.sign(
            msg,
            ec.ECDSA(hashes.SHA256())
        )
    return do_computation

cryptography_ecdsa_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_ecdsa,
                                        generate_ecdsa, name="cryptography-ECDSA-inputs")
cryptography_ecdsa_test_key = TestLib(fixed_inputs_infos, different_key_infos_ecdsa,
                                    generate_ecdsa, name="cryptography-ECDSA-key", multi_init=True)

cryptography_dsa_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_dsa,
                                        generate_dsa, name="cryptography-DSA-inputs")
cryptography_dsa_test_key = TestLib(fixed_inputs_infos, different_key_infos_dsa,
                                    generate_dsa, name="cryptography-DSA-key", multi_init=True)

cryptography_rsa_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_rsa,
                                        generate_rsa, name="cryptography-RSA-inputs")
cryptography_rsa_test_key = TestLib(fixed_inputs_infos, different_key_infos_rsa,
                                    generate_rsa, name="cryptography-RSA-key", multi_init=True)

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

