#from testcases.test_lib import TestLib
#from testcases.test_lib import different_inputs_infos, fixed_inputs_infos
#from testcases.test_lib import different_key_infos_16, fixed_key_infos_16, different_key_infos_32, fixed_key_infos_32, \
#    different_key_infos_64, fixed_key_infos_64, fixed_key_infos_rsa, different_key_infos_rsa,fixed_key_infos_dsa, different_key_infos_dsa,\
#        fixed_key_infos_ecdsa, different_key_infos_ecdsa

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import hashes, hmac, poly1305
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64


with open("testcases/private.pem", "rb") as key_file:
    rsaKey_preload = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend())


def generate_aes_cbc(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()
        

    return do_computation


def generate_aes_cfb(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_aes_ofb(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation


def generate_aes_ctr(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation




def generate_aes_gcm(key, nounce_or_iv):
    backend = default_backend()
    iv = nounce_or_iv
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation




def generate_chacha20(key, nounce_or_iv):
    backend = default_backend()
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    def do_computation(msg: bytes):
        encryptor = cipher.encryptor()
        ct = encryptor.update(msg) + encryptor.finalize()

    return do_computation



def generate_rsa(key_info, nounce_or_iv):
    if key_info.mode == key_info.constant:
        private_key = rsaKey_preload
    elif key_info.mode == key_info.random:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    else:
        raise Exception("key info ERROR: %s" % key_info)

    public_key = private_key.public_key()
    
    def do_computation(msg: bytes):
        ciphertext = public_key.encrypt(
            msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),label=None))
        ciphertext = str(base64.b64encode(ciphertext), encoding='utf-8')
        signer = private_key.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        signature = str(base64.b64encode(signer),encoding='utf-8')
        ct=(ciphertext, signature)
    return do_computation


def generate_dsa(key_info, nounce_or_iv):
    if key_info.mode == key_info.constant:
        p, q, g, x, y = key_info.args
        para_num = dsa.DSAParameterNumbers(p, q, g)
        pub_num = dsa.DSAPublicNumbers(y, para_num)
        pri_num = dsa.DSAPrivateNumbers(x, pub_num)
        private_key = pri_num.private_key(default_backend())
    elif key_info.mode == key_info.random:
        n = key_info.args
        private_key = dsa.generate_private_key(key_size=n, backend=default_backend())
    else:
        raise Exception("key info ERROR: %s" % key_info)
    
    def do_computation(msg: bytes):
        signature = private_key.sign(
            msg,
            hashes.SHA256()
        )
    return do_computation


def generate_ecdsa(key_info, nounce_or_iv):
    if key_info.mode == key_info.constant:
        prival = key_info.args
        private_key = ec.derive_private_key(prival,ec.SECP384R1(), backend=default_backend())
    elif key_info.mode == key_info.random:
        private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
    else:
        raise Exception("key info ERROR: %s" % key_info)

    def do_computation(msg: bytes):
        signature = private_key.sign(
            msg,
            ec.ECDSA(hashes.SHA256())
        )
    return do_computation


def generate_sha256(key, nounce_or_iv):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    
    def do_computation(msg: bytes):
        digest.update(msg)
        digest.finalize()

    return do_computation


def generate_sha3_256(key, nounce_or_iv):
    digest = hashes.Hash(hashes.SHA3_256, backend=default_backend())
    
    def do_computation(msg: bytes):
        digest.update(msg)
        digest.finalize()

    return do_computation


# HMAC
def generate_hmac(key, nounce_or_iv):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    
    def do_computation(msg: bytes):
        h.update(msg)
        h.finalize()

    return do_computation


def generate_poly1305(key, nounce_or_iv):
    p = poly1305.Poly1305(key)
    
    def do_computation(msg: bytes):
        p.update(msg)
        p.finalize()

    return do_computation


#cryptography_poly1305_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                        generate_poly1305, name="cryptography-poly1305-inputs")
#cryptography_poly1305_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
#                                    generate_poly1305, name="cryptography-poly1305-key", multi_init=True)

#cryptography_hmac_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                        generate_hmac, name="cryptography-HMAC-inputs")
#cryptography_hmac_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
#                                    generate_hmac, name="cryptography-HMAC-key", multi_init=True)

#cryptography_sha3_256_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                        generate_sha3_256, name="cryptography-sha3_256-inputs")
#cryptography_sha3_256_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
#                                    generate_sha3_256, name="cryptography-sha3_256-key", multi_init=True)

#cryptography_sha256_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                        generate_sha256, name="cryptography-sha256-inputs")
#cryptography_sha256_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
#                                    generate_sha256, name="cryptography-sha256-key", multi_init=True)

#cryptography_ecdsa_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                        generate_ecdsa, name="cryptography-ECDSA-inputs")
#cryptography_ecdsa_test_key = TestLib(fixed_inputs_infos, different_key_infos_ecdsa,
#                                    generate_ecdsa, name="cryptography-ECDSA-key", multi_init=True)

#cryptography_dsa_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_dsa,
#                                        generate_dsa, name="cryptography-DSA-inputs")
#cryptography_dsa_test_key = TestLib(fixed_inputs_infos, different_key_infos_dsa,
#                                    generate_dsa, name="cryptography-DSA-key", multi_init=True)

#cryptography_rsa_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_rsa,
#                                        generate_rsa, name="cryptography-RSA-inputs")
#cryptography_rsa_test_key = TestLib(fixed_inputs_infos, different_key_infos_rsa,
#                                    generate_rsa, name="cryptography-RSA-key", multi_init=True)

#cryptography_aes_cbc_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                       generate_aes_cbc, name="cryptography-AES-CBC-inputs")
#cryptography_aes_cbc_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
#                                    generate_aes_cbc, name="cryptography-AES-CBC-key", multi_init=True)

#cryptography_aes_cfb_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                       generate_aes_cfb, name="cryptography-AES-CFB-inputs")
#cryptography_aes_cfb_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
#                                    generate_aes_cfb, name="cryptography-AES-CFB-key", multi_init=True)

#cryptography_aes_ofb_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                       generate_aes_ofb, name="cryptography-AES-OFB-inputs")
#cryptography_aes_ofb_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
#                                    generate_aes_ofb, name="cryptography-AES-OFB-key", multi_init=True)

#cryptography_aes_ctr_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                       generate_aes_ctr, name="cryptography-AES-CTR-inputs")
#cryptography_aes_ctr_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
#                                    generate_aes_ctr, name="cryptography-AES-CTR-key", multi_init=True)

# cryptography_aes_gcm_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_16,
#                                        generate_aes_gcm, name="cryptography-AES-GCM-inputs")
# cryptography_aes_gcm_test_key = TestLib(fixed_inputs_infos, different_key_infos_16,
#                                     generate_aes_gcm, name="cryptography-AES-GCM-key", multi_init=True)

# cryptography_chacha20_test_inputs = TestLib(different_inputs_infos, fixed_key_infos_32,
#                                         generate_chacha20, name="cryptography-ChaCha20-inputs")
# cryptography_chacha20_test_key = TestLib(fixed_inputs_infos, different_key_infos_32,
#                                      generate_chacha20, name="cryptography-ChaCha20-key", multi_init=True)


