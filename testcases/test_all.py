from testcases.commons import TestLib
from testcases.commons import BlockCypherIv8Cases, BlockCypherIv16Cases, BlockCypherNonce8Cases, \
    StreamCypher8Cases, StreamCypher12Cases, StreamCypher16Cases, \
    AsymmetricCypherRSACases, AsymmetricCypherDSACases, AsymmetricCypherECDSACases, \
    HashCases, MACCases

from testcases.tests import test_cryptography, test_pycrypto, test_pycryptodomex


class TestCase:
    def __init__(self, test_functions, case_info):
        self.test_cases = []
        for func_name, func in test_functions:
            for count, _case in enumerate(case_info.cases):
                case_name, inputs_pairs, key_pairs, iv_pairs = _case
                test_name = "%s-%s. Testcase number is %s" % (func_name, case_name, count)
                self.test_cases.append(TestLib(inputs_pairs, key_pairs, iv_pairs, func, name=test_name, multi_init=True))

    def do_test(self):
        for test_case in self.test_cases:
            test_case.do_test()


aes_test_functions = [
    ["Cryptography-AES-CBC", test_cryptography.generate_aes_cbc],
    ["PyCrypto-AES-CBC", test_pycrypto.generate_aes_cbc],
    ["PyCryptodome-AES-CBC", test_pycryptodomex.generate_aes_cbc],

    ["Cryptography-AES-CFB", test_cryptography.generate_aes_cfb],
    ["PyCrypto-AES-CFB", test_pycrypto.generate_aes_cfb],
    ["PyCryptodome-AES-CFB", test_pycryptodomex.generate_aes_cfb],

    ["Cryptography-AES-OFB", test_cryptography.generate_aes_ofb],
    ["PyCrypto-AES-OFB", test_pycrypto.generate_aes_ofb],
    ["PyCryptodome-AES-OFB", test_pycryptodomex.generate_aes_ofb],
]
aes_tests = TestCase(aes_test_functions, BlockCypherIv16Cases)

aes_nonce_test_functions = [
    ["Cryptography-AES-CTR", test_cryptography.generate_aes_ctr],
    # ["PyCrypto-AES-CTR", test_pycrypto.generate_aes_ctr],
    ["PyCryptodome-AES-CTR", test_pycryptodomex.generate_aes_ctr],

    # ["Cryptography-AES-CCM", test_cryptography.generate_aes_ccm],
    # ["PyCrypto-AES-CCM", test_pycrypto.generate_aes_ccm],
    ["PyCryptodome-AES-CCM", test_pycryptodomex.generate_aes_ccm],

    # ["Cryptography-AES-EAX", test_cryptography.generate_aes_eax],
    # ["PyCrypto-AES-EAX", test_pycrypto.generate_aes_eax],
    ["PyCryptodome-AES-EAX", test_pycryptodomex.generate_aes_eax],

    ["Cryptography-AES-GCM", test_cryptography.generate_aes_gcm],
    # ["PyCrypto-AES-GCM", test_pycrypto.generate_aes_gcm],
    ["PyCryptodome-AES-GCM", test_pycryptodomex.generate_aes_gcm],

    # ["Cryptography-AES-SIV", test_cryptography.generate_aes_siv],
    # ["PyCrypto-AES-SIV", test_pycrypto.generate_aes_siv],
    ["PyCryptodome-AES-SIV", test_pycryptodomex.generate_aes_siv],

    # ["Cryptography-AES-OCB", test_cryptography.generate_aes_ocb],
    # ["PyCrypto-AES-OCB", test_pycrypto.generate_aes_ocb],
    ["PyCryptodome-AES-OCB", test_pycryptodomex.generate_aes_ocb],

]
aes_nonce_tests = TestCase(aes_nonce_test_functions, BlockCypherNonce8Cases)

chacha20_test_functions = [
    # ["PyCrypto-ChaCha20", test_pycrypto.generate_chacha20],
    ["PyCryptodome-ChaCha20", test_pycryptodomex.generate_chacha20],
]
chacha20_tests = TestCase(chacha20_test_functions, StreamCypher8Cases)

chacha20_16_test_functions = [
    ["Cryptography-ChaCha20", test_cryptography.generate_chacha20],
]
chacha20_16_tests = TestCase(chacha20_16_test_functions, StreamCypher16Cases)

tls_chacha20_test_functions = [
    # ["Cryptography-TLSChaCha20", test_cryptography.generate_tls_chacha20],
    # ["PyCrypto-TLSChaCha20", test_pycrypto.generate_tls_chacha20],
    ["PyCryptodome-TLSChaCha20", test_pycryptodomex.generate_tls_chacha20],
]
tls_chacha20_tests = TestCase(tls_chacha20_test_functions, StreamCypher12Cases)

salsa20_test_functions = [
    # ["Cryptography-Salsa20", test_cryptography.generate_salsa20],
    # ["PyCrypto-Salsa20", test_pycrypto.generate_salsa20],
    ["PyCryptodome-Salsa20", test_pycryptodomex.generate_salsa20],
]
salsa20_tests = TestCase(salsa20_test_functions, StreamCypher8Cases)

rsa_test_functions = [
    ["Cryptography-RSA", test_cryptography.generate_rsa],
    ["PyCrypto-RSA", test_pycrypto.generate_rsa],
    ["PyCryptodome-RSA", test_pycryptodomex.generate_rsa],
]
rsa_tests = TestCase(rsa_test_functions, AsymmetricCypherRSACases)

dsa_test_functions = [
    ["Cryptography-DSA", test_cryptography.generate_dsa],
    # ["PyCrypto-DSA", test_pycrypto.generate_dsa],
    ["PyCryptodome-DSA", test_pycryptodomex.generate_dsa],
]
dsa_tests = TestCase(dsa_test_functions, AsymmetricCypherDSACases)

ecdsa_test_functions = [
    ["Cryptography-ECDSA", test_cryptography.generate_ecdsa],
    # ["PyCrypto-ECDSA", test_pycrypto.generate_ecdsa],
    ["PyCryptodome-ECDSA", test_pycryptodomex.generate_ecdsa],
]
ecdsa_tests = TestCase(ecdsa_test_functions, AsymmetricCypherECDSACases)

hash_test_functions = [
    ["Cryptography-SHA256", test_cryptography.generate_sha256],
    ["PyCrypto-SHA256", test_pycrypto.generate_sha256],
    ["PyCryptodome-SHA256", test_pycryptodomex.generate_sha256],

    ["Cryptography-SHA3-256", test_cryptography.generate_sha3_256],
    # ["PyCrypto-SHA3-256", test_pycrypto.generate_sha3_256],
    ["PyCryptodome-SHA3-256", test_pycryptodomex.generate_sha3_256],
]
hash_tests = TestCase(hash_test_functions, HashCases)

mac_test_functions = [
    ["Cryptography-HMAC", test_cryptography.generate_hmac],
    ["PyCrypto-HMAC", test_pycrypto.generate_hmac],
    ["PyCryptodome-HMAC", test_pycryptodomex.generate_hmac],

    ["Cryptography-POLY1305", test_cryptography.generate_poly1305],
    # ["PyCrypto-POLY1305", test_pycrypto.generate_poly1305],
    ["PyCryptodome-POLY1305", test_pycryptodomex.generate_poly1305],
]
mac_tests = TestCase(mac_test_functions, MACCases)

all_tests = [
    aes_tests,
    aes_nonce_tests,
    chacha20_tests,
    chacha20_16_tests,
    tls_chacha20_tests,
    salsa20_tests,
    hash_tests,
    mac_tests,
    rsa_tests,
    dsa_tests,
    ecdsa_tests,
]

