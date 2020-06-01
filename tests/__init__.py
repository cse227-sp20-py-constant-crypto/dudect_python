from . import test_pycrypto
from . import test_cryptography
from . import test_pycryptodomex

tests = []
# pycrypto
tests.append(test_pycrypto.pycrypto_aes_test_const)
tests.append(test_pycrypto.pycrypto_aes_test_random)
tests.append(test_pycrypto.pycrypto_aes_test_mixed)

tests.append(test_pycrypto.pycrypto_des3_test_const)
tests.append(test_pycrypto.pycrypto_des3_test_random)
tests.append(test_pycrypto.pycrypto_des3_test_mixed)

# cryptography
tests.append(test_cryptography.cryptography_aes_test_const)
tests.append(test_cryptography.cryptography_aes_test_random)
tests.append(test_cryptography.cryptography_aes_test_mixed)

tests.append(test_cryptography.cryptography_3des_test_const)
tests.append(test_cryptography.cryptography_3des_test_random)
tests.append(test_cryptography.cryptography_3des_test_mixed)

tests.append(test_cryptography.cryptography_chacha20_test_const)
tests.append(test_cryptography.cryptography_chacha20_test_random)
tests.append(test_cryptography.cryptography_chacha20_test_mixed)

# pycryptodomex
tests.append(test_pycryptodomex.pycryptodomex_aes_test_const)
tests.append(test_pycryptodomex.pycryptodomex_aes_test_random)
tests.append(test_pycryptodomex.pycryptodomex_aes_test_mixed)

tests.append(test_pycryptodomex.pycryptodomex_des3_test_const)
tests.append(test_pycryptodomex.pycryptodomex_des3_test_random)
tests.append(test_pycryptodomex.pycryptodomex_des3_test_mixed)
