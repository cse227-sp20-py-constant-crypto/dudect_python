from . import test_pycrypto
from . import test_cryptography
from . import test_pycryptodomex

tests = []
# pycrypto
tests.append(test_pycrypto.pycrypto_aes_test_inputs)
tests.append(test_pycrypto.pycrypto_aes_test_key)

tests.append(test_pycrypto.pycrypto_des3_test_inputs)
tests.append(test_pycrypto.pycrypto_des3_test_key)

# cryptography
tests.append(test_cryptography.cryptography_aes_test_inputs)
tests.append(test_cryptography.cryptography_aes_test_key)

tests.append(test_cryptography.cryptography_des3_test_inputs)
tests.append(test_cryptography.cryptography_des3_test_key)

tests.append(test_cryptography.cryptography_chacha20_test_inputs)
tests.append(test_cryptography.cryptography_chacha20_test_key)

tests.append(test_cryptography.cryptography_rsa_test_inputs)
tests.append(test_cryptography.cryptography_rsa_test_key)


# pycryptodomex
tests.append(test_pycryptodomex.pycryptodomex_aes_test_inputs)
tests.append(test_pycryptodomex.pycryptodomex_aes_test_key)

tests.append(test_pycryptodomex.pycryptodomex_des3_test_inputs)
tests.append(test_pycryptodomex.pycryptodomex_des3_test_key)
