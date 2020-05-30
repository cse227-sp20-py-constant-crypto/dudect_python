from . import test_pycrypto
from . import test_cryptography
from . import test_pycryptodomex

tests = []
# pycrypto
tests.append(test_pycrypto.pycrypto_aes_test)
tests.append(test_pycrypto.pycrypto_des3_test)

# cryptography
tests.append(test_cryptography.cryptography_aes_test)
tests.append(test_cryptography.cryptography_3des_test)
tests.append(test_cryptography.cryptography_chacha20_test)

# pycryptodomex
tests.append(test_pycryptodomex.pycryptodomex_aes_test)
tests.append(test_pycryptodomex.pycryptodomex_des3_test)