from . import test_pycrypto
from . import test_cryptography

tests = []
# pycrypto
tests.append(test_pycrypto.pycrypto_aes_test)
tests.append(test_pycrypto.pycrypto_des3_test)

# cryptography
tests.append(test_cryptography.cryptography_aes_test)
tests.append(test_cryptography.cryptography_3des_test)
tests.append(test_cryptography.cryptography_chacha20_test)
