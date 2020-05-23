from dudect import test_constant

from Crypto.Cipher import AES, DES3
from Crypto import Random
from Crypto.Cipher.blockalgo import BlockAlgo
from Crypto.PublicKey import ElGamal
from Crypto.Hash import SHA

import random
from random import randint

number_measurements = 100000


def prepare_inputs(_):
    inputs = []
    n = 64
    for i in range(number_measurements):
        class_id = random.randrange(4)
        if class_id == 0:
            inputs.append({"data": ''.join(["{}".format(randint(0, 9)) for num in range(0, n)]), "class": 0})
#            inputs.append({"data": ''.join(["{}".format(ord(str(randint(0, 9))), 'b') for num in range(0, n)]).encode('utf-8'), "class": 0})

#            inputs.append({"data": b'00000000000000000000000000000000', "class": 0})
        elif class_id == 1:
            inputs.append({"data": Random.new().read(n), "class": 1})
#        elif class_id == 2:
#            inputs.append({"data": b'0000000000000000', "class": 2})
#        else:
#            inputs.append({"data": Random.new().read(32), "class": 3})
#    print(inputs)
    return inputs


def init():
    #AES
#    key = b'Sixteen byte key'
#    iv = Random.new().read(AES.block_size)
#    cipher = AES.new(key, AES.MODE_CBC, iv)
    #DES
    key = b'Sixteen byte key'
    iv = Random.new().read(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    #ElGamal

#    key = ElGamal.generate(1024, Random.new().read)
#
#    while 1:
#        k = random.StrongRandom().randint(1, key.p - 1)
#
#        if GCD(k, key.p - 1) == 1:
#            break
#
#    h = key.encrypt(message, k)
#
#    d = key.decrypt(h)
#    cipher = None
    return cipher


def do_computation(cipher: BlockAlgo, in_msg: bytes):
    cipher.encrypt(in_msg)


if __name__ == "__main__":
    test_constant(init, prepare_inputs, do_computation)
