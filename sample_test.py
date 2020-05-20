from dudect import test_constant

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher.blockalgo import BlockAlgo

from typing import Dict

import random
number_measurements = 100000


def prepare_inputs(_):
    inputs = []
    for i in range(number_measurements):
        class_id = random.randrange(2)
        if class_id == 0:
            inputs.append({"data": b'0000000000000000', "class": 0})
        else:
            inputs.append({"data": Random.new().read(16), "class": 1})
    return inputs


def init():
    key = b'Sixteen byte key'
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher


def do_computation(cipher: BlockAlgo, in_msg: bytes):
    cipher.encrypt(in_msg)


if __name__ == "__main__":
    test_constant(prepare_inputs, init, do_computation)
