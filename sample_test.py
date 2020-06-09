from dudect import test_constant, Input

from Crypto.Cipher import AES
from Crypto import Random
# from Crypto.Cipher.blockalgo import BlockAlgo

import random


number_measurements = 100000


def prepare_inputs():
    inputs = []
    for i in range(number_measurements):
        class_id = random.randrange(2)
        if class_id == 0:
            inputs.append(Input(data=b'0000000000000000', cla=0))
        else:
            inputs.append(Input(data=b'0000000000000000', cla=1))  # constant input msg
            # inputs.append(Input(data=Random.new().read(16), cla=0))  # random vs constant input msg
    return inputs


def init(class_id: int):
    if class_id == 1:
        key = Random.new().read(16)  # random key vs. constant key
    else:
        key = b'Sixteen byte key'
    # key = b'Sixteen byte key'  # fixed key

    # iv = Random.new().read(AES.block_size)
    iv = b'Sixteen byte iv.'  # a fixed iv
    cipher = AES.new(key, AES.MODE_CBC, iv)

    def do_computation(msg: bytes):
        cipher.encrypt(msg)

    return do_computation


if __name__ == "__main__":
    test_constant(init, prepare_inputs, True)
