from dudect import test_constant

import random
from random import randint
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

number_measurements = 100000


def prepare_inputs(_):
    inputs = []
    n = 16
    for i in range(number_measurements):
        class_id = random.randrange(2)
        if class_id == 0:
            #inputs.append({"data": ''.join(["{}".format(randint(0, 9)) for num in range(0, n)]).encode('utf-8'), "class": 0})
            inputs.append({"data": os.urandom(256), "class": 0})
            #inputs.append({"data": b'0000000000000000', "class": 0})
        elif class_id == 1:
            inputs.append({"data": os.urandom(n), "class": 1})
    return inputs


def init():
    backend = default_backend()
    #AES
    #key = os.urandom(32)
    #iv = os.urandom(16)
    #cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    
    #3DES
    #key = os.urandom(16)
    #iv = os.urandom(8)
    #cipher = Cipher(algorithms.TripleDES(key), modes.OFB(iv), backend=backend)
    
    #ChaCha20
    key = os.urandom(32)
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
    return cipher


def do_computation(cipher, in_msg: bytes):
    encryptor = cipher.encryptor()
    ct = encryptor.update(in_msg)
    
if __name__ == "__main__":
    test_constant(init, prepare_inputs, do_computation)