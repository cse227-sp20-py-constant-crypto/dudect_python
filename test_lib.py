from dudect import test_constant, Input
# from prime import generate_prime_key
# from do_test import fixed_random_key_16, fixed_random_key_32, fixed_random_key_64
import random
import os
from itertools import combinations

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

number_measurements = 100000
# tests = []
with open("private.pem", "rb") as key_file:
     rsaKey_preload = serialization.load_pem_private_key(
         key_file.read(),
         password=None,
         backend=default_backend())

def generate_zero_message(n):
    return b'\x00' * n


def generate_one_message(n):
    return b'\xff' * n


def generate_random_message(n):
    return os.urandom(n)


def generate_constant_key(n):
    return ((n//16 + 1) * 'Sixteen byte key')[:n].encode()

# 16 bit prime number -> 32771
def constant_prime_16():
    prime_number = 32771
    prime_number_bin = bin(prime_number).replace("0b","") 
    return prime_number_bin.encode()

def constant_prime_128():
    prime_number = 178440484211328444450461878837823173949
    prime_number_bin = bin(prime_number).replace("0b","") 
    return prime_number_bin.encode()

def constant_prime_256():
    prime_number = 98281221082601051181321538102991394534080740199227571092198396171956183648031
    prime_number_bin = bin(prime_number).replace("0b","") 
    return prime_number_bin.encode()

def constant_prime_512():
    prime_number = 2509105856141885582438364528094555684360502801047540969742570475832028354279239274573243935081144164482840547888775886718668254409033843859987760763250719
    prime_number_bin = bin(prime_number).replace("0b","") 
    return prime_number_bin.encode()

def constant_prime_1024():
    prime_number = 135728548258520491542354562461623261878448003649315854865284863184695523724212541190996589105513026144236640164599242209391952412778633872973364173808873600762809425026877532205980747118959261990686040222994204569241008123472237111672981752393984163356544233101039185179298599007372728517629958678956586792581
    prime_number_bin = bin(prime_number).replace("0b","") 
    return prime_number_bin.encode()

def generate_random_key(n):
    return os.urandom(n)

def generate_random_rsakey():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
def generate_constant_rsakey():
    private_key = rsaKey_preload
    return private_key

def generate_prepare_inputs(inputs_info_pair):
    info0, info1 = inputs_info_pair
    def _prepare_inputs():
        inputs = []
        for i in range(number_measurements):
            class_id = random.randrange(2)
            if class_id == 0:
                inputs.append(Input(data=(info0['func'](*info0['params'])), cla=0))
            else:
                inputs.append(Input(data=(info1['func'](*info1['params'])), cla=1))  # constant input msg
                # inputs.append(Input(data=Random.new().read(16), cla=0))  # random vs constant input msg
        return inputs

    return _prepare_inputs


def generate_init(key_info_pair, generate_do_computation, generate_do_computation_args, generate_do_computation_kwargs):
    key0, key1 = key_info_pair

    def _init(class_id: int):
        if class_id == 1:
            key = key1['func'](*key1['params'])
        else:
            key = key0['func'](*key0['params'])

        do_computation = generate_do_computation(key, *generate_do_computation_args, **generate_do_computation_kwargs)

        return do_computation

    return _init


class TestLib:
    def __init__(self, inputs_infos, key_infos, 
                 generate_do_computation, generate_do_computation_args=(), generate_do_computation_kwargs={},
                 name="no name", multi_init=False, **kwargs):
        self.name = name
        self.inputs_infos = inputs_infos

        self.key_infos = key_infos
        self.generate_do_computation = generate_do_computation
        self.generate_do_computation_args = generate_do_computation_args
        self.generate_do_computation_kwargs = generate_do_computation_kwargs
        self.multi_init = multi_init

    def do_test(self):
        print("Now testing", self.name, '\n')
        try:
            for info0, info1 in self.inputs_infos:
                for key0, key1 in self.key_infos:
                    try:
                        print("class0:", "inputs is %s," % info0["name"], "key is %s." % key0["name"])
                        print("class1:", "inputs is %s," % info1["name"], "key is %s." % key1["name"])
                        _inputs_info_pair = (info0, info1)
                        _prepare_inputs = generate_prepare_inputs(_inputs_info_pair)
                        _key_info_pair = (key0, key1)
                        _init = generate_init(_key_info_pair, self.generate_do_computation, 
                                              self.generate_do_computation_args,
                                              self.generate_do_computation_kwargs)
                        test_constant(_init, _prepare_inputs, self.multi_init)
                        print()
                    except Exception as e:
                        print("ERROR:", e)
                        print()
        except Exception as e:
            print("ERROR:", e)
            print()
        print(self.name, "Done.", "\n")


inputs_zero_16 = {"name": "16-byte zero", "func": generate_zero_message, "params": (16,)}
inputs_one_16 = {"name": "16-byte one", "func": generate_one_message, "params": (16,)}
inputs_random_16 = {"name": "16-byte random", "func": generate_random_message, "params": (16,)}

inputs_zero_64 = {"name": "64-byte zero", "func": generate_zero_message, "params": (64,)}
inputs_one_64 = {"name": "64-byte one", "func": generate_one_message, "params": (64,)}
inputs_random_64 = {"name": "64-byte random", "func": generate_random_message, "params": (64,)}

inputs_zero_256 = {"name": "256-byte zero", "func": generate_zero_message, "params": (256,)}
inputs_one_256 = {"name": "256-byte one", "func": generate_one_message, "params": (256,)}
inputs_random_256 = {"name": "256-byte random", "func": generate_random_message, "params": (256,)}

constant_key_16 = {"func": generate_constant_key, "params": (16,), "name": "16-byte constant key"}
random_key_16 = {"func": generate_random_key, "params": (16,), "name": "16-byte random key"}

constant_key_32 = {"func": generate_constant_key, "params": (32,), "name": "32-byte constant key"}
random_key_32 = {"func": generate_random_key, "params": (32,), "name": "32-byte random key"}

constant_key_64 = {"func": generate_constant_key, "params": (64,), "name": "64-byte constant key"}
random_key_64 = {"func": generate_random_key, "params": (64,), "name": "64-byte random key"}

random_key_rsa = {"func": generate_random_rsakey, "params": (), "name": "Random RSA key"}

constant_key_rsa = {"func": generate_constant_rsakey, "params": (), "name": "Constant RSA key"}

inputs_prime_16 = {"func": constant_prime_128, "params": (), "name": "16-byte prime number message"}
inputs_prime_32 = {"func": constant_prime_256, "params": (), "name": "32-byte prime number message"}
inputs_prime_64 = {"func": constant_prime_512, "params": (), "name": "64-byte prime number message"}
inputs_prime_128 = {"func": constant_prime_1024, "params": (), "name": "128-byte prime number message"}


different_inputs_infos = (
    (inputs_zero_16, inputs_one_16),
    (inputs_zero_16, inputs_random_16),
    (inputs_one_16, inputs_random_16),
    (inputs_prime_16, inputs_zero_16),
    (inputs_prime_16, inputs_one_16),
    (inputs_prime_16, inputs_random_16),
    (inputs_zero_64, inputs_one_64),
    (inputs_zero_64, inputs_random_64),
    (inputs_one_64, inputs_random_64),
    (inputs_prime_64, inputs_zero_64),
    (inputs_prime_64, inputs_one_64),
    (inputs_prime_64, inputs_random_64),
)

# fixed_random_key_16 = random_key_16['func'](*random_key_16['params'])
# fixed_random_key_32 = random_key_32['func'](*random_key_32['params'])
# fixed_random_key_64 = random_key_64['func'](*random_key_64['params'])

fixed_inputs_infos = ((inputs_zero_16, inputs_zero_16), (inputs_one_16, inputs_one_16))

different_key_infos_16 = ((constant_key_16, random_key_16),)
fixed_key_infos_16 = ((constant_key_16, constant_key_16), (random_key_16, random_key_16))

different_key_infos_32 = ((constant_key_32, random_key_32),)
fixed_key_infos_32 = ((constant_key_32, constant_key_32), (random_key_32, random_key_32))

different_key_infos_64 = ((constant_key_64, random_key_64),)
fixed_key_infos_64 = ((constant_key_64, constant_key_64), (random_key_64, random_key_64))

different_key_infos_rsa = ((constant_key_rsa, random_key_rsa),)
fixed_key_infos_rsa = ((constant_key_rsa, constant_key_rsa), (random_key_rsa, random_key_rsa))



