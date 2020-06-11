from dudect import test_constant, Input
import sympy
import random
import os
from itertools import combinations

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

number_measurements = 100000
# tests = []
with open("testcases/private.pem", "rb") as key_file:
     rsaKey_preload = serialization.load_pem_private_key(
         key_file.read(),
         password=None,
         backend=default_backend())


def generate_zero_byte(n):
    return b'\x00' * n


def generate_one_byte(n):
    return b'\xff' * n


def generate_random_byte(n):
    return os.urandom(n)


def generate_constant_byte(n):
    return ((n//16 + 1) * 'Sixteen byte key')[:n].encode()


def int_to_byte(num):
    num_hex = hex(num).replace("0x", "")
    if len(num_hex) % 2 != 0:
        num_hex = '0' + num_hex
    ascii_repr = "".join(["\\x" + num_hex[i:i + 2] for i in range(0, len(num_hex), 2)])
    return eval("b'" + ascii_repr + "'")


def generate_prime_byte(n):
    prime_number = sympy.randprime(2**(8*n-1), 2**(8*n))
    return int_to_byte(prime_number)


def generate_given_byte(b):
    return b


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
                inputs.append(Input(data=info0.execute(), cla=0))
            else:
                inputs.append(Input(data=info1.execute(), cla=1))
        return inputs

    return _prepare_inputs


def generate_init(key_info_pair, generate_do_computation, generate_do_computation_args, generate_do_computation_kwargs):
    key0, key1 = key_info_pair

    def _init(class_id: int):
        if class_id == 1:
            key = key1.execute()
        else:
            key = key0.execute()

        do_computation = generate_do_computation(key, *generate_do_computation_args, **generate_do_computation_kwargs)

        return do_computation

    return _init


class ByteGenerator:
    def __init__(self, func, params=(), name="", spawn_init=False):
        self.func = func
        self.params = params
        self.name = name
        self.spawn_init = spawn_init
        self.counter = 0
        self.max_counter = 50
        self.result = self.func(*self.params)

    def get_name(self):
        return self.name

    def get_result(self):
        return self.result

    def execute(self):
        if self.spawn_init:
            self.counter += 1
            if self.counter > self.max_counter:
                self.reset()
            return self.result
        else:
            return self.func(*self.params)

    def reset(self):
        self.counter = 0
        self.result = self.func(*self.params)


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
                        for g in [info0, info1, key0, key1]:
                            g.reset()
                        print("class0:", "inputs is %s," % info0.get_name(), "key is %s." % key0.get_name(),
                              "key value is %s" % key0.get_result())
                        print("class1:", "inputs is %s," % info1.get_name(), "key is %s." % key1.get_name(),
                              "key value is %s" % key1.get_result())
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


inputs_zero_16 = ByteGenerator(func=generate_zero_byte, params=(16,), name="16-byte zero")
inputs_one_16 = ByteGenerator(func=generate_one_byte, params=(16,), name="16-byte one")
inputs_random_16 = ByteGenerator(func=generate_random_byte, params=(16,), name="16-byte random")
inputs_constant_16 = ByteGenerator(func=generate_constant_byte, params=(16,), name="16-byte constant")

inputs_zero_64 = ByteGenerator(func=generate_zero_byte, params=(64,), name="64-byte zero")
inputs_one_64 = ByteGenerator(func=generate_one_byte, params=(64,), name="64-byte one")
inputs_random_64 = ByteGenerator(func=generate_random_byte, params=(64,), name="64-byte random")
inputs_constant_64 = ByteGenerator(func=generate_constant_byte, params=(64,), name="64-byte constant")

inputs_zero_256 = ByteGenerator(func=generate_zero_byte, params=(256,), name="256-byte zero")
inputs_one_256 = ByteGenerator(func=generate_one_byte, params=(256,), name="256-byte one") 
inputs_random_256 = ByteGenerator(func=generate_random_byte, params=(256,), name="256-byte random")
inputs_constant_256 = ByteGenerator(func=generate_constant_byte, params=(256,), name="256-byte constant")

constant_key_16 = ByteGenerator(func=generate_constant_byte, params=(16,), name="16-byte constant key", spawn_init=True)
random_key_16 = ByteGenerator(func=generate_random_byte, params=(16,), name="16-byte random key", spawn_init=True)

constant_key_32 = ByteGenerator(func=generate_constant_byte, params=(32,), name="32-byte constant key", spawn_init=True)
random_key_32 = ByteGenerator(func=generate_random_byte, params=(32,), name="32-byte random key", spawn_init=True)

constant_key_64 = ByteGenerator(func=generate_constant_byte, params=(64,), name="64-byte constant key", spawn_init=True)
random_key_64 = ByteGenerator(func=generate_random_byte, params=(64,), name="64-byte random key", spawn_init=True)

random_key_rsa = ByteGenerator(func=generate_random_rsakey, params=(), name="Random RSA key", spawn_init=True)

constant_key_rsa = ByteGenerator(func=generate_constant_rsakey, params=(), name="Constant RSA key", spawn_init=True)

prime_key_16 = ByteGenerator(func=generate_prime_byte, params=(16,), name="16-byte prime key", spawn_init=True)
prime_key_32 = ByteGenerator(func=generate_prime_byte, params=(32,), name="32-byte prime key", spawn_init=True)
prime_key_64 = ByteGenerator(func=generate_prime_byte, params=(64,), name="64-byte prime key", spawn_init=True)
prime_key_128 = ByteGenerator(func=generate_prime_byte, params=(128,), name="128-byte prime key", spawn_init=True)


different_inputs_infos = (
    (inputs_zero_16, inputs_one_16),
    (inputs_zero_16, inputs_random_16),
    (inputs_one_16, inputs_random_16),
    (inputs_zero_64, inputs_one_64),
    (inputs_zero_64, inputs_random_64),
    (inputs_one_64, inputs_random_64),
)

fixed_inputs_infos_16 = ((inputs_zero_16, inputs_zero_16), 
                         (inputs_one_16, inputs_one_16),
                         (inputs_constant_16, inputs_constant_16))
fixed_inputs_infos = fixed_inputs_infos_16

fixed_inputs_infos_64 = ((inputs_zero_64, inputs_zero_64), 
                         (inputs_one_64, inputs_one_64),
                         (inputs_constant_64, inputs_constant_64))

different_key_infos_16 = ((constant_key_16, random_key_16),
                          (constant_key_16, random_key_16),
                          (constant_key_16, random_key_16),
                          (constant_key_16, prime_key_16),
                          (constant_key_16, prime_key_16),
                          (constant_key_16, prime_key_16))

fixed_key_infos_16 = ((constant_key_16, constant_key_16), 
                      (random_key_16, random_key_16),
                      (random_key_16, random_key_16),
                      (random_key_16, random_key_16),
                      (prime_key_16, prime_key_16),
                      (prime_key_16, prime_key_16),
                      (prime_key_16, prime_key_16))

fixed_key_infos_32 = ((constant_key_32, constant_key_32), 
                      (random_key_32, random_key_32),
                      (random_key_32, random_key_32),
                      (random_key_32, random_key_32),
                      (prime_key_32, prime_key_32),
                      (prime_key_32, prime_key_32),
                      (prime_key_32, prime_key_32))

fixed_key_infos_64 = ((constant_key_64, constant_key_64), 
                      (random_key_64, random_key_64),
                      (random_key_64, random_key_64),
                      (random_key_64, random_key_64),
                      (prime_key_64, prime_key_64),
                      (prime_key_64, prime_key_64),
                      (prime_key_64, prime_key_64))

different_key_infos_32 = ((constant_key_32, random_key_32),
                          (constant_key_32, random_key_32),
                          (constant_key_32, random_key_32),
                          (constant_key_32, prime_key_32),
                          (constant_key_32, prime_key_32),
                          (constant_key_32, prime_key_32))

different_key_infos_64 = ((constant_key_64, random_key_64),
                          (constant_key_64, random_key_64),
                          (constant_key_64, random_key_64),
                          (constant_key_64, prime_key_64),
                          (constant_key_64, prime_key_64),
                          (constant_key_64, prime_key_64))

different_key_infos_rsa = ((constant_key_rsa, random_key_rsa),
                           (constant_key_rsa, random_key_rsa),
                           (constant_key_rsa, random_key_rsa))

fixed_key_infos_rsa = ((constant_key_rsa, constant_key_rsa),
                       (random_key_rsa, random_key_rsa),
                       (random_key_rsa, random_key_rsa),
                       (random_key_rsa, random_key_rsa))

