from dudect import test_constant, Input
import sympy
import random
import os
import sys
from itertools import combinations
import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import serialization


number_measurements = 1000000
# tests = []


with open("testcases/pems/rsa_private.pem", "rb") as key_file:
    constant_rsa_pem = key_file.read()
with open("testcases/pems/dsa_private.pem", "rb") as key_file:
    constant_dsa_pem = key_file.read()
with open("testcases/pems/ecdsa_private.pem", "rb") as key_file:
    constant_ecdsa_pem = key_file.read()


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
    def __init__(self, inputs_infos, key_infos, nonce_or_iv_infos,
                 generate_do_computation, generate_do_computation_args=(), generate_do_computation_kwargs={},
                 name="no name", multi_init=False, **kwargs):
        self.name = name
        self.inputs_infos = inputs_infos

        self.key_infos = key_infos
        self.nonce_or_iv_infos = nonce_or_iv_infos
        self.generate_do_computation = generate_do_computation
        self.generate_do_computation_args = generate_do_computation_args
        self.generate_do_computation_kwargs = generate_do_computation_kwargs
        self.multi_init = multi_init

    def do_test(self):
        time_stamp = datetime.datetime.now()
        print("[%s] Now testing %s \n" % (time_stamp.strftime('%Y-%m-%d %H:%M:%S'), self.name), flush=True)
        sys.stdout.flush()
        try:
            for info0, info1 in self.inputs_infos:
                for key0, key1 in self.key_infos:
                    for nonce_or_iv0, nonce_or_iv1 in self.nonce_or_iv_infos:
                        try:
                            for g in [info0, info1, key0, key1, nonce_or_iv0, nonce_or_iv1]:
                                if g is not None:
                                    g.reset()
                            print("class-0:", end=" ")
                            if info0 is not None:
                                print("inputs is %s," % info0.get_name(), end=" ")
                            if key0 is not None:
                                print("key is %s." % key0.get_name(), end=" ")
                            if nonce_or_iv0 is not None:
                                print("nonce_or_iv is %s" % nonce_or_iv0.get_name(), end=" ")
                            print()

                            print("class-1:", end=" ")
                            if info1 is not None:
                                print("inputs is %s," % info1.get_name(), end=" ")
                            if key1 is not None:
                                print("key is %s." % key1.get_name(), end=" ")
                            if nonce_or_iv1 is not None:
                                print("nonce_or_iv is %s" % nonce_or_iv1.get_name(), end=" ")
                            print()

                            _inputs_info_pair = (info0, info1)
                            _prepare_inputs = generate_prepare_inputs(_inputs_info_pair)
                            _key_info_pair = (key0, key1)
                            _nonce_or_iv_pairs = (nonce_or_iv0, nonce_or_iv1)
                            _init = generate_init(_key_info_pair, _nonce_or_iv_pairs, self.generate_do_computation,
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
        # print(self.name, "Done.", "\n")


def generate_prepare_inputs(inputs_info_pair):
    info0, info1 = inputs_info_pair

    def _prepare_inputs():
        inputs = []
        for i in range(number_measurements):
            class_id = random.randrange(2)
            if class_id == 0:
                if info0 is not None:
                    _inputs_data = info0.execute()
                else:
                    _inputs_data = []
            else:
                if info1 is not None:
                    _inputs_data = info1.execute()
                else:
                    _inputs_data = []
            inputs.append(Input(data=_inputs_data, cla=class_id))
        return inputs

    return _prepare_inputs


def generate_init(key_info_pair, _nonce_or_iv_pairs,
                  generate_do_computation, generate_do_computation_args, generate_do_computation_kwargs):
    key0, key1 = key_info_pair
    nonce_or_iv0, nonce_or_iv1 = _nonce_or_iv_pairs

    def _init(class_id: int):
        if class_id == 0:
            if key0 is not None:
                key = key0.execute()
            else:
                key = None
            if nonce_or_iv0 is not None:
                nonce_or_iv = nonce_or_iv0.execute()
            else:
                nonce_or_iv = None
        else:
            if key1 is not None:
                key = key1.execute()
            else:
                key = None
            if nonce_or_iv1 is not None:
               nonce_or_iv = nonce_or_iv1.execute()
            else:
                nonce_or_iv = None

        do_computation = generate_do_computation(key, nonce_or_iv, *generate_do_computation_args, **generate_do_computation_kwargs)

        return do_computation

    return _init


def int_to_byte(num):
    num_hex = hex(num).replace("0x", "")
    if len(num_hex) % 2 != 0:
        num_hex = '0' + num_hex
    ascii_repr = "".join(["\\x" + num_hex[i:i + 2] for i in range(0, len(num_hex), 2)])
    return eval("b'" + ascii_repr + "'")


def generate_zero_byte(n):
    return b'\x00' * n


def generate_one_byte(n):
    return b'\xff' * n


def generate_random_byte(n):
    return os.urandom(n)


def generate_constant_byte(n):
    return ((n//16 + 1) * 'Sixteen byte key')[:n].encode()


def generate_prime_byte(n):
    prime_number = sympy.randprime(2**(8*n-1), 2**(8*n))
    return int_to_byte(prime_number)


def generate_given_byte(b):
    return b


def generate_random_rsa_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem


def generate_constant_rsa_key():
    return constant_rsa_pem


def generate_random_dsa_key():
    n = 1024
    private_key = dsa.generate_private_key(key_size=n, backend=default_backend())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem


def generate_constant_dsa_key():
    return constant_dsa_pem


def generate_random_ecdsa_key():
    private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem


def generate_constant_ecdsa_key():
    return constant_ecdsa_pem


# input message
inputs_constant_64 = ByteGenerator(func=generate_constant_byte, params=(64,), name="64-byte constant")
inputs_random_64 = ByteGenerator(func=generate_random_byte, params=(64,), name="64-byte random")
inputs_zero_64 = ByteGenerator(func=generate_zero_byte, params=(64,), name="64-byte zero")
inputs_one_64 = ByteGenerator(func=generate_one_byte, params=(64,), name="64-byte one")

inputs_constant_128 = ByteGenerator(func=generate_constant_byte, params=(128,), name="128-byte constant")
inputs_random_128 = ByteGenerator(func=generate_random_byte, params=(128,), name="128-byte random")
inputs_zero_128 = ByteGenerator(func=generate_zero_byte, params=(128,), name="128-byte zero")
inputs_one_128 = ByteGenerator(func=generate_one_byte, params=(128,), name="128-byte one")

inputs_constant_256 = ByteGenerator(func=generate_constant_byte, params=(256,), name="256-byte constant")
inputs_random_256 = ByteGenerator(func=generate_random_byte, params=(256,), name="256-byte random")
inputs_zero_256 = ByteGenerator(func=generate_zero_byte, params=(256,), name="256-byte zero")
inputs_one_256 = ByteGenerator(func=generate_one_byte, params=(256,), name="256-byte one")


# key
key_constant_16 = ByteGenerator(func=generate_constant_byte, params=(16,), name="16-byte constant key", spawn_init=True)
key_random_16 = ByteGenerator(func=generate_random_byte, params=(16,), name="16-byte random key", spawn_init=True)
key_zero_16 = ByteGenerator(func=generate_zero_byte, params=(16,), name="16-byte zero key", spawn_init=True)
key_one_16 = ByteGenerator(func=generate_one_byte, params=(16,), name="16-byte one key", spawn_init=True)
key_prime_16 = ByteGenerator(func=generate_prime_byte, params=(16,), name="16-byte prime key", spawn_init=True)

key_constant_32 = ByteGenerator(func=generate_constant_byte, params=(32,), name="32-byte constant key", spawn_init=True)
key_random_32 = ByteGenerator(func=generate_random_byte, params=(32,), name="32-byte random key", spawn_init=True)
key_zero_32 = ByteGenerator(func=generate_zero_byte, params=(32,), name="32-byte zero key", spawn_init=True)
key_one_32 = ByteGenerator(func=generate_one_byte, params=(32,), name="32-byte one key", spawn_init=True)
key_prime_32 = ByteGenerator(func=generate_prime_byte, params=(32,), name="32-byte prime key", spawn_init=True)

key_constant_64 = ByteGenerator(func=generate_constant_byte, params=(64,), name="64-byte constant key", spawn_init=True)
key_random_64 = ByteGenerator(func=generate_random_byte, params=(64,), name="64-byte random key", spawn_init=True)
key_zero_64 = ByteGenerator(func=generate_zero_byte, params=(64,), name="64-byte zero key", spawn_init=True)
key_one_64 = ByteGenerator(func=generate_one_byte, params=(64,), name="64-byte one key", spawn_init=True)
key_prime_64 = ByteGenerator(func=generate_prime_byte, params=(64,), name="64-byte prime key", spawn_init=True)

key_random_rsa = ByteGenerator(func=generate_random_rsa_key, params=(), name="Random RSA key", spawn_init=True)
key_constant_rsa = ByteGenerator(func=generate_constant_rsa_key, params=(), name="Constant RSA key", spawn_init=True)

key_random_dsa = ByteGenerator(func=generate_random_dsa_key, params=(), name="Random DSA key", spawn_init=True)
key_constant_dsa = ByteGenerator(func=generate_constant_dsa_key, params=(), name="Constant DSA key", spawn_init=True)

key_random_ecdsa = ByteGenerator(func=generate_random_ecdsa_key, params=(), name="Random ECDSA key", spawn_init=True)
key_constant_ecdsa = ByteGenerator(func=generate_constant_ecdsa_key, params=(), name="Constant ECDSA key", spawn_init=True)


# nonce
nonce_constant_8 = ByteGenerator(func=generate_constant_byte, params=(8,), name="8-byte constant nonce", spawn_init=True)
nonce_random_8 = ByteGenerator(func=generate_random_byte, params=(8,), name="8-byte random nonce", spawn_init=True)
nonce_zero_8 = ByteGenerator(func=generate_zero_byte, params=(8,), name="8-byte zero nonce", spawn_init=True)
nonce_one_8 = ByteGenerator(func=generate_one_byte, params=(8,), name="8-byte one nonce", spawn_init=True)
nonce_prime_8 = ByteGenerator(func=generate_prime_byte, params=(8,), name="8-byte prime nonce", spawn_init=True)

nonce_constant_12 = ByteGenerator(func=generate_constant_byte, params=(12,), name="12-byte constant nonce", spawn_init=True)
nonce_random_12 = ByteGenerator(func=generate_random_byte, params=(12,), name="12-byte random nonce", spawn_init=True)
nonce_zero_12 = ByteGenerator(func=generate_zero_byte, params=(12,), name="12-byte zero nonce", spawn_init=True)
nonce_one_12 = ByteGenerator(func=generate_one_byte, params=(12,), name="12-byte one nonce", spawn_init=True)
nonce_prime_12 = ByteGenerator(func=generate_prime_byte, params=(12,), name="12-byte prime nonce", spawn_init=True)

nonce_constant_16 = ByteGenerator(func=generate_constant_byte, params=(16,), name="16-byte constant nonce", spawn_init=True)
nonce_random_16 = ByteGenerator(func=generate_random_byte, params=(16,), name="16-byte random nonce", spawn_init=True)
nonce_zero_16 = ByteGenerator(func=generate_zero_byte, params=(16,), name="16-byte zero nonce", spawn_init=True)
nonce_one_16 = ByteGenerator(func=generate_one_byte, params=(16,), name="16-byte one nonce", spawn_init=True)
nonce_prime_16 = ByteGenerator(func=generate_prime_byte, params=(16,), name="16-byte prime nonce", spawn_init=True)


# iv
iv_constant_8 = ByteGenerator(func=generate_constant_byte, params=(8,), name="8-byte AES constant iv", spawn_init=True)
iv_random_8 = ByteGenerator(func=generate_random_byte, params=(8,), name="8-byte AES random iv", spawn_init=True)
iv_zero_8 = ByteGenerator(func=generate_zero_byte, params=(8,), name="8-byte AES zero iv", spawn_init=True)
iv_one_8 = ByteGenerator(func=generate_one_byte, params=(8,), name="8-byte AES one iv", spawn_init=True)
iv_prime_8 = ByteGenerator(func=generate_prime_byte, params=(8,), name="8-byte AES prime iv", spawn_init=True)

iv_constant_16 = ByteGenerator(func=generate_constant_byte, params=(16,), name="16-byte AES constant iv", spawn_init=True)
iv_random_16 = ByteGenerator(func=generate_random_byte, params=(16,), name="16-byte AES random iv", spawn_init=True)
iv_zero_16 = ByteGenerator(func=generate_zero_byte, params=(16,), name="16-byte AES zero iv", spawn_init=True)
iv_one_16 = ByteGenerator(func=generate_one_byte, params=(16,), name="16-byte AES one iv", spawn_init=True)
iv_prime_16 = ByteGenerator(func=generate_prime_byte, params=(16,), name="16-byte AES prime iv", spawn_init=True)


# combinations
class BlockCypherIv8Cases:
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_16, key_constant_16), )
    baseline_iv_pairs = ((iv_random_8, iv_random_8), )
    varying_key_pairs = ((key_constant_16, key_random_16), )
    special_key_pairs = ((key_constant_16, key_zero_16), (key_constant_16, key_one_16))
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    varying_iv_pairs = ((iv_constant_8, iv_random_8), )
    special_iv_pairs = ((iv_constant_8, iv_zero_8), (iv_constant_8, iv_one_8))

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, baseline_iv_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, baseline_iv_pairs],
        ["special_key", baseline_inputs_pairs, special_key_pairs, baseline_iv_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, baseline_iv_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, baseline_iv_pairs],
        ["varying_iv", baseline_inputs_pairs, baseline_key_pairs, varying_iv_pairs],
        ["special_iv", baseline_inputs_pairs, baseline_key_pairs, special_iv_pairs],
    ]


class BlockCypherIv16Cases:
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_16, key_constant_16), )
    baseline_iv_pairs = ((iv_random_16, iv_random_16), )
    varying_key_pairs = ((key_constant_16, key_random_16), )
    special_key_pairs = ((key_constant_16, key_zero_16), (key_constant_16, key_one_16))
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    varying_iv_pairs = ((iv_constant_16, iv_random_16), )
    special_iv_pairs = ((iv_constant_16, iv_zero_16), (iv_constant_16, iv_one_16))

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, baseline_iv_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, baseline_iv_pairs],
        ["special_key", baseline_inputs_pairs, special_key_pairs, baseline_iv_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, baseline_iv_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, baseline_iv_pairs],
        ["varying_iv", baseline_inputs_pairs, baseline_key_pairs, varying_iv_pairs],
        ["special_iv", baseline_inputs_pairs, baseline_key_pairs, special_iv_pairs],
    ]


class BlockCypherNonce8Cases:
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_16, key_constant_16), )
    baseline_nonce_pairs = ((nonce_random_8, nonce_random_8), )
    varying_key_pairs = ((key_constant_16, key_random_16), )
    special_key_pairs = ((key_constant_16, key_zero_16), (key_constant_16, key_one_16))
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    varying_nonce_pairs = ((nonce_constant_8, nonce_random_8), )
    special_nonce_pairs = ((nonce_constant_8, nonce_zero_8), (nonce_constant_8, nonce_one_8))

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, baseline_nonce_pairs],
        ["special_key", baseline_inputs_pairs, special_key_pairs, baseline_nonce_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["varying_nonce", baseline_inputs_pairs, baseline_key_pairs, varying_nonce_pairs],
        ["special_nonce", baseline_inputs_pairs, baseline_key_pairs, special_nonce_pairs],
    ]


class StreamCypher8Cases:
    # nonce length is 8
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_32, key_constant_32), )
    baseline_nonce_pairs = ((nonce_random_8, nonce_random_8), )
    varying_key_pairs = ((key_constant_32, key_random_32), )
    special_key_pairs = ((key_constant_32, key_zero_32), (key_constant_32, key_one_32))
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    varying_nonce_pairs = ((nonce_constant_8, nonce_random_8), )
    special_nonce_pairs = ((nonce_constant_8, nonce_zero_8), (nonce_constant_8, nonce_one_8))

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, baseline_nonce_pairs],
        ["special_key", baseline_inputs_pairs, special_key_pairs, baseline_nonce_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["varying_nonce", baseline_inputs_pairs, baseline_key_pairs, varying_nonce_pairs],
        ["special_nonce", baseline_inputs_pairs, baseline_key_pairs, special_nonce_pairs],
    ]


class StreamCypher12Cases:
    # nonce length is 12
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_32, key_constant_32), )
    baseline_nonce_pairs = ((nonce_random_12, nonce_random_12), )
    varying_key_pairs = ((key_constant_32, key_random_32), )
    special_key_pairs = ((key_constant_32, key_zero_32), (key_constant_32, key_one_32))
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    varying_nonce_pairs = ((nonce_constant_12, nonce_random_12), )
    special_nonce_pairs = ((nonce_constant_12, nonce_zero_12), (nonce_constant_12, nonce_one_12))

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, baseline_nonce_pairs],
        ["special_key", baseline_inputs_pairs, special_key_pairs, baseline_nonce_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["varying_nonce", baseline_inputs_pairs, baseline_key_pairs, varying_nonce_pairs],
        ["special_nonce", baseline_inputs_pairs, baseline_key_pairs, special_nonce_pairs],
    ]


class StreamCypher16Cases:
    # nonce length is 16
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_32, key_constant_32), )
    baseline_nonce_pairs = ((nonce_random_16, nonce_random_16), )
    varying_key_pairs = ((key_constant_32, key_random_32), )
    special_key_pairs = ((key_constant_32, key_zero_32), (key_constant_32, key_one_32))
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    varying_nonce_pairs = ((nonce_constant_16, nonce_random_16), )
    special_nonce_pairs = ((nonce_constant_16, nonce_zero_16), (nonce_constant_16, nonce_one_16))

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, baseline_nonce_pairs],
        ["special_key", baseline_inputs_pairs, special_key_pairs, baseline_nonce_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, baseline_nonce_pairs],
        ["varying_nonce", baseline_inputs_pairs, baseline_key_pairs, varying_nonce_pairs],
        ["special_nonce", baseline_inputs_pairs, baseline_key_pairs, special_nonce_pairs],
    ]


class AsymmetricCypherRSACases:
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_rsa, key_constant_rsa), )
    varying_key_pairs = ((key_constant_rsa, key_random_rsa), )
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, none_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, none_pairs],
    ]


class AsymmetricCypherDSACases:
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_dsa, key_constant_dsa), )
    varying_key_pairs = ((key_constant_dsa, key_random_dsa), )
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, none_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, none_pairs],
    ]


class AsymmetricCypherECDSACases:
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_ecdsa, key_constant_ecdsa), )
    varying_key_pairs = ((key_constant_ecdsa, key_random_ecdsa), )
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, none_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, none_pairs],
    ]


class HashCases:
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    varying_inputs_pairs = ((inputs_constant_128, inputs_random_128), )
    special_inputs_pairs = ((inputs_constant_128, inputs_zero_128), (inputs_constant_128, inputs_one_128))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", baseline_inputs_pairs, none_pairs, none_pairs],
        ["varying_inputs", varying_inputs_pairs, none_pairs, none_pairs],
        ["varying_key", special_inputs_pairs, none_pairs, none_pairs],
    ]


class MACCases:
    baseline_inputs_pairs = ((inputs_constant_128, inputs_constant_128), )
    baseline_key_pairs = ((key_constant_32, key_constant_32), )
    varying_key_pairs = ((key_constant_32, key_random_32), )
    special_key_pairs = ((key_constant_32, key_zero_32), (key_constant_32, key_one_32))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, none_pairs],
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, none_pairs],
    ]

