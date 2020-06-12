from dudect import test_constant, Input
import sympy
import random
import os
from itertools import combinations
from Cryptodome.Cipher import AES

number_measurements = 100000
# tests = []


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


class KeyInfo:
    def __init__(self, mode, args):
        self.mode = mode
        self.args = args

    random = "random"
    constant = "constant"


class TestLib:
    def __init__(self, inputs_infos, key_infos, nounce_or_iv_infos,
                 generate_do_computation, generate_do_computation_args=(), generate_do_computation_kwargs={},
                 name="no name", multi_init=False, **kwargs):
        self.name = name
        self.inputs_infos = inputs_infos

        self.key_infos = key_infos
        self.nounce_or_iv_infos = nounce_or_iv_infos
        self.generate_do_computation = generate_do_computation
        self.generate_do_computation_args = generate_do_computation_args
        self.generate_do_computation_kwargs = generate_do_computation_kwargs
        self.multi_init = multi_init

    def do_test(self):
        print("Now testing", self.name, '\n')
        try:
            for info0, info1 in self.inputs_infos:
                for key0, key1 in self.key_infos:
                    for nounce_or_iv0, nounce_or_iv1 in self.nounce_or_iv_infos:
                        try:
                            for g in [info0, info1, key0, key1, nounce_or_iv0, nounce_or_iv1]:
                                g.reset()
                            print("class-0:", "inputs is %s," % info0.get_name(), "key is %s." % key0.get_name(),
                                  "nounce_or_iv is %s" % nounce_or_iv0.get_name())
                            print("class-1:", "inputs is %s," % info1.get_name(), "key is %s." % key1.get_name(),
                                  "nounce_or_iv is %s" % nounce_or_iv1.get_name())
                            _inputs_info_pair = (info0, info1)
                            _prepare_inputs = generate_prepare_inputs(_inputs_info_pair)
                            _key_info_pair = (key0, key1)
                            _nounce_or_iv_pairs = (nounce_or_iv0, nounce_or_iv1)
                            _init = generate_init(_key_info_pair, _nounce_or_iv_pairs, self.generate_do_computation,
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


def generate_init(key_info_pair, _nounce_or_iv_pairs,
                  generate_do_computation, generate_do_computation_args, generate_do_computation_kwargs):
    key0, key1 = key_info_pair
    nounce_or_iv0, nounce_or_iv1 = _nounce_or_iv_pairs

    def _init(class_id: int):
        if class_id == 1:
            key = key1.execute()
            nounce_or_iv = nounce_or_iv1.execute()
        else:
            key = key0.execute()
            nounce_or_iv = nounce_or_iv0.execute()

        do_computation = generate_do_computation(key, nounce_or_iv, *generate_do_computation_args, **generate_do_computation_kwargs)

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


def generate_random_rsa_key_info():
    return KeyInfo(mode=KeyInfo.random, args=None)


def generate_constant_rsa_key_info():
    return KeyInfo(mode=KeyInfo.constant, args=None)


def generate_random_dsa_key_info(n):
    return KeyInfo(mode=KeyInfo.random, args=n)


def generate_constant_dsa_key_info():
    p_dsa = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239
    q_dsa = 864205495604807476120572616017955259175325408501
    g_dsa = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730
    x_dsa = 774290984479563168206130828532207106685994961942
    y_dsa = 114139536920622570869938062331723306749387755293373930319777713731297469469109142401130232217217777321368184441397443931576984650449330134427587575682738623671153548160095548080912063040969633652666498299669170854742832973750730854597032012872351800053401243970059348061331526243448471205166130497310892424132
    return KeyInfo(mode=KeyInfo.constant, args=(p_dsa, q_dsa, g_dsa, x_dsa, y_dsa))


def generate_random_ecdsa_key_info():
    return KeyInfo(mode=KeyInfo.random, args=None)


def generate_constant_ecdsa_key_info():
    ecdsa_prival = 27527805980884633574585232869131596258838654964678772054133772215664562466556135475295268497357775554885493077544888
    return KeyInfo(mode=KeyInfo.constant, args=ecdsa_prival)


# input message
inputs_constant_64 = ByteGenerator(func=generate_constant_byte, params=(64,), name="64-byte constant")
inputs_random_64 = ByteGenerator(func=generate_random_byte, params=(64,), name="64-byte random")
inputs_zero_64 = ByteGenerator(func=generate_zero_byte, params=(64,), name="64-byte zero")
inputs_one_64 = ByteGenerator(func=generate_one_byte, params=(64,), name="64-byte one")

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

key_info_random_rsa = ByteGenerator(func=generate_random_rsa_key_info, params=(), name="Random RSA key", spawn_init=True)
key_info_constant_rsa = ByteGenerator(func=generate_constant_rsa_key_info, params=(), name="Constant RSA key", spawn_init=True)

key_info_random_dsa = ByteGenerator(func=generate_random_dsa_key_info, params=(1024,), name="Random DSA key", spawn_init=True)
key_info_constant_dsa = ByteGenerator(func=generate_constant_dsa_key_info, params=(), name="Constant DSA key", spawn_init=True)

key_info_random_ecdsa = ByteGenerator(func=generate_random_ecdsa_key_info, params=(), name="Random ECDSA key", spawn_init=True)
key_info_constant_ecdsa = ByteGenerator(func=generate_constant_ecdsa_key_info, params=(), name="Constant ECDSA key", spawn_init=True)


# nounce
nounce_constant_8 = ByteGenerator(func=generate_constant_byte, params=(8,), name="8-byte constant nounce", spawn_init=True)
nounce_random_8 = ByteGenerator(func=generate_random_byte, params=(8,), name="8-byte random nounce", spawn_init=True)
nounce_zero_8 = ByteGenerator(func=generate_zero_byte, params=(8,), name="8-byte zero nounce", spawn_init=True)
nounce_one_8 = ByteGenerator(func=generate_one_byte, params=(8,), name="8-byte one nounce", spawn_init=True)
nounce_prime_8 = ByteGenerator(func=generate_prime_byte, params=(8,), name="8-byte prime nounce", spawn_init=True)

nounce_constant_12 = ByteGenerator(func=generate_constant_byte, params=(12,), name="12-byte constant nounce", spawn_init=True)
nounce_random_12 = ByteGenerator(func=generate_random_byte, params=(12,), name="12-byte random nounce", spawn_init=True)
nounce_zero_12 = ByteGenerator(func=generate_zero_byte, params=(12,), name="12-byte zero nounce", spawn_init=True)
nounce_one_12 = ByteGenerator(func=generate_one_byte, params=(12,), name="12-byte one nounce", spawn_init=True)
nounce_prime_12 = ByteGenerator(func=generate_prime_byte, params=(12,), name="12-byte prime nounce", spawn_init=True)


# iv
aes_key_len = AES.block_size
iv_constant_aes = ByteGenerator(func=generate_constant_byte, params=(aes_key_len,), name="AES constant iv", spawn_init=True)
iv_random_aes = ByteGenerator(func=generate_random_byte, params=(aes_key_len,), name="AES random iv", spawn_init=True)
iv_zero_aes = ByteGenerator(func=generate_zero_byte, params=(aes_key_len,), name="AES zero iv", spawn_init=True)
iv_one_aes = ByteGenerator(func=generate_one_byte, params=(aes_key_len,), name="AES one iv", spawn_init=True)
iv_prime_aes = ByteGenerator(func=generate_prime_byte, params=(aes_key_len,), name="AES prime iv", spawn_init=True)


# combinations
class BlockCypherCases:
    baseline_inputs_pairs = ((inputs_constant_256, inputs_constant_256), )
    baseline_key_pairs = ((key_constant_16, key_constant_16), )
    baseline_iv_pairs = ((iv_random_aes, iv_random_aes), )
    varying_key_pairs = ((key_constant_16, key_random_16), )
    special_key_pairs = ((key_constant_16, key_zero_16), (key_constant_16, key_one_16))
    varying_inputs_pairs = ((inputs_constant_256, inputs_random_256), )
    special_inputs_pairs = ((inputs_constant_256, inputs_zero_256), (inputs_constant_256, inputs_one_256))
    varying_iv_pairs = ((iv_constant_aes, iv_random_aes), )
    special_iv_pairs = ((iv_constant_aes, iv_zero_aes), (iv_constant_aes, iv_one_aes))

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, baseline_iv_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, baseline_iv_pairs],
        ["special_key", baseline_inputs_pairs, special_key_pairs, baseline_iv_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, baseline_iv_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, baseline_iv_pairs],
        ["varying_iv", baseline_inputs_pairs, baseline_key_pairs, varying_iv_pairs],
        ["special_iv", baseline_inputs_pairs, baseline_key_pairs, special_iv_pairs],
    ]


class StreamCypher8Cases:
    # nounce length is 8
    baseline_inputs_pairs = ((inputs_constant_256, inputs_constant_256), )
    baseline_key_pairs = ((key_constant_16, key_constant_16), )
    baseline_nounce_pairs = ((nounce_random_8, nounce_random_8), )
    varying_key_pairs = ((key_constant_16, key_random_16), )
    special_key_pairs = ((key_constant_16, key_zero_16), (key_constant_16, key_one_16))
    varying_inputs_pairs = ((inputs_constant_256, inputs_random_256), )
    special_inputs_pairs = ((inputs_constant_256, inputs_zero_256), (inputs_constant_256, inputs_one_256))
    varying_nounce_pairs = ((nounce_constant_8, nounce_random_8), )
    special_nounce_pairs = ((nounce_constant_8, nounce_zero_8), (nounce_constant_8, nounce_one_8))

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, baseline_nounce_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, baseline_nounce_pairs],
        ["special_key", baseline_inputs_pairs, special_key_pairs, baseline_nounce_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, baseline_nounce_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, baseline_nounce_pairs],
        ["varying_nounce", baseline_inputs_pairs, baseline_key_pairs, varying_nounce_pairs],
        ["special_nounce", baseline_inputs_pairs, baseline_key_pairs, special_nounce_pairs],
    ]


class StreamCypher12Cases:
    # nounce length is 12
    baseline_inputs_pairs = ((inputs_constant_256, inputs_constant_256), )
    baseline_key_pairs = ((key_constant_16, key_constant_16), )
    baseline_nounce_pairs = ((nounce_random_12, nounce_random_12), )
    varying_key_pairs = ((key_constant_16, key_random_16), )
    special_key_pairs = ((key_constant_16, key_zero_16), (key_constant_16, key_one_16))
    varying_inputs_pairs = ((inputs_constant_256, inputs_random_256), )
    special_inputs_pairs = ((inputs_constant_256, inputs_zero_256), (inputs_constant_256, inputs_one_256))
    varying_nounce_pairs = ((nounce_constant_12, nounce_random_12), )
    special_nounce_pairs = ((nounce_constant_12, nounce_zero_12), (nounce_constant_12, nounce_one_12))

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, baseline_nounce_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, baseline_nounce_pairs],
        ["special_key", baseline_inputs_pairs, special_key_pairs, baseline_nounce_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, baseline_nounce_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, baseline_nounce_pairs],
        ["varying_nounce", baseline_inputs_pairs, baseline_key_pairs, varying_nounce_pairs],
        ["special_nounce", baseline_inputs_pairs, baseline_key_pairs, special_nounce_pairs],
    ]


class AsymmetricCypherRSACases:
    baseline_inputs_pairs = ((inputs_constant_256, inputs_constant_256), )
    baseline_key_pairs = ((key_info_constant_rsa, key_info_constant_rsa), )
    varying_key_pairs = ((key_info_constant_rsa, key_info_random_rsa), )
    varying_inputs_pairs = ((inputs_constant_256, inputs_random_256), )
    special_inputs_pairs = ((inputs_constant_256, inputs_zero_256), (inputs_constant_256, inputs_one_256))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, none_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, none_pairs],
    ]


class AsymmetricCypherDSACases:
    baseline_inputs_pairs = ((inputs_constant_256, inputs_constant_256), )
    baseline_key_pairs = ((key_info_constant_dsa, key_info_constant_dsa), )
    varying_key_pairs = ((key_info_constant_dsa, key_info_random_dsa), )
    varying_inputs_pairs = ((inputs_constant_256, inputs_random_256), )
    special_inputs_pairs = ((inputs_constant_256, inputs_zero_256), (inputs_constant_256, inputs_one_256))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, none_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, none_pairs],
    ]


class AsymmetricCypherECDSACases:
    baseline_inputs_pairs = ((inputs_constant_256, inputs_constant_256), )
    baseline_key_pairs = ((key_info_constant_ecdsa, key_info_constant_ecdsa), )
    varying_key_pairs = ((key_info_constant_ecdsa, key_info_random_ecdsa), )
    varying_inputs_pairs = ((inputs_constant_256, inputs_random_256), )
    special_inputs_pairs = ((inputs_constant_256, inputs_zero_256), (inputs_constant_256, inputs_one_256))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", baseline_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_inputs", varying_inputs_pairs, baseline_key_pairs, none_pairs],
        ["special_inputs", special_inputs_pairs, baseline_key_pairs, none_pairs],
        ["varying_key", baseline_inputs_pairs, varying_key_pairs, none_pairs],
    ]


class HashCases:
    baseline_inputs_pairs = ((inputs_constant_256, inputs_constant_256), )
    varying_inputs_pairs = ((inputs_constant_256, inputs_random_256), )
    special_inputs_pairs = ((inputs_constant_256, inputs_zero_256), (inputs_constant_256, inputs_one_256))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", baseline_inputs_pairs, none_pairs, none_pairs],
        ["varying_inputs", varying_inputs_pairs, none_pairs, none_pairs],
        ["varying_key", special_inputs_pairs, none_pairs, none_pairs],
    ]


class MACCases:
    baseline_key_pairs = ((key_constant_32, key_constant_32), )
    varying_key_pairs = ((key_constant_32, key_random_32), )
    special_key_pairs = ((key_constant_32, key_zero_32), (key_constant_32, key_one_32))
    none_pairs = ((None, None), )

    cases = [
        ["baseline", none_pairs, baseline_key_pairs, none_pairs],
        ["varying_key", none_pairs, varying_key_pairs, none_pairs],
        ["baseline", none_pairs, baseline_key_pairs, none_pairs],
    ]

