from dudect import test_constant, Input
import sympy
import random
import os
from itertools import combinations

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
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
    return KeyInfo(mode=KeyInfo.random, args=None)


def generate_constant_rsakey():
    return KeyInfo(mode=KeyInfo.constant, args=None)


def generate_random_dsakey(n):
    return KeyInfo(mode=KeyInfo.random, args=n)


def generate_constant_dsakey():
    p_dsa = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239
    q_dsa = 864205495604807476120572616017955259175325408501
    g_dsa = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730
    x_dsa = 774290984479563168206130828532207106685994961942
    y_dsa = 114139536920622570869938062331723306749387755293373930319777713731297469469109142401130232217217777321368184441397443931576984650449330134427587575682738623671153548160095548080912063040969633652666498299669170854742832973750730854597032012872351800053401243970059348061331526243448471205166130497310892424132
    return KeyInfo(mode=KeyInfo.constant, args=(p_dsa, q_dsa, g_dsa, x_dsa, y_dsa)) # private_key


def generate_random_ecdsakey():
    return KeyInfo(mode=KeyInfo.random, args=None)


def generate_constant_ecdsakey():
    ecdsa_prival = 27527805980884633574585232869131596258838654964678772054133772215664562466556135475295268497357775554885493077544888
    return KeyInfo(mode=KeyInfo.constant, args=ecdsa_prival)


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


class KeyInfo:
    def __init__(self, mode, args):
        self.mode = mode
        self.args = args
    
    random = "random"
    constant = "constant"


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

random_key_dsa = ByteGenerator(func=generate_random_dsakey, params=(1024,), name="Random DSA key", spawn_init=True)
constant_key_dsa = ByteGenerator(func=generate_constant_dsakey, params=(), name="Constant DSA key", spawn_init=True)

random_key_ecdsa = ByteGenerator(func=generate_random_ecdsakey, params=(), name="Random ECDSA key", spawn_init=True)
constant_key_ecdsa = ByteGenerator(func=generate_constant_ecdsakey, params=(), name="Constant ECDSA key", spawn_init=True)

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
                          (random_key_16, prime_key_16))

fixed_key_infos_16 = ((constant_key_16, constant_key_16), 
                      (random_key_16, random_key_16),
                      (prime_key_16, prime_key_16))

fixed_key_infos_32 = ((constant_key_32, constant_key_32), 
                      (random_key_32, random_key_32),
                      (prime_key_32, prime_key_32))

fixed_key_infos_64 = ((constant_key_64, constant_key_64), 
                      (random_key_64, random_key_64),
                      (prime_key_64, prime_key_64))

different_key_infos_32 = ((constant_key_32, random_key_32),
                          (random_key_32, prime_key_32))

different_key_infos_64 = ((constant_key_64, random_key_64),
                          (random_key_64, prime_key_64))

different_key_infos_rsa = ((constant_key_rsa, random_key_rsa),)

fixed_key_infos_rsa = ((constant_key_rsa, constant_key_rsa),
                       (random_key_rsa, random_key_rsa))

different_key_infos_dsa = ((constant_key_dsa, random_key_dsa),)

fixed_key_infos_dsa = ((constant_key_dsa, constant_key_dsa),
                       (random_key_dsa, random_key_dsa))

different_key_infos_ecdsa = ((constant_key_ecdsa, random_key_ecdsa),)

fixed_key_infos_ecdsa = ((constant_key_ecdsa, constant_key_ecdsa),
                       (random_key_ecdsa, random_key_ecdsa))