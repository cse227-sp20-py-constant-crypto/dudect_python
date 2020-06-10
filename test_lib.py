from dudect import test_constant, Input

import random
import os
import struct
from itertools import combinations
from sympy import randprime, nextprime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization

p_dsa = 178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239
q_dsa = 864205495604807476120572616017955259175325408501
g_dsa = 174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730
x_dsa = 774290984479563168206130828532207106685994961942
y_dsa = 114139536920622570869938062331723306749387755293373930319777713731297469469109142401130232217217777321368184441397443931576984650449330134427587575682738623671153548160095548080912063040969633652666498299669170854742832973750730854597032012872351800053401243970059348061331526243448471205166130497310892424132


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

def num_to_byte(num):
    num_hex=hex(num).replace("0x","")
    if len(num_hex)%2!=0:
        num_hex='0'+num_hex
    ascii_repr="".join(["\\x"+num_hex[i:i+2] for i in range(0,len(num_hex),2)])
    return eval("b'"+ascii_repr+"'")

def generate_prime_message(n):
    prime=nextprime(n*8-1,1)
    return num_to_byte(prime)

def generate_random_prime_message(n):
    prime=randprime(2**(8*n-1),2**(8*n))
    return num_to_byte(prime)

def generate_random_message(n):
    return os.urandom(n)


def generate_constant_key(n):
    return ((n//16 + 1) * 'Sixteen byte key')[:n].encode()


def generate_random_key(n):
    return os.urandom(n)

def generate_random_rsakey(n):
    return rsa.generate_private_key(public_exponent=65537, key_size=n, backend=default_backend())

def generate_constant_rsakey():
    private_key = rsaKey_preload
    return private_key

def generate_random_dsakey(n):
    return dsa.generate_private_key(key_size=n, backend=default_backend())

def generate_constant_dsakey(p, q, g, x, y):
    ParaNum = dsa.DSAParameterNumbers(p,q,g)
    PubNum=dsa.DSAPublicNumbers(y,ParaNum)
    PriNum=dsa.DSAPrivateNumbers(x,PubNum)
    private_key=PriNum.private_key(default_backend())
    return private_key

def generate_random_ecdsakey():
    return ec.generate_private_key(ec.SECP384R1(), backend=default_backend())

def generate_constant_ecdsakey(prival):
    return ec.derive_private_key(prival,ec.SECP384R1(), backend=default_backend())

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
inputs_prime_16 = {"name": "16-byte prime", "func": generate_prime_message, "params": (16,)}
inputs_random_16 = {"name": "16-byte random", "func": generate_random_message, "params": (16,)}
inputs_random_prime_16 = {"name": "16-byte random prime", "func": generate_random_prime_message, "params": (16,)}

inputs_zero_64 = {"name": "64-byte zero", "func": generate_zero_message, "params": (64,)}
inputs_one_64 = {"name": "64-byte one", "func": generate_one_message, "params": (64,)}
inputs_prime_64 = {"name": "64-byte prime", "func": generate_prime_message, "params": (64,)}
inputs_random_64 = {"name": "64-byte random", "func": generate_random_message, "params": (64,)}
inputs_random_prime_64 = {"name": "64-byte random prime", "func": generate_random_prime_message, "params": (64,)}

inputs_zero_256 = {"name": "256-byte zero", "func": generate_zero_message, "params": (256,)}
inputs_one_256 = {"name": "256-byte one", "func": generate_one_message, "params": (256,)}
inputs_random_256 = {"name": "256-byte random", "func": generate_random_message, "params": (256,)}

constant_key_16 = {"func": generate_constant_key, "params": (16,), "name": "16-byte constant key"}
random_key_16 = {"func": generate_random_key, "params": (16,), "name": "16-byte random key"}

constant_key_32 = {"func": generate_constant_key, "params": (32,), "name": "32-byte constant key"}
random_key_32 = {"func": generate_random_key, "params": (32,), "name": "32-byte random key"}

constant_key_64 = {"func": generate_constant_key, "params": (64,), "name": "64-byte constant key"}
random_key_64 = {"func": generate_random_key, "params": (64,), "name": "64-byte random key"}

constant_key_rsa = {"func": generate_constant_rsakey, "params": (), "name": "Constant RSA key"}
random_key_rsa = {"func": generate_random_rsakey, "params": (2048,), "name": "Random RSA key"}

constant_key_dsa = {"func": generate_constant_dsakey, "params": (p_dsa,q_dsa,g_dsa,x_dsa,y_dsa,), "name": "Constant DSA key"}
random_key_dsa = {"func": generate_random_dsakey, "params": (1024,), "name": "Random DSA key"}

ecdsa_prival=27527805980884633574585232869131596258838654964678772054133772215664562466556135475295268497357775554885493077544888
constant_key_ecdsa = {"func": generate_constant_ecdsakey, "params": (ecdsa_prival, ), "name": "Constant ECDSA key"}
random_key_ecdsa = {"func": generate_random_ecdsakey, "params": (), "name": "Random ECDSA key"}

different_inputs_infos = (
    (inputs_zero_16, inputs_one_16),
    (inputs_zero_16, inputs_random_16),
    (inputs_one_16, inputs_random_16),
    (inputs_zero_16, inputs_prime_16),
    (inputs_one_16, inputs_prime_16),
    (inputs_prime_16, inputs_random_16),
    (inputs_zero_64, inputs_one_64),
    (inputs_zero_64, inputs_random_64),
    (inputs_one_64, inputs_random_64),
    (inputs_zero_64, inputs_prime_64),
    (inputs_one_64, inputs_prime_64),
    (inputs_prime_64, inputs_random_64),
)

fixed_inputs_infos = ((inputs_zero_16, inputs_zero_16), (inputs_one_16, inputs_one_16), (inputs_prime_16, inputs_prime_16))

different_key_infos_16 = ((constant_key_16, random_key_16),)
fixed_key_infos_16 = ((constant_key_16, constant_key_16), (random_key_16, random_key_16))

different_key_infos_32 = ((constant_key_32, random_key_32),)
fixed_key_infos_32 = ((constant_key_32, constant_key_32), (random_key_32, random_key_32))

different_key_infos_64 = ((constant_key_64, random_key_64),)
fixed_key_infos_64 = ((constant_key_64, constant_key_64), (random_key_64, random_key_64))

different_key_infos_rsa = ((constant_key_rsa, random_key_rsa),)
fixed_key_infos_rsa = ((constant_key_rsa, constant_key_rsa), (random_key_rsa, random_key_rsa))

different_key_infos_dsa = ((constant_key_dsa, random_key_dsa),)
fixed_key_infos_dsa = ((constant_key_dsa, constant_key_dsa), (random_key_dsa, random_key_dsa))

different_key_infos_ecdsa = ((random_key_ecdsa, random_key_ecdsa),)
fixed_key_infos_ecdsa = ((constant_key_ecdsa, constant_key_ecdsa), (random_key_ecdsa, random_key_ecdsa))