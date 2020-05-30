from dudect import test_constant

import random
import os
from itertools import combinations


number_measurements = 100000
# tests = []


def generate_zero_message(n):
    return b'\x00' * n


def generate_one_message(n):
    return b'\xff' * n


def generate_random_message(n):
    return os.urandom(n)


def generate_constant_key(n):
    return ((n//16 + 1) * 'Sixteen byte key')[:n].encode()


def generate_random_key(n):
    return os.urandom(n)


def generate_mixed_key(n):
    if random.randrange(2) == 0:
        return generate_constant_key(n)
    else:
        return generate_random_key(n)


def generate_prepare_inputs(inputs_infos):
    num_class_id = len(inputs_infos)
    input_types = {}
    input_lens = {}
    for i, val in enumerate(inputs_infos):
        input_types[i] = val["func"]
        input_lens[i] = val["len"]

    def prepare_inputs(_):
        inputs = []
        for _ in range(number_measurements):
            class_id = random.randrange(num_class_id)
            inputs.append({"data": input_types[class_id](input_lens[class_id]), "class": class_id})
        return inputs
    return prepare_inputs


inputs_zero_16 = {"name": "16-byte zero", "func": generate_zero_message, "len": 16}
inputs_one_16 = {"name": "16-byte one", "func": generate_one_message, "len": 16}
inputs_random_16 = {"name": "16-byte random", "func": generate_random_message, "len": 16}

inputs_zero_64 = {"name": "16-byte zero", "func": generate_zero_message, "len": 64}
inputs_one_64 = {"name": "16-byte one", "func": generate_one_message, "len": 64}
inputs_random_64 = {"name": "16-byte random", "func": generate_random_message, "len": 64}

inputs_zero_256 = {"name": "256-byte zero", "func": generate_zero_message, "len": 256}
inputs_one_256 = {"name": "256-byte one", "func": generate_one_message, "len": 256}
inputs_random_256 = {"name": "256-byte random", "func": generate_random_message, "len": 256}

constant_key = (generate_constant_key, (16,), "16-byte constant key")
random_key = (generate_random_key, (16,), "16-byte random key")
mixed_key = (generate_mixed_key, (16,), "16-byte mixed key")

default_inputs_info_pairs = (
    (inputs_zero_16, inputs_one_16),
    (inputs_zero_16, inputs_random_16),
    (inputs_one_16, inputs_random_16),
    (inputs_zero_64, inputs_one_64),
    (inputs_zero_64, inputs_random_64),
    (inputs_one_64, inputs_random_64),
)

fixed_inputs_info = ((inputs_one_16, inputs_one_16), )


class TestLib:
    def __init__(self, init, do_computation, name="no name",
                 inputs_infos=(), inputs_info_pairs=(), **kwargs):
        self.name = name
        self.inputs_infos = inputs_infos
        if not (inputs_infos or inputs_info_pairs):
            self.inputs_info_pairs = default_inputs_info_pairs
        else:
            self.inputs_info_pairs = tuple(combinations(inputs_infos, 2)) + tuple(inputs_info_pairs)

        def _init():
            return init(**kwargs)

        self.init = _init
        self.do_computation = do_computation

    def do_test(self):
        print("\nNow testing", self.name)
        try:
            for info0, info1 in self.inputs_info_pairs:
                try:
                    print(info0["name"], "vs", info1["name"])
                    _prepare_inputs = generate_prepare_inputs([info0, info1])
                    test_constant(self.init, _prepare_inputs, self.do_computation)
                    print()
                except Exception as e:
                    print("ERROR:", e)
                    print()
        except Exception as e:
            print("ERROR:", e)
            print()
        print("Done. ")
