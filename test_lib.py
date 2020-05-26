from dudect import test_constant

import random
import os
from itertools import combinations


number_measurements = 100000
# tests = []


def generate_zero_message(n):
    return b'0' * n


def generate_integer_message(n):
    return ''.join(["{}".format(random.randint(0, 9)) for _ in range(0, n)]).encode()


def generate_random_message(n):
    return os.urandom(n)


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
            inputs.append({"data": eval(input_types[class_id])(input_lens[class_id]), "class": class_id})
        return inputs
    return prepare_inputs


inputs_zero_16 = {"name": "16-bit zero", "func": "generate_zero_message", "len": 16}
inputs_int_16 = {"name": "16-bit int", "func": "generate_integer_message", "len": 16}
inputs_random_16 = {"name": "16-bit random", "func": "generate_random_message", "len": 16}

inputs_zero_64 = {"name": "16-bit zero", "func": "generate_zero_message", "len": 64}
inputs_int_64 = {"name": "16-bit int", "func": "generate_integer_message", "len": 64}
inputs_random_64 = {"name": "16-bit random", "func": "generate_random_message", "len": 64}

inputs_zero_256 = {"name": "256-bit zero", "func": "generate_zero_message", "len": 256}
inputs_int_256 = {"name": "256-bit int", "func": "generate_integer_message", "len": 256}
inputs_random_256 = {"name": "256-bit random", "func": "generate_random_message", "len": 256}

default_inputs_info_pairs = (
    (inputs_zero_16, inputs_int_16),
    (inputs_zero_16, inputs_random_16),
    (inputs_zero_16, inputs_random_16),
    (inputs_zero_16, inputs_zero_256),
    (inputs_int_16, inputs_int_256),
    (inputs_random_16, inputs_random_256)
)


class TestLib:
    def __init__(self, init, do_computation, name="no name", inputs_infos=(), inputs_info_pairs=()):
        self.name = name
        self.inputs_infos = inputs_infos
        if not (inputs_infos and inputs_info_pairs):
            self.inputs_info_pairs = default_inputs_info_pairs
        else:
            self.inputs_info_pairs = combinations(inputs_infos, 2) + inputs_info_pairs
        # self.name = " vs ".join([info["name"] for info in self.inputs_infos])
        self.init = init
        self.do_computation = do_computation

    def do_test(self):
        print("\nNow testing", self.name)
        for info0, info1 in self.inputs_info_pairs:
            print()
            print(info0["name"], "vs", info1["name"])
            _prepare_inputs = generate_prepare_inputs([info0, info1])
            test_constant(self.init, _prepare_inputs, self.do_computation)
