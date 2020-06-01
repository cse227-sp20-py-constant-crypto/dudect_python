# from dataclasses import dataclass
from typing import List, Callable, NoReturn
import time
import numpy

number_percentiles = 100  # Number of percentiles we will have to deal with long tail
enough_measurements = 10000  # Threshold for enough large measurements
number_tests = 1 + number_percentiles + 1  # Number of t-tests we will do on the test results

t_threshold_bananas = 500  # test failed, with overwhelming probability
t_threshold_moderate = 10  # test failed. Pankaj likes 4.5 but let's be more lenient


class __TestData:
    mean: List[float] = [0.0, 0.0]
    m2: List[float] = [0.0, 0.0]
    n: List[int] = [0, 0]

    def __init__(self, mean: List[float], m2: List[float], n: List[int]):
        self.mean = mean
        self.m2 = m2
        self.n = n

    def push(self, new_data: float, classes: int):
        assert classes == 0 or classes == 1
        self.n[classes] += 1
        delta = new_data - self.mean[classes]
        self.mean[classes] = self.mean[classes] + delta / self.n[classes]
        self.m2[classes] = self.m2[classes] + delta * (new_data - self.mean[classes])

    def compute(self) -> float:
        var = [0.0, 0.0]
        var[0] = self.m2[0] / (self.n[0] - 1)
        var[1] = self.m2[1] / (self.n[1] - 1)
        num = self.mean[0] - self.mean[1]
        den = (var[0] / self.n[0] + var[1] / self.n[1]) ** 0.5
        t_value = num / den
        return t_value


class Input:
    """
    The class representation of a single input.

    Args:
        data: the bytes data to be fed into computation.
        cla: the categorization of this data as 0 or 1.

    Attributes:
        Data: the bytes data to be fed into computation.
        Class: the categorization of this data as 0 or 1.
    """
    Data: bytes
    Class: int

    def __init__(self, data: bytes, cla: int):
        self.Data = data
        self.Class = cla


def test_constant(init: Callable[[int], Callable[[bytes], NoReturn]],
                  prepare_inputs: Callable[[], List[Input]], init_repeatedly: bool) -> NoReturn:
    """
    Test whether a computation is constant-time statistically against two provided classes of inputs.
    TODO: Make it the only public function to external in this package.
    Args:
        init: A function, which initializes the state for computations, returns a closure func to do one computation.
        prepare_inputs: A function returns a List of Input.
        init_repeatedly: decide whether the init function should be executed once for every single measurement or once
            for all measurements.

    Returns:
        No return. Print the test conclusion to stdout.
    """
    inputs = prepare_inputs()
    measurements: List[float] = __do_measurement(init, inputs, init_repeatedly)

    t = __update_statics(measurements, inputs)

    __report(t)


def __do_measurement(init: Callable[[int], Callable[[bytes], NoReturn]], inputs: List[Input],
                     init_repeatedly: bool = False) \
        -> List[float]:
    number_measurements = len(inputs)
    measurements: List[float] = []
    if not init_repeatedly:
        do_one_computation = init(0)
        for i in range(number_measurements):
            start = time.perf_counter()
            do_one_computation(inputs[i].Data)
            end = time.perf_counter()
            measurements.append(end - start)
        return measurements
    for i in range(number_measurements):
        do_one_computation = init(inputs[i].Class)
        start = time.perf_counter()
        do_one_computation(inputs[i].Data)
        end = time.perf_counter()
        measurements.append(end - start)
    return measurements


def __prepare_percentiles(data: List[float]) -> List[float]:
    a = [numpy.percentile(data, 100 * (1 - 0.5 ** (10 * (i + 1) / number_percentiles))) for i in
         range(number_percentiles)]
    return a


def __update_statics(measurements: List[float], inputs: List[Input]) -> List[__TestData]:
    percentiles = __prepare_percentiles(measurements)
    t: List[__TestData] = [__TestData([0.0, 0.0], [0.0, 0.0], [0, 0]) for _ in range(number_tests)]

    for i in range(len(measurements)):
        data = measurements[i]
        class_id = inputs[i].Class

        assert data > 0
        t[0].push(data, class_id)

        for j in range(len(percentiles)):
            if data < percentiles[j]:
                # print(class_id)
                t[j + 1].push(data, class_id)

        if t[0].n[0] > 10000:
            centered = data - t[0].mean[class_id]
            t[number_tests - 1].push(centered ** 2, class_id)

    return t


def __report(t: List[__TestData]) -> None:
    mt = __max_test(t)
    max_t = abs(t[mt].compute())
    max_t_n = t[mt].n[0] + t[mt].n[1]
    max_tau = max_t / max_t_n ** 0.5
    print(f'total measurements: {max_t_n / 1e6:7.2f} Million')
    print(f"max t-value: {max_t:7.2f}, max tau: {max_tau:.2e}, (5/tau)^2: {(5 * 5) / (max_tau * max_tau):.2e}.")
    if max_t > t_threshold_bananas:
        print("Definitely not constant time.")
        return
    if max_t > t_threshold_moderate:
        print("Probably not constant time.")
        return
    print("For the moment, maybe constant time.")


def __max_test(t: List[__TestData]) -> int:
    test_id = 0
    maximum = 0
    for i in range(number_tests):
        if t[i].n[0] > enough_measurements and t[i].n[1] > enough_measurements:  # ?
            temp = abs(t[i].compute())
            if temp > maximum:
                maximum = temp
                test_id = i
    return test_id
