# from dataclasses import dataclass
from typing import List, Callable, Dict, Any, Union, NoReturn
import time
import numpy

number_percentiles = 10000  # Number of t-tests we will do on the test results
enough_measurements = 10000  # Threshold for enough large measurements
number_tests = 1 + number_percentiles + 1

t_threshold_bananas = 500  # test failed, with overwhelming probability
t_threshold_moderate = 10  # test failed. Pankaj likes 4.5 but let's be more lenient


class TestData:
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

    def compute(self):
        var = [0.0, 0.0]
        var[0] = self.m2[0] / (self.n[0] - 1)
        var[1] = self.m2[1] / (self.n[1] - 1)
        num = self.mean[0] - self.mean[1]
        den = (var[0] / self.n[0] + var[1] / self.n[1]) ** 0.5
        t_value = num / den
        return t_value


def test_constant(init: Callable, prepare_inputs: Callable[[Any], List[Dict[str, Union[bytes, int]]]],
                  do_one_computation: Callable[[Any, List[Dict[str, Union[bytes, int]]]], Any]) -> NoReturn:
    """
    Test whether a computation is constant-time statistically against two provided classes of inputs.
    TODO: Make it the only public function to external in this package.
    Args:
        init: A function, which initializes the state for measurement
        prepare_inputs: A function, which must take the return of `init` function as argument (you may ignore it in the
            function body) and return a List of Dict{"data": bytes, "class_id": int}.
            TODO: Make the inputs data representation better?
        do_one_computation: A function, which takes as the first argument the return of `init` function and as the
            second argument the return of `prepare_inputs` function, and then do the to be measured computation

    Returns:
        No return. Print the test conclusion to stdout.
    """
    init_result = init()

    inputs = prepare_inputs(init_result)
    number_measurements = len(inputs)
    measurements: List[float] = do_measurement(init_result, inputs, number_measurements, do_one_computation)

    percentiles = prepare_percentiles(measurements)
    t = update_statics(measurements, inputs, percentiles)
    report(t)


def do_measurement(init: Any, inputs: List[Dict], number_measurements: int, do_one_computation: Callable)\
        -> List[float]:
    measurements: List[float] = []
    for i in range(number_measurements):
        start = time.perf_counter()
        do_one_computation(init, inputs[i]['data'])
        end = time.perf_counter()
        measurements.append(end - start)
    return measurements


def prepare_percentiles(data: List[float]) -> List[float]:
    return [numpy.percentile(data, 1 - 0.5 ** (10 * (i + 1) / number_percentiles)) for i in range(number_percentiles)]


def update_statics(measurements: List[float], inputs: List[Dict], percentiles: List[float]) -> List[TestData]:
    t: List[TestData] = [TestData([0.0, 0.0], [0.0, 0.0], [0, 0]) for _ in range(number_tests)]
    for i in range(len(measurements)):
        data = measurements[i]
        class_id = inputs[i]['class']

        assert data > 0
        t[0].push(data, class_id)

        for j in range(len(percentiles)):
            if data < percentiles[j]:
                t[j + 1].push(data, class_id)

        if t[0].n[0] > 10000:
            centered = data - t[0].mean[class_id]
            t[number_tests - 1].push(centered ** 2, class_id)

    return t


def report(t: List[TestData]) -> None:
    mt = max_test(t)
    max_t = abs(t[mt].compute())
    max_t_n = t[mt].n[0] + t[mt].n[1]
    max_tau = max_t / max_t_n ** 0.5
    print(f'total measurements: {max_t_n / 1e6:7.2f} Millon')
    print(f"max t-value: {max_t:7.2f}, max tau: {max_tau:.2e}, (5/tau)^2: {(5 * 5) / (max_tau * max_tau):.2e}.")
    if max_t > t_threshold_bananas:
        print("Definitely not constant time.")
        return
    if max_t > t_threshold_moderate:
        print("Probably not constant time.")
        return
    if max_t <= t_threshold_moderate:
        print("For the moment, maybe constant time.")
    return


def max_test(t: List[TestData]) -> int:
    test_id = 0
    maximum = 0
    for i in range(number_tests):
        if t[i].n[0] + t[i].n[1] > enough_measurements:  # ?
            temp = abs(t[i].compute())
            if temp > maximum:
                maximum = temp
                test_id = i
    return test_id
