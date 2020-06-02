# dudect_python
## Requirement

- Python3 (< 3.7 is recommended to support pycrypto which is used in `sample_test.py`)
- NumPy

## Get Started
Install dependencies:

```pip install -r requirements.txt```

Run sample test:

```python sample_test.py```

## API
Look at the docstring of `test_constant` function in `dudect.py`


## TODO
Package implementation side:
- [x] Proofread the functionality
- [ ] Wrap this to a package
- [x] Make `test_constant` function the only public function in this package
- [ ] Use our own percentile implementation to remove dependencies on numpy (probably unnecessary)

Research side:
- [ ] Test more crypto primitives from more python packages with this package and see if there's non-constant implementations
