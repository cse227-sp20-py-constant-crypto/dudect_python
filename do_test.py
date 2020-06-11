if __name__ == "__main__":
    from testcases.tests import tests
    for test in tests:
        test.do_test()
    print("All tests finished.")
