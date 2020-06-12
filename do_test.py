if __name__ == "__main__":
    from testcases.test_all import all_tests
    for test in all_tests:
        test.do_test()
    print("All tests finished.")
