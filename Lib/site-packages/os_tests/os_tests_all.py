import unittest
from os_tests.tests.test_cloud_init import TestCloudInit
from os_tests.tests.test_general_check import TestGeneralCheck
from os_tests.tests.test_general_test import TestGeneralTest

test_cloud_init_suite = unittest.TestLoader().loadTestsFromTestCase(TestCloudInit)
test_general_check_suite = unittest.TestLoader().loadTestsFromTestCase(TestGeneralCheck)
test_general_test_suite = unittest.TestLoader().loadTestsFromTestCase(TestGeneralTest)
all_tests = [test_general_check_suite, test_general_test_suite]
TS = unittest.TestSuite(tests=all_tests)

if __name__ == "__main__":
    unittest.TextTestRunner().run(TS)
