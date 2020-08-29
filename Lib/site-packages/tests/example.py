import unittest

from ipynb_tests import tester


class Tests(tester.NotebookTester, unittest.TestCase):
    notebooks_path = 'tests/notebooks/'

    def check_no_raise(self, soup):
        output = self.assert_cell_stdout(soup, 1)

        assert output.find('pre').string.strip() == ':-('

    def check_with_raises(self, soup):
        output = self.assert_cell_stdout(soup, 4)

        assert output.find('pre').string.strip() == ':-)'
