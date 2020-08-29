import subprocess
import unittest

HEAD = """
============================= test session starts ==============================
platform linux -- Python [L1-4]
collecting ... collected 4 items

tests/example.py::Tests::test_no_check PASSED                            [ 25%]
tests/example.py::Tests::test_no_raise FAILED                            [ 50%]
tests/example.py::Tests::test_timeout PASSED                             [ 75%]
tests/example.py::Tests::test_with_raises FAILED                         [100%]

=================================== FAILURES ===================================
""".strip('\n')
CHECK_ERROR = """
E       AssertionError: assert ':-)' == ':-('
E         - :-)
E         + :-(
""".strip('\n')
NOTEBOOK_ERROR = """
E       AssertionError: Notebook tests/notebooks/with-raises-test.ipynb In[1], In[2], In[3] failed - check file:///home/coleopter/src/ipynb-tests/tests/notebooks/with-raises-test.html
""".strip('\n')  # noqa


class NotebookTesterTests(unittest.TestCase):
    def test_pytest_output(self):
        lines = subprocess.run(
            ['pytest', '-v', 'tests/example.py'], stdout=subprocess.PIPE
        ).stdout.decode().splitlines()
        short_lines = [lines[0], 'platform linux -- Python [L1-4]'] + lines[5:]
        head, tail = '\n'.join(short_lines[:10]), '\n'.join(short_lines[10:])

        assert head == HEAD
        assert CHECK_ERROR in tail
        assert NOTEBOOK_ERROR in tail
