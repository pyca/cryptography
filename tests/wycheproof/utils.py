from ..utils import load_wycheproof_tests


def wycheproof_tests(*paths):
    def wrapper(func):
        def run_wycheproof(backend, subtests, pytestconfig):
            wycheproof_root = pytestconfig.getoption(
                "--wycheproof-root", skip=True
            )
            for path in paths:
                for test in load_wycheproof_tests(wycheproof_root, path):
                    with subtests.test():
                        func(backend, test)

        return run_wycheproof

    return wrapper
