def pytest_generate_tests(metafunc):
    from cryptography.bindings import _ALL_APIS

    if "api" in metafunc.fixturenames:
        metafunc.parametrize("api", _ALL_APIS)
