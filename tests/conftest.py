def pytest_generate_tests(metafunc):
    from cryptography.hazmat.bindings import _ALL_BACKENDS

    if "backend" in metafunc.fixturenames:
        metafunc.parametrize("backend", _ALL_BACKENDS)
