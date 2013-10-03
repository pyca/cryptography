def pytest_generate_tests(metafunc):
    from cryptography.bindings.openssl import api

    if "api" in metafunc.fixturenames:
        metafunc.parametrize("api", [api])
