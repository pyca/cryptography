from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.primitives.asymmetric import dh


def test_dh_parameters():
    params = dh.DHParameters(
        65537, 3
    )

    assert params.modulus == 65537
    assert params.generator == 3

    with pytest.raises(TypeError):
        dh.DHParameters(
            None, 3
        )

    with pytest.raises(TypeError):
        dh.DHParameters(
            65537, None
        )

    with pytest.raises(TypeError):
        dh.DHParameters(
            None, None
        )


def test_dh_numbers():
    params = dh.DHParameters(
        65537, 3
    )

    public = dh.DHPublicNumbers(
        params, 1
    )

    assert public.parameters is params
    assert public.public_value == 1

    with pytest.raises(TypeError):
        dh.DHPublicNumbers(
            None, 1
        )

    with pytest.raises(TypeError):
        dh.DHPublicNumbers(
            params, None
        )

    private = dh.DHPrivateNumbers(
        public, 1
    )

    assert private.public_numbers is public
    assert private.private_value == 1

    with pytest.raises(TypeError):
        dh.DHPrivateNumbers(
            None, 1
        )

    with pytest.raises(TypeError):
        dh.DHPrivateNumbers(
            public, None
        )
