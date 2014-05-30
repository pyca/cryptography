# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import absolute_import, division, print_function

import pytest

from cryptography import utils
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.asymmetric import ec


@utils.register_interface(interfaces.EllipticCurve)
class DummyCurve(object):
    name = "dummy-curve"


class TestECC(object):
    def test_ec_numbers(self):
        numbers = ec.EllipticCurvePrivateNumbers(
            1,
            ec.EllipticCurvePublicNumbers(
                2, 3, DummyCurve()
            )
        )

        assert numbers.private_value == 1
        assert numbers.public_numbers.x == 2
        assert numbers.public_numbers.y == 3
        assert isinstance(numbers.public_numbers.curve, DummyCurve)

        with pytest.raises(TypeError):
            ec.EllipticCurvePrivateNumbers(
                None,
                ec.EllipticCurvePublicNumbers(
                    2, 3, DummyCurve()
                )
            )

        with pytest.raises(TypeError):
            ec.EllipticCurvePrivateNumbers(
                1,
                ec.EllipticCurvePublicNumbers(
                    None, 3, DummyCurve()
                )
            )

        with pytest.raises(TypeError):
            ec.EllipticCurvePrivateNumbers(
                1,
                ec.EllipticCurvePublicNumbers(
                    2, None, DummyCurve()
                )
            )

        with pytest.raises(TypeError):
            ec.EllipticCurvePrivateNumbers(
                1,
                ec.EllipticCurvePublicNumbers(
                    2, 3, None
                )
            )

        with pytest.raises(TypeError):
            ec.EllipticCurvePrivateNumbers(
                1,
                None
            )
