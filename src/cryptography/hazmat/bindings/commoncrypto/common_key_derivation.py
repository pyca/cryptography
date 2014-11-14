# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <CommonCrypto/CommonKeyDerivation.h>
"""

TYPES = """
enum {
    kCCPBKDF2 = 2,
};
typedef uint32_t CCPBKDFAlgorithm;
enum {
    kCCPRFHmacAlgSHA1 = 1,
    kCCPRFHmacAlgSHA224 = 2,
    kCCPRFHmacAlgSHA256 = 3,
    kCCPRFHmacAlgSHA384 = 4,
    kCCPRFHmacAlgSHA512 = 5,
};
typedef uint32_t CCPseudoRandomAlgorithm;
typedef unsigned int uint;
"""

FUNCTIONS = """
int CCKeyDerivationPBKDF(CCPBKDFAlgorithm, const char *, size_t,
                         const uint8_t *, size_t, CCPseudoRandomAlgorithm,
                         uint, uint8_t *, size_t);
uint CCCalibratePBKDF(CCPBKDFAlgorithm, size_t, size_t,
                      CCPseudoRandomAlgorithm, size_t, uint32_t);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
