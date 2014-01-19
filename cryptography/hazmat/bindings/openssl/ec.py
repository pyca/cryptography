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

from cryptography.hazmat.bindings.utils import OptionalDeclarations

INCLUDES = """
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
"""

optional = OptionalDeclarations("#ifdef OPENSSL_NO_EC", "HAS_EC")

TYPES = """
{optional.guard_type} {optional.guard_name};
typedef ... EC_KEY;
""".format(optional=optional)

optional.value("static const int", "NID_X9_62_prime192v1")
optional.value("static const int", "NID_X9_62_prime192v2")
optional.value("static const int", "NID_X9_62_prime192v3")
optional.value("static const int", "NID_X9_62_prime239v1")
optional.value("static const int", "NID_X9_62_prime239v2")
optional.value("static const int", "NID_X9_62_prime239v3")
optional.value("static const int", "NID_X9_62_prime256v1")

FUNCTIONS = ""

optional.function("EC_KEY *", "EC_KEY_new", "void")
optional.function("int", "EC_KEY_get_flags", "const EC_KEY *")
optional.function("void", "EC_KEY_set_flags", "EC_KEY *, int")
optional.function("void", "EC_KEY_clear_flags", "EC_KEY *, int")
optional.function("EC_KEY *", "EC_KEY_new_by_curve_name", "int")
optional.function("void", "EC_KEY_free", "EC_KEY *")
optional.function("EC_KEY *", "EC_KEY_copy", "EC_KEY *, const EC_KEY *")
optional.function("EC_KEY *", "EC_KEY_dup", "const EC_KEY *")
optional.function("int", "EC_KEY_up_ref", "EC_KEY *")
optional.function("const", "EC_GROUP *EC_KEY_get0_group", "const EC_KEY *")
optional.function("int", "EC_KEY_set_group", "EC_KEY *, const EC_GROUP *")
optional.function("const BIGNUM *", "EC_KEY_get0_private_key",
                  "const EC_KEY *")
optional.function("int", "EC_KEY_set_private_key", "EC_KEY *, const BIGNUM *")
optional.function("const", "EC_POINT *EC_KEY_get0_public_key",
                  "const EC_KEY *")
optional.function("int", "EC_KEY_set_public_key", "EC_KEY *, const EC_POINT *")
optional.function("unsigned int", "EC_KEY_get_enc_flags", "const EC_KEY *")
optional.function("void", "EC_KEY_set_enc_flags",
                  "EC_KEY *, unsigned int")
optional.function("point_conversion_form_t", "EC_KEY_get_conv_form",
                  "const EC_KEY *")
optional.function("void", "EC_KEY_set_conv_form",
                  "EC_KEY *, point_conversion_form_t")
optional.function(
    "void *", "EC_KEY_get_key_method_data",
    "EC_KEY *, void *(*)(void *), void (*)(void *), void (*)(void *)"
)
optional.function(
    "void *", "EC_KEY_insert_key_method_data",
    "EC_KEY *, void *, void *(*)(void *), void (*)(void *), void (*)(void *)"
)
optional.function("void", "EC_KEY_set_asn1_flag", "EC_KEY *, int")
optional.function("int", "EC_KEY_precompute_mult", "EC_KEY *, BN_CTX *")
optional.function("int", "EC_KEY_generate_key", "EC_KEY *")
optional.function("int", "EC_KEY_check_key", "const EC_KEY *")
optional.function("int", "EC_KEY_set_public_key_affine_coordinates",
                  "EC_KEY *, BIGNUM *, BIGNUM *")
optional.function("EC_KEY *", "EVP_PKEY_get1_EC_KEY", "EVP_PKEY *")
optional.function("int", "EVP_PKEY_set1_EC_KEY", "EVP_PKEY *, EC_KEY *")
optional.function("int", "EVP_PKEY_assign_EC_KEY", "EVP_PKEY *, EC_KEY *")

MACROS = ""

CUSTOMIZATIONS = optional.customisation_source()

CONDITIONAL_NAMES = {
    optional.guard_name: optional.name_list()
}
