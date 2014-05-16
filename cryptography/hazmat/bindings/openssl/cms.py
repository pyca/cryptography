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
#if !defined(OPENSSL_NO_CMS) && OPENSSL_VERSION_NUMBER >= 0x0090808fL
// The next define should really be in the OpenSSL header, but it is missing.
// Failing to include this on Windows causes compilation failures.
#if defined(OPENSSL_SYS_WINDOWS)
#include <windows.h>
#endif
#include <openssl/cms.h>
#endif
"""

TYPES = """
static const long Cryptography_HAS_CMS;

typedef ... CMS_ContentInfo;
typedef ... CMS_SignerInfo;
typedef ... CMS_CertificateChoices;
typedef ... CMS_RevocationInfoChoice;
typedef ... CMS_RecipientInfo;
typedef ... CMS_ReceiptRequest;
typedef ... CMS_Receipt;
"""

FUNCTIONS = """
"""

MACROS = """
BIO *BIO_new_CMS(BIO *, CMS_ContentInfo *);
int i2d_CMS_bio_stream(BIO *, CMS_ContentInfo *, BIO *, int);
int PEM_write_bio_CMS_stream(BIO *, CMS_ContentInfo *, BIO *, int);
int PEM_write_bio_CMS(BIO *, CMS_ContentInfo *);
int CMS_final(CMS_ContentInfo *, BIO *, BIO *, unsigned int);
CMS_ContentInfo *CMS_sign(X509 *, EVP_PKEY *, Cryptography_STACK_OF_X509 *,
                          BIO *, unsigned int);
int CMS_verify(CMS_ContentInfo *, Cryptography_STACK_OF_X509 *, X509_STORE *,
               BIO *, BIO *, unsigned int);
CMS_ContentInfo *CMS_encrypt(Cryptography_STACK_OF_X509 *, BIO *,
                             const EVP_CIPHER *, unsigned int);
int CMS_decrypt(CMS_ContentInfo *, EVP_PKEY *, X509 *, BIO *, BIO *,
                unsigned int);
CMS_SignerInfo *CMS_add1_signer(CMS_ContentInfo *, X509 *, EVP_PKEY *,
                                const EVP_MD *, unsigned int);
"""

CUSTOMIZATIONS = """
#if !defined(OPENSSL_NO_CMS) && OPENSSL_VERSION_NUMBER >= 0x0090808fL
static const long Cryptography_HAS_CMS = 1;
#else
static const long Cryptography_HAS_CMS = 0;
typedef void CMS_ContentInfo;
typedef void CMS_SignerInfo;
typedef void CMS_CertificateChoices;
typedef void CMS_RevocationInfoChoice;
typedef void CMS_RecipientInfo;
typedef void CMS_ReceiptRequest;
typedef void CMS_Receipt;
BIO *(*BIO_new_CMS)(BIO *, CMS_ContentInfo *) = NULL;
int (*i2d_CMS_bio_stream)(BIO *, CMS_ContentInfo *, BIO *, int) = NULL;
int (*PEM_write_bio_CMS_stream)(BIO *, CMS_ContentInfo *, BIO *, int) = NULL;
int (*PEM_write_bio_CMS)(BIO *, CMS_ContentInfo *) = NULL;
int (*CMS_final)(CMS_ContentInfo *, BIO *, BIO *, unsigned int) = NULL;
CMS_ContentInfo *(*CMS_sign)(X509 *, EVP_PKEY *, Cryptography_STACK_OF_X509 *,
                             BIO *, unsigned int) = NULL;
int (*CMS_verify)(CMS_ContentInfo *, Cryptography_STACK_OF_X509 *,
                  X509_STORE *, BIO *, BIO *, unsigned int) = NULL;
CMS_ContentInfo *(*CMS_encrypt)(Cryptography_STACK_OF_X509 *, BIO *,
                                const EVP_CIPHER *, unsigned int) = NULL;
int (*CMS_decrypt)(CMS_ContentInfo *, EVP_PKEY *, X509 *, BIO *, BIO *,
                   unsigned int) = NULL;
CMS_SignerInfo *(*CMS_add1_signer)(CMS_ContentInfo *, X509 *, EVP_PKEY *,
                                   const EVP_MD *, unsigned int) = NULL;
#endif
"""

CONDITIONAL_NAMES = {
    "Cryptography_HAS_CMS": [
        "BIO_new_CMS",
        "i2d_CMS_bio_stream",
        "PEM_write_bio_CMS_stream",
        "PEM_write_bio_CMS",
        "CMS_final",
        "CMS_sign",
        "CMS_verify",
        "CMS_encrypt",
        "CMS_decrypt",
        "CMS_add1_signer",
    ]
}
