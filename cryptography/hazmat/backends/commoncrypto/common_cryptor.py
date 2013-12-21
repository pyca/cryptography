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

INCLUDES = """
#include <CommonCrypto/CommonCryptor.h>
"""

TYPES = """
enum CCAlgorithm {
    kCCAlgorithmAES128 = 0,
    kCCAlgorithmDES,
    kCCAlgorithm3DES,
    kCCAlgorithmCAST,
    kCCAlgorithmRC4,
    kCCAlgorithmRC2,
    kCCAlgorithmBlowfish
};
typedef uint32_t CCAlgorithm;
enum CCCryptorStatus {
    kCCSuccess  = 0,
    kCCParamError       = -4300,
    kCCBufferTooSmall   = -4301,
    kCCMemoryFailure    = -4302,
    kCCAlignmentError   = -4303,
    kCCDecodeError      = -4304,
    kCCUnimplemented    = -4305
};
typedef int32_t CCCryptorStatus;
typedef uint32_t CCOptions;
enum CCOperation {
    kCCEncrypt = 0,
    kCCDecrypt,
};
typedef uint32_t CCOperation;
typedef ... *CCCryptorRef;

enum CCModeOptions {
    kCCModeOptionCTR_LE = 0x0001,
    kCCModeOptionCTR_BE = 0x0002
};

typedef uint32_t CCModeOptions;

enum CCMode {
    kCCModeECB      = 1,
    kCCModeCBC      = 2,
    kCCModeCFB      = 3,
    kCCModeCTR      = 4,
    kCCModeF8       = 5, // Unimplemented for now (not included)
    kCCModeLRW      = 6, // Unimplemented for now (not included)
    kCCModeOFB      = 7,
    kCCModeXTS      = 8,
    kCCModeRC4      = 9,
    kCCModeCFB8     = 10,
};
typedef uint32_t CCMode;
enum CCPadding {
    ccNoPadding         = 0,
    ccPKCS7Padding      = 1,
};
typedef uint32_t CCPadding;

enum {
    /* AES */
    kCCBlockSizeAES128        = 16,
    /* DES */
    kCCBlockSizeDES           = 8,
    /* 3DES */
    kCCBlockSize3DES          = 8,
    /* CAST */
    kCCBlockSizeCAST          = 8,
    kCCBlockSizeRC2           = 8,
    kCCBlockSizeBlowfish      = 8,
};
"""

FUNCTIONS = """
CCCryptorStatus CCCryptorCreateWithMode(
    CCOperation,             /* kCCEncrypt, kCCEncrypt */
    CCMode,
    CCAlgorithm,
    CCPadding,
    const void *,            /* optional initialization vector */
    const void *,           /* raw key material */
    size_t,
    const void *,         /* raw tweak material */
    size_t,
    int,      /* number of rounds. 0 == default */
    CCModeOptions,
    CCCryptorRef *);   /* RETURNED */

CCCryptorStatus CCCryptorCreate(
    CCOperation,             /* kCCEncrypt, etc. */
    CCAlgorithm,            /* kCCAlgorithmDES, etc. */
    CCOptions,          /* kCCOptionPKCS7Padding, etc. */
    const void *,            /* raw key material */
    size_t,
    const void *,             /* optional initialization vector */
    CCCryptorRef *);  /* RETURNED */
CCCryptorStatus CCCryptorUpdate(
    CCCryptorRef,
    const void *,
    size_t,
    void *,              /* data RETURNED here */
    size_t,
    size_t *);      /* number of bytes written */
CCCryptorStatus CCCryptorFinal(
    CCCryptorRef,
    void *,
    size_t,
    size_t *);      /* number of bytes written */
CCCryptorStatus CCCryptorRelease(CCCryptorRef);


/* GCM functions, 10.8+ iOS 5+ */
CCCryptorStatus CCCryptorGCMAddIV(CCCryptorRef, const void *, size_t);
CCCryptorStatus CCCryptorGCMAddAAD(CCCryptorRef, const void *, size_t);
CCCryptorStatus CCCryptorGCMEncrypt(CCCryptorRef, const void *, size_t,
                                    void *);
CCCryptorStatus CCCryptorGCMDecrypt(CCCryptorRef, const void *, size_t,
                                    void *);
CCCryptorStatus CCCryptorGCMFinal(CCCryptorRef, const void *, size_t *);
CCCryptorStatus CCCryptorGCMReset(CCCryptorRef);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""
