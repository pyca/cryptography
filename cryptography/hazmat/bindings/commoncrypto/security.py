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
#include <Security/Security.h>
#include <Security/SecKey.h>
#include <Security/SecEncryptTransform.h>
"""

TYPES = """
typedef ... *SecKeyRef;
typedef ... *SecKeychainRef;
typedef ... *SecAccessRef;
typedef ... *SecTransformRef;
typedef uint32_t SecPadding;

CFStringRef kSecImportExportPassphrase;
CFStringRef kSecImportExportKeychain;
CFStringRef kSecImportExportAccess;

enum {
    kSecPaddingNone = 0,
    kSecPaddingPKCS1 = 1,
    /* The following perform ASN.1 + PKCS1 padding */
    kSecPaddingPKCS1SHA1 = 0x8002,
};

typedef uint32_t SecExternalItemType;
enum {
    kSecItemTypeUnknown,
    kSecItemTypePrivateKey,
    kSecItemTypePublicKey,
    kSecItemTypeSessionKey,
    kSecItemTypeCertificate,
    kSecItemTypeAggregate
};


typedef uint32_t SecExternalFormat; // SecImportExport.h
enum {
    kSecFormatUnknown = 0,
    kSecFormatOpenSSL,
    kSecFormatSSH,
    kSecFormatBSAFE,
    kSecFormatRawKey,
    kSecFormatWrappedPKCS8,
    kSecFormatWrappedOpenSSL,
    kSecFormatWrappedSSH,
    kSecFormatWrappedLSH,
    kSecFormatX509Cert,
    kSecFormatPEMSequence,
    kSecFormatPKCS7,
    kSecFormatPKCS12,
    kSecFormatNetscapeCertSequence,
    kSecFormatSSHv2
};

typedef uint32_t SecItemImportExportFlags;
enum {
    kSecKeyImportOnlyOne        = 0x00000001,
    kSecKeySecurePassphrase     = 0x00000002,
    kSecKeyNoAccessControl      = 0x00000004
};
typedef uint32_t SecKeyImportExportFlags;

typedef struct {
    /* for import and export */
    uint32_t version;
    SecKeyImportExportFlags  flags;
    CFTypeRef                passphrase;
    CFStringRef              alertTitle;
    CFStringRef              alertPrompt;

    /* for import only */
    SecAccessRef             accessRef;
    CFArrayRef               keyUsage;

    CFArrayRef               keyAttributes;
} SecItemImportExportKeyParameters;

CFStringRef kSecEncryptionMode;
CFStringRef kSecEncryptKey;
CFStringRef kSecIVKey;
CFStringRef kSecModeCBCKey;
CFStringRef kSecModeCFBKey;
CFStringRef kSecModeECBKey;
CFStringRef kSecModeNoneKey;
CFStringRef kSecModeOFBKey;
CFStringRef kSecOAEPEncodingParametersAttributeName;
CFStringRef kSecPaddingKey;
CFStringRef kSecPaddingNoneKey;
CFStringRef kSecPaddingOAEPKey;
CFStringRef kSecPaddingPKCS1Key;
CFStringRef kSecPaddingPKCS5Key;
CFStringRef kSecPaddingPKCS7Key;

const CFStringRef kSecTransformInputAttributeName;
const CFStringRef kSecTransformOutputAttributeName;
const CFStringRef kSecTransformDebugAttributeName;
const CFStringRef kSecTransformTransformName;
const CFStringRef kSecTransformAbortAttributeName;

CFStringRef kSecInputIsAttributeName;
CFStringRef kSecInputIsPlainText;
CFStringRef kSecInputIsDigest;
CFStringRef kSecInputIsRaw;

const CFStringRef kSecDigestTypeAttribute;
const CFStringRef kSecDigestLengthAttribute;
const CFStringRef kSecDigestMD5;
const CFStringRef kSecDigestSHA1;
const CFStringRef kSecDigestSHA2;

const CFTypeRef kSecAttrKeyType;
const CFTypeRef kSecAttrKeySizeInBits;
const CFTypeRef kSecAttrIsPermanent;
const CFTypeRef kSecAttrKeyTypeRSA;
const CFTypeRef kSecAttrKeyTypeDSA;
const CFTypeRef kSecAttrKeyTypeEC;
const CFTypeRef kSecAttrKeyTypeEC;
const CFTypeRef kSecUseKeychain;
"""

FUNCTIONS = """
OSStatus SecItemImport(CFDataRef, CFStringRef, SecExternalFormat *,
                       SecExternalItemType *, SecItemImportExportFlags,
                       const SecItemImportExportKeyParameters *,
                       SecKeychainRef, CFArrayRef *);
OSStatus SecPKCS12Import(CFDataRef, CFDictionaryRef, CFArrayRef *);

Boolean SecTransformSetAttribute(SecTransformRef, CFStringRef, CFTypeRef,
                                 CFErrorRef *);
SecTransformRef SecDecryptTransformCreate(SecKeyRef, CFErrorRef *);
SecTransformRef SecEncryptTransformCreate(SecKeyRef, CFErrorRef *);
SecTransformRef SecVerifyTransformCreate(SecKeyRef, CFDataRef, CFErrorRef *);
SecTransformRef SecSignTransformCreate(SecKeyRef, CFErrorRef *) ;
CFTypeRef SecTransformExecute(SecTransformRef, CFErrorRef *);
OSStatus SecKeychainCreate(const char *, UInt32, const void *, Boolean,
                           SecAccessRef, SecKeychainRef *);
OSStatus SecKeychainDelete(SecKeychainRef);
OSStatus SecKeyGeneratePair(CFDictionaryRef, SecKeyRef *, SecKeyRef *);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
