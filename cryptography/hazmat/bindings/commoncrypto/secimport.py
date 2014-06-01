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
#include <Security/SecImportExport.h>
"""

TYPES = """
typedef ... *SecAccessRef;

CFStringRef kSecImportExportPassphrase;
CFStringRef kSecImportExportKeychain;
CFStringRef kSecImportExportAccess;

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
"""

FUNCTIONS = """
OSStatus SecItemImport(CFDataRef, CFStringRef, SecExternalFormat *,
                       SecExternalItemType *, SecItemImportExportFlags,
                       const SecItemImportExportKeyParameters *,
                       SecKeychainRef, CFArrayRef *);
OSStatus SecPKCS12Import(CFDataRef, CFDictionaryRef, CFArrayRef *);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
