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
#include <Security/SecDigestTransform.h>
#include <Security/SecSignVerifyTransform.h>
#include <Security/SecEncryptTransform.h>
"""

TYPES = """
typedef ... *SecTransformRef;

CFStringRef kSecImportExportPassphrase;
CFStringRef kSecImportExportKeychain;
CFStringRef kSecImportExportAccess;

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
"""

FUNCTIONS = """
Boolean SecTransformSetAttribute(SecTransformRef, CFStringRef, CFTypeRef,
                                 CFErrorRef *);
SecTransformRef SecDecryptTransformCreate(SecKeyRef, CFErrorRef *);
SecTransformRef SecEncryptTransformCreate(SecKeyRef, CFErrorRef *);
SecTransformRef SecVerifyTransformCreate(SecKeyRef, CFDataRef, CFErrorRef *);
SecTransformRef SecSignTransformCreate(SecKeyRef, CFErrorRef *) ;
CFTypeRef SecTransformExecute(SecTransformRef, CFErrorRef *);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
