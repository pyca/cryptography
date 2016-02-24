# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#include <windows.h>
#include <Wincrypt.h>
#include <schannel.h>
"""

TYPES = """
typedef int BOOL;
typedef unsigned long DWORD;
typedef wchar_t WCHAR;
typedef long LONG;
typedef void *LPVOID;
typedef const char *LPCSTR;
typedef char *LPSTR;

typedef ... *LPFILETIME;

typedef ... *HCERTCHAINENGINE;
typedef ... *HCERTSTORE;
typedef ... *PCERT_INFO;
typedef ... *HCRYPTPROV_LEGACY;
typedef ... *PCCERT_STRONG_SIGN_PARA;
typedef ... *PCERT_SIMPLE_CHAIN;

typedef struct _CTL_USAGE {
  DWORD cUsageIdentifier;
  LPSTR *rgpszUsageIdentifier;
} CTL_USAGE, *PCTL_USAGE, CERT_ENHKEY_USAGE, *PCERT_ENHKEY_USAGE;

typedef struct _CERT_USAGE_MATCH {
  DWORD             dwType;
  CERT_ENHKEY_USAGE Usage;
} CERT_USAGE_MATCH, *PCERT_USAGE_MATCH;

typedef struct _CERT_CHAIN_PARA {
  DWORD                   cbSize;
  CERT_USAGE_MATCH        RequestedUsage;
  CERT_USAGE_MATCH        RequestedIssuancePolicy;
  DWORD                   dwUrlRetrievalTimeout;
  BOOL                    fCheckRevocationFreshnessTime;
  DWORD                   dwRevocationFreshnessTime;
  LPFILETIME              pftCacheResync;
  PCCERT_STRONG_SIGN_PARA pStrongSignPara;
  DWORD                   dwStrongSignFlags;
} CERT_CHAIN_PARA, *PCERT_CHAIN_PARA;

typedef struct _HTTPSPolicyCallbackData {
  union {
    DWORD cbStruct;
    DWORD cbSize;
  };
  DWORD dwAuthType;
  DWORD fdwChecks;
  WCHAR *pwszServerName;
} HTTPSPolicyCallbackData, *PHTTPSPolicyCallbackData,
SSL_EXTRA_CERT_CHAIN_POLICY_PARA, *PSSL_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _CERT_CHAIN_POLICY_PARA {
  DWORD cbSize;
  DWORD dwFlags;
  void  *pvExtraPolicyPara;
} CERT_CHAIN_POLICY_PARA, *PCERT_CHAIN_POLICY_PARA;

typedef struct _CERT_CHAIN_POLICY_STATUS {
  DWORD cbSize;
  DWORD dwError;
  LONG  lChainIndex;
  LONG  lElementIndex;
  void  *pvExtraPolicyStatus;
} CERT_CHAIN_POLICY_STATUS, *PCERT_CHAIN_POLICY_STATUS;

typedef struct _CERT_TRUST_STATUS {
  DWORD dwErrorStatus;
  DWORD dwInfoStatus;
} CERT_TRUST_STATUS, *PCERT_TRUST_STATUS;

typedef const struct _CERT_CHAIN_CONTEXT* PCCERT_CHAIN_CONTEXT;
typedef struct _CERT_CHAIN_CONTEXT {
  DWORD cbSize;
  CERT_TRUST_STATUS TrustStatus;
  DWORD  cChain;
  PCERT_SIMPLE_CHAIN *rgpChain;
  DWORD cLowerQualityChainContext;
  PCCERT_CHAIN_CONTEXT *rgpLowerQualityChainContext;
  BOOL fHasRevocationFreshnessTime;
  DWORD dwRevocationFreshnessTime;
} CERT_CHAIN_CONTEXT, *PCERT_CHAIN_CONTEXT;

typedef struct _CERT_CONTEXT {
  DWORD dwCertEncodingType;
  BYTE *pbCertEncoded;
  DWORD cbCertEncoded;
  PCERT_INFO pCertInfo;
  HCERTSTORE hCertStore;
} CERT_CONTEXT, *PCERT_CONTEXT;
typedef const CERT_CONTEXT *PCCERT_CONTEXT;
"""

FUNCTIONS = """
HCERTSTORE CertOpenStore(
  LPCSTR,
  DWORD,
  HCRYPTPROV_LEGACY,
  DWORD,
  const void*
);

BOOL CertCloseStore(
  HCERTSTORE,
  DWORD
);

BOOL CertAddEncodedCertificateToStore(
  HCERTSTORE,
  DWORD,
  const BYTE *,
  DWORD,
  DWORD,
  PCCERT_CONTEXT *
);

BOOL CertFreeCertificateContext(
  PCCERT_CONTEXT
);

BOOL CertGetCertificateChain(
  HCERTCHAINENGINE,
  PCCERT_CONTEXT,
  LPFILETIME,
  HCERTSTORE,
  PCERT_CHAIN_PARA,
  DWORD,
  LPVOID,
  PCCERT_CHAIN_CONTEXT *
);

VOID CertFreeCertificateChain(
  PCCERT_CHAIN_CONTEXT
);

BOOL CertVerifyCertificateChainPolicy(
  LPCSTR,
  PCCERT_CHAIN_CONTEXT,
  PCERT_CHAIN_POLICY_PARA,
  PCERT_CHAIN_POLICY_STATUS
);
"""

MACROS = """
static const LPCSTR szOID_PKIX_KP_SERVER_AUTH;
static const LPCSTR szOID_SERVER_GATED_CRYPTO;
static const LPCSTR szOID_SGC_NETSCAPE;
static const LPCSTR szOID_PKIX_KP_CLIENT_AUTH;

static const DWORD USAGE_MATCH_TYPE_AND;
static const DWORD USAGE_MATCH_TYPE_OR;

static const DWORD AUTHTYPE_CLIENT;
static const DWORD AUTHTYPE_SERVER;

static const LPCSTR CERT_CHAIN_POLICY_SSL = ((LPCSTR)4);

static const LPCSTR CERT_STORE_PROV_MEMORY = ((LPCSTR)2);
static const DWORD CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG;

static const DWORD CERT_STORE_ADD_ALWAYS;
static const DWORD X509_ASN_ENCODING;
"""

CUSTOMIZATIONS = """
"""
