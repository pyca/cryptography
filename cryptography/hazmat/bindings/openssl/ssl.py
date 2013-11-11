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
#include <openssl/ssl.h>
"""

TYPES = """
static const int SSL_FILETYPE_PEM;
static const int SSL_FILETYPE_ASN1;
static const int SSL_ERROR_NONE;
static const int SSL_ERROR_ZERO_RETURN;
static const int SSL_ERROR_WANT_READ;
static const int SSL_ERROR_WANT_WRITE;
static const int SSL_ERROR_WANT_X509_LOOKUP;
static const int SSL_ERROR_SYSCALL;
static const int SSL_ERROR_SSL;
static const int SSL_SENT_SHUTDOWN;
static const int SSL_RECEIVED_SHUTDOWN;
static const int SSL_OP_NO_SSLv2;
static const int SSL_OP_NO_SSLv3;
static const int SSL_OP_NO_TLSv1;
static const int SSL_OP_SINGLE_DH_USE;
static const int SSL_OP_EPHEMERAL_RSA;
static const int SSL_OP_MICROSOFT_SESS_ID_BUG;
static const int SSL_OP_NETSCAPE_CHALLENGE_BUG;
static const int SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
static const int SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG;
static const int SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER;
static const int SSL_OP_MSIE_SSLV2_RSA_PADDING;
static const int SSL_OP_SSLEAY_080_CLIENT_DH_BUG;
static const int SSL_OP_TLS_D5_BUG;
static const int SSL_OP_TLS_BLOCK_PADDING_BUG;
static const int SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
static const int SSL_OP_CIPHER_SERVER_PREFERENCE;
static const int SSL_OP_TLS_ROLLBACK_BUG;
static const int SSL_OP_PKCS1_CHECK_1;
static const int SSL_OP_PKCS1_CHECK_2;
static const int SSL_OP_NETSCAPE_CA_DN_BUG;
static const int SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG;
static const int SSL_OP_NO_QUERY_MTU;
static const int SSL_OP_COOKIE_EXCHANGE;
static const int SSL_OP_NO_TICKET;
static const int SSL_OP_ALL;
static const int SSL_VERIFY_PEER;
static const int SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
static const int SSL_VERIFY_CLIENT_ONCE;
static const int SSL_VERIFY_NONE;
static const int SSL_SESS_CACHE_OFF;
static const int SSL_SESS_CACHE_CLIENT;
static const int SSL_SESS_CACHE_SERVER;
static const int SSL_SESS_CACHE_BOTH;
static const int SSL_SESS_CACHE_NO_AUTO_CLEAR;
static const int SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;
static const int SSL_SESS_CACHE_NO_INTERNAL_STORE;
static const int SSL_SESS_CACHE_NO_INTERNAL;
static const int SSL_ST_CONNECT;
static const int SSL_ST_ACCEPT;
static const int SSL_ST_MASK;
static const int SSL_ST_INIT;
static const int SSL_ST_BEFORE;
static const int SSL_ST_OK;
static const int SSL_ST_RENEGOTIATE;
static const int SSL_CB_LOOP;
static const int SSL_CB_EXIT;
static const int SSL_CB_READ;
static const int SSL_CB_WRITE;
static const int SSL_CB_ALERT;
static const int SSL_CB_READ_ALERT;
static const int SSL_CB_WRITE_ALERT;
static const int SSL_CB_ACCEPT_LOOP;
static const int SSL_CB_ACCEPT_EXIT;
static const int SSL_CB_CONNECT_LOOP;
static const int SSL_CB_CONNECT_EXIT;
static const int SSL_CB_HANDSHAKE_START;
static const int SSL_CB_HANDSHAKE_DONE;
static const int SSL_MODE_ENABLE_PARTIAL_WRITE;
static const int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
static const int SSL_MODE_AUTO_RETRY;
static const int SSL3_RANDOM_SIZE;
typedef ... X509_STORE_CTX;
static const int X509_V_OK;
typedef ... SSL_METHOD;
typedef ... SSL_CTX;

typedef struct {
    int master_key_length;
    unsigned char master_key[...];
    ...;
} SSL_SESSION;

typedef struct {
    unsigned char server_random[...];
    unsigned char client_random[...];
    ...;
} SSL3_STATE;

typedef struct {
    SSL3_STATE *s3;
    SSL_SESSION *session;
    ...;
} SSL;

static const int TLSEXT_NAMETYPE_host_name;
"""

FUNCTIONS = """
void SSL_load_error_strings();
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""
