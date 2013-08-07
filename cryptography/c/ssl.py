from functools import wraps

INCLUDES = [
    '#include "openssl/ssl.h"',
]

SETUP = [
    'SSL_library_init',
]

TYPES = [
    # Internally invented symbol to tell us if SSLv2 is supported
    'static const int OPENTLS_NO_SSL2;',

    'typedef ... SSL_METHOD;',
    'typedef ... SSL_CTX;',
]

FUNCTIONS = [
    'int SSL_library_init(void);',

    # methods
    'const SSL_METHOD *SSLv3_method(void);',
    'const SSL_METHOD *SSLv3_server_method(void);',
    'const SSL_METHOD *SSLv3_client_method(void);',
    'const SSL_METHOD *TLSv1_method(void);',
    'const SSL_METHOD *TLSv1_server_method(void);',
    'const SSL_METHOD *TLSv1_client_method(void);',
    'const SSL_METHOD *SSLv23_method(void);',
    'const SSL_METHOD *SSLv23_server_method(void);',
    'const SSL_METHOD *SSLv23_client_method(void);',

    # SSLv2 support is compiled out of some versions of OpenSSL.  These will
    # get special support when we generate the bindings so that if they are
    # available they will be wrapped, but if they are not they won't cause
    # problems (like link errors).
    'SSL_METHOD *SSLv2_method(void);',
    'SSL_METHOD *SSLv2_server_method(void);',
    'SSL_METHOD *SSLv2_client_method(void);',

    # context
    'SSL_CTX *SSL_CTX_new(SSL_METHOD *method);',
    'void SSL_CTX_free(SSL_CTX *ctx);',
]

C_CUSTOMIZATION = [
    """
#ifdef OPENSSL_NO_SSL2
static const int OPENTLS_NO_SSL2 = 1;
SSL_METHOD* (*SSLv2_method)(void) = NULL;
SSL_METHOD* (*SSLv2_client_method)(void) = NULL;
SSL_METHOD* (*SSLv2_server_method)(void) = NULL;
#else
static const int OPENTLS_NO_SSL2 = 0;
#endif
"""]


def _not_implemented_override(wrapped):
    """
    Decorator to help define an override which just raises NotImplementedError,
    useful to define friendly versions of APIs which are not actually available
    in the version of OpenSSL currently in use.

    wrapped is the Python function which will override the cffi-defined
    wrapper.

    This returns a factory to create the override function.  It expects to be
    called by the tls.c.api setup machinery.  See tls/c/__init__.py.
    """
    @wraps(wrapped)
    def _not_implemented_factory(api, from_openssl):
        """
        If SSLv2 is not supported by the OpenSSL library represented by the
        given api object, create an override function which raises
        NotImplementedError instead of trying to call the requested API (which
        would probably result in a null pointer dereference).
        """
        if api.OPENTLS_NO_SSL2:
            # SSLv2 is unsupported, give back the safe wrapper
            @wraps(wrapped)
            def not_implemented(*args, **kwargs):
                raise NotImplementedError()
            return not_implemented
        else:
            # SSLv2 is supported, give back the original function
            return from_openssl

    return _not_implemented_factory


@_not_implemented_override
def SSLv2_method():
    pass


@_not_implemented_override
def SSLv2_client_method():
    pass


@_not_implemented_override
def SSLv2_server_method():
    pass

OVERRIDES = [
    SSLv2_method, SSLv2_client_method, SSLv2_server_method,
]
