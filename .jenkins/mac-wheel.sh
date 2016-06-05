#!/bin/bash -xe
# output the list of things we've installed as a point in time check of how up to date the builder is
/usr/sbin/system_profiler SPInstallHistoryDataType
# Jenkins logs in as a non-interactive shell, so we don't even have /usr/local/bin in PATH
export PATH=/usr/local/bin:$PATH
# pyenv is nothing but trouble with non-interactive shells so we can't eval "$(pyenv init -)"
export PATH="/Users/jenkins/.pyenv/shims:${PATH}"
export PYENV_SHELL=bash

# TODO: upgrade wheel builder VM and run it on El Cap with python.org Pythons.
if [[ "${label}" == "10.10" ]]; then
    case "${TOXENV}" in
        py26)
            PYTHON=/usr/bin/python2.6
            ;;
        py27)
            PYTHON=/usr/bin/python2.7
            ;;
        py27u)
            PYTHON=python2.7
            ;;
        py33)
            PYTHON=python3.3
            ;;
        py34)
            PYTHON=python3.4
            ;;
        py35)
            PYTHON=python3.5
            ;;
        pypy)
            PYTHON=pypy
            ;;
    esac
else
    case "${TOXENV}" in
        py27)
            PYTHON=/Library/Frameworks/Python.framework/Versions/2.7/bin/python2.7
            ;;
        py33)
            PYTHON=/Library/Frameworks/Python.framework/Versions/3.3/bin/python3.3
            ;;
        py34)
            PYTHON=/Library/Frameworks/Python.framework/Versions/3.4/bin/python3.4
            ;;
        py35)
            PYTHON=/Library/Frameworks/Python.framework/Versions/3.5/bin/python3.5
            ;;
    esac
fi
printenv

virtualenv .venv -p $PYTHON
source .venv/bin/activate
pip install -U wheel # upgrade wheel to latest before we use it to build the wheel
CRYPTOGRAPHY_OSX_NO_LINK_FLAGS="1" LDFLAGS="/usr/local/opt/openssl/lib/libcrypto.a /usr/local/opt/openssl/lib/libssl.a" CFLAGS="-I/usr/local/opt/openssl/include" pip wheel cryptography --wheel-dir=wheelhouse --no-use-wheel
pip install -f wheelhouse cryptography --no-index
python -c "from cryptography.hazmat.backends.openssl.backend import backend;print('Loaded: ' + backend.openssl_version_text());print('Linked Against: ' + backend._ffi.string(backend._lib.OPENSSL_VERSION_TEXT).decode('ascii'))"
otool -L `find .venv -name '_openssl*.so'`
lipo -info `find .venv -name '*.so'`
otool -L `find .venv -name '_openssl*.so'` | grep -vG "libcrypto\|libssl"
