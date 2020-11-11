#!/bin/bash
set -e
set -x

shlib_sed() {
  # modify the shlib version to a unique one to make sure the dynamic
  # linker doesn't load the system one.
  sed -i "s/^SHLIB_MAJOR=.*/SHLIB_MAJOR=100/" Makefile
  sed -i "s/^SHLIB_MINOR=.*/SHLIB_MINOR=0.0/" Makefile
  sed -i "s/^SHLIB_VERSION_NUMBER=.*/SHLIB_VERSION_NUMBER=100.0.0/" Makefile
}

# CONFIG_HASH is a global coming from a previous step
OPENSSL_DIR="${GITHUB_WORKSPACE}/osslcache/${TYPE}-${VERSION}-${CONFIG_HASH}"
if [[ "${TYPE}" == "openssl" ]]; then
  curl -O "https://www.openssl.org/source/openssl-${VERSION}.tar.gz"
  tar zxf "openssl-${VERSION}.tar.gz"
  pushd "openssl-${VERSION}"
  # CONFIG_FLAGS is a global coming from a previous step
  ./config ${CONFIG_FLAGS} -fPIC --prefix="${OPENSSL_DIR}"
  shlib_sed
  make depend
  make -j"$(nproc)"
  # avoid installing the docs on versions of OpenSSL that aren't ancient.
  # https://github.com/openssl/openssl/issues/6685#issuecomment-403838728
  make install_sw install_ssldirs
  popd
elif [[ "${TYPE}" == "libressl" ]]; then
  curl -O "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${VERSION}.tar.gz"
  tar zxf "libressl-${VERSION}.tar.gz"
  pushd "libressl-${VERSION}"
  ./config -Wl -Wl,-Bsymbolic-functions -fPIC shared --prefix="${OPENSSL_DIR}"
  shlib_sed
  make -j"$(nproc)" install
  popd
fi
