#!/bin/bash
set -e
set -x

if [[ "${TYPE}" == "openssl" ]]; then
  if [[ "${VERSION}" =~ ^[0-9a-f]{40}$ ]]; then
    git clone https://github.com/openssl/openssl
    pushd openssl
    git checkout "${VERSION}"
  else
    curl -LO "https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/openssl-${VERSION}.tar.gz"
    tar zxf "openssl-${VERSION}.tar.gz"
    pushd "openssl-${VERSION}"
  fi

  # modify the shlib version to a unique one to make sure the dynamic
  # linker doesn't load the system one.
  sed -i "s/^SHLIB_VERSION=.*/SHLIB_VERSION=100/" VERSION.dat

  # CONFIG_FLAGS is a global coming from a previous step
  ./config ${CONFIG_FLAGS} no-tests -fPIC --prefix="${OSSL_PATH}"

  make depend
  make -j"$(nproc)" build_sw
  # avoid installing the docs (for performance)
  # https://github.com/openssl/openssl/issues/6685#issuecomment-403838728
  make install_sw install_ssldirs
  # delete binaries we don't need
  rm -rf "${OSSL_PATH}/bin"
  # Select FIPS algorithms during native initialization, before any operations.
  # Runtime mutation of default properties is not thread safe.
  if [[ "${CONFIG_FLAGS}" =~ enable-fips ]]; then
      # As of alpha16 we have to install it separately and enable it in the config flags
      make -j"$(nproc)" install_fips
      pushd "${OSSL_PATH}"
      cat > ssl/openssl.cnf <<EOF
config_diagnostics = 1
openssl_conf = openssl_init
.include ${OSSL_PATH}/ssl/fipsmodule.cnf
[openssl_init]
providers = provider_sect
alg_section = algorithm_sect
[provider_sect]
fips = fips_sect
base = base_sect
[base_sect]
activate = 1
[algorithm_sect]
default_properties = fips=yes
EOF
      popd
  fi
  popd
elif [[ "${TYPE}" == "libressl" ]]; then
  curl -LO "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${VERSION}.tar.gz"
  tar zxf "libressl-${VERSION}.tar.gz"
  pushd "libressl-${VERSION}"
  cmake -GNinja -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF -DLIBRESSL_APPS=OFF -DLIBRESSL_TESTS=OFF -DCMAKE_INSTALL_PREFIX="${OSSL_PATH}"
  ninja -C build install
  # delete binaries, libtls, and docs we don't need. can't skip install/compile sadly
  rm -rf "${OSSL_PATH}/bin"
  rm -rf "${OSSL_PATH}/share"
  rm -rf "${OSSL_PATH}/lib/libtls*"
  popd
elif [[ "${TYPE}" == "boringssl" ]]; then
  git clone https://boringssl.googlesource.com/boringssl
  pushd boringssl
  git checkout "${VERSION}"
  cmake -GNinja -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=RelWithAsserts -DCMAKE_INSTALL_PREFIX="${OSSL_PATH}"
  ninja -C build install
  # delete binaries we don't need
  rm -rf "${OSSL_PATH}/bin"
  popd
  rm -rf boringssl/
elif [[ "${TYPE}" == "aws-lc" ]]; then
  git clone https://github.com/aws/aws-lc.git
  pushd aws-lc
  git checkout "${VERSION}"
  cmake -GNinja -B build -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DCMAKE_BUILD_TYPE=RelWithAsserts -DCMAKE_INSTALL_PREFIX="${OSSL_PATH}"
  ninja -C build install
  # delete binaries we don't need
  rm -rf "${OSSL_PATH:?}/bin"
  popd # aws-lc
  rm -rf aws-lc/
fi
