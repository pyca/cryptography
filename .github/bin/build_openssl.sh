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

  # CONFIG_FLAGS is a global coming from a previous step. no-tests skips
  # building the test programs and build_sw (rather than the default all
  # target) skips generating the man pages; neither is installed.
  ./config ${CONFIG_FLAGS} no-tests -fPIC --prefix="${OSSL_PATH}"

  make depend
  make -j"$(nproc)" build_sw
  # avoid installing the docs (for performance)
  # https://github.com/openssl/openssl/issues/6685#issuecomment-403838728
  make install_sw install_ssldirs
  # delete binaries we don't need
  rm -rf "${OSSL_PATH}/bin"
  # For OpenSSL 3.0.0 set up the FIPS config. This does not activate it by
  # default, but allows programmatic activation at runtime
  if [[ "${CONFIG_FLAGS}" =~ enable-fips ]]; then
      # As of alpha16 we have to install it separately and enable it in the config flags
      make -j"$(nproc)" install_fips
      pushd "${OSSL_PATH}"
      # include the conf file generated as part of install_fips
      sed -i "s:# .include fipsmodule.cnf:.include $(pwd)/ssl/fipsmodule.cnf:" ssl/openssl.cnf
      # uncomment the FIPS section
      sed -i 's:# fips = fips_sect:fips = fips_sect:' ssl/openssl.cnf
      popd
  fi
  popd
elif [[ "${TYPE}" == "libressl" ]]; then
  curl -LO "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${VERSION}.tar.gz"
  tar zxf "libressl-${VERSION}.tar.gz"
  pushd "libressl-${VERSION}"
  # The tests and apps aren't built: the openssl binary would be deleted
  # below anyway, and the tests depend on it.
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
  # install depends on all, which includes the (large) test suite unless
  # BUILD_TESTING is off. Without a build type CMake passes no
  # optimization flags at all; RelWithAsserts is Release with asserts
  # kept, which is what BoringSSL's own CI uses.
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
  # install depends on all, which includes the (large) test suite and the
  # bssl tool unless they're turned off. See the BoringSSL build above
  # for the build type.
  cmake -GNinja -B build -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DCMAKE_BUILD_TYPE=RelWithAsserts -DCMAKE_INSTALL_PREFIX="${OSSL_PATH}"
  ninja -C build install
  # delete binaries we don't need
  rm -rf "${OSSL_PATH:?}/bin"
  popd # aws-lc
  rm -rf aws-lc/
fi
