#!/bin/bash
# Env: TYPE={openssl,libressl,boringssl,aws-lc,pyemscripten}, VERSION, OSSL_PATH.
# openssl honours CONFIG_FLAGS. pyemscripten needs emsdk on PATH and links a
# private OpenSSL into the wheel because Pyodide's _ssl is baked into
# pyodide.asm.wasm with no exported symbols.

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
  ./config ${CONFIG_FLAGS} -fPIC --prefix="${OSSL_PATH}"

  make depend
  make -j"$(nproc)"
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
  cmake -GNinja -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX="${OSSL_PATH}"
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
  cmake -GNinja -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX="${OSSL_PATH}"
  ninja -C build install
  # delete binaries we don't need
  rm -rf "${OSSL_PATH}/bin"
  popd
  rm -rf boringssl/
elif [[ "${TYPE}" == "aws-lc" ]]; then
  git clone https://github.com/aws/aws-lc.git
  pushd aws-lc
  git checkout "${VERSION}"
  cmake -GNinja -B build -DCMAKE_INSTALL_PREFIX="${OSSL_PATH}"
  ninja -C build install
  # delete binaries we don't need
  rm -rf "${OSSL_PATH:?}/bin"
  popd # aws-lc
  rm -rf aws-lc/
elif [[ "${TYPE}" == "pyemscripten" ]]; then
  # Idempotency check: skip if libssl.a is already present (e.g. when
  # actions/cache restored the install prefix in a prior step, or when
  # cibuildwheel re-invokes CIBW_BEFORE_BUILD_PYODIDE on the same runner).
  if [ -f "${OSSL_PATH}/lib/libssl.a" ] || [ -f "${OSSL_PATH}/lib64/libssl.a" ]; then
      echo "OpenSSL already built at ${OSSL_PATH}; skipping rebuild."
      exit 0
  fi
  curl -LO "https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/openssl-${VERSION}.tar.gz"
  tar zxf "openssl-${VERSION}.tar.gz"
  pushd "openssl-${VERSION}"
  # emconfigure sets CROSS_COMPILE=<emsdk>/em expecting Configure to append
  # "cc"/"ar"/etc. -- but it also sets CC to the full emcc path, so OpenSSL
  # ends up concatenating them. Override both with an empty cross-compile
  # prefix and bare CC/AR/RANLIB names.
  emconfigure ./Configure linux-generic32 \
    no-shared no-asm no-engine no-dso no-tests no-srtp no-cms \
    no-ui-console no-threads \
    --cross-compile-prefix= \
    CC=emcc AR=emar RANLIB=emranlib \
    --prefix="${OSSL_PATH}"
  emmake make -j"$(nproc)" build_libs
  emmake make install_dev
  popd
fi
