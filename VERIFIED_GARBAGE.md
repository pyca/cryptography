# cryptography on verified-garbage

This branch (`vg-backend`) adds [verified-garbage](https://github.com/pyca/verified-garbage)
(VG) as an alternative crypto backend for cryptography. A VG build does not link
or depend on OpenSSL at all. OpenSSL remains the default backend, and an
OpenSSL build behaves exactly as before.

## Building and testing

* Build with `--no-default-features --features verified-garbage`.
* `nox -e local-verified-garbage` runs the full local check (format, lint,
  type-check, Python and Rust tests) on a VG build.
* `nox -e rust-verified-garbage` formats, lints and tests only the Rust code of
  a VG build.
* `nox -e local` now lints both builds.
* The Python-facing Rust module is still called `_rust.openssl` on VG builds,
  so no Python import paths changed.
* VG is a path dependency on `../verified-garbage`, so the build only works
  next to a checkout of that repository. A real release would use a git or
  crates.io dependency.

## Results

Full test suite, with Wycheproof (`--wycheproof-root`), on x86-64 with OpenSSL
3.0.13:

| Build | Passed | Skipped | Failed |
|---|---|---|---|
| verified-garbage | 4647 | 86 | 0 |
| OpenSSL | 4241 | 491 | 0 |
| OpenSSL, without Wycheproof (the baseline command) | 4109 | 630 | 0 |

The last row is the pre-branch baseline (4102 passed, 630 skipped) plus 7 new
regression tests.

The built VG extension links only libc and libgcc, and exports or imports no
OpenSSL symbols.

VG runs about 400 more tests than OpenSSL 3.0.13 does, because it implements
algorithms that version of OpenSSL lacks: ML-KEM, ML-DSA, Argon2, XOFHash,
AES-GCM-SIV, HPKE with ML-KEM, and the IDEA modes.

## Performance

Compared with AWS-LC, as the other backend, by `.github/bin/vg_bench.py`
(139 operations of the public API, run on whichever backend cryptography was
built with) and `.github/bin/vg_bench_compare.py`. To track progress, rerun
both on the same machine and add a dated entry below; compare ratios between
runs, not absolute times, since machines differ.

To reproduce, build two virtualenvs from this branch (AWS-LC built with
`-DCMAKE_BUILD_TYPE=Release`; `OPENSSL_DIR` pointing at it, and
`bindgen-cli` installed, as cryptography's CI does), then run each side twice,
interleaved, and compare:

```sh
uv pip install --python venv-vg/bin/python ./vectors \
  --config-settings-package="cryptography:build-args=--no-default-features --features verified-garbage" .
OPENSSL_DIR=/path/to/aws-lc uv pip install --python venv-awslc/bin/python ./vectors .
for i in 1 2; do for v in awslc vg; do
  venv-$v/bin/python -I .github/bin/vg_bench.py res-$v-$i.json
done; done
python3 .github/bin/vg_bench_compare.py res-awslc-1.json res-awslc-2.json -- res-vg-1.json res-vg-2.json
```

Each figure is the faster of the two passes, each pass the median of 7
rounds. Cloud VMs are noisy: treat differences within about 15% as ties,
especially for rows marked †.

### 2026-10-29: verified-garbage `c4d37d29`, AWS-LC v5.11.0

cryptography `dec03d3` (`vg-backend` rebased on `main`), on the same kind of
VM as before. This host was about 1.3× faster for both libraries than the one
of 2026-10-21, and 72 of 139 rows differed by more than 10% between passes, so
compare the ratios, and only trust changes well above the noise.

**VG faster:**
* ECDSA signing on P-384 and P-521 (2–2.5×).
* ML-KEM (1.4–2.3×).
* RSA verification and OAEP encryption (1.6–2.7×).
* X25519 (1.1–1.5×) and Ed25519 (1.3–1.6×).
* AES-GCM and AES-CCM on small messages.
* Poly1305 on 1 MiB.
* PBKDF2 and HKDF.

**Roughly a tie:**
* RSA private operations and key generation. Private operations ranged from
  1.14× slower to 1.5× faster, and are noisy.
* RSA private key loading (VG 1.22× slower, noisy).
* secp256k1 signing.
* Hashes, HMAC, CMAC, scrypt and Fernet.

**VG slower:**
* Loading EC public numbers (31×) and EC private numbers (5×). The cause is
  unchanged: VG has no point-validation API.
* secp256k1 verification (2.7×) and key generation (1.5×).
* ML-DSA (1.3–2.3×).
* AES-XTS (1.6×) and AES-GCM decryption (1.3×) on 1 MiB; AES-CBC encryption
  on 1 MiB (1.2×).

**Loading an RSA private key without validation** is still about 35× slower
(43 µs against 1.2 µs), all of it in VG's `from_crt` checks.

Changes since 2026-10-21 (verified-garbage `f7e3b8e1`), by the ratios:
* **RSA key generation** went from 2.3× slower than AWS-LC to on par (VG's
  own time roughly halved, 164 ms to 60 ms).
* **ECDSA P-521 signing** went from 1.34× to 2.52× faster.
* **secp256k1** signing went from 1.4× slower to on par, and key generation
  from 1.8× to 1.5× slower; verification is unchanged.
* **ML-KEM** decapsulation went from 1.5–1.8× to 1.9–2.3× faster.
* **X25519 exchange** went from 1.14× to 1.48× faster.
* **VG's `check_key`** went from 132 µs to 95 µs.
* **P-384 signing**'s 3.6× last time was noise (AWS-LC's own time had
  doubled); it is 1.95× now, in line with 2026-10-18.

<details>
<summary>All results</summary>

| Benchmark | AWS-LC 5.11.0 | verified-garbage | VG vs AWS-LC 5.11.0 |
|---|---|---|---|
| `hash/sha256/64B` | 843 ns (76 MB/s) | 702 ns (91 MB/s) | 1.20x faster † |
| `hash/sha256/1KiB` | 1.48 us (690 MB/s) | 1.11 us (927 MB/s) | 1.34x faster † |
| `hash/sha256/1MiB` | 611 us (1,717 MB/s) | 572 us (1,833 MB/s) | 1.07x faster † |
| `hash/sha512/64B` | 802 ns (80 MB/s) | 897 ns (71 MB/s) | 1.12x slower |
| `hash/sha512/1KiB` | 2.17 us (473 MB/s) | 2.07 us (494 MB/s) | 1.04x faster † |
| `hash/sha512/1MiB` | 1.7 ms (616 MB/s) | 1.31 ms (801 MB/s) | 1.30x faster † |
| `hash/sha3-256/64B` | 1.15 us (55 MB/s) | 854 ns (75 MB/s) | 1.35x faster |
| `hash/sha3-256/1KiB` | 2.59 us (396 MB/s) | 3.03 us (338 MB/s) | 1.17x slower |
| `hash/sha3-256/1MiB` | 1.94 ms (541 MB/s) | 2.23 ms (470 MB/s) | 1.15x slower † |
| `hash/blake2b/64B` | n/a | 972 ns (66 MB/s) | — |
| `hash/blake2b/1KiB` | n/a | 1.41 us (725 MB/s) | — |
| `hash/blake2b/1MiB` | n/a | 738 us (1,421 MB/s) | — |
| `hmac/sha256/64B` | 892 ns (72 MB/s) | 962 ns (66 MB/s) | 1.08x slower |
| `poly1305/64B` | 317 ns (202 MB/s) | 343 ns (187 MB/s) | 1.08x slower |
| `hmac/sha256/1KiB` | 1.76 us (583 MB/s) | 1.59 us (643 MB/s) | 1.10x faster |
| `poly1305/1KiB` | 626 ns (1,635 MB/s) | 521 ns (1,967 MB/s) | 1.20x faster † |
| `hmac/sha256/1MiB` | 601 us (1,745 MB/s) | 661 us (1,587 MB/s) | 1.10x slower |
| `poly1305/1MiB` | 313 us (3,353 MB/s) | 99.3 us (10,564 MB/s) | 3.15x faster |
| `cmac/aes128/64B` | 971 ns (66 MB/s) | 1.21 us (53 MB/s) | 1.24x slower † |
| `cmac/aes128/1KiB` | 1.52 us (671 MB/s) | 1.53 us (668 MB/s) | 1.00x slower † |
| `cmac/aes128/1MiB` | 717 us (1,463 MB/s) | 567 us (1,851 MB/s) | 1.26x faster † |
| `aead/aesgcm-128/encrypt/64B` | 401 ns (160 MB/s) | 271 ns (236 MB/s) | 1.48x faster † |
| `aead/aesgcm-128/decrypt/64B` | 439 ns (146 MB/s) | 247 ns (259 MB/s) | 1.78x faster † |
| `aead/aesgcm-128/encrypt/1KiB` | 591 ns (1,733 MB/s) | 373 ns (2,747 MB/s) | 1.59x faster |
| `aead/aesgcm-128/decrypt/1KiB` | 625 ns (1,637 MB/s) | 337 ns (3,042 MB/s) | 1.86x faster † |
| `aead/aesgcm-128/encrypt/1MiB` | 102 us (10,302 MB/s) | 99 us (10,590 MB/s) | 1.03x faster † |
| `aead/aesgcm-128/decrypt/1MiB` | 90.1 us (11,639 MB/s) | 120 us (8,740 MB/s) | 1.33x slower † |
| `aead/aesgcm-256/encrypt/64B` | 525 ns (122 MB/s) | 309 ns (207 MB/s) | 1.70x faster † |
| `aead/aesgcm-256/decrypt/64B` | 492 ns (130 MB/s) | 326 ns (196 MB/s) | 1.51x faster |
| `aead/aesgcm-256/encrypt/1KiB` | 600 ns (1,706 MB/s) | 483 ns (2,121 MB/s) | 1.24x faster † |
| `aead/aesgcm-256/decrypt/1KiB` | 626 ns (1,636 MB/s) | 416 ns (2,462 MB/s) | 1.51x faster |
| `aead/aesgcm-256/encrypt/1MiB` | 103 us (10,166 MB/s) | 98 us (10,698 MB/s) | 1.05x faster † |
| `aead/aesgcm-256/decrypt/1MiB` | 104 us (10,092 MB/s) | 116 us (9,032 MB/s) | 1.12x slower † |
| `aead/chacha20poly1305/encrypt/64B` | 444 ns (144 MB/s) | 378 ns (169 MB/s) | 1.18x faster |
| `aead/chacha20poly1305/decrypt/64B` | 366 ns (175 MB/s) | 355 ns (180 MB/s) | 1.03x faster † |
| `aead/chacha20poly1305/encrypt/1KiB` | 1.01 us (1,016 MB/s) | 931 ns (1,100 MB/s) | 1.08x faster |
| `aead/chacha20poly1305/decrypt/1KiB` | 849 ns (1,206 MB/s) | 702 ns (1,458 MB/s) | 1.21x faster |
| `aead/chacha20poly1305/encrypt/1MiB` | 448 us (2,340 MB/s) | 358 us (2,926 MB/s) | 1.25x faster |
| `aead/chacha20poly1305/decrypt/1MiB` | 576 us (1,819 MB/s) | 318 us (3,299 MB/s) | 1.81x faster † |
| `aead/aesccm-128/encrypt/64B` | 631 ns (101 MB/s) | 426 ns (150 MB/s) | 1.48x faster † |
| `aead/aesccm-128/decrypt/64B` | 544 ns (118 MB/s) | 329 ns (195 MB/s) | 1.66x faster † |
| `aead/aesccm-128/encrypt/1KiB` | 1.93 us (529 MB/s) | 940 ns (1,090 MB/s) | 2.06x faster † |
| `aead/aesccm-128/decrypt/1KiB` | 1.9 us (540 MB/s) | 1.16 us (886 MB/s) | 1.64x faster |
| `aead/aesccm-128/encrypt/1MiB` | 1.29 ms (810 MB/s) | 759 us (1,381 MB/s) | 1.70x faster |
| `aead/aesccm-128/decrypt/1MiB` | 1.09 ms (965 MB/s) | 821 us (1,276 MB/s) | 1.32x faster † |
| `aead/aesgcmsiv-256/encrypt/64B` | 309 ns (207 MB/s) | 433 ns (148 MB/s) | 1.40x slower † |
| `aead/aesgcmsiv-256/decrypt/64B` | 312 ns (205 MB/s) | 356 ns (180 MB/s) | 1.14x slower † |
| `aead/aesgcmsiv-256/encrypt/1KiB` | 647 ns (1,583 MB/s) | 553 ns (1,850 MB/s) | 1.17x faster |
| `aead/aesgcmsiv-256/decrypt/1KiB` | 601 ns (1,704 MB/s) | 515 ns (1,989 MB/s) | 1.17x faster † |
| `aead/aesgcmsiv-256/encrypt/1MiB` | 287 us (3,656 MB/s) | 193 us (5,442 MB/s) | 1.49x faster † |
| `aead/aesgcmsiv-256/decrypt/1MiB` | 237 us (4,419 MB/s) | 217 us (4,832 MB/s) | 1.09x faster |
| `aead/aesocb3-128/encrypt/64B` | n/a | 322 ns (199 MB/s) | — |
| `aead/aesocb3-128/decrypt/64B` | n/a | 382 ns (168 MB/s) | — |
| `aead/aesocb3-128/encrypt/1KiB` | n/a | 527 ns (1,942 MB/s) | — |
| `aead/aesocb3-128/decrypt/1KiB` | n/a | 533 ns (1,920 MB/s) | — |
| `aead/aesocb3-128/encrypt/1MiB` | n/a | 180 us (5,823 MB/s) | — |
| `aead/aesocb3-128/decrypt/1MiB` | n/a | 183 us (5,724 MB/s) | — |
| `aead/aessiv-256/encrypt/64B` | n/a | 394 ns (162 MB/s) | — |
| `aead/aessiv-256/decrypt/64B` | n/a | 418 ns (153 MB/s) | — |
| `aead/aessiv-256/encrypt/1KiB` | n/a | 1.19 us (857 MB/s) | — |
| `aead/aessiv-256/decrypt/1KiB` | n/a | 1.05 us (979 MB/s) | — |
| `aead/aessiv-256/encrypt/1MiB` | n/a | 719 us (1,458 MB/s) | — |
| `aead/aessiv-256/decrypt/1MiB` | n/a | 717 us (1,462 MB/s) | — |
| `cipher/aes128-ctr/encrypt/64B` | 1.8 us (36 MB/s) | 1.41 us (45 MB/s) | 1.27x faster † |
| `cipher/aes128-ctr/encrypt/1KiB` | 2.07 us (494 MB/s) | 1.83 us (560 MB/s) | 1.13x faster |
| `cipher/aes128-ctr/encrypt/1MiB` | 160 us (6,553 MB/s) | 133 us (7,862 MB/s) | 1.20x faster |
| `cipher/aes128-cbc/encrypt/64B` | 1.61 us (40 MB/s) | 1.62 us (40 MB/s) | 1.01x slower |
| `cipher/aes128-cbc/encrypt/1KiB` | 2.4 us (427 MB/s) | 2.92 us (351 MB/s) | 1.22x slower |
| `cipher/aes128-cbc/encrypt/1MiB` | 1.48 ms (707 MB/s) | 1.84 ms (569 MB/s) | 1.24x slower † |
| `cipher/aes256-xts/encrypt/64B` | 1.33 us (48 MB/s) | 1.73 us (37 MB/s) | 1.29x slower † |
| `cipher/aes256-xts/encrypt/1KiB` | 1.74 us (590 MB/s) | 1.86 us (550 MB/s) | 1.07x slower |
| `cipher/aes256-xts/encrypt/1MiB` | 101 us (10,402 MB/s) | 159 us (6,606 MB/s) | 1.57x slower † |
| `cipher/chacha20/encrypt/64B` | n/a | 1.65 us (39 MB/s) | — |
| `cipher/chacha20/encrypt/1KiB` | n/a | 1.87 us (548 MB/s) | — |
| `cipher/chacha20/encrypt/1MiB` | n/a | 283 us (3,704 MB/s) | — |
| `kdf/pbkdf2-sha256/100000` | 12.5 ms | 9.38 ms | 1.33x faster † |
| `kdf/scrypt/n=2^14,r=8,p=1` | 28.3 ms | 30.4 ms | 1.07x slower |
| `kdf/argon2id/m=64MiB,t=3,p=4` | n/a | 137 ms | — |
| `kdf/hkdf-sha256/32B` | 1.67 us | 1.2 us | 1.39x faster † |
| `fernet/encrypt/1KiB` | 2.32 us (442 MB/s) | 3.21 us (319 MB/s) | 1.39x slower † |
| `fernet/decrypt/1KiB` | 1.66 us (617 MB/s) | 1.67 us (612 MB/s) | 1.01x slower † |
| `ed25519/keygen` | 8.61 us | 5.15 us | 1.67x faster † |
| `ed25519/sign` | 9.32 us | 6.88 us | 1.35x faster |
| `ed25519/verify` | 37.8 us | 24.6 us | 1.54x faster |
| `ed448/sign` | n/a | 91.6 us | — |
| `ed448/verify` | n/a | 167 us | — |
| `x25519/keygen` | 7.85 us | 7.01 us | 1.12x faster |
| `x25519/exchange` | 24.5 us | 16.5 us | 1.48x faster † |
| `x448/exchange` | n/a | 118 us | — |
| `ecdsa/p256/keygen` | 8.82 us | 8.79 us | 1.00x faster † |
| `ecdsa/p256/sign` | 18 us | 12.3 us | 1.47x faster † |
| `ecdsa/p256/verify` | 62.2 us | 47.1 us | 1.32x faster † |
| `ecdh/p256/exchange` | 42.9 us | 43 us | 1.00x slower † |
| `ecdsa/p384/keygen` | 54.1 us | 26.6 us | 2.03x faster |
| `ecdsa/p384/sign` | 67.7 us | 34.7 us | 1.95x faster |
| `ecdsa/p384/verify` | 167 us | 150 us | 1.11x faster † |
| `ecdh/p384/exchange` | 147 us | 145 us | 1.02x faster |
| `ecdsa/p521/keygen` | 80.6 us | 56.9 us | 1.42x faster † |
| `ecdsa/p521/sign` | 165 us | 65.3 us | 2.52x faster † |
| `ecdsa/p521/verify` | 323 us | 280 us | 1.15x faster |
| `ecdh/p521/exchange` | 219 us | 254 us | 1.16x slower |
| `ecdsa/secp256k1/keygen` | 146 us | 220 us | 1.50x slower † |
| `ecdsa/secp256k1/sign` | 187 us | 188 us | 1.01x slower † |
| `ecdsa/secp256k1/verify` | 176 us | 472 us | 2.68x slower |
| `ecdh/secp256k1/exchange` | 142 us | 189 us | 1.33x slower † |
| `rsa/2048/sign-pss` | 277 us | 284 us | 1.02x slower † |
| `rsa/2048/sign-pkcs1v15` | 343 us | 288 us | 1.19x faster |
| `rsa/2048/verify-pss` | 20.9 us | 10.2 us | 2.05x faster † |
| `rsa/2048/encrypt-oaep` | 19 us | 10.5 us | 1.81x faster |
| `rsa/2048/decrypt-oaep` | 282 us | 321 us | 1.14x slower † |
| `rsa/3072/sign-pss` | 843 us | 875 us | 1.04x slower † |
| `rsa/3072/sign-pkcs1v15` | 945 us | 862 us | 1.10x faster |
| `rsa/3072/verify-pss` | 32.1 us | 15.3 us | 2.10x faster † |
| `rsa/3072/encrypt-oaep` | 39.8 us | 20.3 us | 1.95x faster |
| `rsa/3072/decrypt-oaep` | 1.04 ms | 698 us | 1.50x faster † |
| `rsa/4096/sign-pss` | 1.67 ms | 1.91 ms | 1.14x slower † |
| `rsa/4096/sign-pkcs1v15` | 1.98 ms | 1.53 ms | 1.29x faster † |
| `rsa/4096/verify-pss` | 53 us | 32.9 us | 1.61x faster † |
| `rsa/4096/encrypt-oaep` | 64.3 us | 23.9 us | 2.69x faster † |
| `rsa/4096/decrypt-oaep` | 1.84 ms | 1.41 ms | 1.31x faster † |
| `rsa/2048/keygen` | 57.7 ms | 60.4 ms | 1.05x slower † |
| `rsa/2048/load-pem-private-key` | 123 us | 150 us | 1.22x slower † |
| `mlkem768/keygen` | 13.5 us | 9.91 us | 1.36x faster |
| `mlkem768/encapsulate` | 14.4 us | 7.89 us | 1.82x faster |
| `mlkem768/decapsulate` | 17.1 us | 8.89 us | 1.93x faster |
| `mlkem1024/keygen` | 18.3 us | 15.2 us | 1.21x faster |
| `mlkem1024/encapsulate` | 19.3 us | 8.55 us | 2.26x faster † |
| `mlkem1024/decapsulate` | 24.5 us | 10.8 us | 2.27x faster † |
| `mldsa44/keygen` | 23.3 us | 41.8 us | 1.79x slower † |
| `mldsa44/sign` | 82.3 us | 135 us | 1.64x slower † |
| `mldsa44/verify` | 24.3 us | 36.4 us | 1.50x slower † |
| `mldsa65/keygen` | 40.7 us | 93.6 us | 2.30x slower † |
| `mldsa65/sign` | 132 us | 222 us | 1.68x slower † |
| `mldsa65/verify` | 38.5 us | 48.8 us | 1.27x slower † |
| `mldsa87/keygen` | 73 us | 133 us | 1.83x slower |
| `mldsa87/sign` | 192 us | 269 us | 1.40x slower |
| `mldsa87/verify` | 74.8 us | 88.6 us | 1.18x slower |
| `x509/load-der` | 1.44 us | 1.41 us | 1.02x faster † |
| `x509/verify-directly-issued-by` | 34 us | 22.1 us | 1.54x faster † |

† passes differed by more than 10% (72 benchmarks)

</details>

### 2026-10-21: verified-garbage `f7e3b8e1`, AWS-LC v5.11.0

cryptography `aa7e689`, on a shared 4-core x86-64 VM (Intel Xeon, 2.1 GHz,
with AVX-512, AVX-512 IFMA, VAES, VPCLMULQDQ, SHA-NI, BMI2 and ADX).

**VG faster:**
* ECDSA signing on P-384 and P-521 (1.3–3.6×, noisy).
* RSA verification and OAEP encryption (2–2.5×).
* Ed25519 (1.5–1.6×).
* ML-KEM (1.1–1.8×).
* AES-GCM and AES-CCM on small messages (1.3–1.9×).
* Poly1305 on 1 MiB (3.4×).
* PBKDF2 and HKDF (1.3×).
* X.509 signature verification (1.4×).

**Roughly a tie:** hashes, HMAC, CMAC, scrypt, Fernet, RSA private
operations (VG 1.05–1.25× faster), and RSA private key loading (VG 1.09×
faster).

**VG slower:**
* Loading EC public numbers (30×) and EC private numbers (4×). VG has no
  point-validation API, so cryptography checks a point with a full ECDH
  scalar multiplication by 1.
* secp256k1 (1.4–3×).
* ML-DSA (1.3–2×).
* RSA key generation (about 2.3×).
* AES-CBC encryption on 1 MiB (1.4×).
* AES-GCM decryption on 1 MiB (1.2×): VG decrypts only in place, so
  cryptography copies the ciphertext first.

**Loading an RSA private key without validation**
(`unsafe_skip_rsa_key_validation`) is still about 45× slower (74 µs against
1.6 µs). VG's `from_crt` checks p·q = n and the CRT values whenever it loads
a key; that time is part of the full load above.

**Supported on one side only:**
* VG only: AES-OCB3, AES-SIV, BLAKE2b, Argon2id, Ed448, X448, and the
  ChaCha20 stream cipher.
* AWS-LC only: none of these operations.

Changes since the previous run (verified-garbage `fa13ed07`, 2026-10-18):
* VG's RSA key validation (`check_key`) went from 778 µs to 132 µs (#2956).
  RSA private key loading went from 5.6× slower than AWS-LC to on par.
* Ed25519 signing went from 1.14× to 1.55× faster (#2982).
* ECDSA P-256 verification went from 1.30× to 1.49× faster, and P-384 from
  1.21× to 1.34× faster (#2989).
* ML-KEM-768 key generation went from 1.05× to 1.32× faster.

<details>
<summary>All results</summary>

| Benchmark | AWS-LC 5.11.0 | verified-garbage | VG vs AWS-LC 5.11.0 |
|---|---|---|---|
| `hash/sha256/64B` | 1.08 us (59 MB/s) | 956 ns (67 MB/s) | 1.13x faster † |
| `hash/sha256/1KiB` | 1.81 us (566 MB/s) | 1.71 us (599 MB/s) | 1.06x faster |
| `hash/sha256/1MiB` | 775 us (1,353 MB/s) | 778 us (1,348 MB/s) | 1.00x slower † |
| `hash/sha512/64B` | 1.31 us (49 MB/s) | 1.19 us (54 MB/s) | 1.10x faster † |
| `hash/sha512/1KiB` | 3.17 us (323 MB/s) | 3.55 us (289 MB/s) | 1.12x slower † |
| `hash/sha512/1MiB` | 2.02 ms (520 MB/s) | 1.8 ms (584 MB/s) | 1.12x faster † |
| `hash/sha3-256/64B` | 1.57 us (41 MB/s) | 1.19 us (54 MB/s) | 1.32x faster † |
| `hash/sha3-256/1KiB` | 4.27 us (240 MB/s) | 4.06 us (252 MB/s) | 1.05x faster |
| `hash/sha3-256/1MiB` | 2.85 ms (368 MB/s) | 2.61 ms (401 MB/s) | 1.09x faster † |
| `hash/blake2b/64B` | n/a | 1.27 us (50 MB/s) | — |
| `hash/blake2b/1KiB` | n/a | 2.16 us (474 MB/s) | — |
| `hash/blake2b/1MiB` | n/a | 1.06 ms (990 MB/s) | — |
| `hmac/sha256/64B` | 1.41 us (45 MB/s) | 1.2 us (53 MB/s) | 1.18x faster † |
| `poly1305/64B` | 428 ns (150 MB/s) | 389 ns (164 MB/s) | 1.10x faster |
| `hmac/sha256/1KiB` | 2.14 us (478 MB/s) | 2.18 us (469 MB/s) | 1.02x slower † |
| `poly1305/1KiB` | 781 ns (1,312 MB/s) | 643 ns (1,592 MB/s) | 1.21x faster † |
| `hmac/sha256/1MiB` | 814 us (1,288 MB/s) | 783 us (1,340 MB/s) | 1.04x faster |
| `poly1305/1MiB` | 375 us (2,794 MB/s) | 110 us (9,501 MB/s) | 3.40x faster † |
| `cmac/aes128/64B` | 1.52 us (42 MB/s) | 1.45 us (44 MB/s) | 1.05x faster † |
| `cmac/aes128/1KiB` | 2.38 us (431 MB/s) | 2.36 us (433 MB/s) | 1.00x faster † |
| `cmac/aes128/1MiB` | 921 us (1,139 MB/s) | 772 us (1,359 MB/s) | 1.19x faster |
| `aead/aesgcm-128/encrypt/64B` | 622 ns (103 MB/s) | 425 ns (151 MB/s) | 1.46x faster |
| `aead/aesgcm-128/decrypt/64B` | 681 ns (94 MB/s) | 450 ns (142 MB/s) | 1.51x faster † |
| `aead/aesgcm-128/encrypt/1KiB` | 790 ns (1,297 MB/s) | 600 ns (1,706 MB/s) | 1.32x faster † |
| `aead/aesgcm-128/decrypt/1KiB` | 920 ns (1,114 MB/s) | 492 ns (2,083 MB/s) | 1.87x faster † |
| `aead/aesgcm-128/encrypt/1MiB` | 109 us (9,658 MB/s) | 98.6 us (10,638 MB/s) | 1.10x faster |
| `aead/aesgcm-128/decrypt/1MiB` | 119 us (8,795 MB/s) | 139 us (7,554 MB/s) | 1.16x slower |
| `aead/aesgcm-256/encrypt/64B` | 603 ns (106 MB/s) | 424 ns (151 MB/s) | 1.42x faster † |
| `aead/aesgcm-256/decrypt/64B` | 635 ns (101 MB/s) | 407 ns (157 MB/s) | 1.56x faster † |
| `aead/aesgcm-256/encrypt/1KiB` | 775 ns (1,321 MB/s) | 634 ns (1,614 MB/s) | 1.22x faster |
| `aead/aesgcm-256/decrypt/1KiB` | 786 ns (1,303 MB/s) | 550 ns (1,863 MB/s) | 1.43x faster † |
| `aead/aesgcm-256/encrypt/1MiB` | 125 us (8,369 MB/s) | 110 us (9,519 MB/s) | 1.14x faster † |
| `aead/aesgcm-256/decrypt/1MiB` | 119 us (8,844 MB/s) | 151 us (6,927 MB/s) | 1.28x slower † |
| `aead/chacha20poly1305/encrypt/64B` | 641 ns (100 MB/s) | 587 ns (109 MB/s) | 1.09x faster |
| `aead/chacha20poly1305/decrypt/64B` | 613 ns (104 MB/s) | 556 ns (115 MB/s) | 1.10x faster † |
| `aead/chacha20poly1305/encrypt/1KiB` | 1.22 us (838 MB/s) | 1.13 us (908 MB/s) | 1.08x faster |
| `aead/chacha20poly1305/decrypt/1KiB` | 1.21 us (847 MB/s) | 1.1 us (934 MB/s) | 1.10x faster † |
| `aead/chacha20poly1305/encrypt/1MiB` | 639 us (1,641 MB/s) | 373 us (2,812 MB/s) | 1.71x faster |
| `aead/chacha20poly1305/decrypt/1MiB` | 621 us (1,689 MB/s) | 392 us (2,675 MB/s) | 1.58x faster |
| `aead/aesccm-128/encrypt/64B` | 836 ns (77 MB/s) | 491 ns (130 MB/s) | 1.70x faster † |
| `aead/aesccm-128/decrypt/64B` | 808 ns (79 MB/s) | 471 ns (136 MB/s) | 1.72x faster |
| `aead/aesccm-128/encrypt/1KiB` | 2.41 us (425 MB/s) | 1.37 us (745 MB/s) | 1.76x faster |
| `aead/aesccm-128/decrypt/1KiB` | 2.3 us (446 MB/s) | 1.37 us (748 MB/s) | 1.68x faster |
| `aead/aesccm-128/encrypt/1MiB` | 1.55 ms (678 MB/s) | 971 us (1,080 MB/s) | 1.59x faster |
| `aead/aesccm-128/decrypt/1MiB` | 1.57 ms (667 MB/s) | 1.01 ms (1,039 MB/s) | 1.56x faster |
| `aead/aesgcmsiv-256/encrypt/64B` | 436 ns (147 MB/s) | 566 ns (113 MB/s) | 1.30x slower † |
| `aead/aesgcmsiv-256/decrypt/64B` | 466 ns (137 MB/s) | 533 ns (120 MB/s) | 1.14x slower † |
| `aead/aesgcmsiv-256/encrypt/1KiB` | 758 ns (1,350 MB/s) | 792 ns (1,293 MB/s) | 1.04x slower |
| `aead/aesgcmsiv-256/decrypt/1KiB` | 710 ns (1,441 MB/s) | 775 ns (1,322 MB/s) | 1.09x slower |
| `aead/aesgcmsiv-256/encrypt/1MiB` | 303 us (3,459 MB/s) | 210 us (5,001 MB/s) | 1.45x faster |
| `aead/aesgcmsiv-256/decrypt/1MiB` | 259 us (4,044 MB/s) | 216 us (4,854 MB/s) | 1.20x faster |
| `aead/aesocb3-128/encrypt/64B` | n/a | 489 ns (131 MB/s) | — |
| `aead/aesocb3-128/decrypt/64B` | n/a | 490 ns (131 MB/s) | — |
| `aead/aesocb3-128/encrypt/1KiB` | n/a | 606 ns (1,691 MB/s) | — |
| `aead/aesocb3-128/decrypt/1KiB` | n/a | 668 ns (1,534 MB/s) | — |
| `aead/aesocb3-128/encrypt/1MiB` | n/a | 217 us (4,827 MB/s) | — |
| `aead/aesocb3-128/decrypt/1MiB` | n/a | 316 us (3,314 MB/s) | — |
| `aead/aessiv-256/encrypt/64B` | n/a | 507 ns (126 MB/s) | — |
| `aead/aessiv-256/decrypt/64B` | n/a | 518 ns (124 MB/s) | — |
| `aead/aessiv-256/encrypt/1KiB` | n/a | 1.38 us (744 MB/s) | — |
| `aead/aessiv-256/decrypt/1KiB` | n/a | 1.59 us (643 MB/s) | — |
| `aead/aessiv-256/encrypt/1MiB` | n/a | 964 us (1,088 MB/s) | — |
| `aead/aessiv-256/decrypt/1MiB` | n/a | 1.08 ms (968 MB/s) | — |
| `cipher/aes128-ctr/encrypt/64B` | 2.39 us (27 MB/s) | 2.16 us (30 MB/s) | 1.11x faster |
| `cipher/aes128-ctr/encrypt/1KiB` | 2.68 us (382 MB/s) | 2.32 us (441 MB/s) | 1.15x faster |
| `cipher/aes128-ctr/encrypt/1MiB` | 181 us (5,787 MB/s) | 144 us (7,261 MB/s) | 1.25x faster |
| `cipher/aes128-cbc/encrypt/64B` | 2.18 us (29 MB/s) | 2.16 us (30 MB/s) | 1.01x faster † |
| `cipher/aes128-cbc/encrypt/1KiB` | 2.95 us (347 MB/s) | 3.46 us (296 MB/s) | 1.17x slower † |
| `cipher/aes128-cbc/encrypt/1MiB` | 1.62 ms (649 MB/s) | 2.25 ms (467 MB/s) | 1.39x slower |
| `cipher/aes256-xts/encrypt/64B` | 2 us (32 MB/s) | 2.12 us (30 MB/s) | 1.06x slower † |
| `cipher/aes256-xts/encrypt/1KiB` | 2.51 us (407 MB/s) | 2.26 us (454 MB/s) | 1.11x faster † |
| `cipher/aes256-xts/encrypt/1MiB` | 122 us (8,569 MB/s) | 162 us (6,468 MB/s) | 1.32x slower † |
| `cipher/chacha20/encrypt/64B` | n/a | 2.08 us (31 MB/s) | — |
| `cipher/chacha20/encrypt/1KiB` | n/a | 2.44 us (419 MB/s) | — |
| `cipher/chacha20/encrypt/1MiB` | n/a | 291 us (3,604 MB/s) | — |
| `kdf/pbkdf2-sha256/100000` | 17.3 ms | 12.8 ms | 1.36x faster |
| `kdf/scrypt/n=2^14,r=8,p=1` | 32.4 ms | 31 ms | 1.05x faster |
| `kdf/argon2id/m=64MiB,t=3,p=4` | n/a | 125 ms | — |
| `kdf/hkdf-sha256/32B` | 2.29 us | 1.8 us | 1.27x faster † |
| `fernet/encrypt/1KiB` | 3.58 us (286 MB/s) | 3.72 us (275 MB/s) | 1.04x slower |
| `fernet/decrypt/1KiB` | 2.43 us (421 MB/s) | 2.57 us (399 MB/s) | 1.05x slower † |
| `ed25519/keygen` | 10.8 us | 7.12 us | 1.52x faster |
| `ed25519/sign` | 11.8 us | 7.59 us | 1.55x faster |
| `ed25519/verify` | 52.2 us | 32.2 us | 1.62x faster |
| `ed448/sign` | n/a | 169 us | — |
| `ed448/verify` | n/a | 247 us | — |
| `x25519/keygen` | 11.6 us | 7.55 us | 1.54x faster † |
| `x25519/exchange` | 29 us | 25.3 us | 1.14x faster † |
| `x448/exchange` | n/a | 165 us | — |
| `ecdsa/p256/keygen` | 11.3 us | 12.2 us | 1.08x slower † |
| `ecdsa/p256/sign` | 22.5 us | 16.5 us | 1.37x faster † |
| `ecdsa/p256/verify` | 79.5 us | 53.3 us | 1.49x faster |
| `ecdh/p256/exchange` | 58.9 us | 53.6 us | 1.10x faster † |
| `ecdsa/p384/keygen` | 65.9 us | 31.1 us | 2.12x faster † |
| `ecdsa/p384/sign` | 152 us | 42.3 us | 3.59x faster † |
| `ecdsa/p384/verify` | 237 us | 177 us | 1.34x faster † |
| `ecdh/p384/exchange` | 180 us | 162 us | 1.11x faster |
| `ecdsa/p521/keygen` | 91.4 us | 81.7 us | 1.12x faster |
| `ecdsa/p521/sign` | 185 us | 138 us | 1.34x faster † |
| `ecdsa/p521/verify` | 392 us | 337 us | 1.16x faster † |
| `ecdh/p521/exchange` | 260 us | 286 us | 1.10x slower † |
| `ecdsa/secp256k1/keygen` | 194 us | 354 us | 1.82x slower † |
| `ecdsa/secp256k1/sign` | 237 us | 335 us | 1.41x slower † |
| `ecdsa/secp256k1/verify` | 214 us | 658 us | 3.08x slower † |
| `ecdh/secp256k1/exchange` | 213 us | 324 us | 1.52x slower |
| `rsa/2048/sign-pss` | 396 us | 324 us | 1.22x faster |
| `rsa/2048/sign-pkcs1v15` | 398 us | 325 us | 1.22x faster |
| `rsa/2048/verify-pss` | 25.3 us | 12.1 us | 2.09x faster † |
| `rsa/2048/encrypt-oaep` | 22 us | 11.4 us | 1.93x faster † |
| `rsa/2048/decrypt-oaep` | 418 us | 331 us | 1.26x faster † |
| `rsa/3072/sign-pss` | 1.07 ms | 952 us | 1.12x faster |
| `rsa/3072/sign-pkcs1v15` | 1.12 ms | 998 us | 1.12x faster † |
| `rsa/3072/verify-pss` | 47.9 us | 23.5 us | 2.04x faster † |
| `rsa/3072/encrypt-oaep` | 50.4 us | 20.4 us | 2.47x faster † |
| `rsa/3072/decrypt-oaep` | 1.01 ms | 946 us | 1.07x faster † |
| `rsa/4096/sign-pss` | 2.05 ms | 1.93 ms | 1.07x faster † |
| `rsa/4096/sign-pkcs1v15` | 2.15 ms | 2.01 ms | 1.07x faster † |
| `rsa/4096/verify-pss` | 78.9 us | 35.2 us | 2.24x faster |
| `rsa/4096/encrypt-oaep` | 79.2 us | 36.4 us | 2.18x faster † |
| `rsa/4096/decrypt-oaep` | 2.11 ms | 1.99 ms | 1.06x faster † |
| `rsa/2048/keygen` | 72.3 ms | 164 ms | 2.27x slower † |
| `rsa/2048/load-pem-private-key` | 188 us | 172 us | 1.09x faster † |
| `mlkem768/keygen` | 15.7 us | 11.9 us | 1.32x faster † |
| `mlkem768/encapsulate` | 16.2 us | 9.27 us | 1.74x faster † |
| `mlkem768/decapsulate` | 19.7 us | 13.5 us | 1.46x faster |
| `mlkem1024/keygen` | 21.9 us | 19.8 us | 1.10x faster † |
| `mlkem1024/encapsulate` | 22.5 us | 12.7 us | 1.77x faster † |
| `mlkem1024/decapsulate` | 28.1 us | 15.5 us | 1.82x faster † |
| `mldsa44/keygen` | 35.3 us | 68.7 us | 1.95x slower † |
| `mldsa44/sign` | 127 us | 162 us | 1.27x slower |
| `mldsa44/verify` | 34.6 us | 46.7 us | 1.35x slower |
| `mldsa65/keygen` | 60.8 us | 129 us | 2.11x slower † |
| `mldsa65/sign` | 188 us | 265 us | 1.41x slower † |
| `mldsa65/verify` | 58.1 us | 76 us | 1.31x slower † |
| `mldsa87/keygen` | 93 us | 159 us | 1.71x slower † |
| `mldsa87/sign` | 253 us | 342 us | 1.35x slower † |
| `mldsa87/verify` | 85.3 us | 133 us | 1.56x slower † |
| `x509/load-der` | 2.21 us | 2.2 us | 1.01x faster |
| `x509/verify-directly-issued-by` | 45 us | 33.2 us | 1.36x faster |

† passes differed by more than 10% (72 benchmarks)

</details>

## Gaps in verified-garbage

Each of these raises `UnsupportedAlgorithm` on VG builds, and the tests that
need it are skipped on VG builds only (through `backend.*_supported()`
predicates).

* **EC**
  * No point decompression, so compressed (`02`/`03`) public keys are
    rejected.
  * No binary `sect*` curves.
  * VG pairs one hash with each curve for ECDSA (P-256 also has SHA-384).
    Other hashes work by re-encoding the digest into a native-hash value with
    the same `bits2int` integer (`ecdsa_input` in
    `src/rust/src/backend/vg/ec.rs`). This was checked by hand for every
    supported curve size, but deserves review.
  * Deterministic ECDSA is reported unsupported on VG, because exact RFC 6979
    is only possible for the native pairs.
  * VG's ECDSA signatures are always deterministic, never randomized.
* **RSA**
  * Only 512–8192-bit moduli and public exponents below 2^33 can be used for
    operations. Keys outside that range still load, but `verify`, `encrypt`
    and `recover_data_from_signature` raise `UnsupportedAlgorithm`.
  * Key generation sizes must be multiples of 128 bits.
  * `unsafe_skip_rsa_key_validation` cannot skip VG's own load-time checks.
  * PSS requires MGF1 over the signature's own hash, and has no SHA-3.
  * OAEP's MGF1 must use SHA-1 or the same hash as OAEP.
  * PKCS#1 v1.5 decryption always uses implicit rejection: bad padding returns
    a pseudo-random message instead of an error.
* **DSA**
  * No parameter generation.
  * Only four (p, q) sizes: 1024/160, 2048/224, 2048/256 and 3072/256 bits.
    This also blocks loading some test certificates and keys that use
    2048/160.
* **DH**
  * No primality check on p or q (OpenSSL tests them).
  * VG refuses a private key whose y is not g^x mod p, and a y of 1.
* **HMAC and PBKDF2**: only MD5, SHA-1 and SHA-2, so no SHA-3, BLAKE2 or
  SM3. This also limits HKDF, KBKDF and PKCS#12 MACs.
* **CMAC**: only AES and 3DES.
* **AES-GCM-SIV**: no 192-bit keys.
* **SM4-GCM**: not implemented.
* **AES-GCM**: decryption with tag lengths of 5–7 or 9–11 bytes is refused.
* **Single DES**: not implemented. Old encrypted PKCS#8 keys that use it are
  decrypted as 3DES with three equal keys, which is the same thing
  mathematically.
* **Platforms**: VG's RSA-OAEP and finite-field DH exist only on x86-64 and
  AArch64, so a VG build of cryptography works only there.

## Gaps on the cryptography side

* **No OpenSSL bindings**: `cryptography.hazmat.bindings.openssl.binding`
  raises `ImportError` on VG builds. pyOpenSSL and anything else that uses
  those bindings won't work.
* **DER only**: BER-encoded PKCS#12 and PKCS#7 files cannot be loaded,
  because the Rust ASN.1 parser that replaces OpenSSL's reads only DER.
* **PKCS#12 MACs**: PBMAC1 (RFC 9579) is not supported.
* **Test-only PKCS#7 verifier**: `test_support.pkcs7_verify` has a
  reimplemented VG version that checks less than OpenSSL's. It doesn't check
  validity periods or the S/MIME purpose, and builds only one level of chain.
* **Zeroization**: VG's routine for wiping secrets isn't public, so
  temporary seeds in cryptography's code are wiped on a best-effort basis.
* **Rust version**: the VG build needs Rust 1.88; cryptography's minimum is
  1.83.

## Open decisions

* **DSA and DH keys loaded from PKCS#8** carry no public value y, and VG
  can't compute g^x mod p. It is currently computed with Python's `pow`,
  which is not constant time in the secret x, and VG then checks the result.
  (Upstream already calls `pow` the same way when validating DSA private
  numbers.) The alternative is refusing these keys on VG, which means no
  PKCS#8 DSA or DH private keys load at all.

ML-DSA `sign_mu` / `verify_mu` use VG's public `sign_mu` / `verify_mu` APIs,
added in verified-garbage#2788.


## Bugs found that also affect the OpenSSL build

Fixed on this branch:

* An overflow panic in the scrypt memory error message for huge `n` and `r`.
* A panic in PKCS#12 serialization for unsupported `hmac_hash` choices; it
  now raises `UnsupportedAlgorithm`.

Not fixed (outside the VG code; worth reporting upstream):

* A deeply nested PBES2 key (about 10000 levels of `AlgorithmIdentifier`)
  crashes the interpreter with a stack overflow on both builds and on the
  released 50.0.2. The cause is unbounded recursion in the ASN.1 parsing.
* On the OpenSSL build, two inputs panic: a legacy PEM `DEK-Info` header with
  an 8-byte AES IV, and PBKDF2 iteration counts of 2^32 or more in encrypted
  PKCS#8 keys.

Three panics specific to VG were also found and fixed: AES-SIV with a list of
associated data, DH parameter serialization, and a stack overflow from deeply
nested PKCS#12 bags.
