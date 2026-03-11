/*
 * Reproducer: AES-GCM PPC64 int truncation via EVP_Cipher.
 *
 * EVP_Cipher takes unsigned int inl, which allows values > INT_MAX.
 * The PPC64 GCM assembly path stores the size_t return from
 * ppc_aes_gcm_encrypt/decrypt into "int s", truncating it.
 * When s goes negative, "len -= s" (with implicit size_t conversion)
 * makes len enormous, causing an out-of-bounds read/write that
 * crashes with SIGSEGV.
 *
 * On non-PPC, the generic code paths handle size_t correctly.
 */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <errno.h>

/*
 * We need a buffer larger than INT_MAX (~2.1GB).
 * Use 2.5GB to clearly exceed the threshold.
 * mmap with MAP_ANONYMOUS gives us zero-filled pages
 * allocated on demand (no physical RAM committed upfront).
 */
#define TEST_LEN ((size_t)2500 * 1024 * 1024)

int main(void)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char *buf = NULL;
    unsigned char *out = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    int ret = 1;

    printf("Testing EVP_Cipher with unsigned int len > INT_MAX...\n");
    printf("  Buffer size: %zu bytes (%.1f GB)\n",
           TEST_LEN, TEST_LEN / (1024.0 * 1024 * 1024));
    fflush(stdout);

    if (TEST_LEN > UINT_MAX) {
        printf("SKIP: TEST_LEN exceeds unsigned int max\n");
        return 0;
    }

    buf = mmap(NULL, TEST_LEN, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        printf("SKIP: mmap input failed: %s\n", strerror(errno));
        return 0;
    }

    out = mmap(NULL, TEST_LEN, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (out == MAP_FAILED) {
        munmap(buf, TEST_LEN);
        printf("SKIP: mmap output failed: %s\n", strerror(errno));
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    cipher = EVP_aes_128_gcm();
    if (!ctx || !cipher) {
        fprintf(stderr, "Failed to create cipher context\n");
        goto cleanup;
    }

    /* Init GCM encrypt */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "EncryptInit failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /*
     * EVP_Cipher takes unsigned int for length.
     * Pass TEST_LEN (~2.5GB) which exceeds INT_MAX.
     *
     * On PPC64, the int truncation in ppc_aes_gcm_crypt causes
     * len -= (negative s) to wrap len to a huge value, making the
     * loop read/write far past the mmap'd region → SIGSEGV.
     *
     * Note: EVP_Cipher returns int, so the return value itself
     * overflows for >2GB output. We ignore it and check the output.
     */
    printf("  Calling EVP_Cipher encrypt with len=%u ...\n",
           (unsigned int)TEST_LEN);
    fflush(stdout);

    EVP_Cipher(ctx, out, buf, (unsigned int)TEST_LEN);

    /*
     * If we get here on PPC, the bug didn't trigger (or was fixed).
     * Verify the ciphertext isn't all zeros (encryption did something).
     */
    printf("  Encrypt completed without crash\n");

    int nonzero = 0;
    for (size_t i = 0; i < 64; i++) {
        if (out[i] != 0)
            nonzero++;
    }
    if (nonzero == 0) {
        printf("  WARNING: ciphertext is all zeros (encryption may have failed)\n");
    } else {
        printf("  Ciphertext looks valid (%d/64 non-zero bytes in header)\n", nonzero);
    }

    /* Check that data past 2GB boundary was also encrypted */
    nonzero = 0;
    size_t boundary = (size_t)2 * 1024 * 1024 * 1024;
    for (size_t i = boundary; i < boundary + 64 && i < TEST_LEN; i++) {
        if (out[i] != 0)
            nonzero++;
    }
    printf("  Past 2GB boundary: %d/64 non-zero bytes\n", nonzero);

    /* Now decrypt and verify round-trip */
    EVP_CIPHER_CTX_reset(ctx);
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "DecryptInit failed\n");
        goto cleanup;
    }

    /* Dirty the start of buf to verify decrypt overwrites it */
    memset(buf, 0xCC, 64);

    printf("  Calling EVP_Cipher decrypt with len=%u ...\n",
           (unsigned int)TEST_LEN);
    fflush(stdout);

    EVP_Cipher(ctx, buf, out, (unsigned int)TEST_LEN);

    printf("  Decrypt completed without crash\n");

    /* Verify decrypted data matches original (zeros from mmap) */
    ret = 0;
    size_t check_points[] = {0, 1, 63, 4096, boundary - 1, boundary,
                             boundary + 1, TEST_LEN - 64, TEST_LEN - 1};
    int num_checks = sizeof(check_points) / sizeof(check_points[0]);
    for (int i = 0; i < num_checks; i++) {
        size_t off = check_points[i];
        if (off >= TEST_LEN)
            continue;
        if (buf[off] != 0) {
            printf("  MISMATCH at offset %zu: expected 0x00, got 0x%02x\n",
                   off, buf[off]);
            ret = 1;
        }
    }

    if (ret == 0)
        printf("PASS: Round-trip correct for %zu bytes\n", TEST_LEN);
    else
        printf("FAIL: Round-trip mismatch\n");

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (buf != MAP_FAILED && buf != NULL)
        munmap(buf, TEST_LEN);
    if (out != MAP_FAILED && out != NULL)
        munmap(out, TEST_LEN);
    return ret;
}
