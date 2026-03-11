/*
 * Reproducer: AES-GCM PPC64 int truncation via EVP_Cipher.
 *
 * EVP_Cipher takes unsigned int inl, which allows values > INT_MAX.
 * The PPC64 GCM assembly path stores the size_t return from
 * ppc_aes_gcm_encrypt/decrypt into "int s", truncating it.
 * This corrupts the "bulk" byte count, which then corrupts the
 * GCM length counter. CRYPTO_gcm128_encrypt_ctr32 detects the
 * overflow and returns an error, causing EVP_Cipher to return -1.
 *
 * On non-PPC, the generic code paths handle size_t correctly,
 * and EVP_Cipher returns (int)outl (a truncated but non-(-1) value).
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
     */
    printf("  Calling EVP_Cipher encrypt with len=%u ...\n",
           (unsigned int)TEST_LEN);
    fflush(stdout);

    int enc_ret = EVP_Cipher(ctx, out, buf, (unsigned int)TEST_LEN);
    printf("  EVP_Cipher encrypt returned: %d\n", enc_ret);

    /*
     * On PPC64, the int truncation in ppc_aes_gcm_crypt causes
     * the bulk value to be corrupted. The subsequent call to
     * CRYPTO_gcm128_encrypt_ctr32 detects the overflow and returns
     * an error, making EVP_Cipher return -1.
     *
     * On non-PPC, EVP_Cipher returns (int)outl = (int)TEST_LEN,
     * which is a truncated but non-(-1) value.
     *
     * So: enc_ret == -1 means the bug triggered.
     */
    if (enc_ret == -1) {
        printf("FAIL: EVP_Cipher returned -1 (GCM internal error from int truncation bug)\n");
        ret = 1;
    } else {
        printf("  EVP_Cipher returned %d (expected: %d from int truncation of outl)\n",
               enc_ret, (int)(unsigned int)TEST_LEN);
        ret = 0;
    }

    if (ret == 0)
        printf("PASS: No GCM int truncation bug detected\n");
    else
        printf("FAIL: GCM int truncation bug detected on this platform\n");

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    if (buf != MAP_FAILED && buf != NULL)
        munmap(buf, TEST_LEN);
    if (out != MAP_FAILED && out != NULL)
        munmap(out, TEST_LEN);
    return ret;
}
