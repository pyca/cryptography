# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/bio.h>
"""

TYPES = """
typedef struct bio_st BIO;
typedef void bio_info_cb(BIO *, int, const char *, int, long, long);
typedef ... bio_st;
typedef ... BIO_METHOD;
typedef ... BUF_MEM;

static const int BIO_TYPE_MEM;
static const int BIO_TYPE_FILE;
static const int BIO_TYPE_FD;
static const int BIO_TYPE_SOCKET;
static const int BIO_TYPE_CONNECT;
static const int BIO_TYPE_ACCEPT;
static const int BIO_TYPE_NULL;
static const int BIO_CLOSE;
static const int BIO_NOCLOSE;
static const int BIO_TYPE_SOURCE_SINK;
static const int BIO_CTRL_RESET;
static const int BIO_CTRL_EOF;
static const int BIO_CTRL_SET;
static const int BIO_CTRL_SET_CLOSE;
static const int BIO_CTRL_FLUSH;
static const int BIO_CTRL_DUP;
static const int BIO_CTRL_GET_CLOSE;
static const int BIO_CTRL_INFO;
static const int BIO_CTRL_GET;
static const int BIO_CTRL_PENDING;
static const int BIO_CTRL_WPENDING;
static const int BIO_C_FILE_SEEK;
static const int BIO_C_FILE_TELL;
static const int BIO_TYPE_NONE;
static const int BIO_TYPE_NBIO_TEST;
static const int BIO_TYPE_BIO;
static const int BIO_TYPE_DESCRIPTOR;
static const int BIO_FLAGS_READ;
static const int BIO_FLAGS_WRITE;
static const int BIO_FLAGS_IO_SPECIAL;
static const int BIO_FLAGS_RWS;
static const int BIO_FLAGS_SHOULD_RETRY;
static const int BIO_TYPE_NULL_FILTER;
static const int BIO_TYPE_SSL;
static const int BIO_TYPE_MD;
static const int BIO_TYPE_BUFFER;
static const int BIO_TYPE_CIPHER;
static const int BIO_TYPE_BASE64;
static const int BIO_TYPE_FILTER;
"""

FUNCTIONS = """
int BIO_free(BIO *);
void BIO_vfree(BIO *);
void BIO_free_all(BIO *);
BIO *BIO_push(BIO *, BIO *);
BIO *BIO_pop(BIO *);
BIO *BIO_next(BIO *);
BIO *BIO_find_type(BIO *, int);
BIO *BIO_new_file(const char *, const char *);
BIO *BIO_new_fp(FILE *, int);
BIO *BIO_new_fd(int, int);
BIO *BIO_new_socket(int, int);
long BIO_ctrl(BIO *, int, long, void *);
long BIO_callback_ctrl(
    BIO *,
    int,
    void (*)(struct bio_st *, int, const char *, int, long, long)
);
long BIO_int_ctrl(BIO *, int, long, int);
size_t BIO_ctrl_pending(BIO *);
size_t BIO_ctrl_wpending(BIO *);
int BIO_read(BIO *, void *, int);
int BIO_gets(BIO *, char *, int);
int BIO_write(BIO *, const void *, int);
int BIO_puts(BIO *, const char *);
int BIO_method_type(const BIO *);
/* Added in 1.1.0 */
int BIO_up_ref(BIO *);

/* These added const to BIO_METHOD in 1.1.0 */
BIO *BIO_new(BIO_METHOD *);
BIO_METHOD *BIO_s_mem(void);
BIO_METHOD *BIO_s_file(void);
BIO_METHOD *BIO_s_fd(void);
BIO_METHOD *BIO_s_socket(void);
BIO_METHOD *BIO_s_null(void);
BIO_METHOD *BIO_f_null(void);
BIO_METHOD *BIO_f_buffer(void);
/* BIO_new_mem_buf became const void * in 1.0.2g */
BIO *BIO_new_mem_buf(void *, int);
long BIO_set_fd(BIO *, int, long);
long BIO_get_fd(BIO *, char *);
long BIO_set_mem_eof_return(BIO *, int);
long BIO_get_mem_data(BIO *, char **);
long BIO_set_mem_buf(BIO *, BUF_MEM *, int);
long BIO_get_mem_ptr(BIO *, BUF_MEM **);
long BIO_set_fp(BIO *, FILE *, int);
long BIO_get_fp(BIO *, FILE **);
long BIO_read_filename(BIO *, char *);
long BIO_write_filename(BIO *, char *);
long BIO_append_filename(BIO *, char *);
long BIO_rw_filename(BIO *, char *);
int BIO_should_read(BIO *);
int BIO_should_write(BIO *);
int BIO_should_io_special(BIO *);
int BIO_retry_type(BIO *);
int BIO_should_retry(BIO *);
int BIO_reset(BIO *);
int BIO_seek(BIO *, int);
int BIO_tell(BIO *);
int BIO_flush(BIO *);
int BIO_eof(BIO *);
int BIO_set_close(BIO *,long);
int BIO_get_close(BIO *);
int BIO_pending(BIO *);
int BIO_wpending(BIO *);
int BIO_get_info_callback(BIO *, bio_info_cb **);
int BIO_set_info_callback(BIO *, bio_info_cb *);
long BIO_get_buffer_num_lines(BIO *);
long BIO_set_read_buffer_size(BIO *, long);
long BIO_set_write_buffer_size(BIO *, long);
long BIO_set_buffer_size(BIO *, long);
long BIO_set_buffer_read_data(BIO *, void *, long);
long BIO_set_nbio(BIO *, long);
void BIO_set_retry_read(BIO *);
void BIO_clear_retry_flags(BIO *);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_110PRE4
int BIO_up_ref(BIO *b) {
    CRYPTO_add(&b->references, 1, CRYPTO_LOCK_BIO);
    return 1;
}
#endif
"""
