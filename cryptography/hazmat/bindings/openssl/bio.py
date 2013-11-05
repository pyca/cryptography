# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

INCLUDES = """
#include <openssl/bio.h>
"""

TYPES = """
typedef struct bio_st BIO;
typedef void bio_info_cb(BIO *, int, const char *, int, long, long);
struct bio_method_st {
    int type;
    const char *name;
    int (*bwrite)(BIO *, const char *, int);
    int (*bread)(BIO *, char *, int);
    int (*bputs)(BIO *, const char *);
    int (*bgets)(BIO *, char*, int);
    long (*ctrl)(BIO *, int, long, void *);
    int (*create)(BIO *);
    int (*destroy)(BIO *);
    long (*callback_ctrl)(BIO *, int, bio_info_cb *);
    ...;
};
typedef struct bio_method_st BIO_METHOD;
struct bio_st {
    BIO_METHOD *method;
    long (*callback)(struct bio_st*, int, const char*, int, long, long);
    char *cb_arg;
    int init;
    int shutdown;
    int flags;
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;
    struct bio_st *prev_bio;
    int references;
    unsigned long num_read;
    unsigned long num_write;
    ...;
};
typedef ... BUF_MEM;
"""

FUNCTIONS = """
BIO* BIO_new(BIO_METHOD *);
int BIO_set(BIO *, BIO_METHOD *);
int BIO_free(BIO *);
void BIO_vfree(BIO *);
void BIO_free_all(BIO *);
BIO *BIO_push(BIO *, BIO *);
BIO *BIO_pop(BIO *);
BIO *BIO_next(BIO *);
BIO *BIO_find_type(BIO *, int);
int BIO_method_type(const BIO *);
BIO_METHOD *BIO_s_mem();
BIO *BIO_new_mem_buf(void *, int);
BIO_METHOD *BIO_s_file();
BIO *BIO_new_file(const char *, const char *);
BIO *BIO_new_fp(FILE *, int);
BIO_METHOD *BIO_s_fd();
BIO *BIO_new_fd(int, int);
BIO_METHOD *BIO_s_socket();
BIO *BIO_new_socket(int, int);
BIO_METHOD *BIO_s_null();
long BIO_ctrl(BIO *, int, long, void *);
long BIO_callback_ctrl(
    BIO *,
    int,
    void (*)(struct bio_st *, int, const char *, int, long, long)
);
char* BIO_ptr_ctrl(BIO *bp, int cmd, long larg);
long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);
size_t BIO_ctrl_pending(BIO *b);
size_t BIO_ctrl_wpending(BIO *b);
int BIO_read(BIO *, void *, int);
int BIO_gets(BIO *, char *, int);
int BIO_write(BIO *, const void *, int);
int BIO_puts(BIO *, const char *);
BIO_METHOD *BIO_f_null();
BIO_METHOD *BIO_f_buffer();
"""

MACROS = """
long BIO_set_fd(BIO *, long, int);
long BIO_get_fd(BIO *, char *);
long BIO_set_mem_eof_return(BIO *, int);
long BIO_get_mem_data(BIO *, char **);
long BIO_set_mem_buf(BIO *, BUF_MEM *, int);
long BIO_get_mem_ptr(BIO *, BUF_MEM **);
long BIO_set_fp(BIO *, FILE *, int);
long BIO_get_fp(BIO *, FILE **);
int BIO_read_filename(BIO *, char *);
int BIO_write_filename(BIO *, char *);
int BIO_append_filename(BIO *, char *);
int BIO_rw_filename(BIO *, char *);
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
#define BIO_TYPE_MEM ...
#define BIO_TYPE_FILE ...
#define BIO_TYPE_FD ...
#define BIO_TYPE_SOCKET ...
#define BIO_TYPE_CONNECT ...
#define BIO_TYPE_ACCEPT ...
#define BIO_TYPE_NULL ...
#define BIO_CLOSE ...
#define BIO_NOCLOSE ...
#define BIO_TYPE_SOURCE_SINK ...
#define BIO_CTRL_RESET ...
#define BIO_CTRL_EOF ...
#define BIO_CTRL_SET ...
#define BIO_CTRL_SET_CLOSE ...
#define BIO_CTRL_FLUSH ...
#define BIO_CTRL_DUP ...
#define BIO_CTRL_GET_CLOSE ...
#define BIO_CTRL_INFO ...
#define BIO_CTRL_GET ...
#define BIO_CTRL_PENDING ...
#define BIO_CTRL_WPENDING ...
#define BIO_C_FILE_SEEK ...
#define BIO_C_FILE_TELL ...
#define BIO_TYPE_NONE ...
#define BIO_TYPE_PROXY_CLIENT ...
#define BIO_TYPE_PROXY_SERVER ...
#define BIO_TYPE_NBIO_TEST ...
#define BIO_TYPE_BER ...
#define BIO_TYPE_BIO ...
#define BIO_TYPE_DESCRIPTOR ...
#define BIO_FLAGS_READ ...
#define BIO_FLAGS_WRITE ...
#define BIO_FLAGS_IO_SPECIAL ...
#define BIO_FLAGS_RWS ...
#define BIO_FLAGS_SHOULD_RETRY ...
#define BIO_TYPE_NULL_FILTER ...
#define BIO_TYPE_SSL ...
#define BIO_TYPE_MD ...
#define BIO_TYPE_BUFFER ...
#define BIO_TYPE_CIPHER ...
#define BIO_TYPE_BASE64 ...
#define BIO_TYPE_FILTER ...
"""

CUSTOMIZATIONS = """
"""
