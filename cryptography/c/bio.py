INCLUDES = [
    '#include <openssl/bio.h>',
]

TYPES = [
    # BIO ctrl constants
    'static const int BIO_CTRL_RESET;',
    'static const int BIO_CTRL_EOF;',
    'static const int BIO_CTRL_SET;',
    'static const int BIO_CTRL_SET_CLOSE;',
    'static const int BIO_CTRL_FLUSH;',
    'static const int BIO_CTRL_DUP;',
    'static const int BIO_CTRL_GET_CLOSE;',
    'static const int BIO_CTRL_INFO;',
    'static const int BIO_CTRL_GET;',
    'static const int BIO_CTRL_PENDING;',
    'static const int BIO_CTRL_WPENDING;',
    'static const int BIO_C_FILE_SEEK;',
    'static const int BIO_C_FILE_TELL;',
    # BIO type constants
    'static const int BIO_TYPE_NONE;',
    'static const int BIO_TYPE_PROXY_CLIENT;',
    'static const int BIO_TYPE_PROXY_SERVER;',
    'static const int BIO_TYPE_NBIO_TEST;',
    'static const int BIO_TYPE_BER;',
    'static const int BIO_TYPE_BIO;',
    'static const int BIO_TYPE_DESCRIPTOR;',
    # BIO flags
    'static const int BIO_FLAGS_READ;',
    'static const int BIO_FLAGS_WRITE;',
    'static const int BIO_FLAGS_IO_SPECIAL;',
    'static const int BIO_FLAGS_RWS;',
    'static const int BIO_FLAGS_SHOULD_RETRY;',
    'typedef ... BUF_MEM;',
    # BIO forward declaration
    'typedef struct bio_st BIO;',
    # BIO callbacks definition
    'typedef void bio_info_cb(BIO *b, int oper, const char *ptr, int arg1, long arg2, long arg3);',
    # BIO_METHOD definition
    '''
    struct bio_method_st {
        int type;
        const char *name;
        int (*bwrite)(BIO*, const char*, int);
        int (*bread)(BIO*, char*, int);
        int (*bputs)(BIO*, const char*);
        int (*bgets)(BIO*, char*, int);
        long (*ctrl)(BIO*, int, long, void*);
        int (*create)(BIO*);
        int (*destroy)(BIO*);
        long (*callback_ctrl)(BIO*, int, bio_info_cb*);
        ...;
    };''',
    'typedef struct bio_method_st BIO_METHOD;',
    # BIO definition
    '''
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
    };''',
]

FUNCTIONS = [
    # BIO create functions
    'BIO* BIO_new(BIO_METHOD *type);',
    'int BIO_set(BIO *a, BIO_METHOD *type);',
    'int BIO_free(BIO *a);',
    'void BIO_vfree(BIO *a);',
    'void BIO_free_all(BIO *a);',
    # BIO stacking functions
    'BIO* BIO_push(BIO *b, BIO *append);',
    'BIO* BIO_pop(BIO *b);',
    'BIO* BIO_next(BIO *b);',
    'BIO* BIO_find_type(BIO *b, int bio_type);',
    'int BIO_method_type(BIO *b);',
    # BIO control functions
    'long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);',
    'long BIO_callback_ctrl(BIO *b, int cmd, void (*fp)(struct bio_st *, int, const char *, int, long, long));',
    'char* BIO_ptr_ctrl(BIO *bp, int cmd, long larg);',
    'long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);',
    'int BIO_reset(BIO *b);',
    'int BIO_seek(BIO *b, int ofs);',
    'int BIO_tell(BIO *b);',
    'int BIO_flush(BIO *b);',
    'int BIO_eof(BIO *b);',
    'int BIO_set_close(BIO *b,long flag);',
    'int BIO_get_close(BIO *b);',
    'int BIO_pending(BIO *b);',
    'int BIO_wpending(BIO *b);',
    'size_t BIO_ctrl_pending(BIO *b);',
    'size_t BIO_ctrl_wpending(BIO *b);',
    'int BIO_get_info_callback(BIO *b,bio_info_cb **cbp);',
    'int BIO_set_info_callback(BIO *b,bio_info_cb *cb);',
    # BIO IO functions
    'int BIO_read(BIO *b, void *buf, int len);',
    'int BIO_gets(BIO *b, char *buf, int size);',
    'int BIO_write(BIO *b, const void *buf, int len);',
    'int BIO_puts(BIO *b, const char *buf);',
    # BIO should functions
    'int BIO_should_read(BIO *b);',
    'int BIO_should_write(BIO *b);',
    'int BIO_should_io_special(BIO *b);',
    'int BIO_retry_type(BIO *b);',
    'int BIO_should_retry(BIO *b);',
]
