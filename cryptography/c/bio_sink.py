INCLUDES = [
    '#include <openssl/bio.h>',
]

TYPES = [
    'static const int BIO_TYPE_MEM;',
    'static const int BIO_TYPE_FILE;',
    'static const int BIO_TYPE_FD;',
    'static const int BIO_TYPE_SOCKET;',
    'static const int BIO_TYPE_CONNECT;',
    'static const int BIO_TYPE_ACCEPT;',
    'static const int BIO_TYPE_NULL;',
    'static const int BIO_CLOSE;',
    'static const int BIO_NOCLOSE;',
    'static const int BIO_TYPE_SOURCE_SINK;',
]

FUNCTIONS = [
    # BIO mem buffers
    'BIO_METHOD *BIO_s_mem(void);',
    'long BIO_set_mem_eof_return(BIO *b, int v);',
    'long BIO_get_mem_data(BIO *b, char **pp);',
    'long BIO_set_mem_buf(BIO *b,BUF_MEM *bm,int c);',
    'long BIO_get_mem_ptr(BIO *b,BUF_MEM **pp);',
    'BIO *BIO_new_mem_buf(void *buf, int len);',
    # BIO files
    'BIO_METHOD *BIO_s_file(void);',
    'BIO *BIO_new_file(const char *filename, const char *mode);',
    'BIO *BIO_new_fp(FILE *stream, int flags);',
    'long BIO_set_fp(BIO *b, FILE *fp, int flags);',
    'long BIO_get_fp(BIO *b, FILE **fpp);',
    'int BIO_read_filename(BIO *b, char *name);',
    'int BIO_write_filename(BIO *b, char *name);',
    'int BIO_append_filename(BIO *b, char *name);',
    'int BIO_rw_filename(BIO *b, char *name);',
    # BIO fd
    'BIO_METHOD *BIO_s_fd(void);',
    'long BIO_set_fd(BIO *bp, long fd, int cmd);',
    'long BIO_get_fd(BIO *bp, char *c);',
    'BIO *BIO_new_fd(int fd, int close_flag);',
    # BIO socket
    'BIO_METHOD *BIO_s_socket(void);'
    'BIO *BIO_new_socket(int sock, int close_flag);'
    # BIO connect
    # TODO
    # BIO accept
    # TODO
    # BIO null
    'BIO_METHOD *BIO_s_null(void);',
]
