static const char *Cryptography_osrandom_engine_id = "osrandom";
static const char *Cryptography_osrandom_engine_name = "osrandom_engine";

#if defined(_WIN32)
static HCRYPTPROV hCryptProv = 0;

static int osrandom_init(ENGINE *e) {
    if (hCryptProv > 0) {
        return 1;
    }
    if (CryptAcquireContext(&hCryptProv, NULL, NULL,
                            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return 1;
    } else {
        return 0;
    }
}

static int osrandom_rand_bytes(unsigned char *buffer, int size) {
    if (hCryptProv == 0) {
        return 0;
    }

    if (!CryptGenRandom(hCryptProv, (DWORD)size, buffer)) {
        ERR_put_error(
            ERR_LIB_RAND, 0, ERR_R_RAND_LIB, "osrandom_engine.py", 0
        );
        return 0;
    }
    return 1;
}

static int osrandom_finish(ENGINE *e) {
    if (CryptReleaseContext(hCryptProv, 0)) {
        hCryptProv = 0;
        return 1;
    } else {
        return 0;
    }
}

static int osrandom_rand_status(void) {
    if (hCryptProv == 0) {
        return 0;
    } else {
        return 1;
    }
}
#else
static struct {
    int fd;
    dev_t st_dev;
    ino_t st_ino;
} urandom_cache = { -1 };

static int osrandom_finish(ENGINE *e);

static int osrandom_init(ENGINE *e) {
    struct stat st;

    if (urandom_cache.fd > -1) {
        return 1;
    }
    urandom_cache.fd = open("/dev/urandom", O_RDONLY);
    if (urandom_cache.fd > -1) {
        int flags = fcntl(urandom_cache.fd, F_GETFD);
        if (flags == -1) {
            osrandom_finish(e);
            return 0;
        } else if (fcntl(urandom_cache.fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
            osrandom_finish(e);
            return 0;
        }
        errno = 0;
        if (fstat(urandom_cache.fd, &st) == -1) {
            /* As long as fstat failed for a reason that's not a bad file
             * descriptor, call osrandom_finish to close the fd */
            if (errno != EBADF) {
                osrandom_finish(e);
                return 0;
            } else {
                urandom_cache.fd = -1;
                return 0;
            }
        }
        urandom_cache.st_dev = st.st_dev;
        urandom_cache.st_ino = st.st_ino;
        return 1;
    } else {
        return 0;
    }
}

static int osrandom_rand_bytes(unsigned char *buffer, int size) {
    ssize_t n;
    struct stat st;

    if (fstat(urandom_cache.fd, &st) == -1 ||
        st.st_dev != urandom_cache.st_dev ||
        st.st_ino != urandom_cache.st_ino) {
        /* The fd has changed since we opened it (or fstat failed) */
        ERR_put_error(
            ERR_LIB_RAND,
            0,
            ERR_R_RAND_LIB,
            "osrandom_engine.py urandom fd changed",
            0
        );
        return 0;
    }
    while (size > 0) {
        do {
            n = read(urandom_cache.fd, buffer, (size_t)size);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) {
            ERR_put_error(
                ERR_LIB_RAND, 0, ERR_R_RAND_LIB, "osrandom_engine.py", 0
            );
            return 0;
        }
        buffer += n;
        size -= n;
    }
    return 1;
}

static int osrandom_finish(ENGINE *e) {
    int n;
    do {
        n = close(urandom_cache.fd);
    } while (n < 0 && errno == EINTR);
    urandom_cache.fd = -1;
    urandom_cache.st_dev = -1;
    urandom_cache.st_ino = -1;
    if (n < 0) {
        return 0;
    } else {
        return 1;
    }
}

static int osrandom_rand_status(void) {
    if (urandom_cache.fd == -1 ||
        urandom_cache.st_dev == -1 ||
        urandom_cache.st_ino == -1) {
        return 0;
    } else {
        return 1;
    }
}
#endif

/* This replicates the behavior of the OpenSSL FIPS RNG, which returns a
   -1 in the event that there is an error when calling RAND_pseudo_bytes. */
static int osrandom_pseudo_rand_bytes(unsigned char *buffer, int size) {
    int res = osrandom_rand_bytes(buffer, size);
    if (res == 0) {
        return -1;
    } else {
        return res;
    }
}

static RAND_METHOD osrandom_rand = {
    NULL,
    osrandom_rand_bytes,
    NULL,
    NULL,
    osrandom_pseudo_rand_bytes,
    osrandom_rand_status,
};

/* Returns 1 if successfully added, 2 if engine has previously been added,
   and 0 for error. */
int Cryptography_add_osrandom_engine(void) {
    ENGINE *e;
    e = ENGINE_by_id(Cryptography_osrandom_engine_id);
    if (e != NULL) {
        ENGINE_free(e);
        return 2;
    } else {
        ERR_clear_error();
    }

    e = ENGINE_new();
    if (e == NULL) {
        return 0;
    }
    if(!ENGINE_set_id(e, Cryptography_osrandom_engine_id) ||
            !ENGINE_set_name(e, Cryptography_osrandom_engine_name) ||
            !ENGINE_set_RAND(e, &osrandom_rand) ||
            !ENGINE_set_init_function(e, osrandom_init) ||
            !ENGINE_set_finish_function(e, osrandom_finish)) {
        ENGINE_free(e);
        return 0;
    }
    if (!ENGINE_add(e)) {
        ENGINE_free(e);
        return 0;
    }
    if (!ENGINE_free(e)) {
        return 0;
    }

    return 1;
}
