/* osurandom engine
 *
 * Windows         CryptGenRandom()
 * macOS >= 10.12  getentropy()
 * OpenBSD 5.6+    getentropy()
 * other BSD       getentropy() if SYS_getentropy is defined
 * Linux 3.4.17+   getrandom() with fallback to /dev/urandom
 * other           /dev/urandom with cached fd
 *
 * The /dev/urandom, getrandom and getentropy code is derived from Python's
 * Python/random.c, written by Antoine Pitrou and Victor Stinner.
 *
 * Copyright 2001-2016 Python Software Foundation; All Rights Reserved.
 */

static const char *Cryptography_osrandom_engine_id = "osrandom";

/****************************************************************************
 * Windows
 */
#if CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_CRYPTGENRANDOM
static const char *Cryptography_osrandom_engine_name = "osrandom_engine CryptGenRandom()";
static HCRYPTPROV hCryptProv = 0;

static int osrandom_init(ENGINE *e) {
    if (hCryptProv != 0) {
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
        CRYPTOGRAPHY_OSRANDOM_put_error(
            "osrandom_engine.py:CryptGenRandom()");
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
    return hCryptProv != 0;
}

static const char *osurandom_get_implementation(void) {
    return "CryptGenRandom";
}

#endif /* CRYPTOGRAPHY_OSRANDOM_ENGINE_CRYPTGENRANDOM */

/****************************************************************************
 * BSD getentropy
 */
#if CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_GETENTROPY
static const char *Cryptography_osrandom_engine_name = "osrandom_engine getentropy()";

static int osrandom_init(ENGINE *e) {
    return 1;
}

static int osrandom_rand_bytes(unsigned char *buffer, int size) {
    int len, res;
    while (size > 0) {
        /* OpenBSD and macOS restrict maximum buffer size to 256. */
        len = size > 256 ? 256 : size;
        res = getentropy(buffer, len);
        if (res < 0) {
            CRYPTOGRAPHY_OSRANDOM_put_error(
                "osrandom_engine.py:getentropy()");
            return 0;
        }
        buffer += len;
        size -= len;
    }
    return 1;
}

static int osrandom_finish(ENGINE *e) {
    return 1;
}

static int osrandom_rand_status(void) {
    return 1;
}

static const char *osurandom_get_implementation(void) {
    return "getentropy";
}
#endif /* CRYPTOGRAPHY_OSRANDOM_ENGINE_GETENTROPY */

/****************************************************************************
 * /dev/urandom helpers for all non-BSD Unix platforms
 */
#ifdef CRYPTOGRAPHY_OSRANDOM_NEEDS_DEV_URANDOM

static struct {
    int fd;
    dev_t st_dev;
    ino_t st_ino;
} urandom_cache = { -1 };

/* return -1 on error */
static int dev_urandom_fd(void) {
    int fd, n, flags;
    struct stat st;

    /* Check that fd still points to the correct device */
    if (urandom_cache.fd >= 0) {
        if (fstat(urandom_cache.fd, &st)
                || st.st_dev != urandom_cache.st_dev
                || st.st_ino != urandom_cache.st_ino) {
            /* Somebody replaced our FD. Invalidate our cache but don't
             * close the fd. */
            urandom_cache.fd = -1;
        }
    }
    if (urandom_cache.fd < 0) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            goto error;
        }
        if (fstat(fd, &st)) {
            goto error;
        }
        /* set CLOEXEC flag */
        flags = fcntl(fd, F_GETFD);
        if (flags == -1) {
            goto error;
        } else if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
            goto error;
        }
        /* Another thread initialized the fd */
        if (urandom_cache.fd >= 0) {
            do {
                n = close(fd);
            } while (n < 0 && errno == EINTR);
            return urandom_cache.fd;
        }
        urandom_cache.st_dev = st.st_dev;
        urandom_cache.st_ino = st.st_ino;
        urandom_cache.fd = fd;
    }
    return urandom_cache.fd;

  error:
    if (fd != -1) {
        do {
            n = close(fd);
        } while (n < 0 && errno == EINTR);
    }
    CRYPTOGRAPHY_OSRANDOM_put_error(
        "osrandom_engine.py:dev_urandom_fd()");
    return -1;
}

static int dev_urandom_read(unsigned char *buffer, int size) {
    int fd;
    ssize_t n;

    fd = dev_urandom_fd();
    if (fd < 0) {
        return 0;
    }

    while (size > 0) {
        do {
            n = read(fd, buffer, (size_t)size);
        } while (n < 0 && errno == EINTR);

        if (n <= 0) {
            CRYPTOGRAPHY_OSRANDOM_put_error(
                "osrandom_engine.py:dev_urandom_read()");
            return 0;
        }
        buffer += n;
        size -= n;
    }
    return 1;
}

static void dev_urandom_close(void) {
    if (urandom_cache.fd >= 0) {
        int fd, n;
        struct stat st;

        if (fstat(urandom_cache.fd, &st)
                && st.st_dev == urandom_cache.st_dev
                && st.st_ino == urandom_cache.st_ino) {
            fd = urandom_cache.fd;
            urandom_cache.fd = -1;
            do {
                n = close(fd);
            } while (n < 0 && errno == EINTR);
        }
    }
}
#endif /* CRYPTOGRAPHY_OSRANDOM_NEEDS_DEV_URANDOM */

/****************************************************************************
 * Linux getrandom engine with fallback to dev_urandom
 */

#if CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_GETRANDOM
static const char *Cryptography_osrandom_engine_name = "osrandom_engine getrandom()";

static int getrandom_works = -1;

static int osrandom_init(ENGINE *e) {
    /* We try to detect working getrandom until we succeed. */
    if (getrandom_works != 1) {
        long n;
        char dest[1];
        n = syscall(SYS_getrandom, dest, sizeof(dest), GRND_NONBLOCK);
        if (n < 0) {
            /* Can fail with:
             * - ENOSYS: Kernel does not support the syscall.
             * - ENOPERM: seccomp prevents syscall.
             * - EAGAIN: Kernel CRPNG has not been seeded yet.
             * EINTR cannot occur for buflen < 256.
             */
            getrandom_works = 0;
        } else {
            getrandom_works = 1;
        }
    }
    /* fallback to dev urandom */
    if (getrandom_works == 0) {
        int fd = dev_urandom_fd();
        if (fd < 0) {
            return 0;
        }
    }
    return 1;
}

static int osrandom_rand_bytes(unsigned char *buffer, int size) {
    if (getrandom_works == 1) {
        long n;
        while (size > 0) {
            do {
                n = syscall(SYS_getrandom, buffer, size, GRND_NONBLOCK);
            } while (n < 0 && errno == EINTR);

            if (n <= 0) {
                CRYPTOGRAPHY_OSRANDOM_put_error(
                    "osrandom_engine.py:SYS_getrandom");
                return 0;
            }
            buffer += n;
            size -= n;
        }
        return 1;
    } else {
        return dev_urandom_read(buffer, size);
    }
}

static int osrandom_finish(ENGINE *e) {
    dev_urandom_close();
    return 1;
}

static int osrandom_rand_status(void) {
    if ((getrandom_works != 1) && (urandom_cache.fd < 0)) {
        return 0;
    }
    return 1;
}

static const char *osurandom_get_implementation(void) {
    if (getrandom_works == 1) {
        return "getrandom";
    }
    return "/dev/urandom";
}
#endif /* CRYPTOGRAPHY_OSRANDOM_ENGINE_GETRANDOM */

/****************************************************************************
 * dev_urandom engine for all remaining platforms
 */

#if CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_DEV_URANDOM
static const char *Cryptography_osrandom_engine_name = "osrandom_engine /dev/urandom";

static int osrandom_init(ENGINE *e) {
    int fd = dev_urandom_fd();
    if (fd < 0) {
        return 0;
    }
    return 1;
}

static int osrandom_rand_bytes(unsigned char *buffer, int size) {
    return dev_urandom_read(buffer, size);
}

static int osrandom_finish(ENGINE *e) {
    dev_urandom_close();
    return 1;
}

static int osrandom_rand_status(void) {
    return urandom_cache.fd >= 0;
}

static const char *osurandom_get_implementation(void) {
    return "/dev/urandom";
}
#endif /* CRYPTOGRAPHY_OSRANDOM_ENGINE_DEV_URANDOM */

/****************************************************************************
 * ENGINE boiler plate
 */

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

static const ENGINE_CMD_DEFN osrandom_cmd_defns[] = {
    {CRYPTOGRAPHY_OSRANDOM_GET_IMPLEMENTATION,
     "get_implementation",
     "Get CPRNG implementation.",
     ENGINE_CMD_FLAG_NO_INPUT},
     {0, NULL, NULL, 0}
};

static int osrandom_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void)) {
    const char *name;
    size_t len;

    switch (cmd) {
    case CRYPTOGRAPHY_OSRANDOM_GET_IMPLEMENTATION:
        /* i: buffer size, p: char* buffer */
        name = osurandom_get_implementation();
        len = strlen(name);
        if ((p == NULL) && (i == 0)) {
            /* return required buffer len */
            return len;
        }
        if ((p == NULL) || i < 0 || ((size_t)i <= len)) {
            /* no buffer or buffer too small */
            ENGINEerr(ENGINE_F_ENGINE_CTRL, ENGINE_R_INVALID_ARGUMENT);
            return 0;
        }
        strncpy((char *)p, name, len);
        return len;
    default:
        ENGINEerr(ENGINE_F_ENGINE_CTRL, ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED);
        return 0;
    }
}

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
            !ENGINE_set_finish_function(e, osrandom_finish) ||
            !ENGINE_set_cmd_defns(e, osrandom_cmd_defns) ||
            !ENGINE_set_ctrl_function(e, osrandom_ctrl)) {
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
