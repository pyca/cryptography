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
#ifdef _WIN32
#include <Wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif
"""

TYPES = """
static const char *const Cryptography_urandom_engine_name;
static const char *const Cryptography_urandom_engine_id;
"""

FUNCTIONS = """
int Cryptography_add_urandom_engine(void);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
static const char *Cryptography_urandom_engine_id= "urandom";
static const char *Cryptography_urandom_engine_name = "urandom_engine";

#ifndef _WIN32
static int urandom_fd = -1;

static int urandom_rand_bytes(unsigned char *buffer, int size) {
    ssize_t n;
    while (0 < size) {
        do {
            n = read(urandom_fd, buffer, (size_t)size);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) {
            return 0;
            break;
        }
        buffer += n;
        size -= n;
    }
    return 1;
}

static int urandom_rand_status(void) {
    if (urandom_fd == -1) {
        return 0;
    } else {
        return 1;
    }
}

static int urandom_init(ENGINE *e) {
    if (urandom_fd > -1) {
        return 1;
    }
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd > -1) {
        return 1;
    } else {
        return 0;
    }
}

static int urandom_finish(ENGINE *e) {
    int n;
    do {
        n = close(urandom_fd);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        return 0;
    } else {
        urandom_fd = -1;
        return 1;
    }
}
#endif

#ifdef _WIN32
static HCRYPTPROV hCryptProv = 0;

static int urandom_init(ENGINE *e) {
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

static int urandom_rand_bytes(unsigned char *buffer, int size) {
    size_t chunk;

    if (hCryptProv == 0) {
        return 0;
    }

    while (size > 0) {
        chunk = size;
        if (!CryptGenRandom(hCryptProv, (DWORD)chunk, buffer)) {
            return 0;
        }
        buffer += chunk;
        size -= chunk;
    }
    return 1;
}

static int urandom_finish(ENGINE *e) {
    if (CryptReleaseContext(hCryptProv, 0)) {
        hCryptProv = 0;
        return 1;
    } else {
        return 0;
    }
}

static int urandom_rand_status(void) {
    if (hCryptProv == 0) {
        return 0;
    } else {
        return 1;
    }
}
#endif /* MS_WINDOWS */

static RAND_METHOD urandom_rand = {
    NULL,
    urandom_rand_bytes,
    NULL,
    NULL,
    urandom_rand_bytes,
    urandom_rand_status,
};

int Cryptography_add_urandom_engine(void) {
    ENGINE *e = ENGINE_new();
    if (e == NULL) {
        return 0;
    }
    if(!ENGINE_set_id(e, Cryptography_urandom_engine_id) ||
            !ENGINE_set_name(e, Cryptography_urandom_engine_name) ||
            !ENGINE_set_RAND(e, &urandom_rand) ||
            !ENGINE_set_init_function(e, urandom_init) ||
            !ENGINE_set_finish_function(e, urandom_finish)) {
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
"""

CONDITIONAL_NAMES = {}
