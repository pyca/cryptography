#ifdef _WIN32
  #include <Wincrypt.h>
#else
  #include <fcntl.h>
  #include <unistd.h>
   /* for defined(BSD) */
  #include <sys/param.h>

  #ifdef BSD
    /* for SYS_getentropy */
    #include <sys/syscall.h>
  #endif

  #ifdef __APPLE__
    #include <sys/random.h>
  #endif

  #ifdef __linux__
    /* for SYS_getrandom */
    #include <sys/syscall.h>
    #ifndef GRND_NONBLOCK
      #define GRND_NONBLOCK 0x0001
    #endif /* GRND_NONBLOCK */
  #endif /* _linux__ */
#endif /* _WIN32 */

#define CRYPTOGRAPHY_OSRANDOM_ENGINE_CRYPTGENRANDOM 1
#define CRYPTOGRAPHY_OSRANDOM_ENGINE_GETENTROPY 2
#define CRYPTOGRAPHY_OSRANDOM_ENGINE_GETRANDOM 3
#define CRYPTOGRAPHY_OSRANDOM_ENGINE_DEV_URANDOM 4

#ifndef CRYPTOGRAPHY_OSRANDOM_ENGINE
  #if defined(_WIN32)
    /* Windows */
    #define CRYPTOGRAPHY_OSRANDOM_ENGINE CRYPTOGRAPHY_OSRANDOM_ENGINE_CRYPTGENRANDOM
  #elif defined(BSD) && defined(SYS_getentropy)
    /* OpenBSD 5.6+ or macOS 10.12+ */
    #define CRYPTOGRAPHY_OSRANDOM_ENGINE CRYPTOGRAPHY_OSRANDOM_ENGINE_GETENTROPY
  #elif defined(__linux__) && defined(SYS_getrandom)
    /* Linux 3.4.17+ */
    #define CRYPTOGRAPHY_OSRANDOM_ENGINE CRYPTOGRAPHY_OSRANDOM_ENGINE_GETRANDOM
  #else
    /* Keep this as last entry, fall back to /dev/urandom */
    #define CRYPTOGRAPHY_OSRANDOM_ENGINE CRYPTOGRAPHY_OSRANDOM_ENGINE_DEV_URANDOM
  #endif
#endif /* CRYPTOGRAPHY_OSRANDOM_ENGINE */

/* Fallbacks need /dev/urandom helper functions. */
#if CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_GETRANDOM || \
     CRYPTOGRAPHY_OSRANDOM_ENGINE == CRYPTOGRAPHY_OSRANDOM_ENGINE_DEV_URANDOM
  #define CRYPTOGRAPHY_OSRANDOM_NEEDS_DEV_URANDOM 1
#endif

#define CRYPTOGRAPHY_OSRANDOM_put_error(funcname) \
      ERR_put_error(ERR_LIB_RAND, 0, 0, funcname, 0)

/* engine ctrl */
#define CRYPTOGRAPHY_OSRANDOM_GET_IMPLEMENTATION ENGINE_CMD_BASE
