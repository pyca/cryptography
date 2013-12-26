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
#include <openssl/crypto.h>
"""

TYPES = """
"""

FUNCTIONS = """
static int Cryptography_setup_locking();
"""

MACROS = """
"""

CUSTOMIZATIONS = """
typedef enum CryptographyLockStatus {
    CRYPTOGRAPHY_LOCK_FAILURE = 0,
    CRYPTOGRAPHY_LOCK_ACQUIRED = 1,
    CRYPTOGRAPHY_LOCK_INTR = 2
} CryptographyLockStatus;

#ifdef _WIN32
#include <windows.h>

typedef struct CryptographyOpaque_ThreadLock NRMUTEX, *PNRMUTEX;

BOOL InitializeNonRecursiveMutex(PNRMUTEX mutex)
{
    mutex->sem = CreateSemaphore(NULL, 1, 1, NULL);
    return !!mutex->sem;
}

VOID DeleteNonRecursiveMutex(PNRMUTEX mutex)
{
    /* No in-use check */
    CloseHandle(mutex->sem);
    mutex->sem = NULL ; /* Just in case */
}

DWORD EnterNonRecursiveMutex(PNRMUTEX mutex, DWORD milliseconds)
{
    return WaitForSingleObject(mutex->sem, milliseconds);
}

BOOL LeaveNonRecursiveMutex(PNRMUTEX mutex)
{
    return ReleaseSemaphore(mutex->sem, 1, NULL);
}

int CryptographyThreadLockInit (struct CryptographyOpaque_ThreadLock *lock)
{
  return InitializeNonRecursiveMutex(lock);
}

void CryptographyOpaqueDealloc_ThreadLock
    (struct CryptographyOpaque_ThreadLock *lock)
{
    if (lock->sem != NULL)
    DeleteNonRecursiveMutex(lock);
}

/*
 * Return 1 on success if the lock was acquired
 *
 * and 0 if the lock was not acquired. This means a 0 is returned
 * if the lock has already been acquired by this thread!
 */
CryptographyLockStatus CryptographyThreadAcquireLock
    (struct CryptographyOpaque_ThreadLock *lock, int intr_flag)
{
    /* Fow now, intr_flag does nothing on Windows, and lock acquires are
     * uninterruptible.  */
    CryptographyLockStatus success;

    if ((lock &&
        EnterNonRecursiveMutex(lock, (DWORD)INFINITE) == WAIT_OBJECT_0)
    ) {
        success = CRYPTOGRAPHY_LOCK_ACQUIRED;
    }
    else {
        success = CRYPTOGRAPHY_LOCK_FAILURE;
    }

    return success;
}

void CryptographyThreadReleaseLock(struct CryptographyOpaque_ThreadLock *lock)
{
    if (!LeaveNonRecursiveMutex(lock))
        /* XXX complain? */;
}

#else

#include <unistd.h>
#include <semaphore.h>

#define CHECK_STATUS(name)  if (status != 0) { perror(name); error = 1; }

struct CryptographyOpaque_ThreadLock {
    sem_t sem;
    int initialized;
};

typedef struct CryptographyOpaque_ThreadLock CryptographyOpaque_ThreadLock;

int CryptographyThreadLockInit
    (struct CryptographyOpaque_ThreadLock *lock)
{
    int status, error = 0;
    lock->initialized = 0;
    status = sem_init(&lock->sem, 0, 1);
    CHECK_STATUS("sem_init");
    if (error)
        return 0;
    lock->initialized = 1;
    return 1;
}

void CryptographyOpaqueDealloc_ThreadLock
    (struct CryptographyOpaque_ThreadLock *lock)
{
    int status, error = 0;
    if (lock->initialized) {
        status = sem_destroy(&lock->sem);
        CHECK_STATUS("sem_destroy");
        /* 'error' is ignored;
           CHECK_STATUS already printed an error message */
    }
}

/*
 * As of February 2002, Cygwin thread implementations mistakenly report error
 * codes in the return value of the sem_ calls (like the pthread_ functions).
 * Correct implementations return -1 and put the code in errno. This supports
 * either.
 */
static int
rpythread_fix_status(int status)
{
    return (status == -1) ? errno : status;
}

CryptographyLockStatus CryptographyThreadAcquireLock
    (struct CryptographyOpaque_ThreadLock *lock, int intr_flag)
{
    CryptographyLockStatus success;
    sem_t *thelock = &lock->sem;
    int status, error = 0;
    struct timespec ts;

    do {
        status = rpythread_fix_status(sem_wait(thelock));
        /* Retry if interrupted by a signal, unless the caller wants to be
           notified.  */
    } while (!intr_flag && status == EINTR);

    /* Don't check the status if we're stopping because of an interrupt.  */
    if (!(intr_flag && status == EINTR)) {
        CHECK_STATUS("sem_wait");
    }

    if (status == 0) {
        success = CRYPTOGRAPHY_LOCK_ACQUIRED;
    } else if (intr_flag && status == EINTR) {
        success = CRYPTOGRAPHY_LOCK_INTR;
    } else {
        success = CRYPTOGRAPHY_LOCK_FAILURE;
    }

    return success;
}

void CryptographyThreadReleaseLock
    (struct CryptographyOpaque_ThreadLock *lock)
{
    sem_t *thelock = &lock->sem;
    int status, error = 0;

    status = sem_post(thelock);
    CHECK_STATUS("sem_post");
}

#endif

static int Cryptography_lock_count = -1;
static CryptographyOpaque_ThreadLock *Cryptography_locks = NULL;

static void Cryptography_locking_function
    (int mode, int n, const char *file, int line)
{
    if ((Cryptography_locks == NULL ||
        n < 0 ||
        n >= Cryptography_lock_count)
    ) {
        return;
    }

    if (mode & CRYPTO_LOCK) {
        CryptographyThreadAcquireLock(&Cryptography_locks[n], 1);
    } else {
        CryptographyThreadReleaseLock(&Cryptography_locks[n]);
    }
}


static int Cryptography_setup_locking() {
    unsigned int i;

    Cryptography_lock_count = CRYPTO_num_locks();

    Cryptography_locks = calloc(Cryptography_lock_count,
                                sizeof(CryptographyOpaque_ThreadLock));

    if (Cryptography_locks == NULL) {
        return -1;
    }

    for (i = 0; i < Cryptography_lock_count; ++i) {
        if (CryptographyThreadLockInit(&Cryptography_locks[i]) != 1) {
            return -1;
        }
    }

    CRYPTO_set_locking_callback(Cryptography_locking_function);

    return 0;
}
"""

CONDITIONAL_NAMES = {}
