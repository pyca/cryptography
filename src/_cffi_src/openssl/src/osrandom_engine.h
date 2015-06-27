#ifdef _WIN32
#include <Wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#endif
