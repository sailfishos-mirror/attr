#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/xattr.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>

#include "attr/libattr.h"

ssize_t setxattrat(int dirfd, const char *path, const char *name,
		   void *value, size_t size, int flags)
{
        if (dirfd == AT_FDCWD)
                return setxattr(path, name, value, size, flags);
        else if (path && !*path)
                return fsetxattr(dirfd, name, value, size, flags);
        else {
                char fd_path[10 * sizeof(int) * CHAR_BIT / 33 + 3];
                ssize_t ret;
                int fd;

                fd = openat(dirfd, path, O_PATH | O_CLOEXEC);
                if (fd == -1)
                        return -1;
                sprintf(fd_path, "/proc/self/fd/%d", fd);
                ret = setxattr(fd_path, name, value, size, flags);
                close(fd);
                return ret;
        }
}
