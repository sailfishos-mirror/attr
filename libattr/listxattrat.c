#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/xattr.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>

#include "attr/libattr.h"

ssize_t listxattrat(int dirfd, const char *path, char *list, size_t size)
{
        if (dirfd == AT_FDCWD)
                return listxattr(path, list, size);
        else if (path && !*path)
                return flistxattr(dirfd, list, size);
        else {
                char fd_path[10 * sizeof(int) * CHAR_BIT / 33 + 3];
                ssize_t ret;
                int fd;

                fd = openat(dirfd, path, O_PATH | O_CLOEXEC);
                if (fd == -1)
                        return -1;
                sprintf(fd_path, "/proc/self/fd/%d", fd);
                ret = listxattr(fd_path, list, size);
                close(fd);
                return ret;
        }
}
