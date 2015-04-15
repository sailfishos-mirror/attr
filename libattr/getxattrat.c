#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/xattr.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <limits.h>

#include "attr/libattr.h"

ssize_t getxattrat(int dirfd, const char *path, const char *name,
		   void *value, size_t size)
{
        if (dirfd == AT_FDCWD)
                return getxattr(path, name, value, size);
        else if (path && !*path)
                return fgetxattr(dirfd, name, value, size);
        else {
                char fd_path[10 * sizeof(int) * CHAR_BIT / 33 + 3];
                ssize_t ret;
                int fd;

                fd = openat(dirfd, path, O_PATH | O_CLOEXEC);
                if (fd == -1)
                        return -1;
                sprintf(fd_path, "/proc/self/fd/%d", fd);
                ret = getxattr(fd_path, name, value, size);
                close(fd);
                return ret;
        }
}
