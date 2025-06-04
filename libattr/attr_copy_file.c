/*
  Copyright (C) 2002 Andreas Gruenbacher <agruen@suse.de>, SuSE Linux AG.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this manual.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Copy extended attributes between files. */

#if defined (HAVE_CONFIG_H)
#include "config.h"
#endif

#include <sys/types.h>
# include <sys/xattr.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(HAVE_ATTR_LIBATTR_H)
# include "attr/libattr.h"
#endif

#define ERROR_CONTEXT_MACROS
#include "error_context.h"
#include "nls.h"

#if !defined(ENOTSUP)
# define ENOTSUP (-1)
#endif

/* Copy extended attributes from src_path to dst_path. If the file
   has an extended Access ACL (system.posix_acl_access) and that is
   copied successfully, the file mode permission bits are copied as
   a side effect. This may not always the case, so the file mode
   and/or ownership must be copied separately. */
int
attr_copy_file(const char *src_path, const char *dst_path,
	       int (*check) (const char *, struct error_context *),
	       struct error_context *ctx)
{
#if defined(HAVE_LISTXATTR) && defined(HAVE_GETXATTR) && defined(HAVE_SETXATTR)
	int ret = 0;
	ssize_t nsize;
	char namesbuf[512];
	char *names = namesbuf, *name, *value = NULL;
	size_t namesalloc = sizeof namesbuf;
	int setxattr_ENOTSUP = 0;

	/* ignore acls by default */
	if (check == NULL)
		check = attr_copy_check_permissions;

	for (;;) {
		size_t more = 2 * namesalloc;
		nsize = llistxattr (src_path, names, namesalloc - 1);
		if (nsize >= 0 || errno != ERANGE)
			break;
		if (names != namesbuf)
			free (names);
		names = namesalloc < more ? malloc (more) : NULL;
		if (names == NULL) {
			error (ctx, "");
			ret = -1;
			goto getout;
		}
		namesalloc = more;
	}

	if (nsize < 0) {
		if (errno != ENOSYS && errno != ENOTSUP) {
			const char *qpath = quote (ctx, src_path);
			error (ctx, _("listing attributes of %s"), qpath);
			quote_free (ctx, qpath);
			ret = -1;
		}
		goto getout;
	}

	/* Append an empty name to defend against a hypothetical syscall bug
	   that yields a buffer ending in non-'\0'.  */
	names[nsize++] = '\0';

	for (name = names; name < names + nsize; name += strlen (name) + 1) {
		void *old_value;
		ssize_t vsize;

		/* Defend against empty name from the above workaround, or from
		   a hypothetical syscall bug that yields an empty name.  */
		if (!*name)
			continue;

		/* check if this attribute shall be preserved */
		if (!check (name, ctx))
			continue;

		vsize = lgetxattr (src_path, name, NULL, 0);
		if (vsize < 0) {
			const char *qpath = quote (ctx, src_path);
			const char *qname = quote (ctx, name);
			error (ctx, _("getting attribute %s of %s"),
			       qname, qpath);
			quote_free (ctx, qname);
			quote_free (ctx, qpath);
			ret = -1;
			continue;
		}
		value = (char *) realloc (old_value = value, vsize);
		if (vsize != 0 && value == NULL) {
			free(old_value);
			error (ctx, "");
			ret = -1;
		}
		vsize = lgetxattr (src_path, name, value, vsize);
		if (vsize < 0) {
			const char *qpath = quote (ctx, src_path);
			const char *qname = quote (ctx, name);
			error (ctx, _("getting attribute %s of %s"),
			       qname, qpath);
			quote_free (ctx, qname);
			quote_free (ctx, qpath);
			ret = -1;
			continue;
		}
		if (lsetxattr (dst_path, name, value, vsize, 0) != 0) {
			if (errno == ENOTSUP)
				setxattr_ENOTSUP = 1;
			else {
				const char *qpath = quote (ctx, dst_path);
				if (errno == ENOSYS) {
					error (ctx, _("setting attributes for "
					       "%s"), qpath);
					ret = -1;
					/* no hope of getting any further */
					break;
				} else {
					const char *qname = quote (ctx, name);
					error (ctx, _("setting attribute %s for "
					       "%s"), qname, qpath);
					quote_free (ctx, qname);
					ret = -1;
				}
				quote_free (ctx, qpath);
			}
		}
	}
	if (setxattr_ENOTSUP) {
		const char *qpath = quote (ctx, dst_path);
		errno = ENOTSUP;
		error (ctx, _("setting attributes for %s"), qpath);
		ret = -1;
		quote_free (ctx, qpath);
	}
getout:
	free (value);
	if (names != namesbuf)
		free (names);
	return ret;
#else
	return 0;
#endif
}
