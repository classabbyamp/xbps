/*-
 * Copyright (c) 2023 classabbyamp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include "xbps_api_impl.h"
#include "uthash.h"

struct xbps_user {
	const char *name;
	uid_t uid;
	gid_t gid;
	const char *cmt;
	const char *homedir;
	const char *shell;
    UT_hash_handle hh_name;
    UT_hash_handle hh_id;
};

struct xbps_user *usertab_by_name = NULL;
struct xbps_user *usertab_by_id   = NULL;

int
xbps_user_init(const char *rootdir, struct xbps_user *user) {
    FILE *fd = NULL;
	char path[] = "/etc/passwd";
	char *line;
	size_t len;
	int rd, i;

	if (xbps_path_prepend(path, sizeof rootdir + sizeof path, rootdir) == -1)
		return -errno;
	if ((fd = fopen(path, "r")) == NULL)
		return -errno;

	while ((rd = getline(&line, &len, fd)) != -1) {
        char *name = NULL, *cmt = NULL, *homedir = NULL, *shell = NULL;
        uid_t uid;
        gid_t gid;

		if (line[rd-1] == '\n') {
			line[rd-1] = '\0';
			rd--;
		}
		while (isblank((unsigned char)*line))
			line++;
		if (line[0] == '\0')
			continue;

        printf("LINE: %s\n", line);
		/* name:password:uid:pgid:comment:homedir:shell */
		name = line++;
		if (!(line = strchr(line, ':'))) continue;
		*line++ = '\0';

		/* skip password */
		if (!(line = strchr(line, ':'))) continue;
		*line++ = '\0';

		uid = (uid_t)strtol(line, &line, 0);
		if (*line != ':') continue;
		*line++ = '\0';

		gid = (gid_t)strtol(line, &line, 0);
		if (*line != ':') continue;
		*line++ = '\0';

		cmt = line++;
		if (!(line = strchr(line, ':'))) continue;
		*line++ = '\0';

		homedir = line++;
		if (!(line = strchr(line, ':'))) continue;
		*line++ = '\0';

		shell = line++;

        user = xbps_add_user(name, uid, gid, cmt, homedir, shell);
        line = NULL;
		i++;
    }
    xbps_dbg_printf("Added %u users from %s\n", i, path);
	return 0;
}

struct xbps_user *
xbps_add_user(const char *name, uid_t uid, gid_t gid, const char *cmt, const char *homedir, const char *shell) {
    if (find_user(name) != NULL)
        return NULL;

    struct xbps_user *user = calloc(1, sizeof(struct xbps_user));

    if (user == NULL)
        return NULL;

    user->name = name;
    user->uid = uid;
    user->gid = gid;
    user->cmt = cmt;
    user->homedir = homedir;
    user->shell = shell;

    xbps_dbg_printf("Added user %s: uid=%u, gid=%u, cmt=%s, homedir=%s, shell=%s\n",
        name, uid, gid, cmt, homedir, shell);
    HASH_ADD_KEYPTR(hh, usertab, user->name, strlen(user->name), user);
    return user;
}

struct xbps_user *
get_user(const char *name) {
    struct xbps_user *s = NULL;
    HASH_FIND_STR(usertab, name, s);
    return s;
}

void
remove_user(struct xbps_user *user) {
    HASH_DEL(usertab, user);
    free(user);
}

struct xbps_group {
	char *name;
	gid_t gid;
	char **members;
	UT_hash_handle hh;
};

// struct xbps_group *
// xbps_groups_open(const char *rootdir)
// {
// 	struct xbps_group *groups;
// 	FILE *fd = NULL;
// 	char path[] = "/etc/group";
// 	char *line;
// 	size_t len;
// 	int rd;

// 	if (xbps_path_prepend(path, sizeof rootdir + sizeof path, rootdir) == -1)
// 		return NULL;
// 	if ((fd = fopen(path, "r")) == NULL)
// 		return NULL;

// 	while ((rd = getline(&line, &len, fd)) != -1) {
// 		struct xbps_group *entry = {0};

// 		if (line[rd-1] == '\n') {
// 			line[rd-1] = '\0';
// 			rd--;
// 		}
// 		while (isblank((unsigned char)*line))
// 			line++;
// 		if (line[0] == '\0')
// 			continue;

// 		/* name:password:gid:user,... */
// 		entry->name = line++;
// 		if (!(line = strchr(line, ':'))) continue;
// 		*line++ = '\0';

// 		/* skip password */
// 		if (!(line = strchr(line, ':'))) continue;
// 		*line++ = '\0';

// 		entry->gid = (gid_t)strtol(line, &line, 0);

// 		HASH_ADD_STR(groups, name, entry);
// 	}
// 	return groups;
// }

// struct xbps_group *
// xbps_groups_get(struct xbps_group *groups, const char *name)
// {
// 	struct xbps_group *group;
// 	HASH_FIND_STR(groups, name, group);
// 	return group;
// }
