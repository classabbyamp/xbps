#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>

#include "uthash.h"

struct xbps_user {
	const char *name;
	uid_t uid;
	gid_t gid;
	const char *cmt;
	const char *homedir;
	const char *shell;
    UT_hash_handle hh;
};

struct xbps_user *usertab = NULL;

struct xbps_user *
add_user(const char *name, uid_t uid, gid_t gid, const char *cmt, const char *homedir, const char *shell) {
    // if (find_user(name) != NULL)
    //     return NULL;

    struct xbps_user *user = calloc(1, sizeof(struct xbps_user));

    if (user == NULL)
        return NULL;

    user->name = name;
    user->uid = uid;
    user->gid = gid;
    user->cmt = cmt;
    user->homedir = homedir;
    user->shell = shell;

    HASH_ADD_KEYPTR(hh, usertab, user->name, strlen(user->name), user);
    return user;
}

struct xbps_user *get_user(const char *name) {
    struct xbps_user *s = NULL;
    HASH_FIND_STR(usertab, name, s);
    return s;
}

void remove_user(struct xbps_user *user) {
    HASH_DEL(usertab, user);
    free(user);
}

struct xbps_user *
xbps_user_init(const char *rootdir) {
    FILE *fd = NULL;
	char path[] = "/etc/passwd";
	char *line;
	size_t len;
	int rd;

	if (xbps_path_prepend(path, sizeof rootdir + sizeof path, rootdir) == -1)
		return NULL;
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

        printf("PARSED:\n\tname: %s\n\tuid: %u\n\tgid: %u\n\tcmt: %s\n\thomedir: %s\n\tshell: %s\n",
            name, uid, gid, cmt, homedir, shell);
        add_user(name, uid, gid, cmt, homedir, shell);
        line = NULL;
    }
    printf("=> all users added.\n");

    struct xbps_user *s;

    for (s = usertab; s != NULL; s = (struct xbps_user *)(s->hh.next)) {
        printf("ENTRY:\n\tname: %s\n\tuid: %u\n\tgid: %u\n\tcmt: %s\n\thomedir: %s\n\tshell: %s\n",
            s->name, s->uid, s->gid, s->cmt, s->homedir, s->shell);
    }

    return 0;
}
