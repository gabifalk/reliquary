/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "tokenstore.h"
#include "meta.h"
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int
tokenstore_valid_label(const char *label)
{
	if (!label || !*label)
		return 0;
	size_t n = strlen(label);
	if (n > TOKENSTORE_MAX_LABEL)
		return 0;
	if (strcmp(label, ".") == 0 || strcmp(label, "..") == 0)
		return 0;
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)label[i];
		if (!(isalnum(c) || c == '.' || c == '_' || c == '-'))
			return 0;
	}
	return 1;
}

void
tokenstore_token_path(const char *store_path, const char *label,
		      char *out, size_t out_len)
{
	snprintf(out, out_len, "%s/%s", store_path, label);
}

int
tokenstore_exists(const char *store_path, const char *label)
{
	char path[512];
	tokenstore_token_path(store_path, label, path, sizeof(path));
	struct stat st;
	return (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? 1 : 0;
}

int
tokenstore_create(const char *store_path, const char *label)
{
	if (!tokenstore_valid_label(label))
		return -1;
	if (tokenstore_exists(store_path, label))
		return -1;
	char path[512];
	tokenstore_token_path(store_path, label, path, sizeof(path));
	return mkdir(path, 0700);
}

int
tokenstore_remove(const char *store_path, const char *label)
{
	if (!tokenstore_valid_label(label))
		return -1;
	if (!tokenstore_exists(store_path, label))
		return -1;
	char path[512];
	tokenstore_token_path(store_path, label, path, sizeof(path));

	DIR *d = opendir(path);
	if (!d)
		return -1;
	struct dirent *ent;
	while ((ent = readdir(d)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0
		    || strcmp(ent->d_name, "..") == 0)
			continue;
		char fpath[768];
		snprintf(fpath, sizeof(fpath), "%s/%s", path, ent->d_name);
		unlink(fpath);
	}
	closedir(d);
	return rmdir(path);
}

int
tokenstore_list(const char *store_path, char labels[][256], int max_labels)
{
	DIR *d = opendir(store_path);
	if (!d)
		return 0;
	int count = 0;
	struct dirent *ent;
	while ((ent = readdir(d)) != NULL && count < max_labels) {
		if (ent->d_name[0] == '.')
			continue;
		char path[512];
		snprintf(path, sizeof(path), "%s/%s", store_path, ent->d_name);
		struct stat st;
		if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
			token_state_t tst;
			if (state_read(path, &tst) == 0 && tst.disconnected)
				continue;
			strncpy(labels[count], ent->d_name, 255);
			labels[count][255] = '\0';
			count++;
		}
	}
	closedir(d);
	return count;
}

int
tokenstore_list_all(const char *store_path, char labels[][256], int max_labels)
{
	DIR *d = opendir(store_path);
	if (!d)
		return 0;
	int count = 0;
	struct dirent *ent;
	while ((ent = readdir(d)) != NULL && count < max_labels) {
		if (ent->d_name[0] == '.')
			continue;
		char path[512];
		snprintf(path, sizeof(path), "%s/%s", store_path, ent->d_name);
		struct stat st;
		if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
			strncpy(labels[count], ent->d_name, 255);
			labels[count][255] = '\0';
			count++;
		}
	}
	closedir(d);
	return count;
}
