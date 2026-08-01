/* SPDX-License-Identifier: GPL-2.0-or-later */

#define _POSIX_C_SOURCE 200809L
#include "client.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static int
read_pin(const char *prompt, char *buf, size_t buf_len)
{
	fprintf(stderr, "%s", prompt);
	fflush(stderr);
	struct termios old, new;
	int is_tty = isatty(fileno(stdin));
	if (is_tty) {
		tcgetattr(fileno(stdin), &old);
		new = old;
		new.c_lflag &= ~ECHO;
		tcsetattr(fileno(stdin), TCSANOW, &new);
	}
	char *r = fgets(buf, (int)buf_len, stdin);
	if (is_tty) {
		tcsetattr(fileno(stdin), TCSANOW, &old);
		fprintf(stderr, "\n");
	}
	if (!r)
		return -1;
	size_t len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';
	return 0;
}

static int
require_store_init(assuan_context_t ctx)
{
	gpg_error_t err = client_command_ok(ctx, "STORE_STATUS");
	if (!err)
		return 0;
	fprintf(stderr,
		"Error: store not initialized"
		" (run 'reliquary-tool init' first)\n");
	return 1;
}

static void
print_error(gpg_error_t err)
{
	if (gpg_err_code(err) == GPG_ERR_NOT_INITIALIZED)
		fprintf(stderr,
			"Error: store not initialized"
			" (run 'reliquary-tool init' first)\n");
	else if (gpg_err_code(err) == GPG_ERR_BAD_PIN)
		fprintf(stderr, "Error: wrong admin PIN\n");
	else
		fprintf(stderr, "Error: %s\n", gpg_strerror(err));
}

static int
cmd_init(assuan_context_t ctx)
{
	char pin[256], pin2[256];
	if (read_pin("New admin PIN: ", pin, sizeof(pin)) != 0)
		return 1;
	if (read_pin("Confirm admin PIN: ", pin2, sizeof(pin2)) != 0)
		return 1;
	if (strcmp(pin, pin2) != 0) {
		fprintf(stderr, "Error: PINs do not match\n");
		return 1;
	}

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "INIT_STORE %s", pin);

	gpg_error_t err = client_command_ok(ctx, cmd);
	if (err) {
		fprintf(stderr, "Error: %s\n", gpg_strerror(err));
		return 1;
	}
	printf("Store initialized.\n");
	return 0;
}

static int
cmd_create(assuan_context_t ctx, int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: reliquary-tool create <label>\n");
		return 1;
	}
	const char *label = argv[0];

	if (require_store_init(ctx))
		return 1;

	char admin_pin[256];
	if (read_pin("Admin PIN: ", admin_pin, sizeof(admin_pin)) != 0)
		return 1;

	char pin[256], pin2[256];
	if (read_pin("New token PIN: ", pin, sizeof(pin)) != 0)
		return 1;
	if (read_pin("Confirm token PIN: ", pin2, sizeof(pin2)) != 0)
		return 1;
	if (strcmp(pin, pin2) != 0) {
		fprintf(stderr, "Error: PINs do not match\n");
		return 1;
	}

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "CREATE_TOKEN %s %s %s",
		 label, pin, admin_pin);

	gpg_error_t err = client_command_ok(ctx, cmd);
	if (err) {
		print_error(err);
		return 1;
	}
	printf("Token '%s' created successfully.\n", label);
	return 0;
}

static int
cmd_delete(assuan_context_t ctx, const char *label)
{
	if (require_store_init(ctx))
		return 1;

	char admin_pin[256];
	if (read_pin("Admin PIN: ", admin_pin, sizeof(admin_pin)) != 0)
		return 1;

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "DELETE_TOKEN %s %s", label, admin_pin);

	gpg_error_t err = client_command_ok(ctx, cmd);
	if (err) {
		print_error(err);
		return 1;
	}
	printf("Token '%s' deleted.\n", label);
	return 0;
}

static int
cmd_clear(assuan_context_t ctx, const char *label)
{
	if (require_store_init(ctx))
		return 1;

	char admin_pin[256];
	if (read_pin("Admin PIN: ", admin_pin, sizeof(admin_pin)) != 0)
		return 1;

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "CLEAR_TOKEN %s %s", label, admin_pin);

	gpg_error_t err = client_command_ok(ctx, cmd);
	if (err) {
		print_error(err);
		return 1;
	}
	printf("Token '%s' cleared.\n", label);
	return 0;
}

static int
cmd_unblock(assuan_context_t ctx, const char *label)
{
	if (require_store_init(ctx))
		return 1;

	char admin_pin[256];
	if (read_pin("Admin PIN: ", admin_pin, sizeof(admin_pin)) != 0)
		return 1;

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "UNBLOCK_TOKEN %s %s", label, admin_pin);

	gpg_error_t err = client_command_ok(ctx, cmd);
	if (err) {
		print_error(err);
		return 1;
	}
	printf("Token '%s' unblocked; retry counter restored.\n", label);
	return 0;
}

struct list_print {
	int count;
};

static gpg_error_t
list_print_cb(void *opaque, const char *line)
{
	struct list_print *lp = opaque;
	if (strncmp(line, "TOKEN ", 6) != 0)
		return 0;
	/* line: "TOKEN <serial> <label> <status>" */
	const char *p = line + 6;
	const char *sp = strchr(p, ' ');	/* after serial */
	if (!sp)
		return 0;
	p = sp + 1;
	sp = strchr(p, ' ');			/* after label */
	if (!sp)
		return 0;
	int label_len = (int)(sp - p);
	const char *status = sp + 1;
	if (strcmp(status, "disconnected") == 0)
		printf("  %.*s (disconnected)\n", label_len, p);
	else
		printf("  %.*s\n", label_len, p);
	lp->count++;
	return 0;
}

static int
cmd_list(assuan_context_t ctx)
{
	struct list_print lp = { 0 };
	gpg_error_t err = client_command_status(ctx, "LIST_TOKENS",
						list_print_cb, &lp);
	if (err) {
		fprintf(stderr, "Error: %s\n", gpg_strerror(err));
		return 1;
	}
	if (lp.count == 0)
		printf("No tokens found.\n");
	return 0;
}

static int
cmd_info(assuan_context_t ctx, const char *label)
{
	char cmd[512];
	gpg_error_t err;
	snprintf(cmd, sizeof(cmd), "OPEN_SESSION %s", label);
	err = client_command_ok(ctx, cmd);
	if (err) {
		fprintf(stderr, "Error: token '%s' not found: %s\n", label,
			gpg_strerror(err));
		return 1;
	}

	printf("Token: %s\n", label);
	char *data = NULL;
	size_t data_len = 0;

	err = client_command(ctx, "GET_ATTRIBUTE created_at", &data, &data_len);
	if (!err && data) {
		printf("  Created: %.*s\n", (int)data_len, data);
		free(data);
		data = NULL;
	}

	/*
	 * Format the per-slot summary client-side from raw attributes; the
	 * daemon exposes each slot's algorithm, not a pre-rendered string.
	 */
	printf("  Slots:\n");
	static const char *slot_names[] = { "sign", "encrypt", "auth" };
	for (int s = 0; s < 3; s++) {
		char acmd[40];
		snprintf(acmd, sizeof(acmd), "GET_ATTRIBUTE algorithm.%d", s);
		data = NULL;
		data_len = 0;
		err = client_command(ctx, acmd, &data, &data_len);
		if (!err && data && data_len > 0)
			printf("    %s: %.*s\n", slot_names[s],
			       (int)data_len, data);
		else
			printf("    %s: empty\n", slot_names[s]);
		free(data);
		data = NULL;
	}

	client_command_ok(ctx, "CLOSE_SESSION");
	return 0;
}

static int
cmd_change_pin(assuan_context_t ctx, const char *label)
{
	char cmd[512];
	gpg_error_t err;
	snprintf(cmd, sizeof(cmd), "OPEN_SESSION %s", label);
	err = client_command_ok(ctx, cmd);
	if (err) {
		fprintf(stderr, "Error: token '%s' not found: %s\n", label,
			gpg_strerror(err));
		return 1;
	}

	char old_pin[256];
	if (read_pin("Current PIN: ", old_pin, sizeof(old_pin)) != 0)
		return 1;
	snprintf(cmd, sizeof(cmd), "LOGIN %s", old_pin);
	err = client_command_ok(ctx, cmd);
	if (err) {
		fprintf(stderr, "Error: wrong PIN: %s\n", gpg_strerror(err));
		return 1;
	}

	char new_pin[256], new_pin2[256];
	if (read_pin("New PIN: ", new_pin, sizeof(new_pin)) != 0)
		return 1;
	if (read_pin("Confirm new PIN: ", new_pin2, sizeof(new_pin2)) != 0)
		return 1;
	if (strcmp(new_pin, new_pin2) != 0) {
		fprintf(stderr, "Error: PINs do not match\n");
		client_command_ok(ctx, "LOGOUT");
		return 1;
	}

	snprintf(cmd, sizeof(cmd), "CHANGE_PIN %s", new_pin);
	err = client_command_ok(ctx, cmd);
	if (err) {
		fprintf(stderr, "Error: %s\n", gpg_strerror(err));
		client_command_ok(ctx, "LOGOUT");
		return 1;
	}

	client_command_ok(ctx, "LOGOUT");
	printf("PIN changed successfully.\n");
	return 0;
}

static int
cmd_genkey(assuan_context_t ctx, int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"Usage: reliquary-tool genkey <label> <slot> <algorithm>\n"
			"\nSlots: sign, encrypt, auth\n"
			"Algorithms: rsa2048, rsa3072, rsa4096,\n"
			"            nistp256, nistp384, nistp521, ed25519\n");
		return 1;
	}
	const char *label = argv[0];
	const char *slot_name = argv[1];
	const char *algo = argv[2];

	int slot;
	if (strcmp(slot_name, "sign") == 0)
		slot = 0;
	else if (strcmp(slot_name, "encrypt") == 0)
		slot = 1;
	else if (strcmp(slot_name, "auth") == 0)
		slot = 2;
	else {
		fprintf(stderr, "Error: unknown slot '%s'"
			" (use sign, encrypt, or auth)\n", slot_name);
		return 1;
	}

	char pin[256];
	if (read_pin("PIN: ", pin, sizeof(pin)) != 0)
		return 1;

	char cmd[512];
	gpg_error_t err;

	snprintf(cmd, sizeof(cmd), "OPEN_SESSION %s", label);
	err = client_command_ok(ctx, cmd);
	if (err) {
		fprintf(stderr, "Error: token '%s' not found: %s\n",
			label, gpg_strerror(err));
		return 1;
	}

	snprintf(cmd, sizeof(cmd), "LOGIN %s", pin);
	err = client_command_ok(ctx, cmd);
	if (err) {
		fprintf(stderr, "Error: wrong PIN: %s\n", gpg_strerror(err));
		return 1;
	}

	snprintf(cmd, sizeof(cmd), "GENKEY %d %s", slot, algo);
	err = client_command_ok(ctx, cmd);
	if (err) {
		fprintf(stderr, "Error: %s\n", gpg_strerror(err));
		client_command_ok(ctx, "LOGOUT");
		return 1;
	}

	client_command_ok(ctx, "LOGOUT");
	printf("Generated %s key in %s slot of '%s'.\n",
	       algo, slot_name, label);
	return 0;
}

static int
cmd_disconnect(assuan_context_t ctx, const char *label)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "DISCONNECT_TOKEN %s", label);
	gpg_error_t err = client_command_ok(ctx, cmd);
	if (err) {
		print_error(err);
		return 1;
	}
	printf("Token '%s' disconnected.\n", label);
	return 0;
}

static int
cmd_connect(assuan_context_t ctx, const char *label)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "CONNECT_TOKEN %s", label);
	gpg_error_t err = client_command_ok(ctx, cmd);
	if (err) {
		print_error(err);
		return 1;
	}
	printf("Token '%s' connected.\n", label);
	return 0;
}

static void
usage(void)
{
	fprintf(stderr, "Usage: reliquary-tool <command> [args...]\n\n");
	fprintf(stderr, "Commands:\n");
	fprintf(stderr,
		"  init                                Initialize store (set admin PIN)\n");
	fprintf(stderr,
		"  create <label>                      Create a new empty token\n");
	fprintf(stderr,
		"  delete <label>                      Delete a token\n");
	fprintf(stderr,
		"  clear <label>                       Clear key slots from a token\n");
	fprintf(stderr,
		"  genkey <label> <slot> <algo>        Generate a key in a slot\n");
	fprintf(stderr, "  list                                List tokens\n");
	fprintf(stderr,
		"  info <label>                        Show token details\n");
	fprintf(stderr,
		"  change-pin <label>                  Change token PIN\n");
	fprintf(stderr,
		"  disconnect <label>                  Hide token from enumeration\n");
	fprintf(stderr,
		"  connect <label>                     Make token visible again\n");
	fprintf(stderr,
		"  unblock <label>                     Restore a locked token's retry counter\n");
	fprintf(stderr,
		"\nSlots: sign, encrypt, auth\n"
		"Algorithms: rsa2048, rsa3072, rsa4096,\n"
		"            nistp256, nistp384, nistp521, ed25519\n");
}

int
main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 1;
	}
	if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		usage();
		return 0;
	}

	assuan_context_t ctx;
	if (client_connect(&ctx) != 0)
		return 1;

	if (crypto_init() != 0) {
		fprintf(stderr, "Error: failed to initialize crypto\n");
		client_disconnect(ctx);
		return 1;
	}

	int rc;
	if (strcmp(argv[1], "init") == 0)
		rc = cmd_init(ctx);
	else if (strcmp(argv[1], "create") == 0)
		rc = cmd_create(ctx, argc - 2, argv + 2);
	else if (strcmp(argv[1], "delete") == 0) {
		if (argc < 3) {
			fprintf(stderr,
				"Usage: reliquary-tool delete <label>\n");
			rc = 1;
		} else
			rc = cmd_delete(ctx, argv[2]);
	} else if (strcmp(argv[1], "clear") == 0) {
		if (argc < 3) {
			fprintf(stderr,
				"Usage: reliquary-tool clear <label>\n");
			rc = 1;
		} else
			rc = cmd_clear(ctx, argv[2]);
	} else if (strcmp(argv[1], "genkey") == 0)
		rc = cmd_genkey(ctx, argc - 2, argv + 2);
	else if (strcmp(argv[1], "list") == 0)
		rc = cmd_list(ctx);
	else if (strcmp(argv[1], "info") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Usage: reliquary-tool info <label>\n");
			rc = 1;
		} else
			rc = cmd_info(ctx, argv[2]);
	} else if (strcmp(argv[1], "change-pin") == 0) {
		if (argc < 3) {
			fprintf(stderr,
				"Usage: reliquary-tool change-pin <label>\n");
			rc = 1;
		} else
			rc = cmd_change_pin(ctx, argv[2]);
	} else if (strcmp(argv[1], "disconnect") == 0) {
		if (argc < 3) {
			fprintf(stderr,
				"Usage: reliquary-tool disconnect <label>\n");
			rc = 1;
		} else
			rc = cmd_disconnect(ctx, argv[2]);
	} else if (strcmp(argv[1], "connect") == 0) {
		if (argc < 3) {
			fprintf(stderr,
				"Usage: reliquary-tool connect <label>\n");
			rc = 1;
		} else
			rc = cmd_connect(ctx, argv[2]);
	} else if (strcmp(argv[1], "unblock") == 0) {
		if (argc < 3) {
			fprintf(stderr,
				"Usage: reliquary-tool unblock <label>\n");
			rc = 1;
		} else
			rc = cmd_unblock(ctx, argv[2]);
	} else {
		fprintf(stderr, "Unknown command: %s\n", argv[1]);
		usage();
		rc = 1;
	}

	client_disconnect(ctx);
	return rc;
}
