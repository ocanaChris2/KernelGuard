// SPDX-License-Identifier: GPL-2.0-only
/*
 * modload - load a kernel module with exactly one system call, and say how it went.
 *
 *   modload FILE [PARAMS]      finit_module(2), the call kmod's insmod and modprobe make
 *   modload -i FILE [PARAMS]   init_module(2), the older call, with the image read into memory
 *
 * BusyBox insmod tries finit_module and, when that fails, init_module as well, so one refused load
 * reaches the kernel's module loader twice.  The driver-load gate suite counts refusals and wants to
 * exercise both entry points, so it needs a loader that makes a single call.  Exit status: 0 loaded,
 * 1 the kernel said no (the errno is printed), 2 bad usage.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	const char *file, *params = "";
	int use_init = 0, fd;
	long rc;

	if (argc > 1 && !strcmp(argv[1], "-i")) {
		use_init = 1;
		argc--;
		argv++;
	}
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "usage: modload [-i] FILE [PARAMS]\n");
		return 2;
	}
	file = argv[1];
	if (argc == 3)
		params = argv[2];

	fd = open(file, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "modload: %s: %s\n", file, strerror(errno));
		return 1;
	}

	if (!use_init) {
		rc = syscall(SYS_finit_module, fd, params, 0);
	} else {
		struct stat st;
		size_t got = 0;
		char *img;

		if (fstat(fd, &st) || st.st_size <= 0) {
			fprintf(stderr, "modload: %s: cannot size the file\n", file);
			return 1;
		}
		img = malloc((size_t)st.st_size);
		if (!img)
			return 1;
		while (got < (size_t)st.st_size) {
			ssize_t n = read(fd, img + got, (size_t)st.st_size - got);

			if (n <= 0) {
				fprintf(stderr, "modload: %s: short read\n", file);
				return 1;
			}
			got += (size_t)n;
		}
		rc = syscall(SYS_init_module, img, (unsigned long)st.st_size, params);
		free(img);
	}

	if (rc) {
		fprintf(stderr, "modload: %s: %s\n", file, strerror(errno));
		return 1;
	}
	return 0;
}
