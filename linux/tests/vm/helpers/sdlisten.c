// SPDX-License-Identifier: GPL-2.0-only
/*
 * sdlisten.c - TEST HELPER, runs only inside the throw-away VM guest.
 *
 * Binds a datagram socket at PATH the way systemd does for NOTIFY_SOCKET and
 * prints every datagram it receives, one per line (newlines inside a message
 * become '|'), until SECONDS have passed.  The suite uses it to check that
 * kgmon announces READY=1, pings the watchdog and says STOPPING=1.
 */
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(int argc, char **argv)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	long deadline;
	int fd;

	if (argc != 3 || strlen(argv[1]) >= sizeof(sa.sun_path)) {
		fprintf(stderr, "usage: sdlisten PATH SECONDS\n");
		return 2;
	}
	strcpy(sa.sun_path, argv[1]);
	unlink(argv[1]);
	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("sdlisten");
		return 1;
	}
	deadline = now_ms() + atol(argv[2]) * 1000;
	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("listening\n");

	for (;;) {
		struct pollfd p = { .fd = fd, .events = POLLIN };
		long left = deadline - now_ms();
		char buf[512];
		ssize_t n;

		if (left <= 0)
			break;
		if (poll(&p, 1, (int)left) <= 0)
			continue;
		n = recv(fd, buf, sizeof(buf) - 1, 0);
		if (n <= 0)
			continue;
		buf[n] = '\0';
		for (char *q = buf; *q; q++)
			if (*q == '\n')
				*q = '|';
		printf("%s\n", buf);
	}
	unlink(argv[1]);
	return 0;
}
