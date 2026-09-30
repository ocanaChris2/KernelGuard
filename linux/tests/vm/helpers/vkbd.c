// SPDX-License-Identifier: GPL-2.0
/*
 * vkbd - virtual keyboard for the input tests (test helper).
 *
 *   vkbd NAME SECONDS
 *
 * Creates a uinput keyboard called NAME, then for SECONDS seconds types a key
 * every 100 ms.  It also reads its own evdev node, which stands in for a
 * legitimate consumer (X11 / libinput): the last line printed is
 *     vkbd: injected=<presses> received=<press events seen through evdev>
 * so a test can show that legitimate delivery keeps working while a rogue
 * handler is detached.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void emit(int fd, int type, int code, int val)
{
	struct input_event ev = { .type = type, .code = code, .value = val };

	if (write(fd, &ev, sizeof(ev)) < 0)
		perror("write");
}

/* find /dev/input/eventN whose name matches */
static int open_evdev(const char *name)
{
	char path[128], nm[128];
	int i;

	for (i = 0; i < 64; i++) {
		int fd;

		snprintf(path, sizeof(path), "/dev/input/event%d", i);
		fd = open(path, O_RDONLY | O_NONBLOCK);
		if (fd < 0)
			continue;
		if (ioctl(fd, EVIOCGNAME(sizeof(nm)), nm) >= 0 && !strcmp(nm, name))
			return fd;
		close(fd);
	}
	return -1;
}

int main(int argc, char **argv)
{
	const char *name = argc > 1 ? argv[1] : "kg-test-kbd";
	int secs = argc > 2 ? atoi(argv[2]) : 5;
	struct uinput_setup us = { .id = { .bustype = BUS_USB, .vendor = 0x1234, .product = 0x5678 } };
	int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK), ev, sent = 0, got = 0, k;
	struct timespec t0, t;

	if (fd < 0) {
		perror("open /dev/uinput");
		return 1;
	}
	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_SYN);
	for (k = KEY_ESC; k <= KEY_M; k++)
		ioctl(fd, UI_SET_KEYBIT, k);
	strncpy(us.name, name, UINPUT_MAX_NAME_SIZE - 1);
	ioctl(fd, UI_DEV_SETUP, &us);
	if (ioctl(fd, UI_DEV_CREATE) < 0) {
		perror("UI_DEV_CREATE");
		return 1;
	}
	usleep(500000);                 /* let every handler attach */
	ev = open_evdev(name);
	printf("vkbd: created \"%s\" (evdev fd %d)\n", name, ev);
	fflush(stdout);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		struct input_event buf[16];
		ssize_t r;

		emit(fd, EV_KEY, KEY_A, 1);
		emit(fd, EV_SYN, SYN_REPORT, 0);
		emit(fd, EV_KEY, KEY_A, 0);
		emit(fd, EV_SYN, SYN_REPORT, 0);
		sent++;
		usleep(100000);
		while (ev >= 0 && (r = read(ev, buf, sizeof(buf))) > 0) {
			int i;

			for (i = 0; i < (int)(r / sizeof(buf[0])); i++)
				if (buf[i].type == EV_KEY && buf[i].value == 1)
					got++;
		}
		clock_gettime(CLOCK_MONOTONIC, &t);
	} while (t.tv_sec - t0.tv_sec < secs);

	ioctl(fd, UI_DEV_DESTROY);
	printf("vkbd: injected=%d received=%d\n", sent, got);
	return 0;
}
