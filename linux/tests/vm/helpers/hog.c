// SPDX-License-Identifier: GPL-2.0
/*
 * hog - cache-thrashing load generator for the PMU test (test helper).
 *
 *   hog NPROC SECONDS [FIRST_CPU]
 *
 * Forks NPROC children, child i pinned to CPU (FIRST_CPU + i), each striding
 * through a 128 MiB buffer one cache line at a time so nearly every access is an
 * L1D and last-level miss - the counter signature a Flush+Reload / Prime+Probe
 * style workload produces.  Child PIDs are printed so the test can compare them
 * with the offender the driver reports.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BUF (128UL << 20)

static void child(int cpu, int seconds)
{
	cpu_set_t set;
	volatile unsigned char *buf;
	struct timespec t0, t;
	unsigned long i, sink = 0;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);

	buf = mmap(NULL, BUF, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		_exit(2);
	memset((void *)buf, 1, BUF);

	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		for (i = 0; i < BUF; i += 4160)         /* 65 lines: defeats the stride prefetcher */
			sink += buf[i];
		clock_gettime(CLOCK_MONOTONIC, &t);
	} while (t.tv_sec - t0.tv_sec < seconds);
	_exit(sink == 12345 ? 1 : 0);
}

int main(int argc, char **argv)
{
	int n = argc > 1 ? atoi(argv[1]) : 1;
	int secs = argc > 2 ? atoi(argv[2]) : 3;
	int first = argc > 3 ? atoi(argv[3]) : 0;
	int i, status;

	for (i = 0; i < n; i++) {
		pid_t p = fork();

		if (p == 0)
			child(first + i, secs);
		printf("hog pid %d cpu %d\n", p, first + i);
	}
	fflush(stdout);
	for (i = 0; i < n; i++)
		wait(&status);
	return 0;
}
