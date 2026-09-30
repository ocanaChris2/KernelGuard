// SPDX-License-Identifier: GPL-2.0-only
/*
 * specget - print the per-task speculation / SMT controls of the calling task.
 * Used by the monitor test to prove that `kgmon run --sensitive` really left the
 * controls set in the command it exec'd, not merely that prctl() returned 0.
 */
#include <errno.h>
#include <linux/prctl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>

static void show(const char *what, int which)
{
	long r = prctl(PR_GET_SPECULATION_CTRL, which, 0, 0, 0);

	if (r < 0)
		printf("specget: %s unsupported (%s)\n", what, strerror(errno));
	else
		printf("specget: %s state=0x%lx%s%s%s\n", what, r,
		       r & PR_SPEC_DISABLE ? " speculation-disabled" : "",
		       r & PR_SPEC_ENABLE ? " speculation-enabled" : "",
		       r & PR_SPEC_PRCTL ? " prctl-controllable" : "");
}

int main(void)
{
	unsigned long cookie = 0;

	show("l1d_flush", PR_SPEC_L1D_FLUSH);
	show("indirect_branch", PR_SPEC_INDIRECT_BRANCH);
	show("store_bypass", PR_SPEC_STORE_BYPASS);
	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, 0, 0 /* PIDTYPE_PID */, &cookie) == 0)
		printf("specget: core_sched cookie=%s\n", cookie ? "set" : "none");
	else
		printf("specget: core_sched unsupported (%s)\n", strerror(errno));
	return 0;
}
