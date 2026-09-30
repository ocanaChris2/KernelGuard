# SPDX-License-Identifier: GPL-2.0-only
#
# KernelGuard for Linux - top-level build.
#
#   make                 kernel module + user-space monitor, for the running kernel
#   make KVER=6.14.0-37-generic
#                        build the module against another installed header tree
#   make module | monitor
#   make check           monitor known-answer tests (no root, nothing loaded)
#   make test            load-test the module inside a throw-away QEMU/KVM guest
#                        (never on this machine) - see tests/vm/run-vm.sh
#   make clean
#
# Loading the module needs root and, on Secure Boot systems, a signature:
# see scripts/kg-deploy.sh and README.md.

KVER ?= $(shell uname -r)
export KVER

all: module monitor

module:
	$(MAKE) -C module KVER=$(KVER)

monitor:
	$(MAKE) -C monitor

check: monitor
	$(MAKE) -C monitor check

# Tests boot a real kernel in QEMU and load a KG_TESTHOOKS build of the module
# there.  KG_KERNEL must point to a *readable* bzImage matching KVER.
TESTS ?= basic integrity pmu smt input hw hwlegacy monitor deploy lifecycle posture escalate stress
test:
	tests/vm/run-vm.sh $(TESTS)

clean:
	-$(MAKE) -C module KVER=$(KVER) clean
	-$(MAKE) -C monitor clean
	-$(MAKE) -C tests/vm/testmods KVER=$(KVER) clean

.PHONY: all module monitor check test clean
