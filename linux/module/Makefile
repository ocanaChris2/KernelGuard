# SPDX-License-Identifier: GPL-2.0-only
# Out-of-tree build of kernelguard.ko.
#
#   make                      build against the running kernel
#   make KVER=6.14.0-37-generic    build against another installed header tree
#   make W=1                  extra compiler warnings (used during development)
#   make clean

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
