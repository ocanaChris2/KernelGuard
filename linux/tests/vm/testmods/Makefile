# SPDX-License-Identifier: GPL-2.0
KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build
# Module.symvers of kernelguard.ko, so fixtures can link against its exported symbols
EXTRA_SYMBOLS ?=

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) KBUILD_EXTRA_SYMBOLS=$(EXTRA_SYMBOLS) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
