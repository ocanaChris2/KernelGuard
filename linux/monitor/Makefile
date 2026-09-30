# SPDX-License-Identifier: GPL-2.0-only
# User-space monitor (kgmon).
#
#   make            build ./kgmon
#   make static     build a static kgmon (used by the VM test rig)
#   make check      run the SHA-256/HMAC known-answer tests
#   make clean

CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -Wall -Wextra -Wshadow -Wstrict-prototypes -Wformat=2 -D_FORTIFY_SOURCE=2 \
           -fstack-protector-strong -I../include
LDFLAGS += -Wl,-z,relro,-z,now

SRC := kgmon.c kg_hmac.c

kgmon: $(SRC) kg_hmac.h ../include/kernelguard_uapi.h
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

static: $(SRC) kg_hmac.h ../include/kernelguard_uapi.h
	$(CC) $(CFLAGS) -static $(SRC) -o kgmon $(LDFLAGS)

check: kgmon
	./kgmon selftest

clean:
	rm -f kgmon

.PHONY: static check clean
