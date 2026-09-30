# SPDX-License-Identifier: GPL-2.0-only
# User-space monitor (kgmon).
#
#   make            build ./kgmon
#   make static     build a static kgmon (used by the VM test rig)
#   make check      run the SHA-256/HMAC known-answer tests
#   make clean

CC      ?= gcc
# Defaults for a plain `make`. A distribution (or `make CFLAGS=... LDFLAGS=...`) supplies its own hardening
# flags instead; the flags the sources need are added with `override`, so a command-line CFLAGS extends them
# rather than dropping the include path.
CFLAGS  ?= -O2 -g -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?= -Wl,-z,relro,-z,now
override CFLAGS += -Wall -Wextra -Wshadow -Wstrict-prototypes -Wformat=2 -I../include

SRC := kgmon.c kg_hmac.c kg_policy.c

kgmon: $(SRC) kg_hmac.h kg_policy.h ../include/kernelguard_uapi.h
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

static: $(SRC) kg_hmac.h kg_policy.h ../include/kernelguard_uapi.h
	$(CC) $(CFLAGS) -static $(SRC) -o kgmon $(LDFLAGS)

check: kgmon
	./kgmon selftest

# Fuzzing the escalation policy parser and engine (see fuzz/fuzz_policy.c).
#   make fuzz                        sanitizer build + a fixed-seed mutation run (FUZZ_ITERS=200000)
#   make fuzz-libfuzzer              coverage-guided build (needs clang)
FUZZ_ITERS ?= 200000
FUZZ_SEEDS := fuzz/seeds/example.conf fuzz/seeds/edge.conf
FUZZ_FLAGS := -O1 -g -fno-omit-frame-pointer -Wall -Wextra -I../include -I.

fuzz/fuzz_policy: fuzz/fuzz_policy.c kg_policy.c kg_policy.h
	$(CC) $(FUZZ_FLAGS) -fsanitize=address,undefined -fno-sanitize-recover=undefined $^ -o $@

fuzz: fuzz/fuzz_policy
	./fuzz/fuzz_policy $(FUZZ_ITERS) $(FUZZ_SEEDS)

fuzz/fuzz_policy_lf: fuzz/fuzz_policy.c kg_policy.c kg_policy.h
	clang $(FUZZ_FLAGS) -DFUZZ_LIBFUZZER -fsanitize=fuzzer,address,undefined $^ -o $@

fuzz-libfuzzer: fuzz/fuzz_policy_lf
	mkdir -p fuzz/corpus && cp $(FUZZ_SEEDS) fuzz/corpus/
	./fuzz/fuzz_policy_lf fuzz/corpus -max_total_time=$${FUZZ_SECONDS:-60}

clean:
	rm -f kgmon fuzz/fuzz_policy fuzz/fuzz_policy_lf
	rm -rf fuzz/corpus

.PHONY: static check clean fuzz fuzz-libfuzzer
