include toolchain.mk

CC = clang
LD = ld.lld
CLANG_FORMAT ?= clang-format
LLVM_VERSION ?= $(PINNED_LLVM_VERSION)
MODE ?= release

ifeq ($(filter $(MODE),release development),)
$(error MODE must be release or development)
endif

.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
OUT := build/$(MODE)
PROGRAMS := seccomp-error seccomp-strict seccomp-init
SOURCES := seccomp-mdwe.c seccomp-init.c sandbox-common.h
FORMAT_SOURCES := $(SOURCES) $(wildcard tests/*.c)

# Old Clang requires an explicit opt-in for zero initialization. Do not pass
# that opt-in to current Clang, which has removed it.
AUTO_INIT := $(shell if printf 'int value;\n' | $(CC) -Werror -ftrivial-auto-var-init=zero -x c -c -o /dev/null - >/dev/null 2>&1; then \
  printf '%s' '-ftrivial-auto-var-init=zero'; \
  elif printf 'int value;\n' | $(CC) -Werror -ftrivial-auto-var-init=zero -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang -x c -c -o /dev/null - >/dev/null 2>&1; then \
  printf '%s' '-ftrivial-auto-var-init=zero -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang'; fi)

BASE_CPPFLAGS := -D_GNU_SOURCE -D_FORTIFY_SOURCE=3
BASE_CFLAGS := -std=c11 -O2 -march=x86-64 -mtune=generic \
  -Wall -Wextra -Wpedantic -Werror -Wformat=2 -Wformat-security \
  -Wconversion -Wsign-conversion -Wshadow -Wstrict-prototypes \
  -fPIE -fvisibility=hidden -fno-plt -fno-strict-aliasing \
  -fno-delete-null-pointer-checks -fwrapv -ffunction-sections -fdata-sections \
  -fstack-protector-all -fstack-clash-protection -fcf-protection=full \
  $(AUTO_INIT) -flto -fsanitize=cfi,cfi-cast-strict,safe-stack,undefined,bounds,integer \
  -fsanitize-trap=all -fno-sanitize-recover=all
BASE_LDFLAGS := --ld-path=$(LD) -pie -Wl,-z,relro,-z,now,-z,noexecstack,-z,text \
  -Wl,-z,defs,-z,pack-relative-relocs,--as-needed,--gc-sections
BASE_LDLIBS := -L/usr/local/lib -Wl,--no-as-needed -lirralloc -Wl,--as-needed -lseccomp

ifeq ($(MODE),development)
# C11 permits mixed declarations. argv and fixed arrays have explicit bounds;
# Clang's C++ span migration diagnostic has no equivalent C replacement.
# glibc's fortified stdio expands its intentionally self-referential stderr.
BASE_CFLAGS += -g -Weverything -Wno-declaration-after-statement -Wno-unsafe-buffer-usage \
  -Wno-disabled-macro-expansion
else
BASE_CFLAGS += -g0
BASE_LDFLAGS += -Wl,--strip-all
endif

.PHONY: all clean development check-toolchain format format-check check FORCE $(PROGRAMS)
all: $(PROGRAMS)

development:
	$(MAKE) MODE=development all

check-toolchain:
	@$(CC) --version | head -1 | grep -F 'clang version ' >/dev/null && test "$$($(CC) -dumpversion)" = "$(LLVM_VERSION)" || { echo 'Compiler must be Clang $(LLVM_VERSION)' >&2; exit 1; }
	@test "$$($(LD) --version | awk '{print $$2}')" = "$(LLVM_VERSION)" || { echo 'Linker must be LLD $(LLVM_VERSION)' >&2; exit 1; }
	@test -n "$(AUTO_INIT)" || { echo 'Compiler does not support automatic zero initialization' >&2; exit 1; }

$(OUT)/config: FORCE | check-toolchain
	@mkdir -p $(OUT)
	@printf '%s\n' "$(CC) $(LD) $(LLVM_VERSION) $(MODE)" "$(BASE_CPPFLAGS) $(CPPFLAGS)" "$(BASE_CFLAGS) $(CFLAGS)" "$(BASE_LDFLAGS) $(LDFLAGS)" "$(BASE_LDLIBS) $(LDLIBS)" > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@

$(OUT)/seccomp-error: seccomp-mdwe.c sandbox-common.h $(OUT)/config
	$(CC) $(BASE_CPPFLAGS) $(CPPFLAGS) -DGL_PERMISSIVE $(BASE_CFLAGS) $(CFLAGS) $< $(BASE_LDFLAGS) $(LDFLAGS) $(BASE_LDLIBS) $(LDLIBS) -o $@

$(OUT)/seccomp-strict: seccomp-mdwe.c sandbox-common.h $(OUT)/config
	$(CC) $(BASE_CPPFLAGS) $(CPPFLAGS) $(BASE_CFLAGS) $(CFLAGS) $< $(BASE_LDFLAGS) $(LDFLAGS) $(BASE_LDLIBS) $(LDLIBS) -o $@

$(OUT)/seccomp-init: seccomp-init.c sandbox-common.h $(OUT)/config
	$(CC) $(BASE_CPPFLAGS) $(CPPFLAGS) $(BASE_CFLAGS) $(CFLAGS) $< $(BASE_LDFLAGS) $(LDFLAGS) $(BASE_LDLIBS) $(LDLIBS) -o $@

$(PROGRAMS): %: $(OUT)/%
	ln -sfn $(OUT)/$@ $@

format:
	@$(CLANG_FORMAT) --version | grep -F 'version $(PINNED_LLVM_VERSION)' >/dev/null
	$(CLANG_FORMAT) -i $(FORMAT_SOURCES)

format-check:
	@$(CLANG_FORMAT) --version | grep -F 'version $(PINNED_LLVM_VERSION)' >/dev/null
	$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_SOURCES)

check: all format-check
	python3 tests/check.py --build-dir $(OUT) --cc $(CC) $(if $(filter development,$(MODE)),--strict-warnings,)

clean:
	rm -rf build
	rm -f $(PROGRAMS)
