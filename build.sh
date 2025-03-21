#!/usr/bin/env bash
# Requires clang and lld to be installed
FLAGS='-fno-strict-overflow -fno-strict-aliasing -fno-delete-null-pointer-checks -fPIE -fPIC -march=x86-64 -mtune=generic -pipe -fno-plt -fexceptions -fwrapv -Wp,-D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security -Wall -Wextra -Werror -fstack-clash-protection -fPIC -fomit-frame-pointer -ftrivial-auto-var-init=zero -fcf-protection -D_FORTIFY_SOURCE=3 -O3 -funroll-loops -fdata-sections -ffunction-sections -flto -fvisibility=hidden -fsanitize=cfi -fsanitize-cfi-cross-dso -fstack-protector-all -Wl,--sort-common -Wl,--as-needed -Wl,-z,relro -Wl,-z,now -Wl,-z,pack-relative-relocs -flto=auto -Wl,-O3 -Wl,-z,noexecstack -Wl,-pie -Wl,--strip-all -Wl,--sort-common -Wl,--no-undefined -Wl,-z,now -Wl,-z,relro -Wl,-O3,--as-needed,-z,defs,-z,relro,-z,now,-z,nodlopen,-z,text -flto -Wl,--gc-sections -lhardened_malloc -fuse-ld=lld'

clang seccomp-mdwe.c -DGL_PERMISSIVE -lseccomp $FLAGS -o seccomp-error
clang seccomp-mdwe.c -lseccomp $FLAGS -o seccomp-strict
clang seccomp-init.c -lseccomp $FLAGS -o seccomp-init
