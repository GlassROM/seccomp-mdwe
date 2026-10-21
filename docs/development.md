# Development

The Makefile builds two payload wrappers and a separate pre-init shim. It never
runs them as part of compilation.

## Tools

| Component | Pinned or tested version |
| --- | --- |
| Clang | 23.1.4 |
| LLD | 23.1.4 |
| clang-format | 23.1.4 |
| libseccomp headers/runtime | 2.5.5 |
| GNU Make | 4.3 |
| Python | 3.12.14 |
| GCC for paxtest | 13.3.0 |
| GnuPG / gpgv | 2.4.4 |

[toolchain.mk](../toolchain.mk) pins the native LLVM tools. Install development
headers and link-time dependencies before building; the runtime loader must
also resolve the resulting shared-library dependencies. GNU Make and Python 3
run the checks. The external test runner needs GCC, gpg, gpgv and network access.
Python 3.12 supplies safe tar extraction for that runner.

Project compilation requires Clang; GCC builds are currently unsupported and
are rejected by the Makefile. GCC is used only for the external paxtest suite.

```sh
make -j2
make check
make -j2 MODE=development
make check MODE=development
make format
make format-check
make clean
```

Output lives under build/release or build/development. Root executable names
are symlinks to the most recently requested profile. The configuration stamp
causes rebuilds when compiler choices or flags change.

## Warnings and hardening

Both profiles use C11, pedantic warnings, an explicit warning set and -Werror.
Development adds -Weverything. Its three exceptions cover:

- C11 declarations after statements.
- Bounds-checked fixed arrays and argument vectors, for which Clang's
  unsafe-buffer migration warning has no C span replacement.
- Intentional self-referential stderr macros in fortified glibc headers.

The init test driver locally permits the reserved __wrap_execv spelling required
by the linker's --wrap=execv interface. Development applies the same strict
warning policy to the C test helpers.

Builds retain PIE, full LTO, CFI, strict CFI casts, SafeStack, undefined/bounds/
integer sanitizers with traps, automatic zero initialization, stack protection,
stack-clash protection, FORTIFY_SOURCE=3, CET instrumentation, RELRO, immediate
binding and a non-executable stack. Release strips symbols; development retains
debug information. Strict CFI cast checks apply to C++ class casts and add no
class-cast coverage to these C sources. Compiler switches alone do not establish
hardware CET enforcement or instrument dependencies and payloads.
See the [Clang CFI reference](https://clang.llvm.org/docs/ControlFlowIntegrity.html)
for the applicable checks.

The Makefile probes -ftrivial-auto-var-init=zero. Only if that fails does it
try the same option with
-enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang.
Both failing rejects the build. This compatibility option was removed in
Clang 18 and is never passed unconditionally.
The removal is recorded in the
[Clang 18 release notes](https://releases.llvm.org/18.1.8/tools/clang/docs/ReleaseNotes.html).

LLVM_VERSION, CC and LD can be supplied explicitly to evaluate another matching
toolchain. Such a build is outside the default pin and needs its own validation.
The legacy opt-in selection was checked with an emulated compiler acceptance
rule; no older Debian compiler was available in the verification environment.

## Checks

tests/check.py compiles disposable syscall probes and intercepts init's final
exec. It checks personality query/set forms, error and kill outcomes, foreign
ABIs, MDWE failure and inheritance, argument forwarding, normal mappings and the
presence-based filesystem toggle. EINVAL, ENOSYS and EPERM are injected for
PR_SET_MDWE through an outer test filter. Unsupported host MDWE skips the real
inheritance checks and reports that limitation.

For static analysis:

```sh
clang --analyze -D_GNU_SOURCE -std=c11 \
  -Xanalyzer -analyzer-output=text seccomp-mdwe.c seccomp-init.c
```

For the external comparison, first run make check to build the test helpers:

```sh
python3 tools/paxtest.py --work-dir build/paxtest
```

Use a fresh work directory. The runner authenticates the release before
extraction, builds it with GCC so black-hat mode stays enabled, regenerates the
launcher with the actual test list, and runs baseline, MDWE-only and
seccomp-error sequentially. It clears SECCOMP_MDWE_FS and LD_PRELOAD for those
runs. It records commands, environment, signature verification and binary hashes.
A shell runner's zero exit status does not make every individual test conclusive.
