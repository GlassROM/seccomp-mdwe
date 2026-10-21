# seccomp-mdwe

seccomp-mdwe adds memory-related syscall restrictions before launching a Linux
program. Its primary use is additional sandboxing in containers using the
gVisor™ sandbox and on pure x86-64 Linux. It attempts PR_SET_MDWE and can
strengthen its restrictions by also denying anonymous or shared executable
mappings and selected memory-modification interfaces.

seccomp-init is a separate pre-init shim with its own policy.

## Scope

seccomp-mdwe only claims to be secure on pure x86_64 and in gVisor™ environments. Proposals suggesting otherwise may be rejected

The supported syscall ABI is x86-64 LP64. Foreign ABIs, including x32, are
rejected. The scope statement is a support boundary; the tests below do not
establish complete security. Read the [protection boundaries](docs/security-model.md).

## Build

Clang, LLD and clang-format are pinned to 23.1.4 in
[toolchain.mk](toolchain.mk). The tested libseccomp version is 2.5.5.
GCC builds of this project are currently unsupported; GCC is used only for
the external paxtest suite.
Build prerequisites, warning exceptions and compiler compatibility handling
are in [development.md](docs/development.md).

```sh
make -j2
make check
make -j2 MODE=development
make check MODE=development
```

The release profile is the default. Development enables -Weverything and
pedantic warnings; release keeps the explicit warning set. Both profiles
retain CFI, strict CFI casts, sanitizers with traps and the other documented
hardening options. Compilation does not execute the programs.

## Use

```sh
./seccomp-error /bin/echo hello
./seccomp-strict /bin/echo hello
SECCOMP_MDWE_FS=1 ./seccomp-error /bin/echo hello
```

| Binary or setting | Behavior |
| --- | --- |
| seccomp-error | Restricted memory operations return EPERM |
| seccomp-strict | Restricted memory operations kill the process |
| SECCOMP_MDWE_FS present | Also install optional filesystem rules |
| SECCOMP_MDWE_FS absent | Install the memory policy without filesystem rules |

The environment variable is presence-based: an empty value or 0 also enables
the filesystem rules. The choice is fixed before the payload starts.
[The policy tables](docs/security-model.md) list the affected syscalls.
With filesystem filtering enabled, openat2 returns ENOSYS in both modes so
programs can attempt a compatibility fallback.

Both payload modes attempt PR_SET_MDWE with PR_MDWE_REFUSE_EXEC_GAIN.
Protection is inherited across fork and exec. If the call is unsupported or
fails, the launcher warns and continues with seccomp. Failure to construct
or load the seccomp filter stops execution.

Personality queries are allowed. Setting a personality returns EPERM in
both modes, without a kill action. An inherited READ_IMPLIES_EXEC personality
is rejected at startup. Private executable file mappings remain available
for normal dynamic loading. Programs that generate code at runtime may
require a different sandbox policy.

## Independent init shim

seccomp-init runs before the real /sbin/init, sets no_new_privs, loads its own
filters and forwards init's arguments. It denies rseq, kcmp, personality changes
and explicit re-enablement of dumpability with EPERM.

It does not enable MDWE or install the payload's memory/filesystem filters.
Do not launch it during ordinary tests or replace a running system's init.
The regression driver intercepts its final exec call. Boot and service behavior
still needs separate deployment testing.

## Paxtest comparison

Paxtest 0.9.15 ran in black-hat mode on 21 October 2026 in an x86_64 Ubuntu
24.04.3 container reporting kernel 6.18.55. GCC 13.3.0 built the unchanged
test sources so the suite's black-hat path remained enabled. The underlying
container runtime was not independently identified.

The same test binaries ran sequentially at baseline, with PR_SET_MDWE alone,
and under the release seccomp-error binary. Both protected runs confirmed
PR_GET_MDWE=1. SECCOMP_MDWE_FS was unset.

| Paxtest group | Baseline | MDWE alone | seccomp-error |
| --- | --- | --- | --- |
| Direct execution in anonymous, BSS, data, heap, stack and shared-library areas: 7 probes | Killed | Killed | Killed |
| Execution after mprotect: 7 probes | Vulnerable | Killed | Killed |
| Writable text segments: 1 probe | Vulnerable | Killed | Killed |

Killed is paxtest's label for a child terminated by a signal. It does not
identify the blocking mechanism. In the error-returning policy, a rejected
protection change can leave a later execution attempt to fault.

Both protected configurations blocked the eight execution probes that
succeeded at baseline. This suite did not show an additional execution-probe
benefit from the seccomp layer in this environment. A separate syscall check
confirmed one additional restriction: MDWE alone permits a new anonymous RX
mapping, while seccomp-error returns EPERM.

The non-PIE main executable showed no address randomization in all runs.
Other ASLR estimates were sampled values; their variation is not attributed
to this policy.

### Reproduction

The external tests use a pinned paxtest version.

```sh
make check
python3 tools/paxtest.py --work-dir build/paxtest
```

The runner requires a fresh work directory.
[Recorded evidence](docs/validation/2026-10-21/README.md) includes raw output,
commands and run conditions.

Release and development each passed 167 focused policy checks. These include
MDWE failure handling and inheritance, personality forms, filesystem opt-in,
error/kill behavior, foreign ABI rejection and intercepted init forwarding.
Static analysis reported no findings. This is one environment and one legacy
test suite, with no claim of complete exploit coverage.

## Project information

- [Development](docs/development.md)
- [Contributing](CONTRIBUTING.md)
- [Agent instructions](AGENTS.md)
- [Vulnerability reports](SECURITY.md)
- [License](LICENSE)

gVisor is a trademark of Google LLC. Microsoft and Windows are trademarks of
the Microsoft group of companies. This project is not affiliated with,
endorsed by or sponsored by Google LLC or Microsoft Corporation. Names identify
third-party software and do not imply security equivalence. See
[third-party naming guidance](TRADEMARKS.md).
