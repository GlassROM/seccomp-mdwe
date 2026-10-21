# Working on seccomp-mdwe

seccomp-mdwe installs Linux syscall filters before executing a payload.
seccomp-init is an independent pre-init shim. Read [README.md](README.md),
[development.md](docs/development.md), and
[security-model.md](docs/security-model.md) before changing behavior.

## Locate the change

| Area | Files |
| --- | --- |
| Payload memory and optional filesystem policy | seccomp-mdwe.c |
| Init policy and argument forwarding | seccomp-init.c |
| Shared personality, dumpability, error and startup handling | sandbox-common.h |
| Compiler selection and hardening | Makefile, toolchain.mk |
| Runtime policy regressions | tests/check.py, tests/*.c |
| Authenticated external comparison | tools/paxtest.py |

## Preserve the policy

- Filesystem filtering depends on the presence of SECCOMP_MDWE_FS.
  Empty values and 0 still enable it.
- With filesystem filtering enabled, openat2 returns ENOSYS in both payload
  modes so callers can use their compatibility fallback.
- Attempt PR_SET_MDWE with PR_MDWE_REFUSE_EXEC_GAIN in both payload modes.
  Failure warns and execution continues with seccomp. Preserve inheritance.
- Personality queries are allowed. Changes return EPERM in both programs,
  including the payload kill policy. Match the kernel's lower 32-bit argument.
- The init shim has its own policy and executes /sbin/init. It does not install
  the payload's memory or optional filesystem filters.
- Seccomp construction, TSYNC and load errors stop execution. libseccomp returns
  negative errno values; report those values rather than stale errno.
- Keep the x86-64 LP64 ABI boundary and rejection of foreign syscall ABIs.
- Review alternate syscalls, pointed-to arguments, inherited descriptors,
  fork/exec behavior and existing executable mappings when changing a rule.
  Classic seccomp cannot inspect memory behind a syscall argument.

## Build and validate

Use the Clang, LLD and clang-format versions in toolchain.mk. Start with a clean
working-tree inspection and preserve unrelated edits.
GCC builds of this project are currently unsupported. The external paxtest
suite uses GCC for its own test binaries.

```sh
make -j2
make check
make -j2 MODE=development
make check MODE=development
make format-check
git diff --check
```

Development enables -Weverything with documented exceptions; release keeps the
explicit warning set. Retain hardening when resolving diagnostics. Add focused
behavior checks for changed rules, including error and kill outcomes.

Never execute the real init shim as a test or replace the running system's init.
The test driver intercepts its final exec and separately exercises its policy.
Paxtest runs only after signature and pinned fingerprint verification. Its
filesystem toggle remains unset. Treat blocked, failed, skipped and inconclusive
tests as distinct outcomes. Record the environment and raw evidence for claims.

## External test pin

Paxtest is pinned to 0.9.15 in tools/paxtest.py. Keep these authentication
values consistent with the runner:

| Field | Value |
| --- | --- |
| Archive SHA-256 | d553848431fd8c2ab6c8361b62e5cedfed1cc1d60088241f4a33d2af15dd667f |
| Signer fingerprint | DE94 52CE 46F4 2094 907F 108B 44D1 C0F8 2525 FE49 |

Use the upstream [archive](https://grsecurity.net/~spender/paxtest-0.9.15.tar.gz),
[detached signature](https://grsecurity.net/~spender/paxtest-0.9.15.tar.gz.sig)
and [public key](https://grsecurity.net/spender-gpg-key.asc). Check the signer
against the separate [upstream download page](https://grsecurity.net/download.php).
Verify the digest and signature before extraction, compilation or execution.

The old paxtest recipe includes the compiler name in the launcher test list.
Regenerate the launcher from genpaxtest using only the actual tests, preserving
the test sources. Select -no-pie explicitly for the ET_EXEC test builds.

## Commits and documentation

Keep commits scoped to related changes. Cryptographically sign and sign off
every authored commit, and include an Assisted-by trailer identifying the actual
agent, model, available reasoning setting and account represented. Author,
committer and sign-off identities come from the build environment's Git
configuration.

Use concise, source-backed documentation. Distinguish intended deployment scope
from tested environments. Follow [TRADEMARKS.md](TRADEMARKS.md) for names and
attribution. Follow [SECURITY.md](SECURITY.md) for vulnerability reports.

## Code Review Rules

Flag rule bypasses through alternate entry points, syscall argument truncation,
foreign ABIs or inherited resources. Check that optional policy stays optional,
personality denials cannot kill, and MDWE failure remains nonfatal. Check that
tests establish the claimed outcome and that init never launches during checks.
