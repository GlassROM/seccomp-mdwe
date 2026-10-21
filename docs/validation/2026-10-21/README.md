# Validation on 21 October 2026

The filter implementation tested here is revision
a5eb448f04de5cffa4f52e38276a04370f1aa5be. The accompanying
[source hashes](source-hashes.json) identify the exact source and test helpers.
The [manifest](manifest.json) records binary hashes, host information and the
three external test commands.

## Results

- [Release policy checks](policy-release.txt): 167 passed.
- [Development policy checks](policy-development.txt): 167 passed.
- clang-format 23.1.4: no formatting differences.
- Clang static analyzer: no findings for the two programs.
- Modern auto-initialization probe, emulated legacy opt-in selection,
  rejection of an unsupported compiler and version mismatch: checked.
  An older Debian compiler was not available.
- ELF inspection: PIE, immediate binding, RELRO and a non-executable stack.

The [baseline](baseline.txt), [MDWE-only](mdwe-only.txt) and
[seccomp-error](seccomp-error.txt) logs are the full paxtest black-hat output.
Eight execution probes labeled Vulnerable at baseline were labeled Killed
under both protected configurations. Return-to-function outcomes were
inconclusive. Paxtest's Killed label does not identify the terminating signal
or establish which layer blocked execution.

[Signature status](signature.txt) records the verified upstream signer.
The fingerprint was checked against
[grsecurity's download page](https://grsecurity.net/download.php).
Authentication preceded extraction and compilation.

## Conditions and limits

The container reported x86_64, Ubuntu 24.04.3 and kernel 6.18.55.
Clang/LLD 23.1.4 built the release wrapper; GCC 13.3.0 built paxtest.
The underlying container runtime was not independently identified.

Both protected external runs confirmed PR_GET_MDWE=1.
SECCOMP_MDWE_FS and LD_PRELOAD were unset. The same paxtest binaries ran
sequentially in all configurations. The generated launcher omitted the
spurious compiler entry from the old upstream recipe; the test sources were
unchanged. ET_EXEC test builds explicitly selected -no-pie.

The init checks intercepted the final exec call and tested argument forwarding.
They did not start the real init system or establish boot/service compatibility.
Passing checks do not establish complete security or hardware CET enforcement.
