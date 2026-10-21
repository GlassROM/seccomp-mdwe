# Vulnerability reports

Send implementation defects or violations of documented seccomp-mdwe guarantees
privately by email:

- To: randomhydrosol@glassrom.org
- CC: www.aryan804@gmail.com
- Subject: seccomp-mdwe vulnerability report

Send attachments without encryption so they can be reviewed directly.

## Scope

Reports against the current master revision are reviewed. Reproduce older
revision findings on current source where possible.

The supported scope is pure x86-64 Linux LP64 and containers using the
gVisor™ sandbox, subject to the [README scope statement](README.md#scope)
and [documented protection boundaries](docs/security-model.md).
The init shim has a separate policy.

Reports should identify observed behavior against a documented syscall or
protection contract. Compiler instrumentation and passing tests do not establish
memory safety, complete isolation or hardware enforcement.

## Reproduction evidence

Include the repository revision, compiler and library versions, CPU/kernel and
container runtime details, exact build/run commands, selected binary and relevant
environment variables. State whether PR_SET_MDWE succeeded.

Supply a minimal reproducer, expected and observed behavior, impact and the
affected contract. Include inherited file descriptors, mappings, personality,
thread state and outer seccomp policy where relevant. Logs, disassembly and
fault locations can support validation. Remove credentials and unrelated
personal data.

Follow-up stays in the email thread for triage, missing evidence, validation and
disclosure coordination.

gVisor is a trademark of Google LLC. This project is independent and is not
affiliated with, endorsed by or sponsored by Google LLC.
