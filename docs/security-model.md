# Protection boundaries

seccomp-mdwe installs a default-allow seccomp filter and then executes a payload.
It was developed to add memory restrictions inside containers using the
gVisor™ sandbox and on pure x86-64 Linux. The supported ABI is x86-64 LP64;
the filter rejects foreign syscall ABIs, including x32.

## Payload policy

Both payload binaries set no_new_privs and attempt
PR_SET_MDWE(PR_MDWE_REFUSE_EXEC_GAIN). MDWE failure produces a warning and
continues with seccomp. Successful MDWE is inherited across fork and exec.
Filter construction, TSYNC and loading failures stop execution.

seccomp-error returns EPERM for restricted operations.
seccomp-strict uses process-wide killing for memory and enabled filesystem
restrictions, except that openat2 returns ENOSYS in both binaries. Personality
changes and attempts to re-enable dumpability always return EPERM in both
binaries. The strict name describes the denial action,
not Linux's separate strict seccomp mode.

| Operation | Restriction |
| --- | --- |
| mprotect, pkey_mprotect | Deny calls containing PROT_EXEC, including redundant executable protections |
| mmap | Deny writable/executable, anonymous/executable and shared/executable combinations |
| shmat | Deny SHM_EXEC |
| memfd_create | Require MFD_NOEXEC_SEAL and deny MFD_EXEC |
| ptrace, process_vm_writev | Deny |
| io_uring_setup, io_uring_enter, io_uring_register | Deny |
| personality | Allow queries with lower 32 bits equal to 0xffffffff; deny changes with EPERM |
| prctl(PR_SET_DUMPABLE) | Deny nonzero settings with EPERM |

Private executable file mappings remain allowed for dynamic loading.
memfd_create is permitted when MFD_NOEXEC_SEAL is set and MFD_EXEC is absent,
including compatible CLOEXEC and sealing flags. The kernel clears the file's
execute bits and sets F_SEAL_EXEC to prevent adding them later. This seal does
not prohibit executable mmap: private RX mappings of these files remain allowed
by this policy. See the
[kernel API description](https://docs.kernel.org/userspace-api/mfd_noexec.html).
The launcher rejects an inherited READ_IMPLIES_EXEC personality before loading
the policy, since readable mappings could otherwise become executable without
PROT_EXEC.

## Optional filesystem rules

The presence of SECCOMP_MDWE_FS adds the rules below. Its value is not parsed;
empty and 0 both enable it. The choice is fixed when the launcher loads the
filter. A payload cannot remove that filter by changing its environment.

| Operation | Restriction |
| --- | --- |
| chmod, fchmod, fchmodat, fchmodat2 | Deny mode arguments containing any execute bit |
| creat, open, openat | Deny creation with execute bits, including O_TMPFILE for open/openat |
| openat2 | Return ENOSYS in both modes because classic seccomp cannot inspect struct open_how |
| execveat | Deny AT_EMPTY_PATH |

These rules are not pathname confinement or a read-only filesystem. They do not
prevent writing existing executable files, renaming files, passing descriptors
or accessing paths otherwise allowed by the surrounding sandbox.

## Independent init shim

seccomp-init sets no_new_privs, installs its own filter and executes /sbin/init
with the original trailing arguments. It denies rseq and kcmp with EPERM and
uses the shared personality and dumpability rules. It does not enable MDWE or
install the payload memory/filesystem rules. Filter inheritance and no_new_privs
affect init and its descendants; deployment needs boot and service testing.

## Remaining obligations

These filters supplement a surrounding sandbox. They do not establish memory
safety, prevent all code reuse, isolate the filesystem or network, or address
all kernel attack surfaces.

The caller must control the initial environment, inherited descriptors, mappings
and shared memory. Existing executable mappings and writable aliases, existing
io_uring SQPOLL mappings, procfs memory access, inherited executable files and
external writers need separate controls. Denying future syscalls cannot revoke
all pre-existing access. Dynamic loading of mutable file-backed code is still
possible where the surrounding system permits it.

Dumpability is cleared before execution and explicit re-enablement is denied.
An exec can reset dumpability; this is not a lifetime guarantee against core
dumps or external process inspection. Kernel policy, resource limits and the
surrounding sandbox remain relevant.

Runtime checks cover the recorded environment. They do not establish complete
security, hardware enforcement or coverage of other ABIs and container runtimes.
See [the recorded comparison](../README.md#paxtest-comparison).

gVisor is a trademark of Google LLC. This project is independent and is not
affiliated with, endorsed by or sponsored by Google LLC.
