#include "sandbox-common.h"

#include <fcntl.h>
#include <linux/memfd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>

/* Stable Linux UAPI values for builds using older development headers. */
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

#ifdef GL_PERMISSIVE
#define GL_SC_ACTION SCMP_ACT_ERRNO(EPERM)
#else
#define GL_SC_ACTION SCMP_ACT_KILL_PROCESS
#endif

static void enable_mdwe(void) {
  /* Stable Linux UAPI values also allow building with pre-6.3 headers. */
#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN (1UL << 0)
#endif
  if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0UL, 0UL, 0UL) < 0) {
    const int error = errno;
    fprintf(stderr,
            "warning: PR_SET_MDWE unavailable: %s; continuing with "
            "seccomp filters\n",
            strerror(error));
  }
}

static void add_memory_filters(scmp_filter_ctx ctx, bool deny_memfd) {
  if (deny_memfd) {
    check_seccomp(rule0(ctx, GL_SC_ACTION, SCMP_SYS(memfd_create)), ctx,
                  "deny all memfd creation");
  } else {
    /* Require an explicit no-exec seal independently of the namespace default.
       Conflicting executable requests remain denied in either policy mode. */
    check_seccomp(rule1(ctx, GL_SC_ACTION, SCMP_SYS(memfd_create),
                        SCMP_A1(SCMP_CMP_MASKED_EQ, MFD_NOEXEC_SEAL, 0)),
                  ctx, "require non-executable memfd");
    check_seccomp(rule1(ctx, GL_SC_ACTION, SCMP_SYS(memfd_create),
                        SCMP_A1(SCMP_CMP_MASKED_EQ, MFD_EXEC, MFD_EXEC)),
                  ctx, "deny executable memfd");
  }
  check_seccomp(rule1(ctx, GL_SC_ACTION, SCMP_SYS(mprotect),
                      SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)),
                ctx, "protect mprotect");
  check_seccomp(rule1(ctx, GL_SC_ACTION, SCMP_SYS(pkey_mprotect),
                      SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)),
                ctx, "protect pkey_mprotect");
  check_seccomp(rule1(ctx, GL_SC_ACTION, SCMP_SYS(mmap),
                      SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC | PROT_WRITE,
                              PROT_EXEC | PROT_WRITE)),
                ctx, "protect writable executable mmap");
  check_seccomp(
      rule2(ctx, GL_SC_ACTION, SCMP_SYS(mmap),
            SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC),
            SCMP_A3(SCMP_CMP_MASKED_EQ, MAP_ANONYMOUS, MAP_ANONYMOUS)),
      ctx, "protect anonymous executable mmap");
  /* MAP_SHARED and MAP_SHARED_VALIDATE both have the MAP_SHARED bit set. */
  check_seccomp(rule2(ctx, GL_SC_ACTION, SCMP_SYS(mmap),
                      SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC),
                      SCMP_A3(SCMP_CMP_MASKED_EQ, MAP_SHARED, MAP_SHARED)),
                ctx, "protect shared executable mmap");
  check_seccomp(rule1(ctx, GL_SC_ACTION, SCMP_SYS(shmat),
                      SCMP_A2(SCMP_CMP_MASKED_EQ, SHM_EXEC, SHM_EXEC)),
                ctx, "protect executable shmat");

  const int denied[] = {SCMP_SYS(ptrace), SCMP_SYS(process_vm_writev),
                        SCMP_SYS(io_uring_setup), SCMP_SYS(io_uring_enter),
                        SCMP_SYS(io_uring_register)};
  for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); ++i) {
    check_seccomp(rule0(ctx, GL_SC_ACTION, denied[i]), ctx,
                  "protect memory syscall");
  }
}

static void add_filesystem_filters(scmp_filter_ctx ctx) {
  const scmp_datum_t execute_bits[] = {S_IXUSR, S_IXGRP, S_IXOTH};
  for (size_t i = 0; i < sizeof(execute_bits) / sizeof(execute_bits[0]); ++i) {
    const scmp_datum_t bit = execute_bits[i];
    const int chmod_calls[] = {SCMP_SYS(chmod), SCMP_SYS(fchmod)};
    for (size_t j = 0; j < sizeof(chmod_calls) / sizeof(chmod_calls[0]); ++j) {
      check_seccomp(rule1(ctx, GL_SC_ACTION, chmod_calls[j],
                          SCMP_A1(SCMP_CMP_MASKED_EQ, bit, bit)),
                    ctx, "protect chmod execute bits");
    }
    const int chmodat_calls[] = {SCMP_SYS(fchmodat), SCMP_SYS(fchmodat2)};
    for (size_t j = 0; j < sizeof(chmodat_calls) / sizeof(chmodat_calls[0]);
         ++j) {
      check_seccomp(rule1(ctx, GL_SC_ACTION, chmodat_calls[j],
                          SCMP_A2(SCMP_CMP_MASKED_EQ, bit, bit)),
                    ctx, "protect fchmodat execute bits");
    }
    check_seccomp(rule1(ctx, GL_SC_ACTION, SCMP_SYS(creat),
                        SCMP_A1(SCMP_CMP_MASKED_EQ, bit, bit)),
                  ctx, "protect creat execute bits");
    const scmp_datum_t creation_flags[] = {O_CREAT, O_TMPFILE};
    for (size_t j = 0; j < sizeof(creation_flags) / sizeof(creation_flags[0]);
         ++j) {
      const scmp_datum_t flag = creation_flags[j];
      check_seccomp(rule2(ctx, GL_SC_ACTION, SCMP_SYS(open),
                          SCMP_A1(SCMP_CMP_MASKED_EQ, flag, flag),
                          SCMP_A2(SCMP_CMP_MASKED_EQ, bit, bit)),
                    ctx, "protect open execute bits");
      check_seccomp(rule2(ctx, GL_SC_ACTION, SCMP_SYS(openat),
                          SCMP_A2(SCMP_CMP_MASKED_EQ, flag, flag),
                          SCMP_A3(SCMP_CMP_MASKED_EQ, bit, bit)),
                    ctx, "protect openat execute bits");
    }
  }
  /* Classic seccomp cannot inspect open_how. Report an unavailable syscall so
     callers can use their compatibility fallback in either policy mode. */
  check_seccomp(rule0(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(openat2)), ctx,
                "protect openat2");
  check_seccomp(
      rule1(ctx, GL_SC_ACTION, SCMP_SYS(execveat),
            SCMP_A4(SCMP_CMP_MASKED_EQ, AT_EMPTY_PATH, AT_EMPTY_PATH)),
      ctx, "protect execveat AT_EMPTY_PATH");
}

static void setup_seccomp(bool filesystem, bool deny_memfd) {
  scmp_filter_ctx ctx = new_filter();
  add_common_filters(ctx);
  add_memory_filters(ctx, deny_memfd);
  if (filesystem) {
    add_filesystem_filters(ctx);
  }
  check_seccomp(seccomp_load(ctx), ctx, "load seccomp filter");
  seccomp_release(ctx);
}

int main(int argc, char *argv[]) {
  if (argc < 2 || argv == NULL || argv[0] == NULL || argv[1] == NULL) {
    fputs("Usage: seccomp-mdwe <program> [args...]\n", stderr);
    return EXIT_FAILURE;
  }
  prepare_process();
  enable_mdwe();
  setup_seccomp(getenv("SECCOMP_MDWE_FS") != NULL,
                getenv("SECCOMP_MDWE_DENY_MEMFD") != NULL);
  execvp(argv[1], &argv[1]);
  perror("execvp");
  return EXIT_FAILURE;
}
