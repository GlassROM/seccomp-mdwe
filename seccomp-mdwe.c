#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <unistd.h>

#ifdef GL_PERMISSIVE
#define GL_SC_ACTION SCMP_ACT_ERRNO(EPERM)
#else
#define GL_SC_ACTION SCMP_ACT_KILL
#endif

static inline void setup_seccomp(void) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

  if (!ctx) {
    perror("seccomp not supported");
    exit(EXIT_FAILURE);
  }

  if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1) < 0) {
    perror("failed to set up seccomp in TSYNC mode, failing safely!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  if (seccomp_rule_add(ctx, GL_SC_ACTION, SCMP_SYS(mprotect), 1,
                       SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)) < 0) {
    perror("mprotect could not be protected, failing safely!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  if (seccomp_rule_add(ctx, GL_SC_ACTION, SCMP_SYS(mmap), 1,
                       SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC | PROT_WRITE,
                               PROT_EXEC | PROT_WRITE)) < 0) {
    perror("mmap could not be protected, failing safely!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  if (seccomp_rule_add(
          ctx, GL_SC_ACTION, SCMP_SYS(mmap), 2,
          SCMP_CMP(2, SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC),
          SCMP_CMP(3, SCMP_CMP_MASKED_EQ, MAP_ANONYMOUS, MAP_ANONYMOUS)) < 0) {
    perror("mmap anon could not be protected, failing safely!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  if (seccomp_rule_add(ctx, GL_SC_ACTION, SCMP_SYS(pkey_mprotect), 1,
                       SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)) < 0) {
    perror("pkey_mprotect could not be protected, failing safely!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  if (seccomp_rule_add(ctx, GL_SC_ACTION, SCMP_SYS(shmat), 1,
                       SCMP_A2(SCMP_CMP_MASKED_EQ, SHM_EXEC, SHM_EXEC)) < 0) {
    perror("shmat could not be protected, failing safely!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  if (seccomp_rule_add(ctx, GL_SC_ACTION, SCMP_SYS(memfd_create), 0) < 0) {
    perror("memfd_create could not be protected, failing safely!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  if (seccomp_load(ctx) < 0) {
    perror("failed to load seccomp filter");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  seccomp_release(ctx);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
    return EXIT_FAILURE;
  }
  printf("Setting up seccomp filters...\n");
  setup_seccomp();
  printf("Seccomp filters set up successfully.\n");

  execvp(argv[1], &argv[1]);

  // Should not get here
  perror("something went horribly wrong");
  return EXIT_FAILURE;
}
