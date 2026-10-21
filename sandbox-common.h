#ifndef SECCOMP_MDWE_SANDBOX_COMMON_H
#define SECCOMP_MDWE_SANDBOX_COMMON_H

#if !defined(__linux__) || !defined(__x86_64__) || defined(__ILP32__)
#error "This project requires the x86-64 Linux LP64 ABI"
#endif

#include <errno.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <unistd.h>

/* Use the array API: the C ABI does not need aggregate varargs. */
static inline int rule0(scmp_filter_ctx ctx, uint32_t action, int call) {
  return seccomp_rule_add_array(ctx, action, call, 0, NULL);
}

static inline int rule1(scmp_filter_ctx ctx, uint32_t action, int call,
                        struct scmp_arg_cmp match) {
  return seccomp_rule_add_array(ctx, action, call, 1, &match);
}

static inline int rule2(scmp_filter_ctx ctx, uint32_t action, int call,
                        struct scmp_arg_cmp first, struct scmp_arg_cmp second) {
  const struct scmp_arg_cmp matches[] = {first, second};
  return seccomp_rule_add_array(ctx, action, call, 2, matches);
}

static inline void check_seccomp(int result, scmp_filter_ctx ctx,
                                 const char *operation) {
  if (result < 0) {
    /* libseccomp returns negative errno values; errno itself can be stale. */
    fprintf(stderr, "%s: %s\n", operation, strerror(-result));
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }
}

static inline scmp_filter_ctx new_filter(void) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    fputs("cannot allocate seccomp filter\n", stderr);
    exit(EXIT_FAILURE);
  }
  check_seccomp(seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1), ctx,
                "enable seccomp thread synchronization");
  check_seccomp(
      seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS),
      ctx, "reject foreign syscall ABIs");
  return ctx;
}

static inline void add_common_filters(scmp_filter_ctx ctx) {
  /* Linux consumes an unsigned 32-bit persona. Reject each missing query bit,
     allowing query arguments even when the ignored upper word is nonzero. */
  for (unsigned int bit = 0; bit < 32; ++bit) {
    check_seccomp(rule1(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality),
                        SCMP_A0(SCMP_CMP_MASKED_EQ, UINT64_C(1) << bit, 0)),
                  ctx, "deny personality changes");
  }
  check_seccomp(rule2(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(prctl),
                      SCMP_A0(SCMP_CMP_MASKED_EQ, UINT32_MAX, PR_SET_DUMPABLE),
                      SCMP_A1(SCMP_CMP_NE, 0, 0)),
                ctx, "deny re-enabling dumpability");
}

static inline void prepare_process(void) {
  /* READ_IMPLIES_EXEC can otherwise make a readable mapping executable
     without the explicit PROT_EXEC bit inspected by the filter. */
  const int persona = personality(UINT32_MAX);
  if (persona < 0) {
    perror("query personality");
    exit(EXIT_FAILURE);
  }
  if (((unsigned int)persona & (unsigned int)READ_IMPLIES_EXEC) != 0) {
    fputs("READ_IMPLIES_EXEC personality is unsupported\n", stderr);
    exit(EXIT_FAILURE);
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) < 0) {
    perror("PR_SET_NO_NEW_PRIVS");
    exit(EXIT_FAILURE);
  }
  if (prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) < 0) {
    perror("PR_SET_DUMPABLE");
    exit(EXIT_FAILURE);
  }
}

#endif
