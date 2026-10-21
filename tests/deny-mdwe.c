#include "../sandbox-common.h"

int main(int argc, char *argv[]) {
  if (argc < 3) {
    return EXIT_FAILURE;
  }
  const int error = atoi(argv[1]);
  if (error != EINVAL && error != ENOSYS && error != EPERM) {
    return EXIT_FAILURE;
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) < 0) {
    return EXIT_FAILURE;
  }
  scmp_filter_ctx ctx = new_filter();
  check_seccomp(rule1(ctx, SCMP_ACT_ERRNO((uint32_t)error), SCMP_SYS(prctl),
                      SCMP_A0(SCMP_CMP_MASKED_EQ, UINT32_MAX, PR_SET_MDWE)),
                ctx, "simulate unavailable MDWE");
  check_seccomp(seccomp_load(ctx), ctx, "load test filter");
  seccomp_release(ctx);
  execvp(argv[2], &argv[2]);
  return EXIT_FAILURE;
}
