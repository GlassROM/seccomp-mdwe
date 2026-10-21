#include "sandbox-common.h"

/* Independent pre-init shim. These filters are inherited by /sbin/init. */
static void setup_seccomp(void) {
  scmp_filter_ctx ctx = new_filter();
  add_common_filters(ctx);
  check_seccomp(rule0(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(rseq)), ctx,
                "deny rseq");
  check_seccomp(rule0(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kcmp)), ctx,
                "deny kcmp");
  check_seccomp(seccomp_load(ctx), ctx, "load init seccomp filter");
  seccomp_release(ctx);
}

int main(int argc, char *argv[]) {
  if (argc < 1 || argv == NULL || argv[0] == NULL) {
    fputs("invalid init argument vector\n", stderr);
    return EXIT_FAILURE;
  }
  prepare_process();
  setup_seccomp();

  /* Reuse the existing null-terminated vector and preserve init's arguments. */
  char init_path[] = "/sbin/init";
  argv[0] = init_path;
  execv(init_path, argv);
  perror("execv(/sbin/init)");
  return EXIT_FAILURE;
}
