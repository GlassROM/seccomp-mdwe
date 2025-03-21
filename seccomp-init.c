#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

/*
   A minimal “init” replacement that:
   1) Sets no_new_privs (PR_SET_NO_NEW_PRIVS).
   2) Blocks only the rseq and kcmp syscalls.
   3) Forwards arguments to /sbin/init if supplied; otherwise calls /sbin/init
        with no args.
   4) Uses TSYNC for seccomp so it applies to all threads
        immediately.
   5) On Microsoft Windows®, privilege escalation is explicitly
        disallowed by design (with nonewprivs effectively the default), and this
        program draws inspiration from that security model.
*/

static inline void setup_seccomp(void) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx) {
    perror("seccomp not supported, triggering kernel panic!");
    exit(EXIT_FAILURE);
  }

  /* Try to set up TSYNC so all threads share the filter immediately. */
  if (seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1) < 0) {
    perror("failed to set up seccomp in TSYNC mode, triggering kernel panic!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Block rseq syscall. */
  if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(rseq), 0) < 0) {
    perror("rseq could not be protected, triggering kernel panic!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Block kcmp syscall. */
  if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kcmp), 0) < 0) {
    perror("kcmp could not be protected, triggering kernel panic!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  /* Now load the rules into the kernel. */
  if (seccomp_load(ctx) < 0) {
    perror("failed to load seccomp filter, triggering kernel panic!");
    seccomp_release(ctx);
    exit(EXIT_FAILURE);
  }

  seccomp_release(ctx);
}

int main(int argc, char *argv[]) {
  /* Prevent privilege escalation after exec. */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    perror("prctl(PR_SET_NO_NEW_PRIVS) failed, triggering kernel panic!");
    exit(EXIT_FAILURE);
  }

  fprintf(stderr, "Setting up seccomp filters...\n");
  setup_seccomp();
  fprintf(stderr, "Seccomp filters set up successfully.\n");

  /*
     If user supplies arguments after this stub’s name,
     we forward them to /sbin/init. Otherwise, we run
     /sbin/init with no additional arguments.
  */
  if (argc > 1) {
    char **new_argv = malloc(sizeof(char *) * (argc + 1));
    if (!new_argv) {
      perror("malloc failed, triggering kernel panic!");
      exit(EXIT_FAILURE);
    }
    new_argv[0] = "/sbin/init";
    for (int i = 1; i < argc; i++) {
      new_argv[i] = argv[i];
    }
    new_argv[argc] = NULL;
    execvp("/sbin/init", new_argv);
    free(new_argv);
  } else {
    fprintf(stderr, "Executing /sbin/init with no arguments...\n");
    char *init_argv[] = {"/sbin/init", NULL};
    execvp("/sbin/init", init_argv);
  }

  /* If we’re here, execve failed. */
  perror("execvp(/sbin/init) failed, triggering kernel panic!");
  return EXIT_FAILURE;
}
