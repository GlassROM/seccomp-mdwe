#include <linux/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

/* Baseline wrapper for the external paxtest comparison. */
int main(int argc, char *argv[]) {
  if (argc < 2) {
    return EXIT_FAILURE;
  }
  if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0UL, 0UL, 0UL) < 0) {
    perror("PR_SET_MDWE");
    return EXIT_FAILURE;
  }
  execvp(argv[1], &argv[1]);
  perror("execvp");
  return EXIT_FAILURE;
}
