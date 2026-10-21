/* Exercise the actual shim policy and argument forwarding without running init.
 */
int init_entry(int argc, char *argv[]);
#define main init_entry
#include "../seccomp-init.c"
#undef main

int __wrap_execv(const char *path, char *const argv[]);

int __wrap_execv(const char *path, char *const argv[]) {
  if (strcmp(path, "/sbin/init") != 0 || strcmp(argv[0], "/sbin/init") != 0) {
    _Exit(EXIT_FAILURE);
  }
  if (argv[1] == NULL) {
    _Exit(EXIT_SUCCESS);
  }
  if (strcmp(argv[1], "single") == 0 && argv[2] != NULL &&
      strcmp(argv[2], "two words") == 0 && argv[3] == NULL) {
    _Exit(EXIT_SUCCESS);
  }
  _Exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  if (argc >= 2 && strcmp(argv[1], "--entry") == 0) {
    return init_entry(argc - 1, &argv[1]);
  }
  if (argc < 2) {
    return EXIT_FAILURE;
  }
  prepare_process();
  setup_seccomp();
  execvp(argv[1], &argv[1]);
  perror("execvp test payload");
  return EXIT_FAILURE;
}
