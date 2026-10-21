#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <linux/prctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int denied_errno(long result, int expected_errno) {
  if (result == -1 && errno == expected_errno) {
    return EXIT_SUCCESS;
  }
  fprintf(stderr, "expected errno %d, got %ld (errno %d)\n", expected_errno,
          result, errno);
  return EXIT_FAILURE;
}

static int denied(long result) { return denied_errno(result, EPERM); }

static int mapping(int protection, int flags) {
  void *address = mmap(NULL, 4096, protection, flags, -1, 0);
  if (address == MAP_FAILED) {
    return denied(-1);
  }
  (void)munmap(address, 4096);
  fputs("mapping unexpectedly succeeded\n", stderr);
  return EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    return EXIT_FAILURE;
  }
  const char *operation = argv[1];
  if (strcmp(operation, "query") == 0 || strcmp(operation, "set") == 0) {
    if (argc != 3) {
      return EXIT_FAILURE;
    }
    const unsigned long value = strtoul(argv[2], NULL, 0);
    errno = 0;
    const long result = syscall(SYS_personality, value);
    return strcmp(operation, "set") == 0
               ? denied(result)
               : (result < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
  }
  if (strcmp(operation, "mdwe") == 0 || strcmp(operation, "no-mdwe") == 0) {
    const int result = prctl(PR_GET_MDWE, 0UL, 0UL, 0UL, 0UL);
    printf("PR_GET_MDWE=%d\n", result);
    return result == (strcmp(operation, "mdwe") == 0 ? 1 : 0) ? EXIT_SUCCESS
                                                              : EXIT_FAILURE;
  }
  if (strcmp(operation, "nnp") == 0) {
    return prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL) == 1 ? EXIT_SUCCESS
                                                               : EXIT_FAILURE;
  }
  if (strcmp(operation, "dumpable") == 0) {
    return denied(prctl(PR_SET_DUMPABLE, 1UL, 0UL, 0UL, 0UL));
  }
  if (strcmp(operation, "x32") == 0) {
    (void)syscall((long)SYS_personality | 0x40000000L, 0xffffffffUL);
    return EXIT_FAILURE;
  }
  if (strcmp(operation, "mmap-wx") == 0) {
    return mapping(PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS);
  }
  if (strcmp(operation, "mmap-rx") == 0) {
    return mapping(PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS);
  }
  if (strcmp(operation, "mmap-rx-allowed") == 0) {
    void *address = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return address != MAP_FAILED && munmap(address, 4096) == 0 ? EXIT_SUCCESS
                                                               : EXIT_FAILURE;
  }
  if (strcmp(operation, "mmap-shared-rx") == 0 ||
      strcmp(operation, "mmap-validate-rx") == 0) {
    const int fd = open("mapping-file", O_CREAT | O_RDWR, 0600);
    if (fd < 0 || ftruncate(fd, 4096) < 0) {
      return EXIT_FAILURE;
    }
    const int flags = strcmp(operation, "mmap-shared-rx") == 0
                          ? MAP_SHARED
                          : MAP_SHARED_VALIDATE;
    errno = 0;
    void *address = mmap(NULL, 4096, PROT_READ | PROT_EXEC, flags, fd, 0);
    return address == MAP_FAILED ? denied(-1) : EXIT_FAILURE;
  }
  if (strcmp(operation, "mprotect") == 0 ||
      strcmp(operation, "pkey-mprotect") == 0) {
    void *address = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) {
      return EXIT_FAILURE;
    }
    errno = 0;
    const long result =
        strcmp(operation, "mprotect") == 0
            ? syscall(SYS_mprotect, address, 4096UL, PROT_READ | PROT_EXEC)
            : syscall(SYS_pkey_mprotect, address, 4096UL, PROT_READ | PROT_EXEC,
                      -1);
    return denied(result);
  }
  if (strcmp(operation, "rw") == 0) {
    void *address = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED || mprotect(address, 4096, PROT_READ) < 0) {
      return EXIT_FAILURE;
    }
    return munmap(address, 4096) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  }
  if (strcmp(operation, "file-rx") == 0) {
    const int fd = open("/bin/true", O_RDONLY);
    if (fd < 0) {
      return EXIT_FAILURE;
    }
    void *address = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (address == MAP_FAILED) {
      return EXIT_FAILURE;
    }
    return munmap(address, 4096) == 0 && close(fd) == 0 ? EXIT_SUCCESS
                                                        : EXIT_FAILURE;
  }
  if (strcmp(operation, "memfd") == 0) {
    return denied(syscall(SYS_memfd_create, "probe", 0U));
  }
  if (strcmp(operation, "shmat") == 0) {
    return denied(syscall(SYS_shmat, -1, NULL, SHM_EXEC));
  }
  if (strcmp(operation, "ptrace") == 0) {
    return denied(syscall(SYS_ptrace, 0L, 0L, NULL, NULL));
  }
  if (strcmp(operation, "process-vm") == 0) {
    return denied(
        syscall(SYS_process_vm_writev, 0L, NULL, 0UL, NULL, 0UL, 0UL));
  }
  if (strcmp(operation, "io-uring") == 0) {
    return denied(syscall(SYS_io_uring_setup, 0U, NULL));
  }
  if (strcmp(operation, "io-uring-enter") == 0) {
    return denied(syscall(SYS_io_uring_enter, -1, 0U, 0U, 0U, NULL, 0UL));
  }
  if (strcmp(operation, "io-uring-register") == 0) {
    return denied(syscall(SYS_io_uring_register, -1, 0U, NULL, 0U));
  }
  if (strcmp(operation, "rseq") == 0) {
    return denied(syscall(SYS_rseq, NULL, 0U, 0U, 0U));
  }
  if (strcmp(operation, "kcmp") == 0) {
    return denied(syscall(SYS_kcmp, 0, 0, 0, 0UL, 0UL));
  }
  long result;
  errno = 0;
  if (strcmp(operation, "chmod") == 0) {
    result = syscall(SYS_chmod, "absent-file", 0700U);
  } else if (strcmp(operation, "fchmod") == 0) {
    result = syscall(SYS_fchmod, -1, 0700U);
  } else if (strcmp(operation, "fchmodat") == 0) {
    result = syscall(SYS_fchmodat, AT_FDCWD, "absent-file", 0700U);
  } else if (strcmp(operation, "fchmodat2") == 0) {
    result = syscall(SYS_fchmodat2, AT_FDCWD, "absent-file", 0700U, 0);
  } else if (strcmp(operation, "creat") == 0) {
    result = syscall(SYS_creat, "created-file", 0700U);
  } else if (strcmp(operation, "open") == 0) {
    result = syscall(SYS_open, "opened-file", O_CREAT | O_RDWR, 0700U);
  } else if (strcmp(operation, "openat") == 0) {
    result =
        syscall(SYS_openat, AT_FDCWD, "openat-file", O_CREAT | O_RDWR, 0700U);
  } else if (strcmp(operation, "tmpfile") == 0) {
    result = syscall(SYS_openat, AT_FDCWD, ".", O_TMPFILE | O_RDWR, 0700U);
  } else if (strcmp(operation, "openat2") == 0) {
    const struct open_how how = {.flags = O_RDONLY};
    result = syscall(SYS_openat2, AT_FDCWD, ".", &how, sizeof(how));
  } else if (strcmp(operation, "execveat") == 0) {
    result = syscall(SYS_execveat, -1, "", argv, NULL, AT_EMPTY_PATH);
  } else {
    return EXIT_FAILURE;
  }
  if (argc == 3 && strcmp(argv[2], "allowed") == 0) {
    return result >= 0 || errno != EPERM ? EXIT_SUCCESS : EXIT_FAILURE;
  }
  return denied_errno(result,
                      strcmp(operation, "openat2") == 0 ? ENOSYS : EPERM);
}
