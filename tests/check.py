#!/usr/bin/env python3
"""Run policy probes in disposable child processes; never launch real init."""
import argparse
import errno
import os
from pathlib import Path
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--build-dir", type=Path, required=True)
parser.add_argument("--cc", default="clang")
parser.add_argument("--strict-warnings", action="store_true")
args = parser.parse_args()
out = args.build_dir.resolve()
tools = out / "tests"
tools.mkdir(exist_ok=True)
for source in ("probe", "init-driver", "deny-mdwe", "mdwe-only"):
    command = [args.cc, "-D_GNU_SOURCE", "-std=c11", "-O2", "-Wall", "-Wextra",
               "-Wpedantic", "-Werror", "-Wconversion", "-Wshadow",
               "-fuse-ld=lld", str(ROOT / "tests" / (source + ".c")),
               "-o", str(tools / source)]
    if args.strict_warnings:
        command += ["-Weverything", "-Wno-declaration-after-statement",
                    "-Wno-unsafe-buffer-usage", "-Wno-disabled-macro-expansion"]
    if source in ("init-driver", "deny-mdwe"):
        command += ["-L/usr/local/lib", "-Wl,--no-as-needed", "-lirralloc",
                    "-Wl,--as-needed", "-lseccomp"]
    if source == "init-driver":
        command += ["-Wl,--wrap=execv"]
    subprocess.run(command, check=True)
environment = dict(os.environ)
environment.pop("SECCOMP_MDWE_FS", None)
passed = 0


def run(label, command, expected=0, filesystem=None, warning=False):
    global passed
    env = dict(environment)
    if filesystem is not None:
        env["SECCOMP_MDWE_FS"] = filesystem
    result = subprocess.run(list(map(str, command)), env=env, cwd=work,
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == expected, (
        label, result.returncode, expected, result.stdout, result.stderr)
    if warning:
        assert "warning: PR_SET_MDWE unavailable:" in result.stderr, result.stderr
    print("PASS", label)
    passed += 1


probe = tools / "probe"
memory = ("mmap-wx", "mmap-rx", "mmap-shared-rx", "mmap-validate-rx",
          "mprotect", "pkey-mprotect", "memfd", "shmat", "ptrace", "process-vm",
          "io-uring", "io-uring-enter", "io-uring-register")
filesystem_calls = ("chmod", "fchmod", "fchmodat", "fchmodat2", "creat", "open",
                    "openat", "tmpfile", "openat2", "execveat")
with tempfile.TemporaryDirectory(prefix="seccomp-check-") as work:
    for name in ("seccomp-error", "seccomp-strict"):
        wrapper = out / name
        for value in ("0xffffffff", "0xffffffffffffffff", "0x12345678ffffffff"):
            run(name + " query " + value, [wrapper, probe, "query", value])
        for value in ("0", "0x400000", "0x100000000", "0xffffffff00400000"):
            run(name + " deny personality " + value, [wrapper, probe, "set", value])
        for operation in ("nnp", "dumpable", "rw", "file-rx"):
            run(name + " " + operation, [wrapper, probe, operation])
        run(name + " foreign ABI", [wrapper, probe, "x32"], -signal.SIGSYS)
        for operation in memory:
            expected = 0 if name == "seccomp-error" else -signal.SIGSYS
            run(name + " " + operation, [wrapper, probe, operation], expected)
        for operation in filesystem_calls:
            run(name + " default filesystem " + operation,
                [wrapper, probe, operation, "allowed"])
            expected = 0 if name == "seccomp-error" else -signal.SIGSYS
            for value in ("", "1", "0"):
                run(name + " filesystem=" + repr(value) + " " + operation,
                    [wrapper, probe, operation], expected, filesystem=value)
        run(name + " no payload", [wrapper], 1)
        run(name + " missing payload", [wrapper, "/definitely/absent"], 1)
        for error in (errno.EINVAL, errno.ENOSYS, errno.EPERM):
            for operation in ("query", "mmap-rx"):
                tail = ["0xffffffff"] if operation == "query" else []
                expected = -signal.SIGSYS if name == "seccomp-strict" and operation == "mmap-rx" else 0
                run(name + " MDWE failure " + str(error) + " " + operation,
                    [tools / "deny-mdwe", error, wrapper, probe, operation, *tail],
                    expected, warning=True)
    init = tools / "init-driver"
    for value in ("0xffffffff", "0xffffffffffffffff", "0x12345678ffffffff"):
        run("init query " + value, [init, probe, "query", value])
    for value in ("0", "0x400000", "0x100000000", "0xffffffff00400000"):
        run("init deny personality " + value, [init, probe, "set", value])
    for operation in ("rseq", "kcmp", "dumpable", "nnp", "no-mdwe", "rw"):
        run("init " + operation, [init, probe, operation])
    run("init foreign ABI", [init, probe, "x32"], -signal.SIGSYS)
    run("init no args forwarding", [init, "--entry"])
    run("init args forwarding", [init, "--entry", "single", "two words"])
    result = subprocess.run([tools / "mdwe-only", probe, "mdwe"], capture_output=True)
    if result.returncode == 0:
        run("MDWE alone permits a new anonymous RX mapping",
            [tools / "mdwe-only", probe, "mmap-rx-allowed"])
        for name in ("seccomp-error", "seccomp-strict"):
            run(name + " MDWE inherited across exec", [out / name, probe, "mdwe"])
            run(name + " MDWE inherited across fork and exec",
                [out / name, "/bin/sh", "-c", '"$1" mdwe & wait', "sh", probe])
    else:
        print("SKIP kernel MDWE inheritance: unavailable in this environment")
print(passed, "policy checks passed")
