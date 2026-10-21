#!/usr/bin/env python3
"""Authenticate paxtest 0.9.15 before building and comparing black-hat runs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = "DE9452CE46F42094907F108B44D1C0F82525FE49"
ARCHIVE_SHA256 = "d553848431fd8c2ab6c8361b62e5cedfed1cc1d60088241f4a33d2af15dd667f"
URLS = {
    "paxtest-0.9.15.tar.gz": "https://grsecurity.net/~spender/paxtest-0.9.15.tar.gz",
    "paxtest-0.9.15.tar.gz.sig": "https://grsecurity.net/~spender/paxtest-0.9.15.tar.gz.sig",
    "spender-gpg-key.asc": "https://grsecurity.net/spender-gpg-key.asc",
}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--work-dir", type=Path, default=ROOT / "build" / "paxtest")
parser.add_argument("--build-dir", type=Path, default=ROOT / "build" / "release")
parser.add_argument("--gcc", default="gcc")
args = parser.parse_args()
compiler_macros = subprocess.check_output(
    [args.gcc, "-dM", "-E", "-x", "c", "/dev/null"], text=True)
if "#define __GNUC__ " not in compiler_macros or "#define __clang__ " in compiler_macros:
    raise SystemExit("GCC is required: paxtest downgrades black-hat mode under Clang")
work = args.work_dir.resolve()
build = args.build_dir.resolve()
work.mkdir(parents=True, exist_ok=True)
for name, url in URLS.items():
    target = work / name
    if not target.exists():
        with urllib.request.urlopen(url, timeout=60) as response:
            target.write_bytes(response.read())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


archive = work / "paxtest-0.9.15.tar.gz"
if sha256(archive) != ARCHIVE_SHA256:
    raise SystemExit("Archive differs from the authenticated 0.9.15 release")
keyring = work / "signer.gpg"
subprocess.run(["gpg", "--batch", "--yes", "--dearmor", "--output", str(keyring),
                str(work / "spender-gpg-key.asc")], check=True)
verification = subprocess.run(
    ["gpgv", "--status-fd", "1", "--keyring", str(keyring),
     str(work / "paxtest-0.9.15.tar.gz.sig"), str(archive)],
    text=True, capture_output=True, check=True)
(work / "signature.txt").write_text(verification.stdout + verification.stderr)
fingerprints = re.findall(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]+) ", verification.stdout, re.M)
if fingerprints != [FINGERPRINT]:
    raise SystemExit("Signature does not match the fingerprint published by upstream")
print("Verified paxtest signature:", FINGERPRINT, flush=True)

source = work / "paxtest-0.9.15"
if source.exists():
    raise SystemExit("Use a fresh work directory; existing extracted sources are not reused")
with tarfile.open(archive) as tar:
    tar.extractall(work, filter="data")
with (work / "build.txt").open("w") as log:
    subprocess.run(["make", "-f", "Makefile.psm", "-j2", "CC=" + args.gcc,
                    "THEARCH=-m64", "CC_ETEXEC=-no-pie", "LD_ETEXEC=-no-pie"],
                   cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True)
# The upstream recipe passes the compiler name to genpaxtest as a test.
# Regenerate only the launcher with the actual TESTS list.
makefile = (source / "Makefile.psm").read_text()
values = {}
for key in ("EXEC_TESTS", "MPROT_TESTS", "SHLIB_TESTS", "MPROTSH_TESTS", "RAND_TESTS",
            "FAST_RAND_TESTS", "RET_TESTS", "RETX_TESTS", "TESTS"):
    value = re.search(r"^" + key + r" = (.*)$", makefile, re.M)[1]
    for variable, expansion in values.items():
        value = value.replace("$(" + variable + ")", expansion)
    values[key] = value
subprocess.run(["sh", "genpaxtest", *values["TESTS"].split()], cwd=source, check=True)

environment = dict(os.environ)
environment.pop("SECCOMP_MDWE_FS", None)
environment.pop("SECCOMP_MDWE_DENY_MEMFD", None)
environment.pop("LD_PRELOAD", None)
probe = build / "tests" / "probe"
mdwe = build / "tests" / "mdwe-only"
subprocess.run([mdwe, probe, "mdwe"], env=environment, check=True)
subprocess.run([build / "seccomp-error", probe, "mdwe"], env=environment, check=True)
subprocess.run([mdwe, probe, "mmap-rx-allowed"], env=environment, check=True)

manifest = {
    "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "uname": list(platform.uname()),
    "os_release": Path("/etc/os-release").read_text(),
    "gcc": subprocess.check_output([args.gcc, "--version"], text=True).splitlines()[0],
    "archive_url": URLS["paxtest-0.9.15.tar.gz"],
    "archive_sha256": sha256(archive),
    "signer_fingerprint": FINGERPRINT,
    "fingerprint_source": "https://grsecurity.net/download.php",
    "binary_sha256": {str(path.relative_to(build)): sha256(path)
                      for path in (build / "seccomp-error", mdwe, probe)},
    "runs": [],
}
for name, prefix in (("baseline", []), ("mdwe-only", [mdwe]),
                     ("seccomp-error", [build / "seccomp-error"])):
    command = [*map(str, prefix), "./paxtest", "blackhat", str(work / (name + ".txt"))]
    print("Running", name, flush=True)
    start = time.monotonic()
    with (work / (name + "-console.txt")).open("w") as log:
        result = subprocess.run(command, cwd=source, env=environment, stdout=log,
                                stderr=subprocess.STDOUT, timeout=600)
    manifest["runs"].append({"name": name, "command": command,
                             "returncode": result.returncode,
                             "seconds": time.monotonic() - start})
    (work / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    if result.returncode:
        raise SystemExit(name + " runner failed; inspect the console log")
    output = (work / (name + ".txt")).read_text()
    if "Mode: 1\nBlackhat\n" not in output or "blackhat mode not supported" in output:
        raise SystemExit(name + " did not run in black-hat mode")
print("Comparison logs:", work, flush=True)
