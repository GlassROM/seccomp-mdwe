# Repository instructions

Read AGENTS.md at the repository root and follow its shared policy, validation
and commit requirements. Development commands and compiler pins are in
docs/development.md and toolchain.mk. Policy boundaries are in
docs/security-model.md.

seccomp-mdwe executes a supplied payload; seccomp-init is a separate pre-init
shim. Never launch the real shim while testing. Use make check and its
intercepted init driver.

Preserve presence-based filesystem opt-in, nonfatal MDWE failure, inherited MDWE,
and EPERM for personality changes in every policy. Test both payload binaries
and both build profiles when changing shared code.
