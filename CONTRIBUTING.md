# Contributing

Changes to syscall filters need a concrete behavior description and a reproducer.
Read [AGENTS.md](AGENTS.md) and [the security model](docs/security-model.md).
Report vulnerabilities through [SECURITY.md](SECURITY.md).

## Development

Use the pinned tools in [toolchain.mk](toolchain.mk). Build and check both
profiles:

```sh
make -j2
make check
make -j2 MODE=development
make check MODE=development
make format
make format-check
git diff --check
```

Keep suppression reasons narrow and visible. Tests should check allowed behavior,
denial errno, kill outcomes and relevant inheritance. The init driver intercepts
the final exec; checks must never start the real system init.

## Commits

Keep related changes together. Every authored commit requires cryptographic
signing, a Signed-off-by trailer and an Assisted-by trailer when an agent
contributes. Author, committer and sign-off identities come from the build
environment's Git configuration. Assistance attribution uses the actual agent
settings and configured account.

One way to supply both signing and the trailers is:

```sh
git commit -S -s -m "Describe the related change" \
  --trailer "Assisted-by: Codex (<actual model and settings>), acting on behalf of <account>"
git verify-commit HEAD
```

State the behavior change, checks performed and remaining limits in the review
description. Use [the naming guidance](TRADEMARKS.md) for third-party marks.

## Agent entry points

AGENTS.md holds shared instructions. The Copilot file is
.github/copilot-instructions.md; CLAUDE.md and GEMINI.md import the shared file.
The paths and import mechanisms follow the official
[Codex](https://developers.openai.com/codex/guides/agents-md),
[Copilot](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions),
[Claude Code](https://code.claude.com/docs/en/memory) and
[Gemini CLI](https://geminicli.com/docs/cli/gemini-md/) documentation.
