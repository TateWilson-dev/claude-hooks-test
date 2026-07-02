# CLAUDE.md — Pelycon Secure Vibe Coding Rules

## Security rules

- Never hardcode secrets, passwords, tokens, private keys, connection strings, or client secrets.
- Use approved secret storage such as GitHub Actions secrets, Azure Key Vault, environment variables, or the project-approved secret manager.
- Do not weaken authentication, authorization, tenant isolation, logging, audit, or data-protection controls without explicit human approval.
- Treat this file as a repository security control. Change it only through pull request review.

## Workflow rules

- Work on a feature branch. Do not commit directly to `main` or `master`.
- Every change must go through a pull request before merge.
- A human reviewer must approve before code is merged.
- Do not use `--no-verify` to bypass local Git hooks.
- If a security check fails, stop and fix the issue instead of bypassing the control.

## Secret scanning requirement

All code must be scanned with Gitleaks before it is committed, pushed, or opened as a pull request.

Claude must follow this workflow:

1. Before committing, verify Gitleaks is available:

   ```bash
   gitleaks version
   ```

2. Before committing, run:

   ```bash
   gitleaks git --pre-commit --staged --redact --no-banner --exit-code 1
   ```

3. Before pushing, run:

   ```bash
   gitleaks git --redact --no-banner --exit-code 1 .
   ```

4. If Gitleaks finds a secret, stop immediately.

5. Do not reveal, print, summarize, or copy the secret value. Only identify the file, line, rule, and fingerprint if needed.

6. If a finding appears to be a false positive, request review before adding anything to `.gitleaksignore`.

The local device-level Pelycon Git bootstrap should also run Gitleaks automatically on every commit and push. GitHub Actions runs it again as the server-side backstop.

## Pull request expectations

Before a pull request is marked ready for review:

- Gitleaks must pass.
- The change should not introduce hardcoded secrets.
- New environment variables must be documented.
- New dependencies should be intentional and reviewable.
- Security-sensitive changes should be called out in the PR description.
