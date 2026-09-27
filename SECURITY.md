# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately to: **`resero-labs@proofpoint.com`**

Include what you found, how to reproduce it, and the versions of sandy,
amap-router-local and amap-connector-claude involved. A partial report is
worth sending. You should expect an acknowledgement that your report was
received. If you do not get one, assume it did not arrive and say so through
any other channel you have.

The same address covers the router and the connector, so you do not need to
work out which repository a problem belongs to before reporting it.

## Supported versions

Fixes are made on the `main` branch. There are no maintained release
branches.

## What is in scope

This repo runs host-side, as the operator. It holds no credentials and
sends no messages. The properties it is responsible for, and whose failure
we treat as a vulnerability, are these:

- **Nothing is written into a sandbox.** Everything is delivered through
  sandy's feature manifest.
- **The feature payload is mounted read-only** into every selected sandbox,
  so an agent cannot alter the relay, the connector binaries or its own
  system prompt. The boundary is the read-only mount (`EROFS`), not file
  permissions.
- **Selection is sandy's.** Nothing read from inside a workspace can
  influence whether a sandbox is selected.
- **Authorisation is the router's.** Nothing on the agent's side can grant
  an agent the ability to task another agent. The rendered router config
  must reflect exactly the operator's policy.
- **`verify` never reports a clean result it did not establish.** A check
  that could not be made is reported as UNKNOWN, never as a pass.

`payload/INBOX-POLICY.md` is guidance to a cooperating agent and enforces
nothing (see `POLICY.md`). An agent ignoring it is not a vulnerability in
this repo. An agent being *able* to act beyond what the router allows is,
and belongs in the router's report.

## Disclosure

We will work with you on timing. The preference is coordinated disclosure
after a fix is available, and we would rather agree a date with you than
impose one.
