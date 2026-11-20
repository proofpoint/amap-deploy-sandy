# D2 text 4 (OPTIONAL): the positive-control dry run

This is one of the setup sitting's texts (proposal b.9 and e.2).

**When it applies.** FINAL b.9 asks for "the Mac positive-control dry run if
E12 = a (the loop runner is not on the Mac)". The stage contract applies E12
(C) instead: "One runner host runs every run" (section 1). Under (C), the loop
already runs the installer on the same host and under the same launch line as
the final run.

This text keeps the one gap that sameness leaves: the operator's own
interactive shell in front of the launch line. That is b.4's "Operator
environment" (11 stops). Whether D2 includes it under E12 (C) is
[OPEN: the operator's decision]. W17 lists it, and b.9 conditions it on
E12 = a.

**What it changes:** it is target-read-only. On the runner host it creates one
run directory. `--dry-run` writes nothing to a target and never prompts (5.1;
3.7 rule 2).

## Precondition

- D2 text 1 (the profile capture) is done, and `launch.first_word` reads
  `file` or `command`.
- The private files and S0's slots are filled for the loop's test targets.
  Until every S0 probe is filled, S0 refuses, by design, and the result
  below is a named `PREFLIGHT.*` refusal, not a PASS.

## Step

Type this in the operator's own terminal on the runner host, exactly as
written, with `<installer checkout>` filled. Use the account and the shell that
D2 text 1 captured for that account: the same login, with no `su` or `sudo`
between. A different route into the account runs other startup files, and
then the capture does not describe what ran.

```sh
/usr/bin/env -i HOME="$HOME" SSH_AUTH_SOCK="$SSH_AUTH_SOCK" TERM="$TERM" PATH=/usr/bin:/bin /usr/bin/python3 -I -B <installer checkout>/install/alpha2_install.py --dry-run; echo "rc=$?"
```

## Result

- **PASS:** `rc=0`, and S10's block names the command `dry-run`.
- **FAIL:** any other `rc`.
  - `RUNNER.ENV` or `PREFLIGHT.INTERPRETER` means the shell, not the
    installer, changed what ran. Compare with D2 text 1's part B.
  - Any other cause is the named stage's.

Record one line in the sitting's private notes:
`POSITIVE-CONTROL dry-run rc=<rc> cause=<CAUSE line or none> summary_sha=<S10 SUMS sha or none>`.
