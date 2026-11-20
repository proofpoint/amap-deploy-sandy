# D2.1, Part A alone: the runner host's fixed facts for the lock

This is the Part-A-only step of the operator profile capture. It follows the
operator's decision to split W17: Part A goes ahead for D2.1 and the lock's
`interpreter` block (F04-F07), and Part B follows separately.

It runs the same two programs as the full capture, unchanged:
- `alpha2/d2/profile-env.sh` (Part A);
- `alpha2/d2/profile_check.py` (the checker and admission).

Both are run by `alpha2/d2/part-a.sh`, under `env -i` and `/bin/sh`.

**What it changes.** It is target-read-only. In `<out>` on the runner host it
creates two files:
- `profile-env.unchecked`, mode 0600, created only if nothing exists at that
  path in any form (file, symlink, FIFO, directory), and removed again by the same
  run;
- `profile-env.txt`, mode 0600, written only if it validates.

It never overwrites or truncates a file.

**Where it runs.** On the runner host, in the operator's own terminal, from
a clean installer checkout at the commit under review. `<out>` is an existing
directory inside the private overlay checkout, holding neither file. The output
is PRIVATE, as in PROFILE-CAPTURE.md: it goes into the overlay only, never into
this repository, a receipt or AMAP.

## Placeholders

- `<checkout>`: the absolute path of the installer checkout.
- `<loop-account>` and `<l3-account>`: the two runner accounts' names. They must
  be the two DIFFERENT accounts; the same name typed twice is refused (a key
  appears twice).

## Steps

The operator's shell runs exactly two command words: `whence` in step 0, and
`/usr/bin/env` in step 1. Everything else runs inside `env -i`. Every word of both
lines is quoted.

**Accepted limit.** A FUNCTION named `whence` (or `builtin`) written to print step
0's expected lines cannot be detected by any check run inside that shell. Neither can
a line editor widget that rewrites the typed line. An honest wrapper function shows
as `function` and is caught. A startup file written to deceive the operator is out of
scope, as in PROFILE-CAPTURE.md's threat model.

0. Check that nothing stands in front of either word. This is read-only. In zsh:

   ```sh
   'whence' '-w' 'whence' '/usr/bin/env'
   ```

   It must print exactly these two lines:

   ```
   whence: builtin
   /usr/bin/env: command
   ```

   In bash, `type -t type /usr/bin/env` must print `builtin` and `file`.
   Anything else (an alias or a function) stops the step here.

1. Run Part A, check it and admit it:

   ```sh
   '/usr/bin/env' '-i' 'PATH=/usr/bin:/bin' '/bin/sh' '<checkout>/alpha2/d2/part-a.sh' '<out>' '<loop-account>' '<l3-account>'
   ```

   Every word is in single quotes, with the placeholders filled in INSIDE the quotes.
   zsh never expands an alias in a quoted word, so no alias, global ones included,
   can replace any word of this line or of step 0.

   The last line is the result:
   - `D2.1-PART-A ADMITTED`. The lines before it are `CHECK env VALID`,
     `ADMITTED profile-env.txt`, and the admitted file's sha256. Write that sha
     down for the review and the lock.
   - `D2.1-PART-A NOT ADMITTED`. The line before it names the reason: a key, a
     limit, or an existing scratch file. It never shows a value. Nothing was
     admitted, and an existing `profile-env.unchecked` was left untouched.

## What the lock takes from it

The lock's F04-F07 are the four `interpreter.*` lines, copied exactly as
admitted:
- `sha256`;
- `resolved_path`;
- `resolved_sha256`;
- `version`.

`interpreter.path` is the constant `/usr/bin/python3`.

The `tool.*`, `sleep.*` and `account.*` lines are not lock fields. They are the
input of S0's `PREFLIGHT.MAC_TOOLS` and of the sleep observation (5.3a).

## If it is not admitted

Read the reason, and do not edit any file.

- `sleep.<unit> was not observed`: systemd answered nothing for a sleep target.
  That is the fact the S0 review needs ([OPEN: sleep probe measured]).
- `profile-env.unchecked already exists`: look at that file. The run did not
  create it, did not touch it, and does not remove it.

Run step 1 again once the cause is understood.
