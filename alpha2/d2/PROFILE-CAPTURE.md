# D2 text 1: the operator profile capture

One of the reviewed texts of the setup sitting D2 (stage contract section 9;
proposal b.9). It covers the proposal's b.4 "Operator environment" gap: "shell
and version, alias and function names, hooks, PATH, tool versions". It also
captures the interpreter facts that `alpha2.lock`'s `interpreter` block pins
(6.1). The interpreter version is part of the capture (b.4).

**What it changes.** It is target-read-only. On the runner host the capture
itself creates exactly two files, `<out>/profile-shell.txt` and
`<out>/profile-env.txt` (mode 0600, each only if it validates), and one private
temporary directory, which it removes. It never overwrites or truncates a file.
Starting a login shell also runs the operator's own startup files, which do
whatever they do at any login; their writes are theirs, not the capture's (see
"Threat model").

**Where it runs.** On the runner host, under E12 (C), where one runner host
runs every run. It runs as the account that will type the launch line, in that
account's own terminal, from a clean installer checkout at the commit under
review. If the operator types launch lines as both runner accounts, run it once
as each, into two `<out>` directories.

**Custody of the output.** The output names host paths, account ids and the
operator's PATH. It is PRIVATE.
- It goes only into the private overlay checkout, beside `alpha2.lock` and
  `alpha2.hosts` (E16).
- It never goes into this repository, a receipt, a log or AMAP.
- It holds no environment value except PATH, TERM and the login shell's path,
  no alias or function body, and no hook text.

## Threat model

The capture runs the operator's OWN startup files, which already run with the
operator's full authority at every login. Its guarantees hold for startup files
that are mistaken or merely unusual, not for ones written to defeat it:

- (i) the capture adds no write beyond its own two output files, and never
  truncates anything;
- (ii) no value reaches the output, except the three stated ones: the PATH
  value, TERM and the login shell's path;
- (iii) a corrupt, incomplete or false result is never admitted. "False"
  includes a hook reported unset while it is still active. The checker
  validates every byte it admits, and the bytes admitted are exactly the bytes
  validated.

"Mistaken or unusual" is the named fixture list in
`alpha2/d2/tests/test_d2_texts.py` (`CaptureTest`):
- aliases and functions over every name the capture uses, including `builtin`,
  `trap`, `unset`, `shopt`, `set`, `printf` and `compgen`;
- an alias over the reserved word `if`;
- a readonly `builtin` function;
- `enable -n unset`, `enable -n trap`, and `enable -n shopt` with an alias over
  `builtin`;
- a readonly or nameref `POSIXLY_CORRECT`;
- multi-line exported values and alias bodies;
- `set --` naming an existing file, and `set --` with `shift`;
- `exit` in a startup file;
- `set -e`, `set -u` with noclobber, and `IFS`;
- DEBUG traps (one writing to fd 3, two using extdebug to skip commands), an ERR
  trap with errtrace, and an EXIT trap;
- startup `exec` redirections, including one that opens fd 3;
- a background job started at login;
- `PROMPT_COMMAND` and `PS0`;
- a file created in `<out>` during the run;
- `BASH_ENV` and `ENV`.

Each fixture is either admitted with names only, with no planted value or marker,
or not admitted at all. In both cases no startup function is called by the
capture.

**Named exclusions.** These are shapes where a startup function MAY run before the
capture refuses. No test claims them as safe refusals:
- a function named `unset`, together with `enable -n unset` or with a
  `POSIXLY_CORRECT` that cannot be set;
- a function named `exit`, likewise.

**Out of scope:** a startup file written to forge or redirect the capture. It
already runs as the operator and can see the capture's temporary path (the path
is in the shell's command text). For example, an EXIT trap can rewrite the file
after the body. Against such a file the checker still refuses anything malformed
or over the size limit. It cannot tell a well-formed forgery from a real capture,
because `env.PATH` and `shell.version` are free text.

## The step

`<checkout>` is the absolute path of the installer checkout. `<out>` is an
existing directory inside the private overlay checkout, without the two files.
`<loop-account>` and `<l3-account>` are the two runner accounts' names (5.3b).
Type this one line:

```sh
/usr/bin/env -i HOME="$HOME" SHELL="$SHELL" TERM="$TERM" USER="$USER" LOGNAME="$LOGNAME" SSH_AUTH_SOCK="$SSH_AUTH_SOCK" PATH=/usr/bin:/bin /bin/sh <checkout>/alpha2/d2/capture.sh <out> <loop-account> <l3-account>
```

The current shell runs no command substitution; it only expands six variables.

**The result is the last line printed**, never the exit code alone:
- `D2-PROFILE COMPLETE` (exit 0): both files were validated and written.
- `D2-PROFILE INCOMPLETE` (exit 1): at least one part was not admitted.
  - The `CHECK shell …` and `CHECK env …` lines above it name the key or the
    reason, never a value.
  - A part that was not admitted wrote no file.
  - To run again, remove from `<out>` only the file that WAS written, after
    reading it. Never remove a file the capture did not write.

Then hash both files and write the two shas down for the review:

```sh
/usr/bin/sha256sum <out>/profile-env.txt <out>/profile-shell.txt
```

## How it works (`alpha2/d2/`)

`capture.sh` runs under `env -i` and does the rest, in this order.

1. **Part B, the operator's shell.** It starts a NEW interactive login shell,
   `"$SHELL" -i -l`, with `profile-shell.sh`'s text as its command text. The
   capture file's path is written into that text, so no startup file can change
   it; a stray `set --` cannot redirect it.
   - No capture descriptor is open while the startup files run. The new
     shell's stdout and stderr are discarded, so nothing a startup file, hook or
     trap prints can reach the capture.
   - Only after startup does the text:
     1. (bash) run five lines with no reserved word and no unquoted name, so no
        alias can act on them. They record the operator's own SHELLOPTS (that is
        `shell.posix_mode`), set `POSIXLY_CORRECT` alone on its line, record
        whether posix mode engaged, run `\unset -f builtin`, and turn alias
        expansion off.
        - In posix mode the special builtins come before any function of the same
          name, so a function named `builtin` is removed without being called.
        - If the removal or the alias step fails, the shell exits there. No
          capture file is written, so nothing is admitted.
        - If posix mode did not engage, the capture ends `refused`.

        From then on, no function the startup files defined is ever called.
        Because of this, `function.names` never lists a function named
        `builtin`;
     2. read the DEBUG and RETURN traps, remove them, and re-read them. A read
        that fails or is skipped, or a trap still set, ends the capture
        `refused`;
     3. open the capture file with noclobber;
     4. write using builtins only, called through `builtin`.
   - Names are read by builtins that cannot see values: `compgen -a`,
     `-A function` and `-e` in bash, and the key lists in zsh.
2. **Part A, the fixed facts.** `profile-env.sh` runs under `env -i`. It records:
   - `interpreter.*` in the lock's five fields;
   - `tool.<name>.{path,resolved_path,sha256,version}` for every fixed tool the
     launch line and the installer call by absolute path. This is the input of
     `PREFLIGHT.MAC_TOOLS`.
   - `sleep.<unit>`: systemd's word for each sleep target, an observation for
     [OPEN: sleep probe measured] (5.3a);
   - `account.<name>.{uid,gid}`.

   Every read is checked. An unreadable file, an empty value, or a sha that is
   not 64 hex digits is recorded as `UNOBSERVED`, and the part ends
   `profile.end=incomplete`. Part A runs each tool's `--version`, so a
   replaced tool runs too; that is inherent in reading a version.
3. **Validation.** `profile_check.py` runs in a separate `env -i` process. It
   requires:
   - printable `key=value` lines, with no key twice;
   - exactly the expected key set for that part and shell;
   - each value's shape: shas, paths, versions, set or unset words, and name
     lists without values;
   - no `ABSENT`, `UNOBSERVED` or `REFUSED`;
   - `profile.end=complete` as the last line.

   It also refuses part B when `launch.first_word` is not `file` (bash) or
   `command` (zsh). Anything else means an alias, function or hook stands in
   front of the launch line's `/usr/bin/env`.
4. **Admission.** `profile_check.py` reads each temporary file once, at most
   64 KiB (a longer file is refused), validates those bytes, and writes exactly
   them into `<out>` as a new file, never over an existing one. It prints
   `ADMITTED <file>` or `NOT ADMITTED <file>: <reason>` for each.

## What the review package proves (not run at D2)

`alpha2/d2/tests/test_d2_texts.py`:

- **Positive control.** Part A's interpreter lines, as a lock block, pass S0's
  own `check_interpreter` on the test host.
  - Each of `sha256`, `resolved_path`, `resolved_sha256` and `version`, changed
    alone, refuses with `PREFLIGHT.INTERPRETER`.
  - `path` is a constant of the lock: S0 never reads it, and the lock check
    (L3) refuses any other value.
- **Hostile startup files.** It runs `capture.sh` end to end, as typed above,
  against a bash login shell whose startup files carry:
  - an rc echo;
  - aliases over `env`, `sed` and `printf`, one with a planted token;
  - multi-line exported values and a multi-line alias body;
  - functions over `env` and `printf`;
  - a DEBUG trap, one of which writes to fd 3;
  - a startup file that opens fd 3 itself;
  - `exit 0` in a startup file;
  - functions named `builtin`, `trap` and `/usr/bin/env`.

  Every case is either admitted with names only, with no planted body, value or
  marker in the capture or on the terminal, or not admitted at all.

## Open

- [OPEN: runner host OS]. Part A uses GNU coreutils (`realpath -e`,
  `sha256sum`), and so does S0 (`a2_s0.check_interpreter`). That fits the runner host. A
  non-GNU runner host would need both changed.
- The zsh branch is UNMEASURED: there is no zsh on the review host. Record each
  runner account's login shell on the runner host before D2. If it is zsh, the zsh branch is
  measured there first.
- `env -i` passes only HOME, SHELL, TERM, USER, LOGNAME and SSH_AUTH_SOCK to the
  login shell. Any other variable that the operator's terminal session inherits
  from outside the startup files is not in `env.names`.
- Left to the owners of each piece: NET's runtime (`PREFLIGHT.NET_RUNTIME`), the
  hypervisor's probes and the budget broker.
