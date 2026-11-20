#!/bin/sh
# D2 text 1, the operator profile capture: the one line the operator types
# (alpha2/d2/PROFILE-CAPTURE.md):
#   /usr/bin/env -i HOME="$HOME" SHELL="$SHELL" TERM="$TERM" USER="$USER" LOGNAME="$LOGNAME" SSH_AUTH_SOCK="$SSH_AUTH_SOCK" PATH=/usr/bin:/bin /bin/sh <checkout>/alpha2/d2/capture.sh <out> <loop-account> <l3-account>
#
# Target-read-only. It creates, on the runner host only:
#   <out>/profile-shell.txt and <out>/profile-env.txt (mode 0600), and one private
#   temporary directory, which it removes.
# It never overwrites a file and never admits an output that profile_check.py, run in a
# separate `env -i` process, did not find valid and complete.
#
# Order:
# 1. Part B: the operator's login shell, $SHELL -i -l, runs profile-shell.sh's text with
#    the capture path written into it. It runs with no fd 3 and with stdout and stderr
#    discarded, so nothing the startup files print reaches the capture. The body opens
#    the capture file itself, only after the startup files have run, with noclobber
#    (see profile-shell.sh).
# 2. Part A: profile-env.sh under `env -i`.
# 3. profile_check.py validates each output (bounded size, exact keys, unique keys,
#    value shapes, the end line) and writes exactly the validated bytes into <out> as a
#    new file. It prints ADMITTED or NOT ADMITTED for each.
# 4. The last line printed is `D2-PROFILE COMPLETE` (exit 0) or
#    `D2-PROFILE INCOMPLETE` (exit 1).

PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-

say() { printf '%s\n' "$*"; }
die() { say "D2-PROFILE INCOMPLETE: $*"; exit 1; }

[ $# -ge 1 ] || die "usage: capture.sh OUT [ACCOUNT ...]"
out=$1
shift
here=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "$0")") || die "cannot resolve the checkout"
[ -d "$out" ] || die "OUT is not a directory"
for f in profile-shell.txt profile-env.txt; do
    if [ -e "$out/$f" ] || [ -L "$out/$f" ]; then die "OUT already holds $f; nothing is overwritten"; fi
done
case ${SHELL:-} in
    /*) [ -x "$SHELL" ] || die "SHELL is not an executable absolute path" ;;
    *) die "SHELL is not an absolute path" ;;
esac
py=/usr/bin/python3
check="$here/profile_check.py"
[ -f "$check" ] || die "profile_check.py missing beside capture.sh"

tmp=$(/usr/bin/mktemp -d) || die "cannot make a private temporary directory"
trap '/usr/bin/rm -f -- "$tmp/shell.txt" "$tmp/env.txt"; /usr/bin/rmdir -- "$tmp"' EXIT

# 1. Part B. The capture file's path is written INTO the command text, in place of the
#    marker, so no startup file can change it (`set --` cannot reach the -c text). The
#    path is checked against a closed shape first. The login shell's own stdout and
#    stderr are discarded, and stdin is empty.
dest="$tmp/shell.txt"
case $dest in
    *[!A-Za-z0-9._/-]*) die "the temporary path has an unexpected character" ;;
esac
body=$(/bin/cat -- "$here/profile-shell.sh") || die "cannot read profile-shell.sh"
body=$(printf '%s\n' "$body" | /usr/bin/sed "s|@@D2_OUT@@|$dest|g") || die "cannot prepare the capture text"
case $body in *@@D2_OUT@@*) die "the capture text was not prepared" ;; esac
"$SHELL" -i -l -c "$body" </dev/null >/dev/null 2>&1
rc_b=$?
say "PART-B shell_rc=$rc_b"

# 2. Part A.
/usr/bin/env -i PATH=/usr/bin:/bin /bin/sh "$here/profile-env.sh" "$@" >"$tmp/env.txt" 2>/dev/null
rc_a=$?
say "PART-A rc=$rc_a"

# 3. Admission. profile_check.py reads each file once, bounded, validates it, and writes
#    exactly those bytes into <out>, as a new file (never over an existing one).
admitted=0
/usr/bin/env -i PATH=/usr/bin:/bin "$py" -I -S -B "$check" shell "$tmp/shell.txt" "$out/profile-shell.txt" \
    && admitted=$((admitted + 1))
/usr/bin/env -i PATH=/usr/bin:/bin "$py" -I -S -B "$check" env "$tmp/env.txt" "$out/profile-env.txt" \
    && admitted=$((admitted + 1))
if [ "$admitted" -eq 2 ]; then
    say "D2-PROFILE COMPLETE"
    exit 0
fi
say "D2-PROFILE INCOMPLETE"
exit 1
