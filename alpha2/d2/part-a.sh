#!/bin/sh
# D2.1, Part A alone (alpha2/d2/PART-A-STEP.md). The one line the operator types:
#   '/usr/bin/env' '-i' 'PATH=/usr/bin:/bin' '/bin/sh' '<checkout>/alpha2/d2/part-a.sh' '<out>' '<loop-account>' '<l3-account>'
# Every word is quoted, so no alias of the operator's zsh, global ones included,
# can stand in for any of them.
#
# Target-read-only. Everything after the operator's `/usr/bin/env` runs here, under
# `env -i` and /bin/sh, so no alias or function of the operator's shell can stand in
# front of any step (the operator's shell runs no other command word).
# - umask 077 before anything is created, so the unchecked scratch file is 0600;
# - the scratch file is created only if NOTHING exists at its path, in any form (file,
#   symlink, dangling symlink, FIFO, directory); anything there is refused and left
#   untouched, and only a file this run created is ever removed;
# - profile-env.sh writes into it; profile_check.py validates it and writes exactly the
#   validated bytes to <out>/profile-env.txt as a new file (never over an existing one);
# - the scratch file this run created is removed; the admitted file's sha256 is printed.
# The last line is `D2.1-PART-A ADMITTED` (exit 0) or `D2.1-PART-A NOT ADMITTED` (exit 1).

PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077
set -C

stop() { printf '%s\n' "D2.1-PART-A NOT ADMITTED: $*"; exit 1; }

[ $# -eq 3 ] || stop "usage: part-a.sh OUT LOOP_ACCOUNT L3_ACCOUNT"
out=$1
here=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "$0")") || stop "cannot resolve the checkout"
[ -d "$out" ] || stop "OUT is not a directory"
scratch="$out/profile-env.unchecked"
# Anything at the path, in any form, is refused: dash's noclobber alone would open an
# existing FIFO or a symlink to a device. Then the create itself is noclobber, in a
# subshell (in dash a failed redirection on the special builtin `:` would end this
# script silently).
if [ -e "$scratch" ] || [ -h "$scratch" ]; then
    stop "$scratch already exists; nothing was changed"
fi
( : > "$scratch" ) 2>/dev/null || stop "$scratch could not be created; nothing was changed"

/bin/sh "$here/profile-env.sh" "$2" "$3" >> "$scratch" 2>/dev/null
printf '%s\n' "PART-A rc=$?"
/usr/bin/python3 -I -S -B "$here/profile_check.py" env "$scratch" "$out/profile-env.txt"
rc=$?
/usr/bin/rm -f -- "$scratch"
if [ "$rc" -eq 0 ]; then
    /usr/bin/sha256sum -- "$out/profile-env.txt"
    printf '%s\n' "D2.1-PART-A ADMITTED"
    exit 0
fi
printf '%s\n' "D2.1-PART-A NOT ADMITTED"
exit 1
