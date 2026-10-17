"""root-trust.sh: what root runs before it trusts anything (ROOT-BOOTSTRAP d3
§3). Standard library only.

Root trusts one thing it does not check by running it, the anchor: /bin/sh,
/usr/bin/env and the operating system's own utilities, under the pinned
environment `anchor()`. Before root executes the recorded python3 and the
pinned writer, the functions rendered here judge them by metadata alone:

- `_rt_route PATH`: PATH walked as host_steps.closure_problems walks a path.
  Every textual ancestor is judged; a link is judged itself and then hopped
  to its TEXTUAL target, resolved against the link's own directory, whose
  ancestors are judged first; visits are keyed by the directory entry the
  target names (host_steps._entry), so each link is visited once and every
  cycle ends; at most MAX_HOPS hops in all.
- each read goes through a sentinel, so a trailing newline is kept, and a
  byte outside printable ASCII in any path, link target or listed name fails.
- the file rule: a regular file, root's, no group or other write, and for
  the interpreter executable; an ACL fails (Linux: `+` in ls's eleventh
  column; macOS: any `ls -led` entry line, since `@` replaces `+` there).
- the writer's sha256 against the document's pin.
- the interpreter's install root whole, with `find`, before python reads it.

`root_exec SHA PYTHON3 WRITER ARGS...` runs all of it and then
`exec PYTHON3 -I -S -B WRITER ARGS...`; the writer's `trusted-exec` judges
the rest. A failure prints `untrusted: <path>: <why>` and exits EXIT; the file
itself ends with status 0, so sourcing it never fails a line (d3.3 §3.7).

The anchor also covers what the launchd wrapper runs outside root_exec, under
the same pinned sh: its own record of a result (printf, date, mv) and its
removal of a stale one (rm), on its own status file (Opus d3.3 N4).

root-trust.sh is rendered, and placed root 0444 beside the writer like the
supervision wrapper: verify compares the placed bytes with a fresh render.
"""

import os
import posixpath
import shlex
import struct
from typing import Any, List, Optional, Sequence, Tuple

#: The check's exit: outside PROBE_EXITS, REFUSED, the partition job's codes,
#: the hub's NO_RESTART (0-11), the engine's 125, the shell's 126-127 and 143.
EXIT = 12
PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
MAX_HOPS = 40
NAME = "root-trust.sh"
#: The anchor shell, whose PT_INTERP is the anchor loader the render names.
ANCHOR_SHELL = "/bin/sh"
#: The one interpreter root runs, per OS (d3 T2), and the root of its install.
LINUX_PYTHON = "/usr/bin/python3"
DARWIN_PYTHON = "/Library/Developer/CommandLineTools/usr/bin/python3"
DARWIN_ROOT = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework"


def anchor(engine: Optional[str] = None) -> List[str]:
    """`/usr/bin/env -i PATH=... LC_ALL=C`, with the engine where the wrapped
    command reaches docker (env -i would wipe it)."""
    return ["/usr/bin/env", "-i", f"PATH={PATH}", "LC_ALL=C"] + ([f"DOCKER_HOST={engine}"] if engine else [])


def elf_interpreter(path: str) -> Optional[str]:
    """An ELF file's PT_INTERP, read from its program headers (nothing runs):
    the loader the kernel starts it with; None for a static file."""
    with open(path, "rb") as f:
        head = f.read(64)
        if head[:4] != b"\x7fELF":
            raise ValueError(f"{path} is not an ELF file")
        wide, end = head[4] == 2, "<" if head[5] == 1 else ">"
        if wide:
            (phoff,), (phentsize, phnum) = struct.unpack(end + "Q", head[32:40]), struct.unpack(end + "HH", head[54:58])
        else:
            (phoff,), (phentsize, phnum) = struct.unpack(end + "I", head[28:32]), struct.unpack(end + "HH", head[42:46])
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            ph = f.read(phentsize)
            if struct.unpack(end + "I", ph[:4])[0] != 3:          # PT_INTERP
                continue
            off, size = (struct.unpack(end + "Q", ph[8:16])[0], struct.unpack(end + "Q", ph[32:40])[0]) if wide \
                else (struct.unpack(end + "I", ph[4:8])[0], struct.unpack(end + "I", ph[16:20])[0])
            f.seek(off)
            return f.read(size).split(b"\0", 1)[0].decode("ascii")
    return None


def allowed_python(kind: str) -> str:
    return DARWIN_PYTHON if kind == "launchd" else LINUX_PYTHON


_FUNCTIONS = r"""
_rt_nl='
'
_rt_fail() { printf 'untrusted: %s: %s\n' "$1" "$2" >&2; exit @EXIT@; }
_rt_print() {
  case $1 in *[![:print:]]*) _rt_fail "?" "a path holds a byte outside printable ASCII" ;; '') _rt_fail "?" "an empty path" ;; esac
}
_rt_dir() {
  case $1 in */*) _rt_d=${1%/*} ;; *) _rt_d=. ;; esac
  [ -n "$_rt_d" ] || _rt_d=/
}
_rt_join() {
  case $1 in /) _rt_j=/$2 ;; *) _rt_j=$1/$2 ;; esac
}
_rt_norm() {
  local p out c
  p=$1; out=
  set -f
  local IFS=/
  for c in $p; do
    case $c in
      ''|.) ;;
      ..) out=${out%/*} ;;
      *) out=$out/$c ;;
    esac
  done
  _rt_n=${out:-/}
}
_rt_readlink() {
  _rt_t=$(/usr/bin/readlink -- "$1" && printf .) || _rt_fail "$1" "cannot be read as a link"
  _rt_t=${_rt_t%.}
  _rt_t=${_rt_t%"$_rt_nl"}
  _rt_print "$_rt_t"
}
_rt_meta() {
  _rt_line=$(/bin/ls -l@LSOPT@dn -- "$1" 2>/dev/null && printf .) || { _rt_absent=1; return 1; }
  _rt_absent=
  _rt_line=${_rt_line%.}
  _rt_line=${_rt_line%"$_rt_nl"}
  case $_rt_line in *"$_rt_nl"*) _rt_fail "$1" "carries an ACL" ;; esac
  _rt_mode=${_rt_line%% *}
  case $_rt_mode in ?*) ;; *) _rt_fail "$1" "cannot be read" ;; esac
  case $_rt_mode in \?*) _rt_fail "$1" "cannot be read" ;; ??????????+*) _rt_fail "$1" "carries an ACL" ;; esac
  set -f; set -- $_rt_line
  _rt_uid=$3
}
_rt_judge() {
  _rt_meta "$1" || _rt_fail "$1" "absent"
  [ "$_rt_uid" = "$_rt_root" ] || _rt_fail "$1" "is not root-owned, or is writable by others"
  case $_rt_mode in l*) ;; ?????w*|????????w*) _rt_fail "$1" "is not root-owned, or is writable by others" ;; esac
}
_rt_seen=${_rt_seen-}
_rt_has() { case "$_rt_nl$_rt_seen$_rt_nl" in *"$_rt_nl$1$_rt_nl"*) return 0 ;; esac; return 1; }
_rt_add() { _rt_seen=$_rt_seen$_rt_nl$1; }
_rt_key() {
  local k
  _rt_dir "$1"
  k=$(cd -P -- "$_rt_d" 2>/dev/null && pwd -P && printf .) || { _rt_norm "$1"; _rt_k="?$_rt_n"; return 0; }
  k=${k%.}; k=${k%"$_rt_nl"}
  _rt_join "$k" "${1##*/}"
  _rt_k=$_rt_j
}
_rt_hops=${_rt_hops:-0}
_rt_up() {
  local x
  x=$1
  while [ "$x" != / ] && [ "$x" != . ]; do
    _rt_dir "$x"; x=$_rt_d
    [ "$x" = "$_rt_top" ] && return 0
    _rt_key "$x"
    _rt_norm "$x"
    _rt_has "up:$_rt_n|$_rt_k" && return 0
    _rt_add "up:$_rt_n|$_rt_k"
    _rt_judge "$x"
    case $_rt_mode in l*) _rt_hop "$x" chain ;; esac
  done
}
_rt_hop() {
  local h
  _rt_hops=$((_rt_hops + 1))
  [ "$_rt_hops" -le @MAX@ ] || _rt_fail "$1" "more than @MAX@ links to follow"
  _rt_readlink "$1"
  case $_rt_t in /*) h=$_rt_t ;; *) _rt_dir "$1"; _rt_join "$_rt_d" "$_rt_t"; h=$_rt_j ;; esac
  _rt_up "$h"
  _rt_visit "$h" "$2"
}
_rt_visit() {
  local v
  v=$1
  _rt_key "$v"
  if [ "$2" = tree ]; then
    _rt_has "tree:$_rt_k" && return 0
    _rt_add "tree:$_rt_k"
  else
    _rt_has "tree:$_rt_k" && return 0
    _rt_has "chain:$_rt_k" && return 0
    _rt_add "chain:$_rt_k"
  fi
  _rt_judge "$v"
  case $_rt_mode in
    l*) _rt_hop "$v" "$2" ;;
    d*) [ "$2" = tree ] && _rt_under "$v" ;;
  esac
  return 0
}
_rt_route() {
  _rt_print "$1"
  case $1 in /*) ;; *) _rt_fail "$1" "is not an absolute path" ;; esac
  case $1 in */) _rt_fail "$1" "names a directory, not a program" ;; esac
  _rt_up "$1"
  _rt_visit "$1" tree
}
_rt_final() {
  local p n
  p=$1; n=0
  while _rt_meta "$p" && case $_rt_mode in l*) true ;; *) false ;; esac; do
    n=$((n + 1)); [ "$n" -le @MAX@ ] || _rt_fail "$1" "more than @MAX@ links to follow"
    _rt_readlink "$p"
    case $_rt_t in /*) p=$_rt_t ;; *) _rt_dir "$p"; _rt_join "$_rt_d" "$_rt_t"; p=$_rt_j ;; esac
  done
  _rt_f=$p
}
_rt_file() {
  _rt_final "$1"
  _rt_judge "$_rt_f"
  case $_rt_mode in -*) ;; *) _rt_fail "$_rt_f" "is not a regular file" ;; esac
  if [ "$2" = exec ]; then
    case $_rt_mode in ???[xst]*|??????[xst]*|?????????[xst]*) ;; *) _rt_fail "$_rt_f" "is not executable" ;; esac
  fi
}
trusted() {
  for _rt_a in "$@"; do _rt_route "$_rt_a"; _rt_file "$_rt_a" exec; done
}
_rt_sha() {
  if [ -x /usr/bin/sha256sum ]; then _rt_s=$(/usr/bin/sha256sum -- "$1") || _rt_fail "$1" "cannot be hashed"
  else _rt_s=$(/usr/bin/shasum -a 256 -- "$1") || _rt_fail "$1" "cannot be hashed"; fi
  _rt_s=${_rt_s%% *}
}
_rt_hop_each() { for _rt_l in "$@"; do _rt_hop "$_rt_l" tree; done; }
_rt_tree() {
  _rt_up "$1"
  _rt_visit "$1" tree
}
_rt_under() {
  local bad
  bad=$(/usr/bin/find -P "$1" \( ! -user "$_rt_root" -o \( ! -type l \( -perm -020 -o -perm -002 \) \) \) -print && printf .) \
    || _rt_fail "$1" "cannot be listed whole"
  [ "$bad" = . ] || _rt_fail "$1" "holds an entry that is not root-owned, or is writable by others"
  bad=$(/usr/bin/find -P "$1" -name '*[![:print:]]*' -print && printf .) || _rt_fail "$1" "cannot be listed whole"
  [ "$bad" = . ] || _rt_fail "$1" "holds a name outside printable ASCII"
  @ACLTREE@
  export _rt_seen _rt_hops
  /usr/bin/find -P "$1" -mindepth 1 -type l -exec /bin/sh -c '. "$0" && _rt_hop_each "$@"' "$_rt_self" {} + \
    || _rt_fail "$1" "holds a link whose route is not root's alone"
}
_rt_conf() {
  local f line pats pat
  f=$1
  _rt_has "conf:$f" && return 0
  _rt_add "conf:$f"
  _rt_route "$f"
  _rt_file "$f" read
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    line=${line#"${line%%[![:space:]]*}"}
    line=${line%"${line##*[![:space:]]}"}
    case $line in
      '') ;;
      include\ *)
        # every blank-separated pattern, each relative one joined to this file's directory (ldconfig's rule)
        pats=${line#include }
        set -f
        for pat in $pats; do
          case $pat in /*) ;; *) _rt_dir "$f"; _rt_join "$_rt_d" "$pat"; pat=$_rt_j ;; esac
          _rt_print "$pat"
          _rt_include "$pat"
        done ;;
      /*)
        _rt_print "$line"
        _rt_up "$line"
        if [ -e "$line" ] || [ -L "$line" ]; then _rt_visit "$line" chain; fi ;;
      *) _rt_fail "$f" "names an entry this check does not read ($line)" ;;
    esac
  done < "$f" || _rt_fail "$f" "cannot be read"
}
_rt_include() {
  local i
  set +f
  set -- $1
  set -f
  for i in "$@"; do
    if [ -e "$i" ] || [ -L "$i" ]; then _rt_conf "$i"; fi
  done
  return 0
}
_rt_loader_config() {
  if [ -e "$_rt_preload" ] || [ -h "$_rt_preload" ]; then _rt_fail "$_rt_preload" "is present: the loader maps it into every process"; fi
  if [ -e "$_rt_ldcache" ] || [ -L "$_rt_ldcache" ]; then _rt_route "$_rt_ldcache"; _rt_file "$_rt_ldcache" read; fi
  if [ -e "$_rt_ldconfd" ] || [ -L "$_rt_ldconfd" ]; then _rt_tree "$_rt_ldconfd"; fi
  # every directory ld.so.conf names, through every file it includes (d3.3 §3.0)
  if [ -e "$_rt_ldconf" ] || [ -L "$_rt_ldconf" ]; then _rt_conf "$_rt_ldconf"; fi
}
_rt_libs() {
  local out err rc line lib n h r found
  if [ "$_rt_trace" = 1 ]; then
    out=$(LD_TRACE_LOADED_OBJECTS=1 "$_rt_loader" "$1" 2>/dev/null; r=$?; printf .; exit "$r"); rc=$?
    err=$(LD_TRACE_LOADED_OBJECTS=1 "$_rt_loader" "$1" 2>&1 >/dev/null)
  else
    out=$("$_rt_loader" --list "$1" 2>/dev/null; r=$?; printf .; exit "$r"); rc=$?
    err=$("$_rt_loader" --list "$1" 2>&1 >/dev/null)
  fi
  [ "$rc" = 0 ] || _rt_fail "$1" "the loader cannot list its libraries (exit $rc)"
  [ -z "$err" ] || _rt_fail "$1" "the loader wrote to its error stream while listing it"
  out=${out%.}
  out=${out%"$_rt_nl"}
  [ "$out" = "${_rt_tab}statically linked" ] && return 0
  [ -n "$out" ] || _rt_fail "$1" "the loader listed nothing"
  found=
  while IFS= read -r line; do
    case $line in
      "$_rt_tab"linux-vdso.so.1\ *|"$_rt_tab"linux-gate.so.1\ *)
        # the whole record, as the Python half's: `(0x<hex>)`, or older glibc's `=>  (0x<hex>)`
        r=${line#"$_rt_tab"linux-????.so.1" "}
        case $r in "=>  (0x"*) r=${r#"=>  "} ;; esac
        h=${r#"(0x"}; h=${h%")"}
        [ "$r" = "(0x$h)" ] || _rt_fail "$1" "the loader printed a line outside the list mode's forms ($line)"
        case $h in ''|*[!0-9a-f]*) _rt_fail "$1" "the loader printed a line outside the list mode's forms ($line)" ;; esac
        continue ;;
      "$_rt_tab"/*" => "*) _rt_fail "$1" "the loader maps a path onto another ($line): its PT_INTERP is not the anchor's" ;;
      "$_rt_tab"?*" => /"*" (0x"*")") n=${line#"$_rt_tab"}; n=${n%% => *}; lib=${line#* => } ;;
      "$_rt_tab"/*" (0x"*")") n=; lib=${line#"$_rt_tab"} ;;
      *) _rt_fail "$1" "the loader printed a line outside the list mode's forms ($line)" ;;
    esac
    h=${lib##* (0x}; h=${h%)}; lib=${lib% (0x*}
    case $n in *[!A-Za-z0-9._+-]*) _rt_fail "$1" "the loader printed a line outside the list mode's forms ($line)" ;; esac
    case $h in ''|*[!0-9a-f]*) _rt_fail "$1" "the loader printed a line outside the list mode's forms ($line)" ;; esac
    case $lib in *[!!-~]*|'') _rt_fail "$1" "the loader printed a line outside the list mode's forms ($line)" ;; esac
    [ -z "$n" ] && [ "$lib" = "$_rt_loader" ] && found=1
    _rt_route "$lib"
    _rt_file "$lib" read
  done <<_RT_LIBS
$out
_RT_LIBS
  [ "$2" != interp ] || [ -n "$found" ] || _rt_fail "$1" "the loader did not list itself as its interpreter"
}
_rt_modules() {
  set +f
  set -- "$1"/*.so
  set -f
  for _rt_m in "$@"; do [ -e "$_rt_m" ] && _rt_libs "$_rt_m"; done
  return 0
}
root_exec() {
  local sha py wr
  sha=$1; py=$2; wr=$3
  shift 3
  set -f
  [ "$_rt_kind" = launchd ] || _rt_loader_config
  [ "$py" = "$_rt_python" ] || _rt_fail "$py" "is not this host's OS interpreter, $_rt_python"
  trusted "$py"
  _rt_key "$_rt_f"
  case $_rt_kind in
    launchd) case $_rt_k in "$_rt_python"|"$_rt_install"/*) ;; *) _rt_fail "$py" "lands outside $_rt_install" ;; esac ;;
    *) case ${_rt_k##*/} in python3.[0-9]|python3.[0-9][0-9]) ;; *) _rt_fail "$py" "does not land on python3.N" ;; esac
       _rt_dir "$_rt_k"; [ "$_rt_d" = "$_rt_bin" ] || _rt_fail "$py" "does not land in $_rt_bin"
       _rt_install=$_rt_lib/${_rt_k##*/} ;;
  esac
  _rt_route "$wr"
  _rt_file "$wr" read
  _rt_sha "$_rt_f"
  [ "$_rt_s" = "$sha" ] || _rt_fail "$wr" "is not the writer the document pins"
  _rt_tree "$_rt_install"
  if [ "$_rt_kind" != launchd ]; then
    trusted "$_rt_loader"
    _rt_libs "$py" interp
    _rt_modules "$_rt_install/lib-dynload"
  fi
  exec "$py" -I -S -B "$wr" "$@"
}
:
"""

#: The ACL sweep over the install root, per OS: macOS lists each entry's ACL
#: lines with -e; Linux marks an ACL with `+` in the mode's eleventh column.
_ACL_TREE = {
    "launchd": r"""bad=$(/usr/bin/find -P "$1" -exec /bin/ls -lden {} + | /usr/bin/awk '/^ [0-9]+: / { print; exit }' && printf .) \
    || _rt_fail "$1" "cannot be listed whole"
  [ "$bad" = . ] || _rt_fail "$1" "holds an entry with an ACL"
""",
    "systemd": r"""bad=$(/usr/bin/find -P "$1" -exec /bin/ls -ldn {} + | /usr/bin/awk 'substr($1, 11, 1) == "+" { print; exit }' && printf .) \
    || _rt_fail "$1" "cannot be listed whole"
  [ "$bad" = . ] || _rt_fail "$1" "holds an entry with an ACL"
""",
}


def trace_form(confstr=getattr(os, "confstr", None)) -> bool:
    """True when this host's glibc is older than 2.33, whose loader lists in
    the LD_TRACE_LOADED_OBJECTS form (d3.3 §3.6b); False for a newer glibc,
    or one that does not say (--list, which fails closed where unsupported)."""
    try:
        v = confstr("CS_GNU_LIBC_VERSION") if confstr else None
    except (ValueError, OSError):
        return False
    parts = (v or "").split()
    if len(parts) != 2 or parts[0] != "glibc":
        return False
    try:
        major, minor = (int(x) for x in parts[1].split(".")[:2])
    except ValueError:
        return False
    return (major, minor) < (2, 33)


def render(kind: str, path: str, root: int = 0, top: str = "", python: Optional[str] = None,
           bin_dir: str = "/usr/bin", lib_dir: str = "/usr/lib", install: Optional[str] = None,
           loader: Optional[str] = None, etc: str = "/etc", trace: Optional[bool] = None) -> str:
    """root-trust.sh for a host whose supervision is `kind` (systemd or
    launchd), to be placed at `path`. The rest exist for tests, which map them
    into a fixture: root's uid; the first directory a walk does not judge; the
    allowed interpreter; Linux's bin and lib directories; the macOS install
    root. Every render a host receives uses the defaults."""
    kind = "launchd" if kind == "launchd" else "systemd"
    body = (_FUNCTIONS.replace("@EXIT@", str(EXIT)).replace("@MAX@", str(MAX_HOPS))
            .replace("@LSOPT@", "e" if kind == "launchd" else "").replace("@ACLTREE@", _ACL_TREE[kind]))
    head = ["# root-trust.sh. Rendered by amap-deploy-sandy (ROOT-BOOTSTRAP d3); placed root 0444 beside the",
            "# writer, sourced by /bin/sh under the pinned environment. Never edit it.",
            f"_rt_kind={kind}",
            f"_rt_self={shlex.quote(path)}",
            f"_rt_python={shlex.quote(python or allowed_python(kind))}",
            f"_rt_install={shlex.quote(install or (DARWIN_ROOT if kind == 'launchd' else ''))}",
            f"_rt_bin={shlex.quote(bin_dir)}",
            # The anchor loader, read at render on the host that renders it (the host it runs on): the
            # PT_INTERP of /bin/sh, the anchor shell; the only loader root lets list or start anything.
            f"_rt_loader={shlex.quote(loader or (elf_interpreter(ANCHOR_SHELL) or '') if kind != 'launchd' else '')}",
            f"_rt_trace={1 if (trace_form() if trace is None else trace) else 0}",
            "_rt_tab='\t'",
            f"_rt_preload={shlex.quote(etc + '/ld.so.preload')}",
            f"_rt_ldcache={shlex.quote(etc + '/ld.so.cache')}",
            f"_rt_ldconf={shlex.quote(etc + '/ld.so.conf')}",
            f"_rt_ldconfd={shlex.quote(etc + '/ld.so.conf.d')}",
            f"_rt_lib={shlex.quote(lib_dir)}",
            f"_rt_root={int(root)}",
            f"_rt_top={shlex.quote(top) if top else '//none'}"]
    return "\n".join(head) + body


def root_line(rt: str, sha256: str, python3: str, writer: str, args: List[str]) -> str:
    """The sh -c body a root command runs: source root-trust.sh, then root_exec."""
    q = shlex.quote
    return f"command . {q(rt)} && command -v root_exec >/dev/null || exit {EXIT}; root_exec {q(sha256)} {q(python3)} {q(writer)} " + \
        " ".join(q(a) for a in args)


#: The §3 grammar's sh -c body in its positional form: root_exec takes every
#: argument from "$@", so a caller may append the command's own arguments.
POSITIONAL = "command . {rt} && command -v root_exec >/dev/null || exit {exit}; root_exec \"$@\""


def root_argv_positional(rt: str, sha256: str, python3: str, writer: str, args: List[str],
                         engine: Optional[str] = None) -> List[str]:
    """The §3 grammar as d3.3 writes it: `… /bin/sh -c '<source>; root_exec
    "$@"' sh <sha256> <python3> <writer> <args…>`. Anything appended to the
    returned argv reaches root_exec as further arguments, after `args`."""
    return anchor(engine) + ["/bin/sh", "-c", POSITIONAL.format(rt=shlex.quote(rt), exit=EXIT), "sh",
                             sha256, python3, writer] + list(args)


#: The typed root lines' sudo: the anchor's own (d3.3 §1, §5(d)).
SUDO = "/usr/bin/sudo"


def typed_argv(rt: str, sha256: str, python3: str, writer: str, tools: List[str], argv: List[str],
               also: Sequence[str] = ()) -> List[str]:
    """One operator-typed root line (d3.3 §5(d)): the anchor's sudo, then the
    §3 grammar, trusted-exec with each recorded tool (sudo never among them),
    each `also` it judges beside argv[0], and `argv`, whose argv[0] is one of
    them or `python3` in its one exact vector. sudo prompts as for any typed
    line: no -n."""
    recorded = [x for t in sorted(set(tools)) if posixpath.basename(t) != "sudo" for x in ("--tool", t)]
    extra = [x for t in also for x in ("--also", t)]
    return [SUDO] + root_argv_positional(rt, sha256, python3, writer,
                                         ["trusted-exec"] + recorded + extra + ["--"] + list(argv))


def root_argv(rt: str, sha256: str, python3: str, writer: str, args: List[str],
              engine: Optional[str] = None) -> List[str]:
    """The whole argv of a root command under the anchor."""
    return anchor(engine) + ["/bin/sh", "-c", root_line(rt, sha256, python3, writer, args)]


# --- The bootstrap: TXN and G, as the operator (d3.3 §5(d) §3) ------------------
#
# Nothing root runs before the barrier exists can be judged by it, so the
# bootstrap is two operator shells around three anchor-only root lines.
# TXN decides everything once, from the state before any byte is replaced
# (GATE0, SAME, the classification, U0), then copies only what its class
# names (B1-B3). G then judges the placed route and bytes before any barrier
# line sources root-trust.sh.

#: The bootstrap's advisory bound on a copied source, at check time only.
SOURCE_MAX = 4194304
#: The reader's capture is refused after it exits when it is larger than this.
CAPTURE_MAX = 65536
CONTEXT_NAME = "deployed-context.json"
#: The operator shell both run in: the system sh, under a pinned PATH.
OPERATOR_ENV = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C", ANCHOR_SHELL, "-c"]
#: Per kind: how the anchor's stat prints a size, and the hash command.
SIZE = {"systemd": "/usr/bin/stat -L -c %s", "launchd": "/usr/bin/stat -L -f %z"}
HASHWORD = {"systemd": "sha256sum", "launchd": "shasum"}
#: Facts a host must measure, None until it has (the design's §6). Each
#: unmeasured answer is unknown, and an unknown answer refuses.
#: `launchctl print system/<label>` for a label that is not loaded: (status, output).
LAUNCHD_NOT_FOUND: Optional[Tuple[int, str]] = None
#: Its line for a weekly run in progress, and for a loaded, idle label.
LAUNCHD_STATE_RUNNING: Optional[str] = None
LAUNCHD_STATE_IDLE: Optional[str] = None
#: `systemctl is-enabled <timer>` for a timer that does not exist, from ONE
#: invocation: (status, stdout, stderr), trailing newlines dropped, a None
#: text meaning that stream was empty. The whole tuple must match.
SYSTEMD_TIMER_MISSING: Optional[Tuple[int, Optional[str], Optional[str]]] = None

GATE = r"""
_g_nl='
'
_g_fail() { printf 'G: %s: %s\n' "$1" "$2" >&2; exit 1; }
_g_judge() {
  _g_p=$1 _g_t=$2
  _g_l=$(@LS@ -l@E@dn -- "$_g_p" && printf .) || _g_fail "$_g_p" "cannot be read"
  _g_l=${_g_l%.}
  _g_l=${_g_l%"$_g_nl"}
  case $_g_l in *"$_g_nl"*) _g_fail "$_g_p" "carries an ACL" ;; esac
  _g_m=${_g_l%% *}
  case $_g_m in ''|\?*) _g_fail "$_g_p" "cannot be read" ;; ??????????+*) _g_fail "$_g_p" "carries an ACL" ;; esac
  case $_g_t$_g_m in dd*|f-*) ;; *) _g_fail "$_g_p" "is not of its type" ;; esac
  case $_g_m in ?????w*|????????w*) _g_fail "$_g_p" "is writable by others" ;; esac
  set -f
  set -- $_g_l
  set +f
  [ "$3" = @ROOT@ ] || _g_fail "$_g_p" "is not root-owned"
  [ "$_g_t" = d ] || [ "$2" = 1 ] || _g_fail "$_g_p" "has more than one link"
}
_g_hw=$1 _g_wpin=$2 _g_rpin=$3 _g_writer=$4 _g_rt=$5
shift 5
[ $# -ge 2 ] || _g_fail route "names no directory"
for _g_d in "$@"; do _g_judge "$_g_d" d; done
_g_judge "$_g_writer" f
_g_judge "$_g_rt" f
echo G-ROUTE-OK
for _g_w in "$_g_wpin" "$_g_rpin"; do
  case $_g_w in *[!0-9a-f]*|"") _g_fail pin "not 64 lowercase hex" ;; esac
  [ ${#_g_w} -eq 64 ] || _g_fail pin "not 64 lowercase hex"
done
case $_g_hw in
  sha256sum) set -- @SHA256SUM@ --strict --status -c - ;;
  shasum) set -- @SHASUM@ -a 256 @STRICT@ --status -c - ;;
  *) _g_fail hashword "neither sha256sum nor shasum" ;;
esac
printf '%s  %s\n' "$_g_wpin" "$_g_writer" "$_g_rpin" "$_g_rt" | "$@" || _g_fail bytes "not the pinned bytes"
echo G-BYTES-OK
echo BOOTSTRAP-OK
"""

TXN = r"""
_t_nl='
'
trap 'printf "TXN: interrupted\n" >&2; exit 3' INT TERM HUP
_t_fail() { printf 'GATE0: %s: %s\n' "$1" "$2" >&2; exit 1; }
_t_stop() { printf 'TXN: %s\n' "$1" >&2; exit "${2:-1}"; }
case ${10-} in
  systemd) [ $# -eq 17 ] || _t_stop "wrong operand count for systemd" ;;
  launchd) [ $# -eq 18 ] || _t_stop "wrong operand count for launchd" ;;
  *) _t_stop "wrong operand count for ${10-?}" ;;
esac
[ "${10}" = @KIND@ ] || _t_stop "this TXN is rendered for @KIND@, not ${10}"
writer_dir=$1 writer=$2 rt=$3 context=$4 wpin=$5 rpin=$6 hashword=$7 writer_src=$8 rt_src=$9 kind=${10}
shift 10
if [ "$kind" = systemd ]; then hub=$1 wsvc=$2 wtimer=$3; shift 3; else hub=$1 wlabel=$2; shift 2; fi
py=$1 amap=$2 docsource=$3 docpath=$4
shift 4
staged= placed=
[ "$kind" = launchd ] && staged=$1 placed=$2
run_dir=${rt_src%/*}

# The same-count role check: each operand in its own slot.
_t_name() {
  case $1 in [A-Za-z0-9]*) ;; *) return 1 ;; esac
  case $1 in *[!A-Za-z0-9$2._-]*) return 1 ;; esac
}
_t_unit() { _t_name "$1" @ && case $1 in ?*"$2") return 0 ;; esac; return 1; }
_t_path() {
  case $1 in /*) ;; *) return 1 ;; esac
  case "$1/" in *//*|*/./*|*/../*) return 1 ;; esac
}
_t_path "$writer_dir" && [ "$writer_dir" != / ] || _t_stop "the writer's directory is not an absolute, normal path"
[ "$writer" = "$writer_dir/${writer##*/}" ] && [ "$rt" = "$writer_dir/@RTNAME@" ] \
  && [ "$context" = "$writer_dir/@CONTEXT@" ] || _t_stop "the writer, root-trust.sh and the context are not in the writer's directory"
_t_path "$run_dir" && [ "$run_dir" != "" ] || _t_stop "the staged root-trust.sh is not in an absolute, normal run directory"
_t_path "$writer_src" || _t_stop "the writer's source is not an absolute, normal path"
if [ "$kind" = systemd ]; then
  _t_unit "$hub" .service && _t_unit "$wsvc" .service && _t_unit "$wtimer" .timer \
    || _t_stop "the units are not a hub .service, a weekly .service and a weekly .timer, in that order"
else
  _t_name "$hub" "" && _t_name "$wlabel" "" || _t_stop "the labels are not launchd labels"
  [ "$placed" = "@LAUNCHD_DIR@/$wlabel.plist" ] || _t_stop "the placed weekly plist is not @LAUNCHD_DIR@/<weekly label>.plist"
  case $staged in *.plist) ;; *) _t_stop "the staged weekly plist is not a .plist" ;; esac
  _t_path "$staged" || _t_stop "the staged weekly plist is not an absolute, normal path"
  case $staged in "$run_dir"/?*) ;; *) _t_stop "the staged weekly plist is not under the run directory" ;; esac
fi
case $docsource in spec|overlay) ;; *) _t_stop "the document source is neither spec nor overlay" ;; esac
_t_path "$docpath" || _t_stop "the document is not an absolute, normal path"
for _t_w in "$wpin" "$rpin"; do
  case $_t_w in *[!0-9a-f]*|"") _t_fail pin "not 64 lowercase hex" ;; esac
  [ ${#_t_w} -eq 64 ] || _t_fail pin "not 64 lowercase hex"
done
case $hashword in sha256sum|shasum) ;; *) _t_fail hashword "neither sha256sum nor shasum" ;; esac

# GATE0's rules, as the operator.
_t_meta() {
  _t_l=$(@LS@ -l@E@dn -- "$1" 2>/dev/null && printf .) || { _t_why="cannot be read"; return 1; }
  _t_l=${_t_l%.}
  _t_l=${_t_l%"$_t_nl"}
  case $_t_l in *"$_t_nl"*) _t_why="carries an ACL"; return 2 ;; esac
  _t_mode=${_t_l%% *}
  case $_t_mode in ''|\?*) _t_why="cannot be read"; return 2 ;; ??????????+*) _t_why="carries an ACL"; return 2 ;; esac
  set -f
  set -- $_t_l
  set +f
  _t_links=$2 _t_uid=$3
}
_t_searchdir() {
  _t_meta "$1" || _t_fail "$1" "$_t_why"
  case $_t_mode in d*) ;; *) _t_fail "$1" "is not a directory" ;; esac
  [ "$_t_uid" = @ROOT@ ] || _t_fail "$1" "is not root-owned"
  case $_t_mode in ?????w*|????????w*) _t_fail "$1" "is writable by others" ;; esac
  case $_t_mode in ?????????[xt]*) ;; *) _t_fail "$1" "is not searchable by others" ;; esac
}
_t_ancestors() {
  _t_cur= _t_rest=${1#/} _t_on=yes
  [ -n "@TOP@" ] && _t_on=no
  [ "$_t_on" = yes ] && _t_searchdir /
  while :; do
    case $_t_rest in */*) _t_c=${_t_rest%%/*}; _t_rest=${_t_rest#*/} ;; *) break ;; esac
    _t_cur=$_t_cur/$_t_c
    if [ "$_t_on" = no ]; then [ "$_t_cur" = "@TOP@" ] && _t_on=yes; continue; fi
    _t_searchdir "$_t_cur"
  done
  _t_parent=${_t_cur:-/}
}
_t_listed() {
  _t_ls=$(@LS@ -a1 -- "$1" 2>/dev/null && printf .) || _t_fail "$1" "cannot be listed"
  _t_ls=${_t_ls%.}
  printf '%s' "$_t_ls" | grep -Fxq -- "$2"
  case $? in 0) return 0 ;; 1) return 1 ;; esac
  _t_fail "$1" "cannot be searched for $2"
}
_t_hash() {
  case $hashword in
    sha256sum) _t_h=$(@SHA256SUM@ -- "$1" 2>/dev/null) || return 1 ;;
    *) _t_h=$(@SHASUM@ -a 256 -- "$1" 2>/dev/null) || return 1 ;;
  esac
  _t_h=${_t_h%% *}
  case $_t_h in *[!0-9a-f]*|"") return 1 ;; esac
  [ ${#_t_h} -eq 64 ]
}
# SAME: 0 the leaf is root's alone and the pin's bytes, 1 proven absent, 2 read and different, 3 anything else.
_t_same() {
  _t_s=3 _t_sh= _t_sw=
  if [ "$_t_wd" = absent ]; then _t_s=1; return 0; fi
  _t_listed "$writer_dir" "${1##*/}" || { _t_s=1; return 0; }
  _t_meta "$1" || { _t_sw="$1: $_t_why"; return 0; }
  case $_t_mode in -*) ;; *) _t_sw="$1: is not a regular file"; return 0 ;; esac
  [ "$_t_uid" = @ROOT@ ] && [ "$_t_links" = 1 ] || { _t_sw="$1: is not root's alone with one link"; return 0; }
  case $_t_mode in ?????w*|????????w*) _t_sw="$1: is writable by others"; return 0 ;; esac
  _t_hash "$1" || { _t_sw="$1: cannot be hashed"; return 0; }
  _t_sh=$_t_h
  if [ "$_t_h" = "$2" ]; then _t_s=0; else _t_s=2; fi
}

_t_ancestors "$writer_dir"
if _t_listed "$_t_parent" "${writer_dir##*/}"; then _t_searchdir "$writer_dir"; _t_wd=present; else _t_wd=absent; fi
_t_same "$writer" "$wpin"; ws=$_t_s wsw=${_t_sw-} wh=$_t_sh
_t_same "$rt" "$rpin"; rs=$_t_s rsw=${_t_sw-} rh=$_t_sh
# The context's presence bit alone decides the class; nothing here opens it.
ctx=absent
if [ "$_t_wd" = present ] && _t_listed "$writer_dir" "@CONTEXT@"; then ctx=present; fi
plist=none
if [ "$kind" = launchd ]; then
  _t_ancestors "$placed"
  _t_searchdir "$_t_parent"
  if _t_listed "$_t_parent" "${placed##*/}"; then
    @CMP@ -s -- "$staged" "$placed"
    case $? in 0) plist=same ;; 1) plist=differs ;; *) _t_stop "the weekly plists cannot be compared ($staged, $placed)" 3 ;; esac
  fi
fi
[ "$ws" -lt 3 ] || _t_stop "SAME failed for the writer ($wsw): nothing is written" 3
[ "$rs" -lt 3 ] || _t_stop "SAME failed for root-trust.sh ($rsw): nothing is written" 3

# PARTIAL's informational note on the context: its digest only after the
# listing shows a regular, root's-alone file in the root-owned directory
# GATE0 judged; anything else is named, never hashed. It is never adopted.
_t_ctxdiag() {
  [ "$ctx" = present ] || { printf absent; return 0; }
  _t_meta "$context" || { printf 'present, %s' "$_t_why"; return 0; }
  case $_t_mode in -*) ;; *) printf 'present, not a regular file (%s)' "$_t_mode"; return 0 ;; esac
  [ "$_t_uid" = @ROOT@ ] && [ "$_t_links" = 1 ] || { printf "present, not root's alone with one link"; return 0; }
  _t_hash "$context" || { printf 'present, unreadable'; return 0; }
  printf 'present, sha256 %s (informational: the maintainers read its pins from that file)' "$_t_h"
}
_t_state() { case $1 in 0) printf 'sha256 %s (the pin)' "$3" ;; 1) printf absent ;; *) printf 'sha256 %s' "$2" ;; esac; }
if [ "$ws" = 1 ] && [ "$rs" = 1 ] && [ "$ctx" = absent ]; then class=FRESH
elif [ "$ws" = 2 ] && [ "$rs" = 0 ]; then class=WRITER-ONLY
elif [ "$ws" = 0 ] && [ "$rs" = 0 ]; then class=NOTHING
elif [ "$ws" = 2 ] && [ "$rs" = 2 ]; then class=BOTH
elif [ "$ws" = 0 ] && [ "$rs" = 2 ]; then class=RT-ONLY
else class=PARTIAL
fi
case $class in
  BOTH) _t_stop "a two-leaf update is not supported yet (post-M1, §5b)" ;;
  RT-ONLY) _t_stop "root-trust.sh's render changed (deploy pin or host loader); an image-only update with the deploy pin unchanged is not affected (on launchd an image-only update re-registers the weekly job, see U0)" ;;
  PARTIAL) _t_stop "a partial bootstrap pair: the maintainers' call. The writer: $(_t_state "$ws" "$wh" "$wpin"), expected sha256 $wpin; root-trust.sh: $(_t_state "$rs" "$rh" "$rpin"), expected sha256 $rpin; the context: $(_t_ctxdiag)" ;;
esac

# U0, the update guard: read-only and tri-state; every unknown answer refuses.
_t_held() { _t_stop "U0: $1. A running or enabled job holds the old pin. The remedies are: none needed if nothing is running or enabled; otherwise a one-time operator-typed quiescence, a trust-model exception (§6, N5). Run nothing else."; }
_t_unknown() { _t_stop "U0: $1 answered ($_t_rc, $_t_out): unknown. Measure the state and fix the observation; nothing is assumed absent."; }
_t_active() { _t_out=$(@SYSTEMCTL@ --no-pager is-active "$1" 2>/dev/null); _t_rc=$?; }
_t_print() { _t_out=$(@LAUNCHCTL@ print "system/$1" 2>&1); _t_rc=$?; }
_t_notfound() { [ -n "@LDNF_SET@" ] && [ "$_t_rc" = "@LDNF_RC@" ] && [ "$_t_out" = @LDNF_TEXT@ ]; }
# A fresh capture directory, $run_dir/<prefix>.<UTC time>[-N]: mkdir is the
# atomic arbiter, so nothing can already be inside it.
_t_fresh() {
  _t_at=$(@DATE@ -u +%Y%m%dT%H%M%SZ) || _t_stop "no time for the capture's name"
  _t_d=$run_dir/$1.$_t_at _t_i=0
  while [ -e "$_t_d" ] || [ -h "$_t_d" ]; do
    _t_i=$((_t_i + 1))
    [ "$_t_i" -lt 1000 ] || _t_stop "no free capture name in $run_dir"
    _t_d=$run_dir/$1.$_t_at-$_t_i
  done
  @MKDIR@ -m 0700 "$_t_d" || _t_stop "the capture directory $_t_d cannot be made: nothing was read"
}
# One capture file's text: a regular file within @CAPMAX@ bytes, trailing newlines dropped.
_t_slurp() {
  [ -f "$1" ] && [ ! -h "$1" ] || _t_stop "the capture $1 is not a regular file"
  _t_sz=$(@SIZE@ "$1") || _t_sz=
  case $_t_sz in ""|*[!0-9]*) _t_stop "the capture $1 cannot be measured" ;; esac
  [ "$_t_sz" -le @CAPMAX@ ] || _t_stop "the capture $1 is larger than @CAPMAX@ bytes"
  _t_txt=$(cat -- "$1" && printf .) || _t_stop "the capture $1 cannot be read"
  _t_txt=${_t_txt%.}
  while :; do case $_t_txt in *"$_t_nl") _t_txt=${_t_txt%"$_t_nl"} ;; *) break ;; esac; done
}
_t_units() {
  if [ "$kind" = systemd ]; then
    for _t_u in "$hub" "$wsvc"; do
      _t_active "$_t_u"
      case "$_t_rc:$_t_out" in 3:inactive|3:failed) ;; 0:active|0:reloading|0:activating|3:activating) _t_held "$_t_u is $_t_out" ;; *) _t_unknown "is-active $_t_u" ;; esac
    done
    _t_active "$wtimer"
    case "$_t_rc:$_t_out" in 3:inactive) ;; 0:active|0:reloading|0:activating|3:activating) _t_held "$wtimer is $_t_out" ;; *) _t_unknown "is-active $wtimer" ;; esac
    # ONE invocation, its status, stdout and stderr captured together.
    _t_fresh u0
    @SYSTEMCTL@ --no-pager is-enabled "$wtimer" > "$_t_d/out" 2> "$_t_d/err"
    _t_rc=$?
    _t_slurp "$_t_d/out"; _t_out=$_t_txt
    _t_slurp "$_t_d/err"; _t_err=$_t_txt
    case "$_t_rc:$_t_out" in
      1:disabled|1:masked) return 0 ;;
      0:enabled|0:enabled-runtime) _t_held "$wtimer is $_t_out" ;;
    esac
    if [ -n "@SDM_SET@" ] && [ "$_t_rc" = "@SDM_RC@" ] && [ "$_t_out" = @SDM_OUT@ ] && [ "$_t_err" = @SDM_ERR@ ]; then
      return 0
    fi
    _t_unknown "is-enabled $wtimer"
  else
    for _t_u in "$hub" "$wlabel"; do
      _t_print "$_t_u"
      [ "$_t_rc" = 0 ] && _t_held "$_t_u is loaded"
      _t_notfound || _t_unknown "print system/$_t_u"
    done
  fi
}
_t_weekly() {
  _t_print "$wlabel"
  if [ "$_t_rc" = 0 ]; then
    if [ -n "@LD_RUNNING_SET@" ] && printf '%s\n' "$_t_out" | grep -Fxq -- @LD_RUNNING@; then
      _t_stop "a weekly run is in progress; re-run after it ends"
    fi
    [ -n "@LD_IDLE_SET@" ] && printf '%s\n' "$_t_out" | grep -Fxq -- @LD_IDLE@ && return 0
    _t_unknown "print system/$wlabel"
  fi
  _t_notfound || _t_unknown "print system/$wlabel"
}
_t_reader() {
  _t_fresh hsc
  if [ "$docsource" = spec ]; then
    "$py" "$amap" hub-start-check --until-stopped --old-context --spec "$docpath" > "$_t_d/out"
  else
    "$py" "$amap" --overlay "$docpath" hub-start-check --until-stopped --old-context > "$_t_d/out"
  fi
  _t_rrc=$?
  _t_last="(no regular capture of at most @CAPMAX@ bytes)"
  if [ -f "$_t_d/out" ] && [ ! -h "$_t_d/out" ]; then
    _t_sz=$(@SIZE@ "$_t_d/out") || _t_sz=
    case $_t_sz in ""|*[!0-9]*) _t_sz=@CAPMAX@1 ;; esac
    if [ "$_t_sz" -le @CAPMAX@ ]; then
      _t_last=$(@TAIL@ -n 1 -- "$_t_d/out" && printf .) || _t_stop "the capture cannot be read"
      _t_last=${_t_last%.}
      _t_last=${_t_last%"$_t_nl"}
      [ "$_t_rrc" = 0 ] && [ "$_t_last" = NOT-RUNNING ] && return 0
    fi
  fi
  _t_stop "the old hub is not shown stopped (the old-context check exited $_t_rrc): $_t_last"
}
case $class in
  FRESH) _t_units ;;
  WRITER-ONLY) _t_reader; _t_units ;;
  NOTHING) [ "$plist" = differs ] && _t_weekly ;;
esac
echo GATE0-OK

# B1-B3: anchor-only, only as the class says. Root opens no source by path.
if [ "$_t_wd" = absent ]; then
  @SUDO@ /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C /usr/bin/install -d -o 0 -g 0 -m 0755 "$writer_dir" \
    || _t_stop "B1 failed: the writer's directory was not made"
fi
case $class in FRESH|WRITER-ONLY)
  { test -f /dev/stdin && [ "$(@SIZE@ /dev/stdin)" -le @SRCMAX@ ] \
    && @SUDO@ /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C /usr/bin/install -o 0 -g 0 -m 0444 /dev/stdin "$writer"; } < "$writer_src" \
    || _t_stop "B2 failed: the writer was not copied" ;;
esac
if [ "$class" = FRESH ]; then
  { test -f /dev/stdin && [ "$(@SIZE@ /dev/stdin)" -le @SRCMAX@ ] \
    && @SUDO@ /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C /usr/bin/install -o 0 -g 0 -m 0444 /dev/stdin "$rt"; } < "$rt_src" \
    || _t_stop "B3 failed: root-trust.sh was not copied"
fi
echo "TXN-OK $class"
"""


def _measured(v: Optional[str]) -> str:
    """A measured text as one shell word. An unmeasured one is never read:
    TXN tests its presence flag (_present), never the word itself."""
    return shlex.quote(v) if v is not None else "''"


def _present(v: Any) -> str:
    """A measured value's presence flag in TXN: `1`, or empty while unmeasured."""
    return "" if v is None else "1"


def render_gate(kind: str, root: int = 0, ls: str = "/bin/ls", lsopt: Optional[str] = None,
                sha256sum: str = "/usr/bin/sha256sum", shasum: str = "/usr/bin/shasum", strict: str = "--strict") -> str:
    """G for a host whose supervision is `kind`. The rest exist for tests,
    which map them into a fixture; every rendered plan uses the defaults."""
    e = ("e" if kind == "launchd" else "") if lsopt is None else lsopt
    return (GATE.replace("@LS@", ls).replace("@E@", e).replace("@ROOT@", str(int(root)))
            .replace("@SHA256SUM@", sha256sum).replace("@SHASUM@", shasum).replace("@STRICT@", strict))


def render_txn(kind: str, systemctl: str, root: int = 0, top: str = "", sudo: str = SUDO, ls: str = "/bin/ls",
               lsopt: Optional[str] = None, size: Optional[str] = None, launchctl: str = "/bin/launchctl",
               launchd_dir: str = "/Library/LaunchDaemons", sha256sum: str = "/usr/bin/sha256sum",
               shasum: str = "/usr/bin/shasum", cmp: str = "/usr/bin/cmp", tail: str = "/usr/bin/tail",
               mkdir: str = "/bin/mkdir", date: str = "/bin/date",
               measured: Optional[dict] = None) -> str:
    """TXN for a host whose supervision is `kind`, with the host's recorded
    systemctl. The rest exist for tests, which map them into a fixture (and
    may supply measured facts); every rendered plan uses the defaults."""
    kind = "launchd" if kind == "launchd" else "systemd"
    m = {"LAUNCHD_NOT_FOUND": LAUNCHD_NOT_FOUND, "LAUNCHD_STATE_RUNNING": LAUNCHD_STATE_RUNNING,
         "LAUNCHD_STATE_IDLE": LAUNCHD_STATE_IDLE, "SYSTEMD_TIMER_MISSING": SYSTEMD_TIMER_MISSING}
    m.update(measured or {})
    nf, sdm = m["LAUNCHD_NOT_FOUND"], m["SYSTEMD_TIMER_MISSING"]
    e = ("e" if kind == "launchd" else "") if lsopt is None else lsopt
    subs = {"@KIND@": kind, "@ROOT@": str(int(root)), "@TOP@": top, "@SUDO@": sudo, "@LS@": ls, "@E@": e,
            "@SIZE@": size or SIZE[kind], "@SYSTEMCTL@": shlex.quote(systemctl), "@LAUNCHCTL@": launchctl,
            "@LAUNCHD_DIR@": launchd_dir, "@SHA256SUM@": sha256sum, "@SHASUM@": shasum, "@CMP@": cmp,
            "@TAIL@": tail, "@MKDIR@": mkdir, "@DATE@": date, "@RTNAME@": NAME, "@CONTEXT@": CONTEXT_NAME,
            "@SRCMAX@": str(SOURCE_MAX), "@CAPMAX@": str(CAPTURE_MAX),
            "@LDNF_SET@": _present(nf), "@LDNF_RC@": "" if nf is None else str(int(nf[0])),
            "@LDNF_TEXT@": _measured(None if nf is None else nf[1]),
            "@LD_RUNNING_SET@": _present(m["LAUNCHD_STATE_RUNNING"]), "@LD_RUNNING@": _measured(m["LAUNCHD_STATE_RUNNING"]),
            "@LD_IDLE_SET@": _present(m["LAUNCHD_STATE_IDLE"]), "@LD_IDLE@": _measured(m["LAUNCHD_STATE_IDLE"]),
            "@SDM_SET@": _present(sdm), "@SDM_RC@": "" if sdm is None else str(int(sdm[0])),
            "@SDM_OUT@": shlex.quote("" if sdm is None else sdm[1] or ""),
            "@SDM_ERR@": shlex.quote("" if sdm is None else sdm[2] or "")}
    out = TXN
    for k, v in subs.items():
        out = out.replace(k, v)
    return out
