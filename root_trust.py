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
from typing import List, Optional

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


def typed_argv(rt: str, sha256: str, python3: str, writer: str, tools: List[str], argv: List[str]) -> List[str]:
    """One operator-typed root line (d3.3 §5(d)): the anchor's sudo, then the
    §3 grammar, trusted-exec with each recorded tool (sudo never among them)
    and `argv`, whose argv[0] is one of them or `python3` in its one exact
    vector. sudo prompts as for any typed line: no -n."""
    recorded = [x for t in sorted(set(tools)) if posixpath.basename(t) != "sudo" for x in ("--tool", t)]
    return [SUDO] + root_argv_positional(rt, sha256, python3, writer, ["trusted-exec"] + recorded + ["--"] + list(argv))


def root_argv(rt: str, sha256: str, python3: str, writer: str, args: List[str],
              engine: Optional[str] = None) -> List[str]:
    """The whole argv of a root command under the anchor."""
    return anchor(engine) + ["/bin/sh", "-c", root_line(rt, sha256, python3, writer, args)]
