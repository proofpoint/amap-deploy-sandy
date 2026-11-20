__d2_so=${SHELLOPTS-}
POSIXLY_CORRECT=y
__d2_px=${SHELLOPTS-}
\unset -f builtin 2>/dev/null || ${BASH_VERSION:+\exit} ${BASH_VERSION:+3}
\builtin ${BASH_VERSION:+shopt -u expand_aliases}${ZSH_VERSION:+setopt no_aliases} || \exit 3
# D2 profile capture, part B: the capture body, run in the operator's own login shell.
#
# Never run by hand. alpha2/d2/capture.sh runs under `env -i`. It writes the capture
# file's path into this text in place of the marker in the `3>` redirection below, and
# passes the result as the command text of a NEW interactive login shell:
#   "$SHELL" -i -l -c "<this text, with the path in it>"
# The path is part of the command text, which no startup file can change. It is never
# an argument or a variable, which startup could rewrite (`set --`). The text is not
# sourced with `.`, because bash's `.` hides a DEBUG trap from the file it runs (bash(1)).
#
# What it guarantees, for startup files that are mistaken but not hostile (see
# PROFILE-CAPTURE.md, "Threat model"):
# 1. While the startup files run, no capture descriptor exists. The launcher closes fd 3
#    and discards the shell's stdout and stderr.
# 2. Lines 1-5 use no reserved word and no unquoted name, so an alias over `if` or
#    any name cannot act on them (an alias never applies to an assignment or to a
#    quoted word):
#    - line 1 records the operator's own SHELLOPTS (for shell.posix_mode);
#    - line 2, `POSIXLY_CORRECT=y`, puts bash in posix mode, where the special
#      builtins (`unset`, `exit`, `trap`, `set`) come before any function of the same
#      name. Alone on its line, so a readonly POSIXLY_CORRECT aborts only that line;
#    - line 3 records whether posix mode engaged;
#    - line 4, `\unset -f builtin`, removes a function named `builtin` without
#      calling it. If that fails (a readonly function, `enable -n unset`), the shell
#      EXITS before anything else runs: no capture file, so nothing is admitted;
#    - line 5 turns alias expansion off, and on failure (`enable -n shopt`) exits the
#      same way.
#    From line 6 on, `builtin X` is the real builtin and no startup function is
#    called. If posix mode did not engage (a readonly or nameref POSIXLY_CORRECT),
#    the capture ends `refused`.
#    (A function named `builtin` is therefore absent from function.names.)
#    Named exclusions, where a startup function MAY run before the refusal: a function
#    named `unset` together with either `enable -n unset` or a POSIXLY_CORRECT that
#    cannot be set; a function named `exit` likewise. See PROFILE-CAPTURE.md.
# 3. (Line 5) Alias expansion is off for every later line.
# 4. The operator's DEBUG and RETURN traps are read, then removed in this new shell, and
#    the removal is re-read. A read that fails or is skipped, or a trap still set after
#    the removal, ends the capture `refused`. No hook runs after that: PROMPT_COMMAND,
#    precmd and preexec do not run under -c.
# 5. Only then is the capture file opened, as fd 3 of one braced group, with noclobber:
#    an existing file is never truncated.
# 6. Names are read only by builtins that cannot see values:
#    - bash: `compgen -a`, `-A function`, `-e`;
#    - zsh: `${(k)aliases}`, `${(k)functions}`, the exported `${(k)parameters}`.
#    No output that carries a value is parsed. The only values written are PATH, TERM
#    and the login shell's path.
# 7. The last line is `profile.end=complete` or `profile.end=refused`. The launcher
#    validates the whole file in a separate `env -i` process (profile_check.py) before
#    anything is admitted.

__d2_ok=1
__d2_shadow=
if [[ -n ${BASH_VERSION:-} ]]; then
    # Read the traps, remove them, and VERIFY the removal. Each read starts from a
    # sentinel, so a read that fails (`enable -n trap`) or is skipped (an extdebug
    # DEBUG trap returning nonzero) leaves UNREAD, never an empty "unset".
    builtin shopt -u extdebug
    __d2_t=UNREAD; __d2_t=$(builtin trap -p DEBUG) || __d2_t=UNREAD
    __d2_r=UNREAD; __d2_r=$(builtin trap -p RETURN) || __d2_r=UNREAD
    builtin trap - DEBUG RETURN
    builtin set +o functrace
    __d2_c=UNREAD; __d2_c=$(builtin trap -p DEBUG RETURN) || __d2_c=UNREAD
    # In posix mode `trap -p SIG` prints `trap -- - SIG` for a trap that is not set.
    [[ ${__d2_t-} = "trap -- - DEBUG" ]] && __d2_t=
    [[ ${__d2_r-} = "trap -- - RETURN" ]] && __d2_r=
    [[ ${__d2_c-UNREAD} = $'trap -- - DEBUG\ntrap -- - RETURN' ]] && __d2_c=
    [[ :${__d2_px-}: == *:posix:* ]] || __d2_ok=0
    if [[ ${__d2_t-UNREAD} = UNREAD || ${__d2_r-UNREAD} = UNREAD || -n ${__d2_c-UNREAD} ]]; then
        __d2_ok=0
    fi
    # Noclobber: the redirection below creates the capture file and never
    # truncates one that exists.
    builtin set -C
    {
        builtin printf '%s=%s\n' profile.schema d2-profile-shell/3
        builtin printf '%s=%s\n' shell.login "${SHELL:-UNSET}"
        builtin printf '%s=%s\n' shell.kind bash
        builtin printf '%s=%s\n' shell.version "$BASH_VERSION"
        case :$__d2_so: in *:posix:*) __d2_v=on ;; *) __d2_v=off ;; esac
        builtin printf '%s=%s\n' shell.posix_mode "$__d2_v"
        __d2_v=$(builtin compgen -a)
        builtin printf 'alias.names=%s\n' "${__d2_v//$'\n'/ }"
        __d2_v=
        for __d2_f in $(builtin compgen -A function); do
            case $__d2_f in __d2_*) ;; *) __d2_v="$__d2_v${__d2_v:+ }$__d2_f" ;; esac
        done
        builtin printf 'function.names=%s\n' "$__d2_v"
        __d2_v=$(builtin compgen -e)
        builtin printf 'env.names=%s\n' "${__d2_v//$'\n'/ }"
        if [[ -n ${PROMPT_COMMAND+x} ]]; then __d2_v=set; else __d2_v=unset; fi
        builtin printf '%s=%s\n' hook.PROMPT_COMMAND "$__d2_v"
        if [[ -n ${PS0:-} ]]; then __d2_v=set; else __d2_v=unset; fi
        builtin printf '%s=%s\n' hook.PS0 "$__d2_v"
        if [[ -n ${__d2_t-} ]]; then __d2_v=set; else __d2_v=unset; fi
        builtin printf '%s=%s\n' hook.trap_DEBUG "$__d2_v"
        if [[ -n ${__d2_r-} ]]; then __d2_v=set; else __d2_v=unset; fi
        builtin printf '%s=%s\n' hook.trap_RETURN "$__d2_v"
        if [[ -n ${BASH_ENV+x} ]]; then __d2_v=set; else __d2_v=unset; fi
        builtin printf '%s=%s\n' hook.BASH_ENV "$__d2_v"
        if [[ -n ${ENV+x} ]]; then __d2_v=set; else __d2_v=unset; fi
        builtin printf '%s=%s\n' hook.ENV "$__d2_v"
        __d2_v=$(builtin type -t /usr/bin/env)
        builtin printf '%s=%s\n' launch.first_word "${__d2_v:-none}"
        __d2_v=$(builtin type -t sudo)
        builtin printf '%s=%s\n' launch.sudo "${__d2_v:-none}"
        builtin printf '%s=%s\n' env.PATH "$PATH"
        if [[ -n ${SSH_AUTH_SOCK:-} ]]; then __d2_v=set; else __d2_v=unset; fi
        builtin printf '%s=%s\n' env.SSH_AUTH_SOCK "$__d2_v"
        builtin printf '%s=%s\n' env.TERM "${TERM:-UNSET}"
        if [[ ${__d2_ok-0} = 1 ]]; then
            builtin printf '%s\n' profile.end=complete
        else
            builtin printf '%s\n' profile.end=refused
        fi
    } 3>'@@D2_OUT@@' >&3
elif [[ -n ${ZSH_VERSION:-} ]]; then
    # UNMEASURED: there is no zsh on the review host. Same order, using zsh's builtins.
    for __d2_n in builtin trap; do
        if (( ${+functions[$__d2_n]} )); then
            __d2_shadow="$__d2_shadow $__d2_n"
            __d2_ok=0
        fi
    done
    __d2_t=unset
    (( ${+functions[TRAPDEBUG]} )) && __d2_t=set
    case "$(trap)" in *' DEBUG'*) __d2_t=set ;; esac
    builtin trap - DEBUG
    (( ${+functions[TRAPDEBUG]} )) && builtin unfunction TRAPDEBUG
    {
        for __d2_n in ${=__d2_shadow}; do builtin print -r -- "shadow.$__d2_n=function"; done
        builtin print -r -- "profile.schema=d2-profile-shell/3"
        builtin print -r -- "shell.login=${SHELL:-UNSET}"
        builtin print -r -- "shell.kind=zsh"
        builtin print -r -- "shell.version=$ZSH_VERSION"
        builtin print -r -- "alias.names=${(j: :)${(ok)aliases}}"
        builtin print -r -- "alias.global_names=${(j: :)${(ok)galiases}}"
        builtin print -r -- "function.names=${(j: :)${(ok)functions:#__d2_*}}"
        builtin print -r -- "env.names=${(j: :)${(ok)parameters[(R)*export*]}}"
        builtin print -r -- "hook.preexec_functions=${(j: :)${preexec_functions-}}"
        builtin print -r -- "hook.precmd_functions=${(j: :)${precmd_functions-}}"
        builtin print -r -- "hook.zshaddhistory_functions=${(j: :)${zshaddhistory_functions-}}"
        builtin print -r -- "hook.trap_DEBUG=$__d2_t"
        if [[ -n ${ZDOTDIR+x} ]]; then __d2_v=set; else __d2_v=unset; fi
        builtin print -r -- "hook.ZDOTDIR=$__d2_v"
        builtin print -r -- "launch.first_word=${$(builtin whence -w /usr/bin/env)##*: }"
        builtin print -r -- "launch.sudo=${$(builtin whence -w sudo)##*: }"
        builtin print -r -- "env.PATH=$PATH"
        if [[ -n ${SSH_AUTH_SOCK:-} ]]; then __d2_v=set; else __d2_v=unset; fi
        builtin print -r -- "env.SSH_AUTH_SOCK=$__d2_v"
        builtin print -r -- "env.TERM=${TERM:-UNSET}"
        if [[ $__d2_ok = 1 ]]; then
            builtin print -r -- "profile.end=complete"
        else
            builtin print -r -- "profile.end=refused"
        fi
    } 3>'@@D2_OUT@@' >&3
fi
