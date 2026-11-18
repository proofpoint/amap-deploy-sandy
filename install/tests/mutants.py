"""Mutation run: each mutant disables one guard in a copy of install/,
regenerates MANIFEST there (so the manifest test cannot kill it for free),
and runs the whole suite. A mutant the suite does not turn red SURVIVED.

Usage: python3 -I -B install/tests/mutants.py [--jobs N] [label ...]
Exit 0 only when every selected mutant is killed and every old string
matched exactly once.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALL = os.path.dirname(HERE)

M = [
    # a2_host
    ("ENV-SET", "a2_host.py", 'if set(environ) != set(ENV_NAMES):\n        raise Refusal("RUNNER.ENV")\n    if environ["PATH"]',
     'if False:\n        raise Refusal("RUNNER.ENV")\n    if environ["PATH"]'),
    ("ENV-PATH", "a2_host.py", 'if environ["PATH"] != LAUNCH_PATH:', 'if False:'),
    ("ENV-HOME", "a2_host.py", 'if environ["HOME"] != home:', 'if False:'),
    ("ENV-L3-AGENT", "a2_host.py", 'if account == "l3" and environ["SSH_AUTH_SOCK"] != "":', 'if False:'),
    ("ENV-NAMES", "a2_host.py", 'if set(environ) != set(ENV_NAMES) or environ.get("PATH") != LAUNCH_PATH:', 'if False:'),
    ("ENV-RECEIVED-DUP", "a2_host.py", "if not sep or not key or key in out:", "if not sep or not key:"),
    ("ENV-RECEIVED", "a2_admit.py", "site.environ = a2_host.received_environ()", "site.environ = dict(os.environ)"),
    ("ACCT-EUID", "a2_host.py", "if uid != euid:", "if False:"),
    ("ACCT-L3", "a2_host.py", 'return "l3" if inv.loop in ("L3", None) else "loop"', 'return "loop" if inv.loop in ("L3", None) else "loop"'),
    ("ACCT-DESTROY", "a2_host.py", 'if inv.command == "destroy":\n        return "l3"', 'if inv.command == "destroy":\n        return None'),
    ("ACCT-CALL", "a2_admit.py", "    a2_host.check_account(inv, account)\n", ""),
    # a2_private
    ("L1-BOM", "a2_private.py", 'if raw[:3] == b"\\xef\\xbb\\xbf":', "if False:"),
    ("L1-DUP", "a2_private.py", 'if k in seen:\n            raise Invalid("L1", "$")', "if False:\n            pass"),
    ("L1-NAN", "a2_private.py", "object_pairs_hook=_no_dup, parse_constant=_no_constant)", "object_pairs_hook=_no_dup)"),
    ("L1-SCHEMA", "a2_private.py", 'if not isinstance(doc, dict) or doc.get("schema") != schema_token:', "if not isinstance(doc, dict):"),
    ("L2-CLOSED", "a2_private.py", 'if key not in fields:\n            raise Invalid("L2"', 'if False:\n            raise Invalid("L2"'),
    ("L3-PATTERN", "a2_private.py", "if not isinstance(value, str) or _COMPILED[pattern].fullmatch(value) is None:\n        return False",
     "if not isinstance(value, str):\n        return False"),
    ("L3-SEGMENT", "a2_private.py", 'if any(s in (".", "..") for s in segs):', "if False:"),
    ("L3-UNIQUE", "a2_private.py", "if len(set(vals)) != len(vals):", "if False:"),
    ("L3-ACCOUNTS", "a2_private.py", 'if r["loop_account"] == r["l3_account"]:', "if False:"),
    ("L3-SCOPES", "a2_private.py", 'if scopes != {"loop", "l3"}:', "if False:"),
    ("L3-CONNECTOR", "a2_private.py", 'if a["connector"] not in comps:', "if False:"),
    ("L4-RAW", "a2_private.py", '    for rx in DENY:\n        if rx.search(text):\n            raise Invalid("L4", "$")\n', ""),
    ("L4-PARSED", "a2_private.py", '            if rx.search(s):\n                raise', '            if False:\n                raise'),
    # a2_args
    ("ARGS-LOOP-ONLY", "a2_args.py", 'if "--loop" in keys and keys & {"--only", "--from", "--leak-run"}:', "if False:"),
    ("ARGS-NONCE", "a2_args.py", "else NONCE.fullmatch(v) is not None if kind == \"nonce\"", "else True if kind == \"nonce\""),
    ("ARGS-UNKNOWN", "a2_args.py", "        else:\n            raise _bad()\n    return _resolve(flags)", "        else:\n            i += 1\n    return _resolve(flags)"),
    # a2_locks
    ("ROOT-IDENT", "a2_locks.py", 'if host_identity is None or host_identity != r["host_id"]:', "if False:"),
    ("ROOT-MODE", "a2_locks.py", "or st.st_uid != root_uid or stat.S_IMODE(st.st_mode) != 0o755:", "or st.st_uid != root_uid:"),
    ("ROOT-OWNER", "a2_locks.py", "if not stat.S_ISDIR(st.st_mode) or st.st_uid != root_uid or", "if not stat.S_ISDIR(st.st_mode) or"),
    ("ROOT-REALPATH", "a2_locks.py", "if os.path.realpath(root) != root:", "if False:"),
    ("ROOT-PARENT", "a2_locks.py", "            if _writable_by(pst, uid, gids):\n                raise", "            if False:\n                raise"),
    ("ROOT-FS", "a2_locks.py", "if fs_type_of(root) not in LOCAL_FS_TYPES:", "if False:"),
    ("LOCK-ALL-OR-NOTHING", "a2_locks.py", "    except Refusal:\n        release(held)\n        raise", "    except Refusal:\n        raise"),
    ("LOCK-INHERIT", "a2_locks.py", "        os.set_inheritable(fd, True)\n", "        pass\n"),
    ("LOCK-FILE-MODE", "a2_locks.py", "            or stat.S_IMODE(st.st_mode) != 0o644):\n        os.close(fd)", "            ):\n        os.close(fd)"),
    ("LOCK-NOFOLLOW", "a2_locks.py", "fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)",
     "fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)"),
    ("LOCK-RUNNER-FIRST", "a2_locks.py", "    if writes_target:\n        order.append((RUNNER_LOCK", "    if False:\n        order.append((RUNNER_LOCK"),
    ("LOCK-DUP-TARGET", "a2_locks.py", "    if len(set(names)) != len(names):\n        raise Refusal(\"RUNNER.HOSTS_TARGETS\")\n    return sorted", "    return sorted"),
    ("LOCK-HELD-PROBE", "a2_locks.py", "            else:\n                raise Refusal(\"RUNNER.ADMISSION\")\n        finally:", "            else:\n                pass\n        finally:"),
    ("LOCK-HELD-OWN", "a2_locks.py", "        try:\n            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n        except OSError:\n            raise Refusal(\"RUNNER.ADMISSION\")",
     "        try:\n            pass\n        except OSError:\n            raise Refusal(\"RUNNER.ADMISSION\")"),
    ("LOCK-HELD-INODE", "a2_locks.py", "        if fd is None:\n            raise Refusal(\"RUNNER.ADMISSION\")", "        if fd is None:\n            continue"),
    ("CUSTODY-INODE", "a2_locks.py", "            if (pst.st_dev, pst.st_ino) != (fst.st_dev, fst.st_ino):\n                return \"lost\"", "            pass"),
    ("DESTROY-SCOPE", "a2_locks.py", 'return [v for v in hosts["vms"] if v["name"] not in deny]', 'return [v for v in hosts["vms"] if v["scope"] == account]'),
    # a2_stop
    ("STOP-PERMIT-REG", "a2_stop.py", "                if stat.S_ISREG(est.st_mode):\n                    continue", "                continue"),
    ("STOP-EXTRA-TOP", "a2_stop.py", "    if set(names) - set(SETTERS):\n        return \"set\"", "    pass"),
    ("STOP-MISSING", "a2_stop.py", 'return "set" if e.errno == errno.ENOENT else "UNOBSERVED"', 'return "unset" if e.errno == errno.ENOENT else "UNOBSERVED"'),
    ("STOP-APPLIES-L3", "a2_stop.py", 'if inv.command == "install" and inv.loop in ("L3", None):\n        return False', 'if False:\n        return False'),
    ("STOP-CALL", "a2_admit.py", 'if a2_stop.applies(c.inv) and a2_stop.read(c.lock_root) != "unset":', "if False:"),
    # a2_budget
    ("BUD-REC-MODE", "a2_budget.py", "or stat.S_IMODE(st.st_mode) != 0o644 or st.st_nlink != 1", "or st.st_nlink != 1"),
    ("BUD-REC-NLINK", "a2_budget.py", "or stat.S_IMODE(st.st_mode) != 0o644 or st.st_nlink != 1", "or stat.S_IMODE(st.st_mode) != 0o644"),
    ("BUD-DUP-RUN", "a2_budget.py", '            if rec["run_id"] in out:\n                raise Unobserved()', "            pass"),
    ("BUD-TOP-NAMES", "a2_budget.py", "    if set(top) != set(SUBDIRS):\n        raise Unobserved()", "    pass"),
    ("BUD-DIR-MODE", "a2_budget.py", "or stat.S_IMODE(st.st_mode) != 0o755 or _has_acl(path)):", "or _has_acl(path)):"),
    ("BUD-SCHEMA", "a2_budget.py", 'if rec["kind"] != "start" or rec["run_id"] != run_id_from_name:', "if False:"),
    ("SR-ACCOUNT", "a2_budget.py", "    if sub != account:\n        raise", "    if False:\n        raise"),
    ("SR-COMMAND", "a2_budget.py", 'if rec["command"] != inv.command or rec["loop"] != loop_token(inv.loop):', "if False:"),
    ("SR-SHAS", "a2_budget.py", 'if rec["lock_sha256"] != lock_sha or rec["hosts_sha256"] != hosts_sha:', "if False:"),
    ("SR-INSTALLER", "a2_budget.py", 'if rec["installer_sha256"] != installer_sha:', "if False:"),
    ("SR-STALE", "a2_budget.py", "if started > t_now or t_now - started > STALE_S:", "if started > t_now:"),
    ("SR-FUTURE", "a2_budget.py", "if started > t_now or t_now - started > STALE_S:", "if t_now - started > STALE_S:"),
    ("BRK-SOCK-OWNER", "a2_budget.py", "return stat.S_ISSOCK(st.st_mode) and st.st_uid == root_uid", "return stat.S_ISSOCK(st.st_mode)"),
    ("BRK-SOCK-CALL", "a2_budget.py", "    if not socket_owner_ok(st, root_uid):\n        raise", "    if False:\n        raise"),
    ("BRK-PEER", "a2_budget.py", "    return peer_uid == root_uid", "    return True"),
    ("BRK-PEER-CALL", "a2_budget.py", "struct.calcsize(\"iII\")), root_uid):\n                raise Refusal(\"PREFLIGHT.BUDGET\")", "struct.calcsize(\"iII\")), root_uid) and False:\n                raise Refusal(\"PREFLIGHT.BUDGET\")"),
    # a2_admit
    ("ADM-RECORD", "a2_admit.py", "    if c.inv.writes_target:\n        admission_sha = a2_budget", "    if False:\n        admission_sha = a2_budget"),
    ("ADM-FIND-HELD", "a2_admit.py", "    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)\n", "    held = {}\n"),
    ("ADM-LOOPTASKS", "a2_admit.py", 'if site.loop_tasks(c.hosts) != "none":', "if False:"),
    ("ADM-USAGE-80", "a2_admit.py", "or pct >= 80 or pct < 0:", "or pct >= 81 or pct < 0:"),
    ("ADM-USAGE-UNSET", "a2_admit.py", '    elif site.usage_path != "b":\n        raise Refusal("PREFLIGHT.BUDGET")', "    else:\n        pass"),
    ("ADM-GATE-OPEN", "a2_admit.py", 'len(gate) == 2 and gate[0] == "open"', 'len(gate) == 2'),
    ("ADM-GATE-TIME", "a2_admit.py", "if site.full_run_bound_s is None or gate[1] < site.full_run_bound_s:", "if site.full_run_bound_s is None:"),
    ("ADM-RUNID", "a2_admit.py", '    if not a2_private.matches("run_id", run_id):\n        raise Refusal("RUNNER.ADMISSION")\n', ""),
    ("ADM-LAUNCH-RELEASE", "a2_admit.py", "    except BaseException:\n        a2_locks.release(held)\n        raise", "    except BaseException:\n        raise"),
    # S0-route mutants: each disables one re-check on the S0 route only,
    # restoring it afterwards, so only an S0 direct-path test can kill it.
    ("S0-GATE", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = (site.arm_gate, site.full_run_bound_s); site.arm_gate, site.full_run_bound_s = (lambda h: (\"open\", 10 ** 9)), 0\n    try:\n        c = _common(argv, site)\n    finally:\n        site.arm_gate, site.full_run_bound_s = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("S0-LEAK", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = a2_private.load_pair; a2_private.load_pair = lambda a, b: (__import__(\"json\").loads(a), __import__(\"json\").loads(b))\n    try:\n        c = _common(argv, site)\n    finally:\n        a2_private.load_pair = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("S0-PARENT", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = a2_locks._writable_by; a2_locks._writable_by = lambda *a: False\n    try:\n        c = _common(argv, site)\n    finally:\n        a2_locks._writable_by = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("S0-ROOT", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = a2_locks.check_lock_root; a2_locks.check_lock_root = lambda *a, **k: None\n    try:\n        c = _common(argv, site)\n    finally:\n        a2_locks.check_lock_root = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("S0-NAMES", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = a2_locks.check_names_distinct; a2_locks.check_names_distinct = lambda h: None\n    try:\n        c = _common(argv, site)\n    finally:\n        a2_locks.check_names_distinct = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("S0-L4", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = a2_private.check_deny; a2_private.check_deny = lambda *a: None\n    try:\n        c = _common(argv, site)\n    finally:\n        a2_private.check_deny = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("S0-L3-LOCK", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = a2_private.check_lock; a2_private.check_lock = lambda *a: None\n    try:\n        c = _common(argv, site)\n    finally:\n        a2_private.check_lock = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("S0-L3-HOSTS", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = a2_private.check_hosts; a2_private.check_hosts = lambda *a: None\n    try:\n        c = _common(argv, site)\n    finally:\n        a2_private.check_hosts = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("S0-ENV", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = a2_host.check_env; a2_host.check_env = lambda *a: None\n    try:\n        c = _common(argv, site)\n    finally:\n        a2_host.check_env = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("S0-ACCOUNT", "a2_admit.py", "    c = _common(argv, site)\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)",
     "    _sv = a2_host.check_account; a2_host.check_account = lambda *a: None\n    try:\n        c = _common(argv, site)\n    finally:\n        a2_host.check_account = _sv\n    held = a2_locks.find_held(c.order, site.root_uid, site.fd_dir)"),
    ("NAMES-DISTINCT", "a2_locks.py", "    if len(set(names)) != len(names):\n        raise Refusal(\"RUNNER.HOSTS_TARGETS\")\n\n\ndef targets", "    pass\n\n\ndef targets"),
    ("GATE-SHAPE", "a2_admit.py", "and isinstance(gate[1], int) and not isinstance(gate[1], bool) and gate[1] >= 0)", "and True)"),
    ("PRIVATE-NOFOLLOW", "a2_admit.py", "fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)\n        except OSError:\n            raise Refusal(\"PREFLIGHT.PRIVATE_SOURCE\")",
     "fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)\n        except OSError:\n            raise Refusal(\"PREFLIGHT.PRIVATE_SOURCE\")"),
    ("PRIVATE-REG", "a2_admit.py", "            if not stat.S_ISREG(os.fstat(fd).st_mode):\n                raise", "            if False:\n                raise"),
    ("PRIVATE-EOF", "a2_admit.py", "            raw = _read_to_eof(fd, READ_MAX)", "            raw = os.read(fd, READ_MAX + 1)"),
    ("RECORD-NOFOLLOW", "a2_budget.py", "        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)\n    except OSError:\n        raise Unobserved()",
     "        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)\n    except OSError:\n        raise Unobserved()"),
    ("RECORD-EOF", "a2_budget.py", "            b = os.read(fd, RECORD_MAX + 1 - n)\n            if not b:\n                break\n            chunks.append(b)\n            n += len(b)\n        raw",
     "            b = os.read(fd, RECORD_MAX + 1 - n)\n            chunks.append(b)\n            break\n        raw"),
    ("STARTED-CAL", "a2_budget.py", "        time.strptime(rec[\"started_at\"], \"%Y-%m-%dT%H:%M:%SZ\")\n    except ValueError:\n        return False",
     "        pass\n    except ValueError:\n        return False"),
    # e3 schema and causes
    ("TAG-EQUAL", "a2_private.py", '        if c["tag"] != doc["overlay"]["tag"]:\n            raise', "        if False:\n            raise"),
    ("DENY-L3-DUP", "a2_private.py", "        if len(set(deny)) != len(deny):\n            raise", "        if False:\n            raise"),
    ("DENY-L3-VM", "a2_private.py", "            if n not in vm_names:\n                raise", "            if False:\n                raise"),
    ("DENY-UNCONFIGURED", "a2_locks.py", "    if not isinstance(hard_deny, list):\n        return False", "    if hard_deny is None:\n        hard_deny = []"),
    ("NOT-STARTED-EXEC", "a2_admit.py", "    except Exception:\n        pass\n    a2_locks.release(held)", "    except OSError:\n        pass\n    a2_locks.release(held)"),
    ("BRK-SENT-BOUNDARY", "a2_budget.py", 'raise Refusal("PREFLIGHT.BUDGET" if sent == 0 else "RUNNER.NOT_STARTED")', 'raise Refusal("PREFLIGHT.BUDGET")'),
    ("BRK-LATE", "a2_budget.py", "                if left <= 0:\n                    raise Refusal(\"RUNNER.NOT_STARTED\")\n                s.settimeout(left)", "                s.settimeout(None)"),
    ("BRK-REFUSAL", "a2_budget.py", '    if ans == REFUSAL and type(ans.get("refused")) is bool:\n        raise Refusal("PREFLIGHT.BUDGET")', '    if False:\n        raise Refusal("PREFLIGHT.BUDGET")'),
    ("BRK-REFUSAL-STRICT", "a2_budget.py", '    if ans == REFUSAL and type(ans.get("refused")) is bool:', '    if isinstance(ans, dict) and "refused" in ans:'),
    ("BRK-ANSWER", "a2_budget.py", 'or not matches("run_id", ans["run_id"]) or not matches("sha256", ans["sha256"])):\n        raise Refusal("RUNNER.NOT_STARTED")',
     'or not matches("run_id", ans["run_id"])):\n        raise Refusal("RUNNER.NOT_STARTED")'),
    # package 2a: output guard
    ("GUARD-CHECK", "a2_guard.py", "            if bytes(v) and bytes(v) in raw:\n                raise", "            if False:\n                raise"),
    ("GUARD-RC3", "a2_guard.py", "rc=3 if self.wrote_target else None)", "rc=None)"),
    ("GUARD-ZERO", "a2_guard.py", "                v[i] = 0\n", "                pass\n"),
    ("GUARD-CAP", "a2_guard.py", "        if len(value) > FACT_CAP:\n", "        if False:\n"),
    # package 2a: receipts, manifest, SUMS
    ("REC-RC0-CAUSE", "a2_record.py", '        if facts["RESULT"] not in PASS_RESULTS or has_cause:', '        if facts["RESULT"] not in PASS_RESULTS:'),
    ("REC-FAIL-RULES", "a2_record.py", '        if facts["RESULT"] != "FAIL" or "CAUSE" not in facts or "CAUSE_TEXT" not in facts:', '        if "CAUSE" not in facts or "CAUSE_TEXT" not in facts:'),
    ("REC-CAUSE-STAGE", "a2_record.py", '        if stage_part != "RUNNER" and stage_part != STAGE_NAME[stage_id]:', '        if False:'),
    ("REC-CAUSE-TEXT", "a2_record.py", '        if want is None or facts["CAUSE_TEXT"] != want:', '        if want is None:'),
    ("REC-VALUE", "a2_record.py", '        if not KEY.fullmatch(k) or not isinstance(v, str) or not VALUE.fullmatch(v):', '        if not KEY.fullmatch(k) or not isinstance(v, str):'),
    ("REC-REQUIRED", "a2_record.py", '    for k in REQUIRED:\n        if k not in facts:', '    for k in ():\n        if k not in facts:'),
    ("REC-END-LAST", "a2_record.py", '        if not sep or not KEY.fullmatch(k) or not VALUE.fullmatch(v) or k in facts:', '        if not sep or not KEY.fullmatch(k) or not VALUE.fullmatch(v):'),
    ("REC-NO-REWRITE", "a2_record.py", '        else:\n            raise ValueError("receipt exists")', '        else:\n            pass'),
    ("REC-READ-BIND", "a2_record.py", '        if (facts["LOCK_SHA"] != self.lock_sha or facts["HOSTS_SHA"] != self.hosts_sha', '        if (False'),
    ("REC-READ-LOOP", "a2_record.py", '                or facts["LOOP"] != ("-" if self.loop is None else self.loop)):', '                ):'),
    ("REC-READ-INSTALLER", "a2_record.py", '        if facts["INSTALLER_SHA"] != self.installer_sha:\n            raise', '        if False:\n            raise'),
    ("REC-READ-FAILED", "a2_record.py", '        if rc != 0:\n            raise Refusal(stage_name + ".PREDECESSOR_FAILED")', '        if False:\n            raise Refusal(stage_name + ".PREDECESSOR_FAILED")'),
    ("REC-READ-NOFOLLOW", "a2_record.py", '    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)', '    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)'),
    ("REC-FINAL-ONCE", "a2_record.py", '        if self.final:\n            raise ValueError("the manifest is final")\n        data =', '        if False:\n            raise ValueError("the manifest is final")\n        data ='),
    ("SUMS-CHAIN", "a2_record.py", '        if m is None or int(m.group(1)) != i or m.group(3) != prev:', '        if m is None or int(m.group(1)) != i:'),
    ("SUMS-NUMBER", "a2_record.py", '        if m is None or int(m.group(1)) != i or m.group(3) != prev:', '        if m is None or m.group(3) != prev:'),
    ("SUMS-REPEAT", "a2_record.py", '        if path in seen or not (path in (MANIFEST, SUMMARY) or RECEIPT_PATH.fullmatch(path)):', '        if not (path in (MANIFEST, SUMMARY) or RECEIPT_PATH.fullmatch(path)):'),
    ("SUMS-PATH", "a2_record.py", '        if path in seen or not (path in (MANIFEST, SUMMARY) or RECEIPT_PATH.fullmatch(path)):', '        if path in seen:'),
    ("SUMS-DIGEST", "a2_record.py", '        if hashlib.sha256(data).hexdigest() != m.group(2):\n            raise', '        if False:\n            raise'),
    ("SUMS-UNLISTED", "a2_record.py", '    if present - seen:\n        raise', '    if False:\n        raise'),
    # package 2a: git plumbing
    ("GIT-NO-RENAMES", "a2_git.py", '"diff-tree", "--no-renames", "--no-ext-diff"', '"diff-tree", "--no-ext-diff"'),
    ("GIT-PROTOCOLS", "a2_git.py", '               "-c", "protocol.allow=never"]', '               "-c", "protocol.allow=always"]'),
    # package 2a: S0
    ("S0-INT-VERSION", "a2_s0.py", '            or resolved_sha != want["resolved_sha256"] or version != want["version"]):', '            or resolved_sha != want["resolved_sha256"]):'),
    ("S0-INT-LAUNCH", "a2_s0.py", '    if (launch_sha != want["sha256"] or resolved != want["resolved_path"]', '    if (resolved != want["resolved_path"]'),
    ("S0-INT-RESOLVED", "a2_s0.py", '            or resolved_sha != want["resolved_sha256"] or version != want["version"]):', '            or version != want["version"]):'),
    ("S0-INT-MANIFEST", "a2_s0.py", '    if site.installer_sha != lock["installer"]["sha256"]:\n        raise', '    if False:\n        raise'),
    ("S0-INT-HEAD", "a2_s0.py", '        if (site.git.head(checkout) != lock["installer"]["commit"]\n                or not site.git.status_clean(checkout)):', '        if (not site.git.status_clean(checkout)):'),
    ("S0-INT-CLEAN", "a2_s0.py", '        if (site.git.head(checkout) != lock["installer"]["commit"]\n                or not site.git.status_clean(checkout)):', '        if (site.git.head(checkout) != lock["installer"]["commit"]):'),
    ("S0-PS-CLEAN", "a2_s0.py", '        if not git.status_clean(repo):\n            raise', '        if False:\n            raise'),
    ("S0-PS-BLOB", "a2_s0.py", '            if entry is None or entry[1] != "blob" or entry[2] != a2_git.blob_id(raw, fmt):', '            if entry is None or entry[1] != "blob":'),
    ("S0-PS-MODE", "a2_s0.py", '        if entry[0] != "100644":\n            raise', '        if False:\n            raise'),
    ("S0-PS-DESCENT", "a2_s0.py", '        if peeled != ov["commit"] and not git.is_ancestor(bare, ov["commit"], peeled):', '        if False:'),
    ("S0-PS-ONE", "a2_s0.py", '            if len(changes) != 1:\n                raise', '            if False:\n                raise'),
    ("S0-PS-PATH", "a2_s0.py", '            if path != LOCK_NAME or new_mode != "100644" or old_mode not in ("100644", "000000"):', '            if new_mode != "100644" or old_mode not in ("100644", "000000"):'),
    ("S0-PS-ANNOTATED", "a2_s0.py", '    if typ != "tag" or peeled != head:', '    if peeled != head:'),
    ("S0-PS-PEELED", "a2_s0.py", '    if typ != "tag" or peeled != head:', '    if typ != "tag":'),
    ("S0-PS-LISTED", "a2_s0.py", '    if not listed:\n        raise Refusal(wrong_cause)', '    if False:\n        raise Refusal(wrong_cause)'),
    ("S0-L7-MODE", "a2_s0.py", '        if stat.S_IMODE(st.st_mode) & 0o007:', '        if False:'),
    ("S0-L7-ROOTS", "a2_s0.py", '            if real == root or real.startswith(root.rstrip("/") + "/"):', '            if False:'),
    ("S0-L7-UNSET", "a2_s0.py", '    if site.sandbox_mount_roots is None:\n        raise', '    if site.sandbox_mount_roots is None:\n        return\n        raise'),
    ("S0-LIVE", "a2_s0.py", '        if (work == live or work.startswith(live.rstrip("/") + "/")', '        if (False'),
    ("S0-LIVE-UNSET", "a2_s0.py", '    if site.live_deploy_paths is None:\n        raise', '    if site.live_deploy_paths is None:\n        return\n        raise'),
    ("S0-FETCH-ANNOTATED", "a2_s0.py", '        if typ != "tag" or peeled != comp["commit"]:', '        if peeled != comp["commit"]:'),
    ("S0-FETCH-PEELED", "a2_s0.py", '        if typ != "tag" or peeled != comp["commit"]:', '        if typ != "tag":'),
    ("S0-PROBES", "a2_s0.py", '        if probe(c.hosts) != "ok":\n            raise', '        if False:\n            raise'),
    ("S0-CUSTODY-PLACE", "a2_s0.py", '    if facts["CUSTODY_LOCKS"] != "held" or facts["CUSTODY_PLACEMENT"] != "match":', '    if facts["CUSTODY_LOCKS"] != "held":'),
    ("S0-CUSTODY-STOP", "a2_s0.py", '    if facts["CUSTODY_STOP"] not in ("unset", "-"):\n        return', '    if False:\n        return'),
    ("ADOPT-NONINHERIT", "a2_locks.py", "    for fd in keep:\n        os.set_inheritable(fd, False)", "    for fd in keep:\n        pass"),
    ("ADOPT-STRAYS", "a2_locks.py", "        if target.startswith(root):\n            try:\n                os.close(fd)", "        if False:\n            try:\n                os.close(fd)"),
    ("ADOPT-CALL", "a2_admit.py", "    a2_locks.adopt(held, c.lock_root, site.fd_dir)\n", ""),
    ("FETCH-EXCL-RUN", "a2_s0.py", "        os.mkdir(c.run_id, 0o700, dir_fd=top_fd)\n", "        os.makedirs(\"/proc/%d/fd/%d/%s\" % (os.getpid(), top_fd, c.run_id), exist_ok=True)\n"),
    ("FETCH-EXCL-NAME", "a2_s0.py", "        os.mkdir(name + \".git\", 0o700, dir_fd=c.fetch_fd)\n", "        os.makedirs(\"/proc/%d/fd/%d/%s.git\" % (os.getpid(), c.fetch_fd, name), exist_ok=True)\n"),
    ("FETCH-NOFOLLOW", "a2_s0.py", "        top_fd = os.open(FETCH_DIR, a2_rundir.DIR_FLAGS, dir_fd=work_fd)", "        top_fd = os.open(FETCH_DIR, os.O_RDONLY | os.O_DIRECTORY, dir_fd=work_fd)"),
    ("REPORT-GUARD", "a2_causes.py", "    if guard is not None:\n        try:\n            for ln in lines:\n                guard.check(ln)", "    if False:\n        try:\n            for ln in lines:\n                guard.check(ln)"),
    ("REPORT-GUARD-SECOND", "a2_causes.py", "            except Refusal:\n                lines = []", "            except Refusal:\n                pass"),
    ("MAIN-GUARD", "a2_main.py", "        return a2_causes.report(r, site.out, site.guard)", "        return a2_causes.report(r, site.out)"),
    # 2a r2
    ("GIT-FSMONITOR", "a2_git.py", '"-c", "core.fsmonitor=false",', ''),
    ("GIT-HOOKS", "a2_git.py", 'cfg = ["-c", "core.hooksPath=/dev/null", ', 'cfg = ['),
    ("GIT-GLOBAL", "a2_git.py", '            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",\n', ''),
    ("GIT-NO-REPLACE", "a2_git.py", '            "GIT_NO_REPLACE_OBJECTS": "1",\n', ''),
    ("GIT-OPTIONAL-LOCKS", "a2_git.py", '            "GIT_OPTIONAL_LOCKS": "0"}', '            }'),
    ("GIT-LSREMOTE-EXACT", "a2_git.py", "            if ref == want:", "            if ref.endswith(want):"),
    ("MAIN-ENV", "a2_main.py", 'site.git = a2_git.Git(a2_git.env_for(c.home, site.environ.get("SSH_AUTH_SOCK", "")))', 'site.git = a2_git.Git(dict(__import__("os").environ))'),
    ("MAIN-FINISH", "a2_main.py", "        rec.write_manifest(final=True)\n    except Exception:\n        pass", "        pass\n    except Exception:\n        pass"),
    ("MAIN-NOTBUILT-RC", "a2_main.py", "        stop = Refusal(NOT_BUILT, rc=3)", "        stop = Refusal(NOT_BUILT)"),
    ("VALUE-CTRL", "a2_record.py", 'VALUE = re.compile(r"[\\x20-\\x7e]*")', 'VALUE = re.compile(r"[^\\n]*")'),
    ("PARSE-VALUE", "a2_record.py", "        if not sep or not KEY.fullmatch(k) or not VALUE.fullmatch(v) or k in facts:", "        if not sep or not KEY.fullmatch(k) or k in facts:"),
    ("GUARD-SUMS", "a2_record.py", "        self.guard.check(line)\n", ""),
    ("GUARD-MANIFEST", "a2_record.py", "        self.guard.check(data)\n        _write_atomic(self.run_fd, MANIFEST, data)", "        _write_atomic(self.run_fd, MANIFEST, data)"),
    ("REC-AFTER-FINAL", "a2_record.py", '        if self.final:\n            raise ValueError("the manifest is final")\n        allf', '        allf'),
    ("L7-REALPATH", "a2_s0.py", "            root = os.path.realpath(root)\n", ""),
    ("S0-READ-CHECKOUT", "a2_s0.py", '    bare = c.fetched["overlay"]', '    bare = repo'),
    ("S0-PS-PARSE-CAUGHT", "a2_s0.py", "    except (a2_git.GitError, ValueError):\n        raise Refusal(\"PREFLIGHT.PRIVATE_SOURCE\")\n    return head", "    except a2_git.GitError:\n        raise Refusal(\"PREFLIGHT.PRIVATE_SOURCE\")\n    return head"),
    ("L7-FILE-REALPATH", "a2_s0.py", "            real = os.path.realpath(path)", "            real = path"),
    ("FETCH-TOP-CHECK", "a2_s0.py", "        a2_rundir._check_dir_fd(top_fd, uid)\n", ""),
    ("S0-UNCLASSIFIED-FACTS", "a2_s0.py", '        run.write_receipt("S0", None, started, "FAIL", facts, rc=3, cause="PREFLIGHT.UNCLASSIFIED")', '        run.write_receipt("S0", None, started, "FAIL", [], rc=3, cause="PREFLIGHT.UNCLASSIFIED")'),
    # package 2b: S1
    ("S1-CORE-SET", "a2_s1.py", "        setrlimit(resource.RLIMIT_CORE, (0, 0))\n", "        pass\n"),
    ("S1-CORE-VERIFY", "a2_s1.py", "        if getrlimit(resource.RLIMIT_CORE) != (0, 0):\n            raise OSError(\"limit not zero\")", "        if False:\n            raise OSError(\"limit not zero\")"),
    ("S1-STDIN-TTY", "a2_s1.py", "    if not os.isatty(stdin_fd):\n        raise Refusal(\"CREDENTIALS.NO_ECHO\")", "    if False:\n        raise Refusal(\"CREDENTIALS.NO_ECHO\")"),
    ("S1-FORM-SLOT", "a2_s1.py", "    if form_rules is None:\n        raise Refusal(\"CREDENTIALS.FORM\", \"form rule: not supplied\")", "    if form_rules is None:\n        return"),
    ("S1-FORM-RULE", "a2_s1.py", "        if not v or rule(v) is not True:", "        if not v:"),
    ("S1-FORM-EMPTY", "a2_s1.py", "        if not v or rule(v) is not True:", "        if rule(v) is not True:"),
    ("S1-LIVE-SLOT", "a2_s1.py", "    if live_check is None:\n        raise Refusal(\"CREDENTIALS.KEY_NOT_LIVE\")", "    if live_check is None:\n        return \"pass\""),
    ("S1-LIVE-TRUE", "a2_s1.py", "    if ok is not True:\n        raise Refusal(\"CREDENTIALS.KEY_NOT_LIVE\")", "    if not ok:\n        raise Refusal(\"CREDENTIALS.KEY_NOT_LIVE\")"),
    ("S1-STUB-ONLY-LEAK", "a2_s1.py", '    if inv.loop == "L2-leak":\n        return "stub"', '    if inv.loop in ("L2-leak", "L2"):\n        return "stub"'),
    ("S1-L5-RAW", "a2_s1.py", "            if needle in raw or any(needle in s for s in strings):", "            if any(needle in s for s in strings):"),
    ("S1-L5-PARSED", "a2_s1.py", "            if needle in raw or any(needle in s for s in strings):", "            if needle in raw:"),
    ("S1-L5-CALL", "a2_s1.py", "        check_l5(values, c)\n", ""),
    ("S1-DRYRUN-NOPROMPT", "a2_s1.py", '    if c.inv.command == "dry-run":\n', '    if False:\n'),
    # package 2b: S10 and eligibility
    ("S10-SUMMARY-LAST", "a2_s10.py", "    guard.check(data)\n    a2_record._write_atomic(c.run_fd, a2_record.SUMMARY, data)\n    run._append_sums(a2_record.SUMMARY, data)", "    guard.check(data)\n    a2_record._write_atomic(c.run_fd, a2_record.SUMMARY, data)"),
    ("S10-SUMS-PRINT", "a2_s10.py", '    guard.emit(site.out, "SUMS sha256 " + sums_sha)', '    pass'),
    ("S10-NOT-ELIGIBLE-LINE", "a2_s10.py", '    lines.append("ELIGIBLE" if eligible else "NOT ELIGIBLE: " + reason)', '    lines.append("ELIGIBLE")'),
    ("S10-REPLY-DEPTH", "a2_s10.py", '    if c.inv.loop in ("L2", "L3"):\n        lines.append', '    if False:\n        lines.append'),
    # package 2b: the runner
    ("RUN-S10-ALWAYS", "a2_main.py", "    if rec is not None and not rec.final:\n        try:\n            try:\n                facts = a2_s0.custody(c, site)", "    if False:\n        try:\n            try:\n                facts = a2_s0.custody(c, site)"),
    ("RUN-CUSTODY-S1", "a2_main.py", "        cause = _custody_cause(facts, guard.wrote_target)\n        if cause:", "        cause = None\n        if cause:"),
    ("RUN-HELD-CLEAR", "a2_main.py", "        if held is not None:\n            held.clear()", "        if held is not None:\n            pass"),
    # package 2b r2.1
    ("S1-HOLD-EACH", "a2_s1.py", "                raise Refusal(\"CREDENTIALS.FORM\", \"form rule: empty\")\n            guard.hold(value)\n", "                raise Refusal(\"CREDENTIALS.FORM\", \"form rule: empty\")\n"),
    ("S1-CLEAR", "a2_s1.py", "        for v in self.values.values():\n            for i in range(len(v)):\n                v[i] = 0\n        self.values = {}", "        self.values = {}"),
    ("S1-RESTORE", "a2_s1.py", "        termios.tcsetattr(fd, termios.TCSAFLUSH, saved)\n        return termios.tcgetattr", "        return termios.tcgetattr"),
    ("S1-RESTORE-CHECK", "a2_s1.py", "        if not restored and not failed:\n            raise", "        if False:\n            raise"),
    ("S1-ECHO-OFF", "a2_s1.py", "        quiet[3] = quiet[3] & ~ECHO_BITS", "        quiet[3] = quiet[3]"),
    ("S1-ECHO-VERIFY", "a2_s1.py", "        if now[3] & ECHO_BITS:\n            raise", "        if False:\n            raise"),
    ("S1-ECHONL-ONLY", "a2_s1.py", "ECHO_BITS = termios.ECHO | termios.ECHONL", "ECHO_BITS = termios.ECHO"),
    ("S1-VALUE-MAX", "a2_s1.py", "            if len(buf) > limit:\n", "            if False:\n"),
    ("S1-READ-ZERO", "a2_s1.py", "    except BaseException:\n        _zero(buf)\n        raise", "    except BaseException:\n        raise"),
    ("S1-PROMPT-ZERO", "a2_s1.py", "    except BaseException:\n        _zero_all(values)\n        raise\n    finally:\n        os.close(fd)", "    except BaseException:\n        raise\n    finally:\n        os.close(fd)"),
    ("S1-EOF", "a2_s1.py", "            if not b:\n                raise Refusal(\"CREDENTIALS.NO_ECHO\")", "            if not b:\n                break"),
    ("S1-EMPTY", "a2_s1.py", "            if not value:\n                raise Refusal(\"CREDENTIALS.FORM\", \"form rule: empty\")", "            if False:\n                raise Refusal(\"CREDENTIALS.FORM\", \"form rule: empty\")"),
    ("S1-SIGNALS", "a2_s1.py", "            for sig in STOP_SIGNALS:\n                self.saved[sig] = signal.signal(sig, self._handler)", "            for sig in ():\n                self.saved[sig] = signal.signal(sig, self._handler)"),
    ("S1-SIGNALS-RESTORE", "a2_s1.py", "        for sig, old in self.saved.items():\n            signal.signal(sig, old)", "        for sig, old in self.saved.items():\n            pass"),
    ("S1-TSTP", "a2_s1.py", "signal.signal(signal.SIGTSTP, signal.SIG_IGN)", "signal.getsignal(signal.SIGTSTP)"),
    ("S1-OTHER-CLEAR", "a2_s1.py", "        if held is not None:\n            held.clear()\n        guard.release_all()\n        raise", "        raise"),
    ("S1-LEAK-LENGTH", "a2_s1.py", '        facts.append(("FORM", "pass"))', '        facts.append(("FORM", "pass"))\n        facts.append(("KEY_LEN", str(len(values[API_KEY]))))'),
    ("S1-LEAK-PREFIX", "a2_s1.py", '        facts.append(("FORM", "pass"))', '        facts.append(("FORM", "pass"))\n        facts.append(("KEY_HINT", bytes(values[API_KEY][:8]).decode("ascii", "replace")))'),
    ("S1-LEAK-SHA", "a2_s1.py", '        facts.append(("FORM", "pass"))', '        facts.append(("FORM", "pass"))\n        facts.append(("KEY_SHA", __import__("hashlib").sha256(bytes(values[API_KEY])).hexdigest()))'),
    ("MAIN-ACTIVE-STAGE", "a2_main.py", '        active = "S1"\n', ''),
    ("MAIN-UNCLASSIFIED-RECEIPT", "a2_main.py", "                rec.write_receipt(active, None, rec.started, \"FAIL\", facts, rc=3, cause=cause)", "                pass"),
    ("MAIN-UNCLASSIFIED-RC", "a2_main.py", "        stop = Refusal(cause, rc=3)", "        stop = Refusal(cause)"),
    ("MAIN-BASEEXCEPTION", "a2_main.py", "    except BaseException:\n        stops.holding = True\n        # A failure the running stage", "    except Exception:\n        stops.holding = True\n        # A failure the running stage"),
    ("MAIN-RELEASE", "a2_main.py", "            held.clear()\n        guard.release_all()", "            held.clear()"),
    ("EL-NEVER-RAISE", "a2_s10.py", "    except Exception:\n        return False, \"the run record is malformed\"", "    except ZeroDivisionError:\n        return False, \"the run record is malformed\""),
    ("EL-SUMS-VERIFY", "a2_s10.py", '    except Refusal:\n        return False, "SUMS does not verify"', '    except Refusal:\n        pass'),
    ("EL-MANIFEST-SCHEMA", "a2_s10.py", "    bad = check_manifest(man)\n    if bad:\n        return False, bad", "    bad = None\n    if bad:\n        return False, bad"),
    ("EL-MAN-KEYS", "a2_s10.py", "    if not isinstance(man, dict) or set(man) - set(MANIFEST_KEYS):", "    if not isinstance(man, dict):"),
    ("EL-MAN-STATE", "a2_s10.py", '    if man.get("state") not in ("active", "final"):', '    if False:'),
    ("EL-MAN-ENDED", "a2_s10.py", '        if not a2_private.matches("utc", man.get("ended")):\n            return', '        if False:\n            return'),
    ("EL-MAN-DUP", "a2_s10.py", "        if (st[\"stage\"], host) in seen:\n            return", "        if False:\n            return"),
    ("EL-MAN-RECEIPT-PATH", "a2_s10.py", "        if st[\"receipt\"] != \"receipts/\" + a2_record.receipt_name(st[\"stage\"], None if host == \"-\" else host):", "        if False:"),
    ("EL-HOSTS-SHA", "a2_s10.py", '    if hashlib.sha256(hosts_raw).hexdigest() != man["hosts_sha256"]:\n        return', '    if False:\n        return'),
    ("EL-HOSTS-SCHEMA", "a2_s10.py", "        a2_private.check_hosts(hosts)\n", "        pass\n"),
    ("EL-TAIL", "a2_s10.py", "    if paths[-len(tail):] != tail:\n        return", "    if False:\n        return"),
    ("EL-RECEIPT-LINES", "a2_s10.py", '    if paths[:-len(tail)] != [st["receipt"] for st in stages]:\n        return', '    if False:\n        return'),
    ("EL-DIGEST", "a2_s10.py", '    if any(digests[st["receipt"]] != st["sha256"] for st in stages):\n        return', '    if False:\n        return'),
    ("EL-COMMAND", "a2_s10.py", '    if man["command"] != "install" or man["loop"] not in RUN_ELIGIBLE_LOOPS:', '    if man["loop"] not in RUN_ELIGIBLE_LOOPS:'),
    ("EL-LOOP", "a2_s10.py", '    if man["command"] != "install" or man["loop"] not in RUN_ELIGIBLE_LOOPS:', '    if man["command"] != "install":'),
    ("EL-SOURCE-RUN", "a2_s10.py", '    if man["source_run"] is not None:\n        return', '    if False:\n        return'),
    ("EL-STATE-FINAL", "a2_s10.py", '    if man["state"] != "final":\n        return', '    if False:\n        return'),
    ("EL-UNEXPECTED", "a2_s10.py", "    if set(have) - set(expected):\n        return", "    if False:\n        return"),
    ("EL-MISSING", "a2_s10.py", "        if st is None:\n            return", "        if st is None:\n            continue"),
    ("EL-RC", "a2_s10.py", '        if st["rc"] != 0:\n            return', '        if False:\n            return'),
    ("EL-CHECK-RECEIPT", "a2_s10.py", "            except ValueError:\n                return False, \"a receipt breaks a 3.3 rule: \" + st[\"stage\"]", "            except ValueError:\n                facts, rc = a2_record.parse_receipt(data)[0], st[\"rc\"]"),
    ("EL-RC-ROW", "a2_s10.py", '            if rc != st["rc"]:\n                return', '            if False:\n                return'),
    ("EL-RUN-BIND", "a2_s10.py", '            if (facts["RUN_ID"] != man["run_id"] or facts["COMMAND"] != man["command"]\n                    or facts["LOOP"] != loop_token):', '            if (False):'),
    ("EL-RESULT", "a2_s10.py", '            if facts["RESULT"] not in ("CHANGED", "ALREADY", "PASS"):', '            if facts["RESULT"] not in ("CHANGED", "ALREADY", "PASS", "PLANNED"):'),
    ("EL-UNOBSERVED", "a2_s10.py", '            if any(v == "UNOBSERVED" for v in facts.values()):', '            if False:'),
    ("EL-INSTALLER-SHA", "a2_s10.py", '            if facts["INSTALLER_SHA"] != man["installer_sha256"]:\n                return', '            if False:\n                return'),
    ("EL-LOCK-SHA", "a2_s10.py", '            if facts["LOCK_SHA"] != man["lock_sha256"]:\n                return', '            if False:\n                return'),
    ("EL-HOSTS-SHA-RCPT", "a2_s10.py", '            if facts["HOSTS_SHA"] != man["hosts_sha256"]:\n                return', '            if False:\n                return'),
    ("EL-S9", "a2_s10.py", '            if st["stage"] == "S9" and facts.get("PROCESSING_PROOF") != "pass":', '            if False:'),
    ("EL-PERVM-S6B", "a2_s10.py", 'PER_VM = ("S2", "S4", "S5", "S6", "S6b", "S7", "S8")', 'PER_VM = ("S2", "S4", "S5", "S6", "S7", "S8")'),
    ("S10-PREFIX-VERIFY", "a2_s10.py", "    run.write_manifest(final=True)\n    a2_record.verify_sums(c.run_fd)\n", "    run.write_manifest(final=True)\n"),
    ("S10-OPSTEPS-THREE", "a2_s10.py", "or len(operator_steps) != OPERATOR_STEPS", "or len(operator_steps) < 1"),
    ("S10-RESULT-RC", "a2_s10.py", '    lines = ["RESULT " + ("FAIL" if failed else "PASS")]', '    lines = ["RESULT " + ("FAIL" if failed or not eligible else "PASS")]'),
    ("S10-RUN-VMS", "a2_s10.py", "        if a[\"vm\"] not in names:\n            continue", "        if False:\n            continue"),
    ("S10-INFERRED-SSH", "a2_s10.py", '"vm %s access: ssh %s INFERRED"', '"vm %s access: ssh %s"'),
    ("S10-NONCE", "a2_s10.py", "    nonce = secrets.token_hex(8)", "    nonce = \"0123456789abcdef\""),
    ("S10-CUSTODY-FAIL", "a2_s10.py", "    if custody_cause:\n        run.write_receipt(\"S10\"", "    if False:\n        run.write_receipt(\"S10\""),
    # package 2b r2.2
    ("MAIN-S1-BEFORE-CUSTODY", "a2_main.py", '        active = "S1"\n        facts = a2_s0.custody(c, site)\n', '        facts = a2_s0.custody(c, site)\n        active = "S1"\n'),
    ("MAIN-S10-CUSTODY-GUARD", "a2_main.py", "            except (Exception, KeyboardInterrupt):\n                # 3.4: a read-back", "            except KeyboardInterrupt:\n                # 3.4: a read-back"),
    ("MAIN-S10-UNOBSERVED", "a2_main.py", 'facts = dict.fromkeys(CUSTODY_KEYS, "UNOBSERVED")', 'facts = dict.fromkeys(CUSTODY_KEYS, "-")'),
    ("MAIN-S10-RC", "a2_main.py", "cause, rc = UNREAD_AT_S10, 3", "cause, rc = UNREAD_AT_S10, 2"),
    ("MAIN-S10-STOP-RC", "a2_main.py", "            if rc == 3 and (stop is None or stop.rc < 3):", "            if False:"),
    ("S10-CUSTODY-RC", "a2_s10.py", "rc=custody_rc, cause=custody_cause", "rc=2, cause=custody_cause"),
    ("S1-QUIT", "a2_s1.py", "signal.SIGHUP, signal.SIGQUIT)", "signal.SIGHUP)"),
    ("S1-MASK-BLOCK", "a2_s1.py", "            _mask(signal.SIG_BLOCK, MASKED)\n", ""),
    ("S1-MASK-TSTP", "a2_s1.py", "MASKED = STOP_SIGNALS + (signal.SIGTSTP,)", "MASKED = STOP_SIGNALS"),
    ("S1-MASK-PUT-BACK", "a2_s1.py", "                _mask(signal.SIG_SETMASK, old)", "                pass"),
    ("S1-MASK-CALLER", "a2_s1.py", "            if old is None:\n                old = _mask(signal.SIG_BLOCK, ())\n            try:\n                _mask(signal.SIG_BLOCK, MASKED)\n", "            old = _mask(signal.SIG_BLOCK, MASKED)\n            try:\n"),
    ("S1-MASK-RERUN", "a2_s1.py", "        except _Interrupted as e:\n            pending = e\n", "        except _Interrupted as e:\n            pending = e\n            break\n"),
    ("S1-MASK-PENDING", "a2_s1.py", "    if pending is not None:\n        raise pending", "    if False:\n        raise pending"),
    ("S1-EXIT-MASK", "a2_s1.py", "        _uninterrupted(back)", "        back()"),
    ("S1-TERM-MASK", "a2_s1.py", "        restored = _uninterrupted(lambda: _restore_terminal(fd, saved))", "        restored = _restore_terminal(fd, saved)"),
    # package 2b r2.3
    ("MAIN-S10-KBI", "a2_main.py", "            except (Exception, KeyboardInterrupt):\n                # 3.4: a read-back", "            except Exception:\n                # 3.4: a read-back"),
    # package 2c
    ("RUN-STOPS-INSTALL", "a2_main.py", "            for sig in a2_s1.STOP_SIGNALS:\n                self.saved[sig] = signal.signal(sig, self._handler)", "            for sig in ():\n                self.saved[sig] = signal.signal(sig, self._handler)"),
    ("RUN-STOPS-RESTORE", "a2_main.py", "            for sig, handler in self.saved.items():\n                signal.signal(sig, handler)\n", "            for sig, handler in self.saved.items():\n                pass\n"),
    ("RUN-STOPS-HOLD", "a2_main.py", "        if self.holding:\n            self.pending = signum\n            return", "        if False:\n            self.pending = signum\n            return"),
    ("RUN-STOPS-FIRST-HOLD", "a2_main.py", "        self.holding = True\n        raise RunStopped()", "        raise RunStopped()"),
    ("RUN-STOPS-BASE-HOLD", "a2_main.py", "    except BaseException:\n        stops.holding = True\n", "    except BaseException:\n"),
    ("RUN-STOPS-FINALLY-HOLD", "a2_main.py", "    finally:\n        stops.holding = True\n", "    finally:\n"),
    ("RUN-STOPPED-IS-INTERRUPT", "a2_main.py", "class RunStopped(KeyboardInterrupt):", "class RunStopped(Exception):"),
    ("MAIN-S1-CUSTODY-ARG", "a2_main.py", "        held = a2_s1.run_s1(c, site, rec, guard, s1_custody)", "        held = a2_s1.run_s1(c, site, rec, guard)"),
    ("MAIN-S1-UNOBSERVED", "a2_main.py", "                facts = s1_custody if s1_custody is not None else UNOBSERVED_CUSTODY", "                facts = s1_custody if s1_custody is not None else []"),
    ("MAIN-S1-READ-FACTS", "a2_main.py", "                facts = s1_custody if s1_custody is not None else UNOBSERVED_CUSTODY", "                facts = UNOBSERVED_CUSTODY"),
    ("S1-CUSTODY-FACTS", "a2_s1.py", "    facts = list(custody)", "    facts = []"),
    ("RPP-UNSET", "a2_admit.py", "    if not private_dir:\n        raise Refusal", "    if False:\n        raise Refusal"),
    # rundir and loader
    ("RUNDIR-EXCL", "a2_rundir.py", "    try:\n        os.mkdir(run_id, 0o700, dir_fd=runs_fd)\n    except OSError:\n        raise Refusal(\"RUNNER.RUN_DIR\")",
     "    try:\n        os.mkdir(run_id, 0o700, dir_fd=runs_fd)\n    except OSError:\n        pass"),
    ("RUNDIR-NOFOLLOW", "a2_rundir.py", "DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC",
     "DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC"),
    ("RUNDIR-MODE", "a2_rundir.py", "or stat.S_IMODE(st.st_mode) != 0o700:", ":"),
    ("RUNDIR-OWNER", "a2_rundir.py", "if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or", "if not stat.S_ISDIR(st.st_mode) or"),
    ("RUNDIR-WORK-CHECK", "a2_rundir.py", "        _check_dir_fd(work_fd, uid)\n", ""),
    ("RUNDIR-RECEIPTS-AT", "a2_rundir.py", "os.mkdir(RECEIPTS_NAME, 0o700, dir_fd=run_fd)",
     "os.mkdir(os.path.join(os.readlink(\"/proc/self/fd/%d\" % runs_fd), run_id, RECEIPTS_NAME), 0o700)"),
    ("DENY-NAMES", "a2_locks.py", "isinstance(n, str) and n in names for n in hard_deny)", "isinstance(n, str) for n in hard_deny)"),
    ("MANIFEST-LINE", "alpha2_install.py", '_LINE = re.compile(rb"([0-9a-f]{64})  ([A-Za-z0-9_]{1,64}\\.py)")',
     '_LINE = re.compile(rb"([0-9A-Fa-f]{64})  (.{1,64}\\.py)")'),
    ("SITE-IDENT", "a2_site.py", "        self.host_identity = lambda: None", "        self.host_identity = _machine_id"),
    ("LOADER-HASH", "alpha2_install.py", "if hashlib.sha256(data).hexdigest() != self.listed[fname]:", "if False:"),
    ("LOADER-UNLISTED", "alpha2_install.py", "            return None\n        _refuse_interpreter()", "            return None\n        return None"),
    ("RUN-STOPS-EXIT-BLOCK", "a2_main.py", "            signal.pthread_sigmask(signal.SIG_BLOCK, a2_s1.MASKED)\n            for sig, handler in", "            for sig, handler in"),
    ("REC-WHOLE-BLOCK", "a2_record.py", "        signal.pthread_sigmask(signal.SIG_BLOCK, WRITE_MASK)\n", ""),
    ("REC-RECEIPT-WHOLE", "a2_record.py", "        return _whole(lambda: self._write_receipt(stage_id, host, started, result, facts, rc, cause, now))", "        return self._write_receipt(stage_id, host, started, result, facts, rc, cause, now)"),
    ("REC-MANIFEST-WHOLE", "a2_record.py", "        return _whole(lambda: self._write_manifest(final, now))", "        return self._write_manifest(final, now)"),
    ("S1-ZERO-ALL-MASK", "a2_s1.py", "    _uninterrupted(lambda: _clear(values))\n", "    _clear(values)\n"),
    ("RUN-STOPS-SETMASK-FINALLY", "a2_main.py", "        finally:\n            signal.pthread_sigmask(signal.SIG_SETMASK, old)\n        return False", "        finally:\n            pass\n        signal.pthread_sigmask(signal.SIG_SETMASK, old)\n        return False"),
    ("RUN-STOPS-BLOCK-IN-TRY", "a2_main.py", "        try:\n            signal.pthread_sigmask(signal.SIG_BLOCK, a2_s1.MASKED)\n", "        signal.pthread_sigmask(signal.SIG_BLOCK, a2_s1.MASKED)\n        try:\n"),
    ("RUN-STOPS-BLOCK-LATE", "a2_main.py", "            signal.pthread_sigmask(signal.SIG_BLOCK, a2_s1.MASKED)\n            for sig, handler in self.saved.items():\n                signal.signal(sig, handler)\n", "            for sig, handler in self.saved.items():\n                signal.signal(sig, handler)\n            signal.pthread_sigmask(signal.SIG_BLOCK, a2_s1.MASKED)\n"),
    ("RUN-STOPS-CLOSED", "a2_main.py", "    stops.closed = True\n    raise stop", "    raise stop"),
    ("MAIN-SIGINT-EXIT", "a2_main.py", "                if stops.closed:\n                    return SIGINT_EXIT", "                if False:\n                    return SIGINT_EXIT"),
    ("MAIN-RUN-STOPS", "a2_main.py", "                return run(argv[2], argv[3:], site, stops)", "                return run(argv[2], argv[3:], site)"),
    ("S1-SIGNALS-CLEAR", "a2_s1.py", "            if exc_type is not None or self.pending is not None:\n                _clear(self.values)\n", "            pass\n"),
    ("S1-UNINT-BLOCK-IN-TRY", "a2_s1.py", "            try:\n                _mask(signal.SIG_BLOCK, MASKED)\n                result = fn()", "            _mask(signal.SIG_BLOCK, MASKED)\n            try:\n                result = fn()"),
    ("S1-READ-INTO-VALUES", "a2_s1.py",
     "            value = values[label] = bytearray()\n            sigs.begin_read()\n            try:\n                _read_line(fd, VALUE_MAX, value)\n            finally:\n                sigs.reading = False\n",
     "            value = bytearray()\n            sigs.begin_read()\n            try:\n                _read_line(fd, VALUE_MAX, value)\n            finally:\n                sigs.reading = False\n            values[label] = value\n"),
    # option A: S1's handlers raise only during a read; elsewhere a stop is recorded
    ("S1-HOLD-OUTSIDE-READ", "a2_s1.py", "        if self.reading:\n            self.reading = False\n            raise _Interrupted()", "        if True:\n            self.reading = False\n            raise _Interrupted()"),
    ("S1-RESTORE-IDEMPOTENT", "a2_s1.py", "        for sig, old in self.saved.items():\n            signal.signal(sig, old)", "        for sig, old in self.saved.items():\n            self.saved[sig] = signal.signal(sig, old)"),
    ("S1-HAND-BACK-CLEAR-PENDING", "a2_s1.py", "            if exc_type is not None or self.pending is not None:\n", "            if exc_type is not None:\n"),
    ("S1-READ-REGION-END", "a2_s1.py", "            finally:\n                sigs.reading = False\n", "            finally:\n                pass\n"),
    ("S1-READ-PENDING", "a2_s1.py", "        self.reading = True\n        if self.pending is not None:", "        self.reading = True\n        if False:"),
    ("S1-SESSION-PENDING", "a2_s1.py", "            if sigs.pending is not None:\n                raise _Interrupted()\n            text =", "            text ="),
    ("S1-PROMPT-PENDING", "a2_s1.py", "        if sigs.pending is not None:\n            raise _Interrupted()\n    except (_Interrupted, Refusal)", "    except (_Interrupted, Refusal)"),
    ("S1-PENDING-OVER-REFUSAL", "a2_s1.py", "        if isinstance(e, _Interrupted) or sigs.pending is not None:", "        if isinstance(e, _Interrupted):"),
    ("S1-HANDLER-ONE-SHOT", "a2_s1.py", "        if self.reading:\n            self.reading = False\n", "        if self.reading:\n"),
]


#: Mutants the suite cannot kill because another mechanism enforces the
#: same rule, with the reason. They are reported, never counted as killed.
EQUIVALENT = {
    "L1-BOM": "json.loads itself refuses a leading BOM (ValueError), which is the same L1 refusal",
    "FETCH-EXCL-NAME": ("each repository is made inside this run's fetch directory, which was itself just "
                        "created exclusively and empty; the names (overlay, c-<component>) are unique "
                        "within a run, so no name can pre-exist there"),
    "GIT-NO-REPLACE": ("every tree, blob and ancestry read is made in the fresh bare repository, which "
                       "has no replace refs; in the checkout only HEAD's id, status and ls-files are read, "
                       "and replace refs change none of them. The variable states it for every repository"),
    "S0-PS-DESCENT": ("the bare repository holds exactly the closure of the one tag fetched into it, so "
                      "any overlay.commit present there is the peeled commit or one of its ancestors; one "
                      "that is not is absent, and the tree comparison refuses it"),
    "GIT-HOOKS": ("no git command the installer runs fires a hook: the checkout is only read (no ref "
                  "update, and GIT_OPTIONAL_LOCKS=0 means no index write), and each fetch repository is "
                  "created fresh by this run with no hooks of its own; core.hooksPath=/dev/null states it"),
    "GIT-NO-RENAMES": ("diff-tree is plumbing and detects no renames unless -M is given; it reads no "
                       "diff.renames setting. --no-renames states the rule explicitly"),
    "S0-PS-MODE": ("rule 3 already requires the one changed entry, alpha2.lock, to have new mode 100644, "
                   "and that entry always exists: overlay.commit cannot contain a lock that names "
                   "overlay.commit, so the lock always differs"),
    "S0-PS-PATH": ("the lock always differs between overlay.commit and HEAD (a commit cannot contain a "
                   "lock that names it), so when the comparison has exactly one entry that entry is "
                   "alpha2.lock"),
    "ROOT-REALPATH": ("the abspath pattern admits no '.', '..' or empty segment, so a lock root that is not "
                      "its realpath has a symlink in it; lstat refuses a symlinked last component (not a "
                      "directory) and the parent walk refuses a symlinked parent (lstat mode 0777). On "
                      "Linux only: a macOS symlink can have mode 0755, and there this is not equivalent"),
}


def _one(mutant):
    """Run one mutant in its own copy; returns (label, verdict) or
    (label, None) for a bad mutant."""
    label, fname, old, new = mutant
    tmp = tempfile.mkdtemp(prefix="a2mut-")
    try:
        dst = os.path.join(tmp, "install")
        shutil.copytree(INSTALL, dst, ignore=shutil.ignore_patterns("__pycache__"))
        # The suite reads the contract at <repo>/alpha2/STAGE-CONTRACT.md.
        os.mkdir(os.path.join(tmp, "alpha2"))
        shutil.copy(os.path.join(os.path.dirname(INSTALL), "alpha2", "STAGE-CONTRACT.md"),
                    os.path.join(tmp, "alpha2"))
        p = os.path.join(dst, fname)
        with open(p, encoding="utf-8") as f:
            src = f.read()
        if src.count(old) != 1:
            return label, None
        with open(p, "w", encoding="utf-8") as f:
            f.write(src.replace(old, new))
        subprocess.run([sys.executable, "-I", "-B", os.path.join(dst, "tests", "make_manifest.py")],
                       check=True, stdin=subprocess.DEVNULL)
        try:
            r = subprocess.run([sys.executable, "-I", "-B", "-m", "unittest", "discover", "-s",
                                os.path.join(dst, "tests"), "-t", os.path.join(dst, "tests")],
                               capture_output=True, text=True, timeout=600, cwd=dst,
                               stdin=subprocess.DEVNULL)
            verdict = "KILLED" if r.returncode != 0 else "SURVIVED"
        except subprocess.TimeoutExpired:
            # The suite did not pass: a hang under a mutant is a kill, and is
            # reported as one so it can be looked at.
            verdict = "KILLED (timeout)"
        if verdict == "SURVIVED" and label in EQUIVALENT:
            verdict = "EQUIVALENT (" + EQUIVALENT[label] + ")"
        return label, verdict
    finally:
        shutil.rmtree(tmp, True)


def run(labels, jobs=1):
    """Each mutant runs in its own copy, `jobs` at a time; the report is in
    the order of M whatever order they finish in."""
    from concurrent.futures import ThreadPoolExecutor
    chosen = [m for m in M if not labels or m[0] in labels]
    if labels and len(chosen) != len(labels):
        print("UNKNOWN LABEL in", labels)
        return 2
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(_one, chosen))
    bad = sum(1 for _, v in results if v is None)
    survived = [lb for lb, v in results if v == "SURVIVED"]
    equivalent = [lb for lb, v in results if v and v.startswith("EQUIVALENT")]
    for lb, v in results:
        print("%-20s %s" % (lb, "BAD-MUTANT: old string did not match exactly once" if v is None else v))
    print("mutants=%d killed=%d survived=%d equivalent=%d bad=%d"
          % (len(chosen), len(chosen) - len(survived) - len(equivalent) - bad,
             len(survived), len(equivalent), bad))
    if survived:
        print("SURVIVORS:", " ".join(survived))
    return 0 if not survived and not bad else 1


if __name__ == "__main__":
    args = sys.argv[1:]
    jobs = 1
    if args[:1] == ["--jobs"]:
        jobs = int(args[1])
        args = args[2:]
    sys.exit(run(args, jobs))
