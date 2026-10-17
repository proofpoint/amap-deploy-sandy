"""Mutation checks for the local router's upgrade base (router_fingerprint.py):
each mutant breaks one guard, and that guard's row in test_router_fingerprint
must then FAIL. Not a test module (pytest does not collect it). Run from the
repository root, with the sibling checkouts reachable:

    python3 -B tests/router_fingerprint_mutants.py [LABEL ...]

It runs on hygiene_mutants' harness: the unmutated copy must pass first, a
kill is a test FAILURE (an error is reported ERRORED, not killed), and a
mutant whose text is not found exactly once is BAD; any of those exits 1.

A mutant inside PROGRAM also changes PROGRAM's sha256, which a test pins, so
the pin alone kills it; its own witness row is named beside it and is checked
separately (`--witness`), with the pin row excluded.

Equivalent in production, and so not listed (the design's residue): removing
GIT_GRAFT_FILE=/dev/null or core.commitGraph=false, which a reader of
re-hashed object bytes never consults. "Parent read from rev-list" is listed,
with its reduced-scope SYNTHETIC witness, and is not a production kill.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hygiene_mutants as hm  # noqa: E402

RF = "router_fingerprint.py"

#: (label, file, text, replacement)
MUTANTS = [
    ("range dropped", RF,
     "    measured = set(fp[:fp.index(mfrom) + 1])",
     "    measured = set(fp)"),
    ("exact map loosened to subset", RF,
     "    return py_map(router) == py\n",
     "    return set(py.items()) <= set(py_map(router).items())\n"),
    ("superset direction", RF,
     "    return py_map(router) == py\n",
     "    return set(py_map(router).items()) <= set(py.items())\n"),
    ("blob compared without name", RF,
     "    return py_map(router) == py\n",
     "    return sorted(py_map(router).values()) == sorted(py.values())\n"),
    ("mixed class resolved favourably", RF,
     "    if not set(m) <= measured:",
     "    if not set(m) & measured:"),
    ("router/tests in extraction", RF,
     "            router = _parse_tree(obj(top[\"router\"][1], \"tree\"))\n",
     "            router = _parse_tree(obj(top[\"router\"][1], \"tree\"))\n"
     "            if router.get(\"tests\", [\"\"])[0] == \"dir\":\n"
     "                router.update({\"tests/\" + k: v for k, v in "
     "_parse_tree(obj(router[\"tests\"][1], \"tree\")).items()})\n"),
    ("entrypoint compare dropped", RF,
     "            and result[\"entrypoint\"] == tree[\"entrypoint\"])",
     ")"),
    ("UNKNOWN's exit made 0", RF,
     "EXIT = {MEASURED: 0, UNMEASURED: 1, UNKNOWN: 2,",
     "EXIT = {MEASURED: 0, UNMEASURED: 1, UNKNOWN: 0,"),
    ("UNMEASURED's exit made 0", RF,
     "EXIT = {MEASURED: 0, UNMEASURED: 1, UNKNOWN: 2,",
     "EXIT = {MEASURED: 0, UNMEASURED: 0, UNKNOWN: 2,"),
    ("pin equality dropped", RF,
     "    if b[\"target\"] != pin:",
     "    if False:"),
    ("CLI passes the bases target as the pin", RF,
     "    bad = precheck(capture, bases, pin)\n",
     "    pin = json.loads(bases)[\"target\"]\n    bad = precheck(capture, bases, pin)\n"),
    ("bases dirty check dropped", RF,
     "    if dirty:\n        return _show(_unknown(\"bases_dirty\", dirty), out)",
     "    if False:\n        return _show(_unknown(\"bases_dirty\", dirty), out)"),
    ("errors ignored", RF,
     "    if r[\"errors\"]:\n        return _unknown(\"errors\"",
     "    if False:\n        return _unknown(\"errors\""),
    ("schema check dropped", RF,
     "        _structure(doc)\n",
     "        pass\n"),
    ("program sha check dropped", RF,
     "    if doc[\"program_sha256\"] != PROGRAM_SHA256:",
     "    if False:"),
    ("source ignored", RF,
     "    return source == \"running\"",
     "    return True"),
    ("shallow check dropped", RF,
     "    if history[\"shallow\"]:\n        return _unknown(\"shallow\", \"the hop checkout is shallow; its",
     "    if False:\n        return _unknown(\"shallow\", \"the hop checkout is shallow; its"),
    ("early shallow marker dropped", RF,
     "    if shallow or types[target] != \"commit\":",
     "    if types[target] != \"commit\":"),
    ("object-format check dropped", RF,
     "    if run([\"rev-parse\", \"--show-object-format\"]).stdout != b\"sha1\\n\":",
     "    if False:"),
    ("commit grammar loosened to the first parent line anywhere", RF,
     "        if _STRUCTURAL.match(line):\n            raise",
     "        if False:\n            raise"),
    ("a bare or tab-separated parent or tree header accepted", RF,
     "_STRUCTURAL = re.compile(rb\"(?:tree|parent)(?:[ \\t]|$)\")",
     "_STRUCTURAL = re.compile(rb\"(?:tree|parent) \")"),
    ("bases bytes not compared with the committed bytes", RF,
     "    if data != committed:",
     "    if False:"),
    ("bases staged change not refused", RF,
     "    if len(staged) != 1 or staged[0][1] != path.name or staged[0][0] != [mode, blob, \"0\"]:",
     "    if False:"),
    ("bases index compared by blob alone", RF,
     "    if len(staged) != 1 or staged[0][1] != path.name or staged[0][0] != [mode, blob, \"0\"]:",
     "    if not staged or staged[0][0][1] != blob:"),
    ("bases entry read from the index instead of HEAD", RF,
     "        head = _records(hg.git(repo, \"ls-tree\", \"-z\", \"HEAD\", \"--\", path.name))",
     "        head = [([m, \"blob\", o], n) for (m, o, _), n in "
     "_records(hg.git(repo, \"ls-files\", \"--stage\", \"-z\", \"--\", path.name))]"),
    ("ls output split at the last tab", RF,
     "            meta, _, name = rec.partition(\"\\t\")",
     "            meta, _, name = rec.rpartition(\"\\t\")"),
    ("bases committed mode not checked", RF,
     "    if mode != BASES_MODE:",
     "    if False:"),
    ("time grammar accepts any script's digits (_AT's year)", RF,
     "_AT = re.compile(r\"([0-9]{4})-",
     "_AT = re.compile(r\"(\\d{4})-"),
    ("time grammar accepts any script's digits (_AT's fraction)", RF,
     ":([0-9]{2})\\.([0-9]{6})Z\")",
     ":([0-9]{2})\\.(\\d{6})Z\")"),
    ("time grammar accepts any script's digits (_WHOLE's month)", RF,
     "_WHOLE = re.compile(r\"([0-9]{4})-([0-9]{2})-",
     "_WHOLE = re.compile(r\"([0-9]{4})-(\\d{2})-"),
    ("time grammar accepts any script's digits (_DOCKER_TS's fraction)", RF,
     "(?:\\.([0-9]{1,9}))?Z\")",
     "(?:\\.(\\d{1,9}))?Z\")"),
    ("promisor lookup exit 3 read as present", RF,
     "ok=(0, 1)).returncode == 0",
     "ok=(0, 1, 3)).returncode == 0"),
    ("verify_image shallow check dropped", RF,
     "    if history[\"shallow\"]:\n        return _unknown(\"shallow\", \"the hop checkout is shallow\")\n",
     "    if False:\n        return _unknown(\"shallow\", \"the hop checkout is shallow\")\n"),
    ("verify_image promisor check dropped", RF,
     "    if history[\"promisor\"]:\n        return _unknown(\"promisor\", \"the hop checkout has a promisor remote "
     "or partial clone configured\")\n    if set(history[\"types\"]) != {commit}:",
     "    if False:\n        return _unknown(\"promisor\", \"the hop checkout has a promisor remote "
     "or partial clone configured\")\n    if set(history[\"types\"]) != {commit}:"),
    ("the two-second status edge moved to one", RF,
     "STALE_AFTER_S = 2",
     "STALE_AFTER_S = 1"),
    ("the microsecond pid1_age lower bound widened", RF,
     "PID1_AGE_US = (Fraction(-5, 100) * NS",
     "PID1_AGE_US = (Fraction(-7, 100) * NS"),
    ("duplicate environ names ignored (PROGRAM)", RF,
     "            if name in env:\n                err(",
     "            if False:\n                err("),
    ("run's catch-all dropped", RF,
     "    except Exception as e:     # noqa: BLE001\n        out(f\"router-fingerprint: UNKNOWN internal",
     "    except ZeroDivisionError as e:     # noqa: BLE001\n        out(f\"router-fingerprint: UNKNOWN internal"),
    ("the final inspect by the mutable name", RF,
     "docker + [\"inspect\", str(cid)]",
     "docker + [\"inspect\", container]"),
    ("duplicate tree names allowed", RF,
     "        if name in out:\n            raise",
     "        if False:\n            raise"),
    ("raw mode compared as 040000", RF,
     "b\"120000\": \"link\", b\"40000\": \"dir\"}",
     "b\"120000\": \"link\", b\"040000\": \"dir\"}"),
    ("replace switch dropped (GIT_NO_REPLACE_OBJECTS)", "hygiene_gate.py",
     "               GIT_NO_REPLACE_OBJECTS=\"1\", GIT_GRAFT_FILE=os.devnull)",
     "               GIT_GRAFT_FILE=os.devnull)"),
    ("promisor check dropped", RF,
     "    if history[\"promisor\"]:\n        return _unknown(\"promisor\", \"the hop checkout has a promisor remote "
     "or partial clone configured\")\n    if set(history[\"types\"]) != {target, mfrom}:",
     "    if False:\n        return _unknown(\"promisor\", \"the hop checkout has a promisor remote "
     "or partial clone configured\")\n    if set(history[\"types\"]) != {target, mfrom}:"),
    ("commit-object check dropped", RF,
     "    if history[\"types\"][target] != \"commit\" or history[\"types\"][mfrom] != \"commit\":",
     "    if False:"),
    ("side-branch check dropped", RF,
     "    if mfrom not in fp:",
     "    if False:"),
    ("boundary widened by one", RF,
     "    measured = set(fp[:fp.index(mfrom) + 1])",
     "    measured = set(fp[:fp.index(mfrom) + 2])"),
    ("HEAD walked instead of target", RF,
     "    c: Optional[str] = target\n",
     "    c: Optional[str] = run([\"rev-parse\", \"HEAD\"]).stdout.decode().strip()\n"),
    ("re-hash dropped", RF,
     "        if hashlib.sha1(b\"%s %d\\0\" % (kind.encode(\"ascii\"), len(body)) + body).hexdigest() != oid:",
     "        if False:"),
    ("parent read from rev-list (SYNTHETIC, reduced scope; equivalent in production)", RF,
     "        root, parent = _parse_commit(obj(c, \"commit\"))\n",
     "        root, _ = _parse_commit(obj(c, \"commit\"))\n"
     "        _rl = run([\"rev-list\", \"--first-parent\", \"--max-count=2\", c]).stdout.decode().split()\n"
     "        parent = _rl[1] if len(_rl) > 1 else None\n"),
    ("id preflight dropped", RF,
     "            raise HistoryReadError(f\"{v!r} is not a full lowercase 40-hex commit id\")",
     "            pass"),
    ("CLI precheck skipped", RF,
     "    bad = precheck(capture, bases, pin)\n    if bad:\n        return _show(bad, out)\n    dirty",
     "    dirty"),
    ("__pycache__ allowed", RF,
     "    if PYCACHE in r[\"entries\"]:\n        return _unknown(\"pycache\"",
     "    if False:\n        return _unknown(\"pycache\""),
    ("/app layout ignored", RF,
     "    if r[\"app\"] != APP_LAYOUT or r[\"docker\"] != DOCKER_LAYOUT:\n        return _unknown(\"layout\"",
     "    if False:\n        return _unknown(\"layout\""),
    ("allow-list widened to any name", RF,
     "    if (any(k not in PYTHON_ENV_ALLOWED for k in names)",
     "    if (False"),
    ("env subset check dropped", RF,
     "    if any(img_env.get(k) != v for k, v in p[\"python_env\"].items()):",
     "    if False:"),
    ("env value ignored", RF,
     "    if any(img_env.get(k) != v for k, v in p[\"python_env\"].items()):",
     "    if any(k not in img_env for k in p[\"python_env\"]):"),
    ("run form loosened", RF,
     "or argv[5:7] != [\"run\", \"--interval\"]",
     "or argv[6:7] != [\"--interval\"]"),
    ("config binding dropped", RF,
     " or not (argv[4] == p[\"router_config\"] == c[\"path\"])):",
     "):"),
    ("cwd dropped", RF,
     "    if p[\"cwd\"] != ROUTER_CWD:",
     "    if False:"),
    ("LD check dropped", RF,
     "    if p[\"ld_env\"]:",
     "    if False:"),
    ("umask check dropped", RF,
     "    if p[\"umask\"] != ROUTER_UMASK:",
     "    if False:"),
    ("user-site check dropped", RF,
     "    if it[\"user_site\"]:",
     "    if False:"),
    ("interpreter check dropped", RF,
     "    if (it[\"name\"], it[\"major\"], it[\"minor\"]) != INTERPRETER or it[\"pid1_exe\"] != it[\"exec_exe\"]:",
     "    if False:"),
    ("last_poll binding dropped", RF,
     "    if lp is None or lp < sa + STALE_AFTER_S or lp >",
     "    if lp is None or lp >"),
    ("selected T binding dropped", RF,
     "    if t_ns is None or t_ns < (sa - STARTED_SLACK_S) * NS:",
     "    if t_ns is None:"),
    ("process_started_ts ignored", RF,
     "    us = t[\"process_started_ts\"] is not None",
     "    us = False"),
    ("one-second allowance removed", RF,
     "STARTED_SLACK_S = 1",
     "STARTED_SLACK_S = 0"),
    ("ctime binding dropped", RF,
     "    if c[\"ctime_ns\"] > t_ns:",
     "    if False:"),
    ("config identity check dropped (the whole conjunction)", RF,
     "    if not (c[\"realpath_ok\"] and c[\"regular\"] and c[\"stable\"]):",
     "    if False:"),
    ("config stability check dropped (stable alone)", RF,
     "    if not (c[\"realpath_ok\"] and c[\"regular\"] and c[\"stable\"]):",
     "    if not (c[\"realpath_ok\"] and c[\"regular\"]):"),
    ("clock skew check dropped", RF,
     "    if abs(t[\"at\"] - k[\"now_ns\"]) > CLOCK_SKEW_NS:",
     "    if False:"),
    ("clock skew measured against at_before only", RF,
     "    if abs(t[\"at\"] - k[\"now_ns\"]) > CLOCK_SKEW_NS:",
     "    if abs(t[\"at_before\"] - k[\"now_ns\"]) > CLOCK_SKEW_NS:"),
    ("PID 1 age binding dropped", RF,
     "    if not lo <= t_ns - est <= hi:",
     "    if False:"),
    ("future-stamp check dropped", RF,
     " or lp > k[\"now_ns\"] // NS + FUTURE_SLACK_S:",
     ":"),
    ("history root check dropped", RF,
     "    if not fp or fp[0] != target:",
     "    if False:"),
    ("history keys check dropped", RF,
     "    if set(history[\"types\"]) != {target, mfrom}:",
     "    if False:"),
    ("reload flag ignored", RF,
     "        if not isinstance(v, dict) or RELOAD_FLAG in v:",
     "        if False:"),
    ("absent flag read as failure", RF,
     "    if cls[\"present\"] and cls[\"value\"] is not None:",
     "    if True:"),
    ("peer-lane check dropped", RF,
     "    if r[\"peer_lane\"][\"peer_entries\"]:",
     "    if False:"),
    ("plugin check dropped", RF,
     "        if stp[\"value\"][\"sha256\"] != plugin_sha256:",
     "        if False:"),
    ("config-branch compare dropped", RF,
     "    elif c[\"transport_plugin\"][\"present\"] and c[\"transport_plugin\"][\"sha256\"] != plugin_sha256:",
     "    elif False:"),
    ("walk onerror dropped (PROGRAM)", RF,
     "os.walk(state_dir, onerror=failed.append, followlinks=False)",
     "os.walk(state_dir, followlinks=False)"),
    ("verify-image accepts running", RF,
     "    if doc[\"source\"] != \"image\":",
     "    if False:"),
    ("read_history ignores the given git", RF,
     "            p = subprocess.run([git, \"-C\", hop_repo, *opts, *args]",
     "            p = subprocess.run([\"git\", \"-C\", hop_repo, *opts, *args]"),
    ("exception escapes", RF,
     "    except Exception as e:     # noqa: BLE001 — every failure is an answer, never a traceback",
     "    except ZeroDivisionError as e:"),
    ("FIFO opened blocking (PROGRAM)", RF,
     "        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)\n    except OSError as e:\n"
     "        err(\"cannot open the live config \"",
     "        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)\n    except OSError as e:\n"
     "        err(\"cannot open the live config \""),
    ("the first fstat's identity replaced by the second's (PROGRAM)", RF,
     "        out.update(regular=True, dev=st1.st_dev, ino=st1.st_ino, ctime_ns=st1.st_ctime_ns)",
     "        out.update(regular=True)"),
]
TESTS = {RF: "test_router_fingerprint", "hygiene_gate.py": "test_router_fingerprint"}

#: For a PROGRAM mutant, the row that witnesses its own guard (the pin row aside).
WITNESS = {
    "walk onerror dropped (PROGRAM)":
        "test_router_fingerprint.ProgramRows.test_a_mode_000_directory_lands_in_errors_never_false",
    "FIFO opened blocking (PROGRAM)": "test_router_fingerprint.ProgramRows.test_a_fifo_with_no_writer_does_not_hang",
    "the first fstat's identity replaced by the second's (PROGRAM)":
        "test_router_fingerprint.ProgramRows.test_config_positive_control",
    "duplicate environ names ignored (PROGRAM)":
        "test_router_fingerprint.ProgramRows.test_a_name_set_twice_in_the_environ_is_an_error",
}


def witness() -> int:
    """Each PROGRAM mutant against its own witness row alone: a kill there is
    the guard's, not the pin's."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH="tests:.")
    bad = 0
    for label, path, old, new in MUTANTS:
        if label not in WITNESS:
            continue
        with tempfile.TemporaryDirectory() as t:
            d = hm.copy_tree(t)
            p = os.path.join(d, path)
            with open(p) as f:
                src = f.read()
            with open(p, "w") as f:
                f.write(src.replace(old, new))
            r = subprocess.run([sys.executable, "-B", "-m", "unittest", WITNESS[label]], cwd=d, env=env,
                               capture_output=True, timeout=300)
            tail = r.stderr.decode("utf-8", "replace")[-400:]
            killed = r.returncode != 0 and "failures=" in tail
            print("killed  " if killed else ("ERRORED " if r.returncode else "SURVIVED"), label, "(its witness)",
                  flush=True)
            bad += not killed
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--witness"]:
        raise SystemExit(witness())
    hm.MUTANTS, hm.TESTS = MUTANTS, TESTS
    raise SystemExit(hm.main(sys.argv[1:]))
