"""The root-lines work's mutation harness (d3.3 §5(d)): each mutant replaces
one exact source anchor (which must occur exactly once), runs its named test
target, and must turn it red. It is not a test: run it by hand from the
repository root, as a gate does.

    python3 -B tests/root_lines_mutants.py [LABEL ...]

It runs on delegation_mutants' harness: a copy of the tree in a temporary
directory, every selected target first run UNMUTATED and required green, a
label that names no mutant refused, and exit 0 only when every selected
mutant is KILLED. A kill by errors alone is reported as such."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import delegation_mutants as dm  # noqa: E402

HS, PJ = "host_steps.py", "partition_job.py"

M = [
    # label, file, old, new, test target
    ("judge-sentinel-before", HS,
     "    j = judge(sys.executable, also=[docker], recorded=[docker],",
     "    out(JUDGE_SENTINEL)\n    j = judge(sys.executable, also=[docker], recorded=[docker],",
     "test_partition_judge"),
    ("judge-sentinel-on-problems", HS,
     '    for p in j.problems:\n        out(f"untrusted: {p}")\n    out(f"phase: {j.phase}")\n    return ROOT_TRUST_EXIT',
     '    for p in j.problems:\n        out(f"untrusted: {p}")\n    out(f"phase: {j.phase}")\n    out(JUDGE_SENTINEL)\n'
     '    return ROOT_TRUST_EXIT',
     "test_partition_judge"),
    ("judge-exit-0-on-problems", HS,
     '    out(f"phase: {j.phase}")\n    return ROOT_TRUST_EXIT\n',
     '    out(f"phase: {j.phase}")\n    return 0\n',
     "test_partition_judge"),
    ("judge-discovery-before-file-rule", HS,
     "        if problems:\n            return Judgment(sorted(set(problems)), \"tools\")\n    except Tooling as e:",
     "        pass\n    except Tooling as e:",
     "test_partition_judge"),
    ("judge-first-tool-only", HS,
     "            except Tooling as e:\n                problems.append(str(e))\n                continue\n",
     "            except Tooling as e:\n                return Judgment([str(e)], \"tools\")\n",
     "test_partition_judge"),
    ("judge-bound-moved-first", HS,
     "        tools = [argv0] + [t for t in also if t != argv0]\n        for t in tools:\n"
     "            if os.path.basename(t) == \"sudo\":",
     "        if after_refusals is not None:\n            after_refusals()\n"
     "        tools = [argv0] + [t for t in also if t != argv0]\n        for t in tools:\n"
     "            if os.path.basename(t) == \"sudo\":",
     "test_partition_judge"),
    ("judge-verb-truncates", HS,
     '    for p in j.problems:\n        out(f"untrusted: {p}")',
     '    for p in j.problems[:5]:\n        out(f"untrusted: {p}")',
     "test_partition_judge"),
    ("judge-no-loader-dirs", HS,
     "        if not darwin or fallthrough:\n            closure[OPTIONAL] = sorted(set(closure[OPTIONAL] + loader_dirs(platform)))\n"
     "        judged = []\n        bad = closure_problems(closure, platform=platform, seen=judged)",
     "        judged = []\n        bad = closure_problems(closure, platform=platform, seen=judged)",
     "test_partition_judge"),
    ("judge-no-acls", HS,
     "        bad += acl_problems(sorted(set(judged)), platform=platform)\n    except Tooling as e:\n"
     "        return Judgment([str(e)], \"closure\")",
     "    except Tooling as e:\n        return Judgment([str(e)], \"closure\")",
     "test_partition_judge"),
    ("judge-no-docker", HS,
     "    j = judge(sys.executable, also=[docker], recorded=[docker],",
     "    j = judge(sys.executable, also=[], recorded=[docker],",
     "test_partition_judge"),
    ("judge-no-pins", HS,
     "        for t, want in sorted((shas or {}).items()):\n            if t in passed:",
     "        for t, want in sorted(()):\n            if t in passed:",
     "test_partition_judge"),
    ("judge-any-python3", HS,
     "    if not python3 or not sys.executable or os.path.realpath(python3) != os.path.realpath(sys.executable):",
     "    if False:",
     "test_partition_judge"),
    ("judge-pin-of-unjudged-tool", HS,
     "            if t in passed:\n                bad = _pin_problem(t, want)",
     "            if True:\n                bad = _pin_problem(t, want)",
     "test_partition_judge"),
    ("pj-judge-line-shell", PJ,
     '                         [py, "-I", "-S", "-B", writer, "partition-judge", "--python3", py,',
     '                         ["/bin/sh", "-c", "partition-judge", "--python3", py,',
     "test_partition_plan_steps"),
    # partition-fetch (d3.3 §5(d) §1.10)
    ("fetch-env-inherited", HS,
     '    return {"PATH": exec_dir, "GIT_EXEC_PATH": exec_dir,',
     '    return {**os.environ, "PATH": exec_dir, "GIT_EXEC_PATH": exec_dir,',
     "test_partition_fetch"),
    ("fetch-path-usr-bin", HS,
     '    return {"PATH": exec_dir, "GIT_EXEC_PATH": exec_dir,',
     '    return {"PATH": exec_dir + ":/usr/bin", "GIT_EXEC_PATH": exec_dir,',
     "test_partition_fetch"),
    ("fetch-no-git-exec-path", HS,
     '    return {"PATH": exec_dir, "GIT_EXEC_PATH": exec_dir,',
     '    return {"PATH": exec_dir,',
     "test_partition_fetch"),
    ("fetch-third-link", HS,
     '            os.symlink(helper, "git-remote-https", dir_fd=gfd)\n',
     '            os.symlink(helper, "git-remote-https", dir_fd=gfd)\n            os.symlink("/bin/sh", "sh", dir_fd=gfd)\n',
     "test_partition_fetch"),
    ("fetch-no-phase-a", HS,
     '        if j.phase != "clean":\n            raise Untrusted("; ".join(j.problems[:5]))\n        _pgid_guard(efd)\n        staged',
     '        _pgid_guard(efd)\n        staged',
     "test_partition_fetch"),
    ("fetch-no-phase-b", HS,
     "        _phase_b(efd, made, git, helper)\n",
     "",
     "test_partition_fetch"),
    ("fetch-phase-b-no-readlink", HS,
     "                    or os.readlink(alias, dir_fd=gfd) != target):",
     "                    ):",
     "test_partition_fetch"),
    ("fetch-judge-the-aliases", HS,
     "        j = judge(sys.executable, also=[git, helper], recorded=[git, helper])",
     "        aliases = [os.path.join(exec_root, GIT_EXEC, n) for n in (\"git\", \"git-remote-https\")]\n"
     "        j = judge(sys.executable, also=aliases, recorded=[git, helper] + aliases)",
     "test_partition_fetch"),
    ("pj-fetch-also-other-variable", PJ,
     '"--exec-root", p.exec_root, "--pin", pin, "--repo", PUBLIC_REPO], also=[git, helper])',
     '"--exec-root", p.exec_root, "--pin", pin, "--repo", PUBLIC_REPO], also=[git, py])',
     "test_partition_plan_steps"),
    ("fetch-no-template", HS,
     '["clone", "--no-checkout", "--quiet", "--template=", "--", repo, src]',
     '["clone", "--no-checkout", "--quiet", "--", repo, src]',
     "test_partition_fetch"),
    ("fetch-no-config-global", HS,
     '"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1",',
     '"GIT_CONFIG_NOSYSTEM": "1", "GIT_ATTR_NOSYSTEM": "1",',
     "test_partition_fetch"),
    ("fetch-no-protocol-pins", HS,
     '"-c", "init.templateDir=", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",',
     '"-c", "init.templateDir=",',
     "test_partition_fetch"),
    ("fetch-archive", HS,
     '["-C", src, "ls-tree", "-z", pin, "--", *names]',
     '["-C", src, "archive", "--format=tar", pin, "--", *names]',
     "test_partition_fetch"),
    ("fetch-no-mode-check", HS,
     '        if mode not in (b"100644", b"100755") or kind != b"blob":',
     "        if False:",
     "test_partition_fetch"),
    ("fetch-slash-in-name", HS,
     'MANIFEST_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*")',
     'MANIFEST_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]*")',
     "test_partition_fetch"),
    ("fetch-reserved-names", HS,
     "        if line in (CLOSURE, PIN):\n",
     "        if False:\n",
     "test_partition_fetch"),
    ("fetch-no-manifest-written", HS,
     "        _write_at(nfd, CLOSURE, manifest, 0o444, exclusive=True)\n",
     "",
     "test_partition_fetch"),
    ("fetch-64-hex-pin", HS,
     'PIN_FORM = re.compile(r"[0-9a-f]{40}")',
     'PIN_FORM = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")',
     "test_partition_fetch"),
    ("fetch-no-new-session", HS,
     "cwd=cwd, close_fds=True, start_new_session=True)",
     "cwd=cwd, close_fds=True)",
     "test_partition_fetch"),
    ("fetch-kill-not-killpg", HS,
     "                os.killpg(pgid, signal.SIGKILL)",
     "                os.kill(pgid, signal.SIGKILL)",
     "test_partition_fetch"),
    ("fetch-no-empty-check", HS,
     "    if not _await_empty(pgid):",
     "    if False:",
     "test_partition_fetch"),
    ("fetch-capture-output", HS,
     "        while sel.get_map():",
     "        o, e = child.communicate(timeout=deadline_s)\n        out, err = bytearray(o), bytearray(e)\n"
     "        while False:",
     "test_partition_fetch"),
    ("fetch-stderr-kills", HS,
     "                    dropped += max(0, len(chunk) - max(0, room))\n",
     "                    dropped += max(0, len(chunk) - max(0, room))\n                    if dropped:\n"
     "                        why = \"wrote too much to stderr\"\n                        break\n",
     "test_partition_fetch"),
    ("fetch-core-retakes-lock", HS,
     '    nfd = os.open("bundle.new", _DIR, dir_fd=efd)',
     '    _take_partition_lock(efd)\n    nfd = os.open("bundle.new", _DIR, dir_fd=efd)',
     "test_partition_fetch"),
    ("fetch-not-exclusive", HS,
     "            _write_at(nfd, name, blob, 0o444, exclusive=True)",
     "            _write_at(nfd, name, blob, 0o444)",
     "test_partition_fetch"),
    ("fetch-swap-unverified", HS,
     "        _verify_bundle(efd, pin)\n    except (Tooling, Handoff):",
     "        pass\n    except (Tooling, Handoff):",
     "test_partition_fetch"),
    ("fetch-include-path-restored", HS,
     '"-c", "uploadpack.packObjectsHook=")',
     '"-c", "uploadpack.packObjectsHook=", "-c", "include.path=")',
     "test_partition_fetch"),
    ("fetch-guard-after-removals", HS,
     "        _pgid_guard(efd)\n        staged = True\n        for name in (SRC_NEW, BUNDLE_NEW, GIT_EXEC):\n"
     "            try:\n                _remove_tree(efd, name)\n            except FileNotFoundError:\n"
     "                pass\n        _empty_home(efd)",
     "        staged = True\n        for name in (SRC_NEW, BUNDLE_NEW, GIT_EXEC):\n"
     "            try:\n                _remove_tree(efd, name)\n            except FileNotFoundError:\n"
     "                pass\n        _pgid_guard(efd)\n        _empty_home(efd)",
     "test_partition_fetch"),
    ("fetch-stale-group-killed", HS,
     '    raise Survivor(f"the git process group {pgid} a previous run recorded',
     '    os.killpg(pgid, signal.SIGKILL)\n    os.unlink(PGID_FILE, dir_fd=efd)\n    return\n'
     '    raise Survivor(f"the git process group {pgid} a previous run recorded',
     "test_partition_fetch"),
    ("fetch-wait-unbounded", HS,
     "            child.wait(timeout=max(0.0, min(end - time.monotonic(), 0.2)))",
     "            child.wait()",
     "test_partition_fetch"),
    ("fetch-lookup-error-is-failure", HS,
     "        os.killpg(pgid, 0)\n    except ProcessLookupError:\n        return True\n    except PermissionError:\n"
     "        pass\n    return False",
     "        os.killpg(pgid, 0)\n    except ProcessLookupError:\n        return False\n    except PermissionError:\n"
     "        pass\n    return False",
     "test_partition_fetch"),
    ("provision-no-guard", HS,
     "        _pgid_guard(efd)\n        return _provision_core(efd, lock_fd)",
     "        return _provision_core(efd, lock_fd)",
     "test_partition_fetch"),
    ("ps-darwin-shim-accepted", "partition_setup.py",
     '    if getattr(getattr(spec, "supervision", None), "kind", None) == "launchd" and \\',
     '    if False and \\',
     "test_partition_plan_steps"),
]


def main(labels):
    dm.M = M
    return dm.main(labels)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
