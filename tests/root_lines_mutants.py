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
]


def main(labels):
    dm.M = M
    return dm.main(labels)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
