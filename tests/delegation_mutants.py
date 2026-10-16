"""The delegation work's mutation harness: each mutant replaces one exact
source anchor (which must occur exactly once), runs its named test target,
and must turn it red. It is not a test: run it by hand from the repository
root, as a gate does.

    python3 -B tests/delegation_mutants.py [LABEL ...]

Every mutant is applied to a copy of the tree in a temporary directory; the
working tree is never touched. It first runs every selected target
UNMUTATED in that copy and refuses (exit 2) unless
each is green, so a target that cannot import never counts as a kill. With
labels, only those run, and a label that names no mutant refuses the whole
run rather than run everything. Exit 0 only when every selected mutant is
KILLED."""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

M = [
    # label, file, old, new, test target
    ("fk-keyid", "fleet_keys.py", "    if kid != hashlib.sha256(bytes.fromhex(pk)).hexdigest():", "    if False:", "test_fleet_keys"),
    ("fk-trust", "fleet_keys.py", "        if outside:\n            raise", "        if False:\n            raise", "test_fleet_keys"),
    ("fk-pin", "fleet_keys.py", "    if got != pin.sha256:", "    if False:", "test_fleet_keys"),
    ("fk-canonical", "fleet_keys.py", "    if canonical(doc) != raw:", "    if False:", "test_fleet_keys"),
    ("dr-peers", "delegation_render.py", 'gate(dc.key_table_input(), "delegation.runtimes")\n', "pass\n", "test_delegation_render"),
    ("dr-activate", "delegation_render.py", 'gate(dc.key_table_input(), "delegation.runtimes")\n',
     "try:\n    P.activate(cfg, plugin, now=datetime.datetime.now(datetime.timezone.utc))\nexcept P.DelegationRefused as e:\n"
     "    refused(e.reason, e.detail)\n", "test_delegation_render"),
    ("dr-dupkey", "delegation_render.py", 'if dc.signing_key_id in {k["key_id"] for r in dc.runtimes for k in r.keys}:', "if False:",
     "test_delegation_render"),
    ("dr-candidate", "delegation_render.py", "    P.candidate_view_of(codec, tuple(plugin.api))\n", "",
     "test_delegation_render"),
    ("dr-hook", "delegation_render.py", "sys.addaudithook(no_key)\n", "\n", "test_delegation_render"),
    ("hk-notyet", "hub_keys.py", '        return rh.UNKNOWN, "NOT YET ACTIVATED', '        return rh.PASS, "NOT YET ACTIVATED', "test_signing_matrix"),
    ("hk-stale", "hub_keys.py", "    if age > pe.FRESH_FOR_S or age < -pe.CLOCK_TOLERANCE_S:", "    if False:", "test_signing_matrix"),
    ("hk-bytes", "hub_keys.py",
     "        same = isinstance(staged, dict) and DELEGATION_KEY in staged and _member(staged) == _member(doc)",
     '        same = sg.approved["staged"].encode() == json.dumps(doc).encode()', "test_signing_matrix"),
    ("hk-toplevel", "hub_keys.py", '    section = status.get("classification") if isinstance(status, dict) else None',
     "    section = status if isinstance(status, dict) else None", "test_signing_matrix"),
    ("hk-platform", "hub_keys.py", "    why = platform_problem(h1, t1)\n    if why:", "    why = ''\n    if why:", "test_signing_matrix"),
    ("hk-fstype", "hub_keys.py", '    if host.get("fstype") not in LOCAL_FS or host.get("fstype") != seen.get("fstype"):', "    if False:",
     "test_signing_matrix"),
    ("hk-bootid", "hub_keys.py", '    if host.get("boot_id") != seen.get("boot_id"):', "    if False:", "test_signing_matrix"),
    ("hk-kind", "hub_keys.py", '    if host.get("kind") != "systemd":', "    if False:", "test_signing_matrix"),
    ("hk-settle", "hub_keys.py", '    if h1["now"] - h1["ctime_ns"] / 1e9 < CTIME_SETTLE_S:', "    if False:", "test_signing_matrix"),
    ("hk-sha-only", "hub_keys.py", '    if any(t5[k] != t1[k] for k in TUPLE_KEYS) or t5["sha256"] != host_sha:',
     '    if t5["sha256"] != host_sha:', "test_signing_matrix"),
    ("hk-one-poll", "hub_keys.py", '        if isinstance(s.get("polls"), int) and s["polls"] >= polls + 2:',
     '        if isinstance(s.get("polls"), int) and s["polls"] >= polls + 1:', "test_signing_matrix"),
    ("hk-interval", "hub_keys.py", "    if interval < 1:", "    if False:", "test_signing_matrix"),
    ('hk-realpath', 'hub_keys.py', '    return mount_fstype(os.path.realpath(path), mountinfo)', '    return mount_fstype(path, mountinfo)', 'test_signing_matrix.MountinfoTest'),
    ('hk-latin1', 'hub_keys.py', '    "        mp = unescape_mount(f[4])\\n"', '    "        mp = f[4].encode(\'latin-1\').decode(\'unicode_escape\')\\n"', 'test_signing_matrix.MountinfoTest'),
    ('hk-boundary', 'hub_keys.py', '    "        if path == mp or (not exact and path.startswith(mp.rstrip(\'/\') + \'/\')):\\n"', '    "        if path == mp or (not exact and path.startswith(mp)):\\n"', 'test_signing_matrix.MountinfoTest'),
    ("hk-finite", "hub_keys.py", " or isinstance(interval, bool) or not math.isfinite(interval):",
     " or isinstance(interval, bool):", "test_signing_matrix"),
    ("hk-end-platform", "hub_keys.py",
     '    why = h5.reason if isinstance(h5, rh.Unresolved) else platform_problem(h5, t5)\n    if why:',
     "    why = ''\n    if why:", "test_signing_matrix"),
    ("hk-inode", "hub_keys.py", "    why = inode_problem(h1, t1)\n    if why:", "    why = ''\n    if why:",
     "test_signing_matrix"),
    ("ai-a", "activation_install.py", "    if gate:\n", "    if False:\n", "test_activation_install"),
    ("ai-b-self", "activation_install.py", "    if got != activation_sha256:", "    if got != hashlib.sha256(raw).hexdigest():",
     "test_activation_install"),
    ("ai-c-passing", "activation_install.py", "    if token is None:", "    if False:", "test_activation_install"),
    ("ai-c-binding", "activation_install.py",
     '    if edoc["bindings"].get("local_router") != pa.activation_binding(approved["spec"], staged):', "    if False:",
     "test_activation_install"),
    ("ai-d", "activation_install.py", "    if fresh != staged:", "    if False:", "test_activation_install"),
    ("ai-e", "activation_install.py", "    if current not in (pre_activation, final):", "    if False:", "test_activation_install"),
    ("ai-f", "activation_install.py", "    refused = validate_bytes(final)", "    refused = None", "test_activation_install"),
    ("hs-place-nlink", "host_steps.py",
     '        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:\n            raise StepError(f"{src} is not a regular file with one link',
     '        if not stat.S_ISREG(st.st_mode):\n            raise StepError(f"{src} is not a regular file with one link',
     "test_host_steps.PlaceTest"),
    ("hs-place-size", "host_steps.py", '    if total > DOC_MAX:\n        raise StepError(f"{src} is larger',
     '    if False:\n        raise StepError(f"{src} is larger', "test_host_steps.PlaceTest"),
    ("hs-place-follow", "host_steps.py", "        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK",
     "        fd = os.open(src, os.O_RDONLY | os.O_NONBLOCK", "test_host_steps.PlaceTest"),
    ("pi-history", "partition_incident.py", "    eligible = live is False and isinstance(prior, list) and only_observed(prior)",
     "    eligible = live is False", "test_partition_incident"),
    ("pi-g4", "partition_incident.py", "    named = _observe(fx.router_running)\n    if named is not False:",
     "    named = False\n    if named is not False:", "test_partition_incident"),
    ("pi-pending", "partition_incident.py",
     '        if "stop_ok" not in kinds and not (prospective and "stop_not_required" in kinds\n'
     '                                          and only_observed(self.events)):',
     '        if "stop_ok" not in kinds and not (prospective and "stop_not_required" in kinds):', "test_partition_incident"),
    ("hs-g1", "host_steps.py", '    if not isinstance(doc, dict) or "delegation" in doc:\n        return "A2 is pre-activation',
     '    if not isinstance(doc, dict):\n        return "A2 is pre-activation', "test_partition_weekly_writer.ProspectiveWriterTest"),
    ("hs-g2", "host_steps.py", '        up = engine.running(recovery["router_container_id"])\n        if up is not False:',
     "        up = False\n        if up is not False:", "test_partition_weekly_writer.ProspectiveWriterTest"),
    ("hs-g3", "host_steps.py", '    if pending:\n        return f"{', '    if False:\n        return f"{',
     "test_partition_weekly_writer.ProspectiveWriterTest"),
    ("hs-g4", "host_steps.py", '    up = engine.running_by_name(name)\n    if up is not False:\n        return (f"A2 runs',
     '    up = False\n    if up is not False:\n        return (f"A2 runs', "test_partition_weekly_writer.ProspectiveWriterTest"),
    ("hs-history", "host_steps.py",
     "    eligible = mode == MODES[1] and observed and isinstance(prior, list) and _only_observed(prior)",
     "    eligible = mode == MODES[1] and observed", "test_partition_weekly_writer.ProspectiveWriterTest"),
    ("hs-act-g4", "host_steps.py", "        named = router_running() if router_running is not None else None",
     "        named = False", "test_partition_weekly_writer.ProspectiveWriterTest"),
    ("hs-pass-target", "host_steps.py", "            if code == EXIT_PASS and prospective:", "            if False:",
     "test_partition_weekly_writer.ProspectiveWriterTest"),
    ("pr-placed", "partition_run.py", "    if not placed:\n        return INCOMPLETE", "    if False:\n        return INCOMPLETE",
     "test_partition_run.A2OutcomeTest"),
    ("pr-p02", "partition_run.py", '    if verdicts.get("P02") != "PASS":', "    if False:", "test_partition_run.A2OutcomeTest"),
    ("pr-aggregate", "partition_run.py",
     '    p01_ok = bool(dispositions) and all(v == "PASS" for v in measured.values()) \\\n'
     "        and set(dispositions) - set(measured) == set(unmeasured) \\",
     "    p01_ok = True \\", "test_partition_run.A2OutcomeTest"),
    ("pp-planned-uid", "partition_probe.py", "        if up in uids and down in uids and uids[up] == uids[down]:",
     "        if up in walks and down in walks and uids[up] == uids[down]:", "test_partition_run.A2OutcomeTest"),
    ("as-no-delegation", "amap_sandy.py", "        doc = dict(doc, **keys)\n        nested =",
     '        doc = dict(doc, **keys)\n        if (policy.get("hop_link") or {}).get("delegation"):\n'
     '            doc["delegation"] = {"signing_key": {}}\n        nested =', "test_hop_render.InstallRenderTest"),
]


def run(tree, target):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([tree, os.path.join(tree, "tests")]))
    return subprocess.run([sys.executable, "-B", "-m", "unittest", f"tests.{target}"], cwd=tree, env=env,
                          capture_output=True, text=True, timeout=900)


def main(labels):
    unknown = sorted(set(labels) - {m[0] for m in M})
    if unknown:
        print(f"refused: no mutant is labelled {', '.join(unknown)}; nothing ran")
        return 2
    chosen = [m for m in M if not labels or m[0] in labels]
    with tempfile.TemporaryDirectory() as tmp:
        tree = os.path.join(tmp, "tree")
        shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        return judge(tree, chosen)


def judge(tree, chosen):
    for target in sorted({m[4] for m in chosen}):
        if run(tree, target).returncode != 0:
            print(f"refused: {target} is not green unmutated, so no kill in it would mean anything")
            return 2
    killed = survived = broken = 0
    for label, path, old, new, target in chosen:
        full = os.path.join(tree, path)
        with open(full) as f:
            src = f.read()
        if src.count(old) != 1:
            print(f"{label}: ANCHOR {src.count(old)}x in {path}; not run")
            broken += 1
            continue
        try:
            with open(full, "w") as f:
                f.write(src.replace(old, new))
            r = run(tree, target)
        finally:
            with open(full, "w") as f:
                f.write(src)
        red = r.returncode != 0
        killed += red
        survived += not red
        print(f"{label}: {'KILLED' if red else 'SURVIVED'} ({target})")
    print(f"SUMMARY selected={len(chosen)} killed={killed} survived={survived} anchor_broken={broken}")
    return 0 if killed == len(chosen) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
