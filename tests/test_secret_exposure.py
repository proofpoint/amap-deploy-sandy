"""secret_exposure: every container on every engine, against the secret.

Containers are dicts in `docker inspect`'s field names (Name with its
leading slash, Mounts[].Type/Name/Source/Destination/RW, Config.Env and
Labels, HostConfig.Privileged/CapAdd/PidMode/IpcMode/..., State.Running);
`docker context ls --format '{{json .}}'` prints one JSON object per line.
Identity is a fake `stat` over a dict of path -> (st_dev, st_ino), so an
alias (a firmlink, a case variant) is two paths with the same identity, and
a path absent from the dict does not exist. Docker is never run.
"""

import contextlib
import json
import stat
import unittest
from collections import namedtuple

import host_setup as hs
import router_health as rh
import secret_exposure as se
import secret_setup as ss
from test_secret_setup import full_doc, sec

Id = namedtuple("Id", "st_dev st_ino st_mode", defaults=(stat.S_IFDIR | 0o755,))
RUNTIME = "ex-down"
VOL = "ex-secret"

IDS = {"/": 1, "/Users": 2, "/Users/op": 3, "/Users/op/OrbStack": 4, "/Users/op/dev": 5,
       "/Users/op/dev/ws": 6, "/Users/op/OrbStack/docker": 7, "/Users/op/.ssh": 8,
       "/opt": 10, "/opt/ex": 11, "/opt/ex/libexec": 12, "/opt/ex/etc": 13, "/opt/amapx": 14,
       "/srv": 20, "/srv/op": 21, "/srv/op/clones": 22, "/srv/op/clones/deploy": 23,
       "/srv/op/clones/deploy/tests": 24, "/srv/op/clones/overlay": 25, "/srv/op/clones/producer": 26,
       "/srv/op/clones/runtime": 27, "/srv/op/run": 28, "/srv/op/uv-cache": 29, "/srv/op/uv-python": 30,
       "/srv/op/ssh": 31, "/srv/op/ssh/config": 32, "/srv/op/ssh/known_hosts": 33,
       "/var": 40, "/var/ex": 41, "/var/ex/status": 42, "/var/lib": 43, "/var/lib/docker": 44,
       "/var/lib/docker/volumes": 45, "/var/lib/docker/volumes/ex-secret": 46,
       "/var/lib/docker/volumes/ex-secret/_data": 47, "/var/run": 48, "/var/run/docker.sock": 49,
       "/usr": 50, "/usr/bin": 51, "/usr/local": 52, "/usr/local/bin": 53,
       "/usr/bin/git": 54, "/usr/local/bin/docker": 55, "/usr/bin/python3": 56, "/usr/bin/ssh": 57,
       "/usr/bin/ssh-keygen": 58, "/usr/bin/sudo": 59, "/usr/bin/install": 60, "/usr/bin/sha256sum": 61,
       "/usr/bin/systemd-analyze": 62, "/usr/local/bin/uv": 63, "/usr/local/bin/orb": 64}
ALIASES = {"/System": 90, "/System/Volumes": 91, "/System/Volumes/Data": 92,
           "/System/Volumes/Data/Users": 2, "/System/Volumes/Data/Users/op": 3,
           "/System/Volumes/Data/Users/op/OrbStack": 4, "/users/op/orbstack": 4, "/users": 2,
           "/users/op": 3, "/private": 93, "/private/var": 40, "/private/var/lib": 43,
           "/private/var/lib/docker": 44}


def stat_of(extra=None):
    table = dict(IDS)
    table.update(ALIASES)
    table.update(extra or {})

    def st(p):
        if p not in table:
            raise FileNotFoundError(p)
        v = table[p]
        return v if isinstance(v, Id) else Id(1, v)
    return st


def exposure_sec(**over):
    s = sec()
    s["tools"]["orb"] = "/usr/local/bin/orb"
    s["caps_allow"] = {"NET_ADMIN": "the vpn container manages its tunnel"}
    s["attestations"] = {"native_agents": [], "other_runtimes": []}
    s["exposure"] = {"secret_roots": ["/Users/op/OrbStack", "/Users/op/.ssh"],
                     "integrity_roots": [], "engine_sockets": ["/var/run/docker.sock"],
                     "authorized_keys": []}
    s.update(over)
    return s


def specs(**over):
    d = full_doc()
    d[ss.SECTION] = exposure_sec(**over)
    spec = hs.load_spec(d)
    return spec, spec.secrets


def container(name, mounts=(), *, labels=None, env=(), running=True, **host):
    h = {"Privileged": False, "CapAdd": None, "PidMode": "", "IpcMode": "private", "UsernsMode": "",
         "CgroupnsMode": "private", "Devices": [], "DeviceCgroupRules": None, "SecurityOpt": None,
         "VolumesFrom": None}
    h.update(host)
    return {"Id": name * 4, "Name": "/" + name, "Mounts": list(mounts),
            "Config": {"Env": list(env), "Labels": labels or {}}, "HostConfig": h,
            "State": {"Running": running}}


def vol(dest="/run/secrets/ex", rw=False, name=VOL):
    return {"Type": "volume", "Name": name, "Source": f"/var/lib/docker/volumes/{name}/_data",
            "Destination": dest, "RW": rw}


def bind(src, dest="/mnt", rw=True):
    return {"Type": "bind", "Source": src, "Destination": dest, "RW": rw}


def runtime(**over):
    kw = {"SecurityOpt": ["no-new-privileges"]}
    kw.update(over)
    return container(RUNTIME, [vol()], **kw)


def workspace():
    return container("agent-ws", [bind("/Users/op/dev/ws", "/workspace")])


ORB_EMPTY = (0, "", "")


def engine(contexts=None, by_context=None, orb=ORB_EMPTY, mountpoint="/var/lib/docker/volumes/ex-secret/_data",
           fail=None):
    """A fake rh.run answering the docker CLI per context, and orb."""
    contexts = contexts or [("default", "unix:///var/run/docker.sock")]
    by_context = by_context if by_context is not None else {"default": [runtime(), workspace()]}

    def run(argv, **kw):
        if fail:
            hit = fail(argv)
            if hit is not None:
                return rh.Proc(tuple(argv), *hit)
        if argv[0].endswith("orb"):
            return rh.Proc(tuple(argv), *orb)
        args = argv[1:]
        ctx = None
        if args[:1] == ["--context"]:
            ctx, args = args[1], args[2:]
        if args[:2] == ["context", "ls"]:
            return rh.Proc(tuple(argv), 0, "".join(json.dumps({"Name": n, "DockerEndpoint": e}) + "\n"
                                                   for n, e in contexts), "")
        cs = by_context.get(ctx, [])
        if args[:1] == ["ps"]:
            return rh.Proc(tuple(argv), 0, "".join(c["Id"] + "\n" for c in cs), "")
        if args[:2] == ["volume", "inspect"]:
            return rh.Proc(tuple(argv), 0, mountpoint + "\n", "")
        if args[:2] == ["image", "inspect"]:
            return rh.Proc(tuple(argv), 0, "sha256:" + "a" * 64 + "\n", "")
        if args[:1] == ["inspect"]:
            ids = set(args[1:])
            return rh.Proc(tuple(argv), 0, json.dumps([c for c in cs if c["Id"] in ids]), "")
        raise AssertionError(f"unexpected {argv}")
    return run


@contextlib.contextmanager
def free_lock():
    yield None


class Base(unittest.TestCase):

    def sweep(self, run=None, *, s=None, lstat_=None, stat_=None, lock=free_lock):
        spec, sx = s or specs()
        orig = rh.run
        rh.run = run or engine()
        self.addCleanup(setattr, rh, "run", orig)
        return se.checks(spec, sx, lstat_=lstat_ or (lambda p: Id(1, 1)), stat_=stat_ or stat_of(),
                         realpath=lambda p: p, lock=lock)

    def bad(self, found):
        return {c.claim: (c.result, c.actual) for c in found if c.result != rh.PASS}

    def assertOnly(self, found, fragment, result=rh.FAIL):
        bad = self.bad(found)
        self.assertTrue(bad, "nothing stopped passing")
        for claim, (r, actual) in bad.items():
            self.assertIn(fragment, claim)
            self.assertEqual(r, result, (claim, actual))
        return bad


class GoodTest(Base):

    def test_the_runtime_and_a_workspace_pass_every_rule(self):
        found = self.sweep()
        self.assertGreaterEqual(len(found), 6)
        self.assertEqual(self.bad(found), {})


class MountsTest(Base):

    def test_another_container_mounting_the_volume_fails_running_or_stopped(self):
        for running in (True, False):
            with self.subTest(running=running):
                other = container("other", [vol("/x", rw=False)], running=running)
                found = self.sweep(engine(by_context={"default": [runtime(), other]}))
                self.assertOnly(found, "only ex-down mounts the volume")

    def test_any_one_shot_seen_under_the_lock_fails(self):
        for running, why in ((False, "left behind by a crash"), (True, "running while verify holds")):
            with self.subTest(running=running):
                shot = container("x", [vol("/v", rw=True)], labels={se.ONESHOT_LABEL: "writer"},
                                 running=running)
                bad = self.assertOnly(self.sweep(engine(by_context={"default": [runtime(), shot]})),
                                      "only ex-down mounts the volume")
                self.assertIn(why, str(bad))

    def test_the_runtime_mounting_it_read_write_or_elsewhere_fails(self):
        for m in (vol(rw=True), vol(dest="/data/secret")):
            with self.subTest(m=m):
                rt = container(RUNTIME, [m], SecurityOpt=["no-new-privileges"])
                self.assertOnly(self.sweep(engine(by_context={"default": [rt]})), "only ex-down mounts")

    def test_another_container_mounting_it_exactly_as_the_runtime_does_fails(self):
        twin = container("twin", [vol()], SecurityOpt=["no-new-privileges"])
        self.assertOnly(self.sweep(engine(by_context={"default": [runtime(), twin]})), "only ex-down mounts")

    def test_another_volume_is_none_of_this_rules_business(self):
        other = container("db", [vol("/var/lib/db", rw=True, name="db-data")])
        self.assertEqual(self.bad(self.sweep(engine(by_context={"default": [runtime(), other]}))), {})


class OverlapTest(Base):

    def run_bind(self, src, rw=True, stat_=None):
        c = container("x", [bind(src, rw=rw)])
        return self.sweep(engine(by_context={"default": [runtime(), c]}), stat_=stat_)

    def test_a_bind_above_or_below_a_secret_root_fails(self):
        for src in ("/Users/op", "/Users", "/", "/Users/op/OrbStack/docker"):
            with self.subTest(src=src):
                self.assertOnly(self.run_bind(src, rw=False), "no container binds a path that overlaps")

    def test_the_volumes_backing_path_is_a_secret_root(self):
        self.assertOnly(self.run_bind("/var/lib/docker", rw=False), "overlaps")
        self.assertOnly(self.run_bind("/var/lib/docker/volumes/ex-secret/_data", rw=False), "overlaps")

    def test_a_firmlink_or_case_variant_is_the_same_directory(self):
        for src in ("/System/Volumes/Data/Users/op", "/users/op/orbstack", "/private/var/lib/docker"):
            with self.subTest(src=src):
                self.assertOnly(self.run_bind(src, rw=False), "overlaps")

    def test_a_prefix_that_is_not_a_component_does_not_match(self):
        self.assertEqual(self.bad(self.run_bind("/opt/amapx")), {})

    def test_a_read_only_bind_of_the_tooling_is_allowed_but_writable_is_not(self):
        self.assertEqual(self.bad(self.run_bind("/srv/op/clones/deploy", rw=False)), {})
        self.assertOnly(self.run_bind("/srv/op/clones/deploy", rw=True), "overlaps")
        self.assertOnly(self.run_bind("/srv/op/clones/deploy/tests", rw=True), "overlaps")

    def test_any_bind_above_the_tooling_fails_read_only_too(self):
        self.assertOnly(self.run_bind("/srv/op/clones", rw=False), "overlaps")

    def test_a_source_that_cannot_be_stated_is_unknown_never_pass(self):
        self.assertOnly(self.run_bind("/Users/op/OrbStack/gone", rw=False), "overlaps", rh.UNKNOWN)

    def test_the_name_fallback_strips_the_data_volume_prefix_and_ignores_case(self):
        for src in ("/System/Volumes/Data/Users/op/OrbStack/gone", "/USERS/op/OrbStack/gone",
                    "/private/var/lib/docker/volumes/ex-secret/_data/gone"):
            with self.subTest(src=src):
                self.assertOnly(self.run_bind(src, rw=False), "overlaps", rh.UNKNOWN)

    def test_an_unrelated_missing_source_passes(self):
        self.assertEqual(self.bad(self.run_bind("/nowhere/else", rw=False)), {})

    def test_overlap_relations(self):
        st = stat_of()
        self.assertEqual(se.overlap("/Users/op", "/Users/op/OrbStack", st), "ancestor")
        self.assertEqual(se.overlap("/Users/op/OrbStack/docker", "/Users/op/OrbStack", st), "descendant")
        self.assertEqual(se.overlap("/users/op/orbstack", "/Users/op/OrbStack", st), "equal")
        self.assertIsNone(se.overlap("/opt/amapx", "/opt/ex", st))
        u = se.overlap("/System/Volumes/Data/Users/op/new", "/Users/op", st)
        self.assertIsInstance(u, rh.Unresolved)
        self.assertEqual(u.relation, "descendant")


class PrivilegesTest(Base):

    def one(self, c):
        return self.sweep(engine(by_context={"default": [runtime(), c]}))

    def test_each_dangerous_setting_fails(self):
        cases = {"privileged": dict(Privileged=True),
                 "read_search": dict(CapAdd=["DAC_READ_SEARCH"]),
                 "ptrace": dict(CapAdd=["CAP_SYS_PTRACE"]),
                 "all": dict(CapAdd=["ALL"]),
                 "pid of the runtime": dict(PidMode=f"container:{RUNTIME}"),
                 "host pid": dict(PidMode="host"),
                 "host ipc": dict(IpcMode="host"),
                 "host userns": dict(UsernsMode="host"),
                 "host cgroupns": dict(CgroupnsMode="host"),
                 "device": dict(Devices=[{"PathOnHost": "/dev/sda"}]),
                 "device rule": dict(DeviceCgroupRules=["b 8:* rmw"]),
                 "apparmor": dict(SecurityOpt=["apparmor=unconfined"]),
                 "seccomp": dict(SecurityOpt=["seccomp=unconfined"]),
                 "volumes from the runtime": dict(VolumesFrom=[f"{RUNTIME}:ro"]),
                 "an unlisted cap": dict(CapAdd=["SYSLOG"])}
        for what, host in cases.items():
            with self.subTest(what=what):
                self.assertOnly(self.one(container("x", **host)), "no container holds a privilege")

    def test_an_allowlisted_cap_with_its_reason_passes(self):
        self.assertEqual(self.bad(self.one(container("vpn", CapAdd=["NET_ADMIN"]))), {})

    def test_a_hard_denied_cap_fails_even_when_allowlisted(self):
        s = specs(caps_allow={"SYS_PTRACE": "a debugger"})
        orig = rh.run
        found = self.sweep(engine(by_context={"default": [runtime(), container("x", CapAdd=["SYS_PTRACE"])]}),
                           s=s)
        rh.run = orig
        self.assertOnly(found, "no container holds a privilege")

    def test_default_namespace_modes_pass(self):
        c = container("x", IpcMode="shareable", PidMode="", UsernsMode="", CgroupnsMode="private")
        self.assertEqual(self.bad(self.one(c)), {})

    def test_the_runtime_must_add_nothing_and_forbid_new_privileges(self):
        for rt in (runtime(SecurityOpt=None), runtime(CapAdd=["NET_ADMIN"])):
            with self.subTest(rt=rt["HostConfig"]):
                found = self.sweep(engine(by_context={"default": [rt]}))
                self.assertOnly(found, "no container holds a privilege")


class RoutesTest(Base):

    def test_an_engine_or_agent_variable_fails(self):
        for var in ("DOCKER_HOST=tcp://x:2375", "SSH_AUTH_SOCK=/tmp/agent.sock"):
            with self.subTest(var=var):
                c = container("x", env=["PATH=/usr/bin", var])
                found = self.sweep(engine(by_context={"default": [runtime(), c]}))
                self.assertOnly(found, "no container can reach an engine")

    def test_a_socket_bind_fails_and_the_engine_socket_is_also_an_overlap(self):
        c = container("x", [bind("/var/run/docker.sock", "/var/run/docker.sock", rw=True)])
        found = self.sweep(engine(by_context={"default": [runtime(), c]}),
                           lstat_=lambda p: Id(1, 1, stat.S_IFSOCK | 0o660))
        bad = self.bad(found)
        self.assertIn("no container can reach an engine", bad)
        self.assertIn("no container binds a path that overlaps the secret or the code that handles it", bad)


    def test_any_socket_bind_fails_not_only_the_listed_engines(self):
        c = container("x", [bind("/srv/elsewhere/agent.sock", "/run/a.sock", rw=True)])
        found = self.sweep(engine(by_context={"default": [runtime(), c]}),
                           lstat_=lambda p: Id(1, 1, stat.S_IFSOCK | 0o660) if p.endswith(".sock")
                           else Id(1, 1))
        self.assertOnly(found, "no container can reach an engine")


class EnginesTest(Base):

    def test_every_context_is_swept(self):
        bad = container("evil", [vol("/x")])
        run = engine(contexts=[("default", "unix:///var/run/docker.sock"), ("other", "ssh://engine.example.org")],
                     by_context={"default": [runtime()], "other": [bad]})
        self.assertIn("other/evil", str(self.assertOnly(self.sweep(run), "only ex-down mounts")))

    def test_an_engine_that_cannot_list_is_unknown(self):
        run = engine(contexts=[("default", "unix:///var/run/docker.sock"), ("other", "ssh://x")],
                     fail=lambda a: (1, "", "cannot connect") if "--context" in a and "other" in a else None)
        self.assertOnly(self.sweep(run), "every engine on this host can be asked", rh.UNKNOWN)

    def test_a_socket_no_context_names_is_unknown(self):
        run = engine(contexts=[("desktop", "unix:///Users/op/.docker/run/docker.sock")],
                     by_context={"desktop": [runtime()]})
        found = self.sweep(run, lstat_=lambda p: Id(1, 1, stat.S_IFSOCK | 0o660))
        self.assertOnly(found, "every engine on this host can be asked", rh.UNKNOWN)

    def test_no_contexts_at_all_is_one_unknown(self):
        run = engine(fail=lambda a: (1, "", "daemon down") if "context" in a else None)
        found = self.sweep(run)
        self.assertEqual([c.result for c in found], [rh.UNKNOWN])

    def test_an_orbstack_machine_fails(self):
        self.assertOnly(self.sweep(engine(orb=(0, "ubuntu\n", ""))), "no OrbStack machine")

    def test_a_busy_lock_is_one_unknown(self):
        @contextlib.contextmanager
        def busy():
            yield rh.Unresolved("held for 60s")
        found = self.sweep(lock=busy)
        self.assertEqual([(c.result, c.claim) for c in found],
                         [(rh.UNKNOWN, "no container can reach the secret")])


class NotesTest(unittest.TestCase):

    def test_the_attestations_are_printed_as_recorded(self):
        _, s = specs()
        self.assertEqual(se.notes(s), ["attested native_agents: []", "attested other_runtimes: []"])

    def test_missing_attestations_say_so(self):
        _, s = specs(attestations={})
        self.assertIn("attested native_agents: NOT RECORDED", se.notes(s))


if __name__ == "__main__":
    unittest.main()
