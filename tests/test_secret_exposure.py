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


def container(name, mounts=(), *, labels=None, env=(), running=True, image="sha256:" + "b" * 64, user="",
              **host):
    h = {"Privileged": False, "CapAdd": None, "PidMode": "", "IpcMode": "private", "UsernsMode": "",
         "CgroupnsMode": "private", "Devices": [], "DeviceCgroupRules": None, "SecurityOpt": None,
         "VolumesFrom": None}
    h.update(host)
    return {"Id": name * 4, "Name": "/" + name, "Mounts": list(mounts), "Image": image,
            "Config": {"Env": list(env), "Labels": labels or {}, "User": user}, "HostConfig": h,
            "State": {"Running": running}}


def vol(dest="/run/secrets/ex", rw=False, name=VOL):
    return {"Type": "volume", "Name": name, "Source": f"/var/lib/docker/volumes/{name}/_data",
            "Destination": dest, "RW": rw}


def bind(src, dest="/mnt", rw=True):
    return {"Type": "bind", "Source": src, "Destination": dest, "RW": rw}


PINNED_ID = "sha256:" + "a" * 64


def runtime(mounts=None, **over):
    """The runtime as rendered: the pinned image's ID, its user, one
    read-only mount, every capability dropped, no new privileges."""
    kw = {"SecurityOpt": ["no-new-privileges"], "CapDrop": ["ALL"], "image": PINNED_ID, "user": "2102:2202"}
    kw.update(over)
    return container(RUNTIME, [vol()] if mounts is None else mounts, **kw)


def workspace():
    return container("agent-ws", [bind("/Users/op/dev/ws", "/workspace")])


ORB_EMPTY = (0, "", "")


def engine(contexts=None, by_context=None, orb=ORB_EMPTY, mountpoint="/var/lib/docker/volumes/ex-secret/_data",
           fail=None, volumes=("default",)):
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
        if args[:2] == ["volume", "ls"]:
            return rh.Proc(tuple(argv), 0, VOL + "\n" if ctx in volumes else "", "")
        if args[:2] == ["volume", "inspect"]:
            return rh.Proc(tuple(argv), 0, mountpoint + "\n", "")
        if args[:2] == ["image", "inspect"]:
            return rh.Proc(tuple(argv), 0, PINNED_ID + "\n", "")
        if args[:1] == ["inspect"]:
            ids = set(args[1:])
            return rh.Proc(tuple(argv), 0, json.dumps([c for c in cs if c["Id"] in ids]), "")
        raise AssertionError(f"unexpected {argv}")
    return run


@contextlib.contextmanager
def free_lock():
    yield None


class Base(unittest.TestCase):

    def sweep(self, run=None, *, s=None, lstat_=None, stat_=None, lock=free_lock, realpath=lambda p: p,
              platform="linux"):
        spec, sx = s or specs()
        orig = rh.run
        rh.run = run or engine()
        self.addCleanup(setattr, rh, "run", orig)
        return se.checks(spec, sx, lstat_=lstat_ or (lambda p: Id(1, 1)), stat_=stat_ or stat_of(),
                         realpath=realpath, lock=lock, platform=platform)

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
                rt = runtime([m])
                self.assertOnly(self.sweep(engine(by_context={"default": [rt]})), "only ex-down mounts")

    def test_another_container_mounting_it_exactly_as_the_runtime_does_fails(self):
        twin = container("twin", [vol()], SecurityOpt=["no-new-privileges"], CapDrop=["ALL"], image=PINNED_ID,
                         user="2102:2202")
        self.assertOnly(self.sweep(engine(by_context={"default": [runtime(), twin]})), "only ex-down mounts")

    def test_the_runtime_is_exempt_only_as_rendered(self):
        cases = {"another image": runtime(image="sha256:" + "c" * 64),
                 "root user": runtime(user="0:0"),
                 "no cap drop": runtime(CapDrop=None),
                 "new privileges allowed": runtime(SecurityOpt=["no-new-privileges=false"]),
                 "two mounts": runtime([vol(), vol("/again")])}
        for what, rt in cases.items():
            with self.subTest(what=what):
                self.assertOnly(self.sweep(engine(by_context={"default": [rt]})), "only ex-down mounts")

    def test_the_runtimes_name_on_another_engine_fails(self):
        run = engine(contexts=[("default", "unix:///var/run/docker.sock"), ("desktop", "unix:///x/docker.sock")],
                     by_context={"default": [runtime()], "desktop": [runtime()]})
        self.assertIn("desktop/ex-down", str(self.assertOnly(self.sweep(run), "only ex-down mounts")))

    def test_an_image_that_cannot_be_resolved_is_unknown(self):
        run = engine(fail=lambda a: (1, "", "no such image") if "image" in a else None)
        self.assertOnly(self.sweep(run), "only ex-down mounts", rh.UNKNOWN)

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

    def test_a_source_that_cannot_be_stated_is_unknown_even_with_no_relation(self):
        self.assertOnly(self.run_bind("/nowhere/else", rw=False), "overlaps", rh.UNKNOWN)

    def test_a_missing_source_under_a_symlink_is_named_by_where_the_link_points(self):
        """/Users/op/dev/ws/link -> /Users/op/OrbStack; link/gone does not exist,
        so it is compared by name, and its resolved name is the one that
        relates it to the secret root."""
        c = container("x", [bind("/Users/op/dev/ws/link/gone", rw=False)])
        found = self.sweep(engine(by_context={"default": [runtime(), c]}),
                           realpath=lambda p: p.replace("/Users/op/dev/ws/link", "/Users/op/OrbStack"))
        bad = self.assertOnly(found, "overlaps", rh.UNKNOWN)
        self.assertIn("compared by name: descendant", str(bad))

    def test_a_source_this_user_may_not_stat_is_unknown(self):
        def st(p):
            if p.startswith("/var/lib/docker/volumes"):
                raise PermissionError(13, "denied", p)
            return stat_of()(p)
        c = container("x", [bind("/var/lib/docker/volumes/ex-secret/_data/link", rw=False)])
        found = self.sweep(engine(by_context={"default": [runtime(), c]}), stat_=st)
        self.assertOnly(found, "overlaps", rh.UNKNOWN)

    def test_a_symlinked_source_is_judged_by_its_target(self):
        """/Users/op/dev/ws/sneaky -> /Users/op/OrbStack/docker: its own
        parents are the workspace's, its target's are the secret root's."""
        st = stat_of({"/Users/op/dev/ws/sneaky": 7})
        c = container("x", [bind("/Users/op/dev/ws/sneaky", rw=False)])
        found = self.sweep(engine(by_context={"default": [runtime(), c]}), stat_=st,
                           realpath=lambda p: "/Users/op/OrbStack/docker" if p == "/Users/op/dev/ws/sneaky" else p)
        self.assertOnly(found, "overlaps")

    def test_overlap_relations(self):
        st = stat_of()
        self.assertEqual(se.overlap("/Users/op/dev/ws/l", "/Users/op/OrbStack", stat_of({"/Users/op/dev/ws/l": 7}),
                                    lambda p: "/Users/op/OrbStack/docker" if p.endswith("/l") else p),
                         "descendant")
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

    def test_a_hard_denied_cap_is_named_as_one_no_allowlist_admits(self):
        bad = self.assertOnly(self.one(container("x", CapAdd=["DAC_READ_SEARCH"])), "no container holds a privilege")
        self.assertIn("adds DAC_READ_SEARCH, which no allowlist admits", str(bad))

    def test_an_allowlisted_cap_with_its_reason_passes(self):
        self.assertEqual(self.bad(self.one(container("vpn", CapAdd=["NET_ADMIN"]))), {})

    def test_a_hard_denied_cap_cannot_be_allowlisted_the_section_does_not_load(self):
        with self.assertRaises(hs.SpecError):
            specs(caps_allow={"SYS_PTRACE": "a debugger"})

    def test_default_namespace_modes_pass(self):
        c = container("x", IpcMode="shareable", PidMode="", UsernsMode="", CgroupnsMode="private")
        self.assertEqual(self.bad(self.one(c)), {})

    def test_the_runtime_must_add_nothing_and_forbid_new_privileges(self):
        self.assertOnly(self.sweep(engine(by_context={"default": [runtime(CapAdd=["NET_ADMIN"])]})),
                        "no container holds a privilege")
        self.assertOnly(self.sweep(engine(by_context={"default": [runtime(SecurityOpt=None)]})),
                        "only ex-down mounts")


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
                           else Id(1, 1),
                           stat_=stat_of({"/srv/elsewhere": 80, "/srv/elsewhere/agent.sock": 83}))
        self.assertOnly(found, "no container can reach an engine")


    def test_a_symlink_to_a_socket_is_a_socket(self):
        c = container("x", [bind("/srv/elsewhere/link", "/run/a.sock", rw=True)])
        found = self.sweep(engine(by_context={"default": [runtime(), c]}),
                           lstat_=lambda p: Id(1, 1, stat.S_IFLNK | 0o777),
                           stat_=stat_of({"/srv/elsewhere": 80, "/srv/elsewhere/link": Id(1, 81, stat.S_IFSOCK | 0o660)}))
        self.assertIn("no container can reach an engine", self.bad(found))

    def test_a_sibling_of_an_engine_socket_is_not_protected_but_its_directory_is(self):
        sibling = container("x", [bind("/var/run/other", rw=True)])
        found = self.sweep(engine(by_context={"default": [runtime(), sibling]}),
                           stat_=stat_of({"/var/run/other": 82}))
        self.assertEqual(self.bad(found), {})
        above = container("y", [bind("/var/run", rw=False)])
        self.assertOnly(self.sweep(engine(by_context={"default": [runtime(), above]})), "overlaps")


class EnginesTest(Base):

    def test_every_local_engine_is_swept(self):
        bad = container("evil", [vol("/x")])
        run = engine(contexts=[("default", "unix:///var/run/docker.sock"), ("other", "unix:///x/docker.sock")],
                     by_context={"default": [runtime()], "other": [bad]})
        self.assertIn("other/evil", str(self.assertOnly(self.sweep(run), "only ex-down mounts")))

    def test_a_remote_engine_is_left_to_its_own_host_and_named_in_the_notes(self):
        bad = container("evil", [vol("/x")])
        run = engine(contexts=[("default", "unix:///var/run/docker.sock"), ("far", "ssh://engine.example.org")],
                     by_context={"default": [runtime()], "far": [bad]})
        self.assertEqual(self.bad(self.sweep(run)), {})
        _, sx = specs()
        orig = rh.run
        rh.run = run
        self.addCleanup(setattr, rh, "run", orig)
        self.assertIn("far (ssh://engine.example.org)", " ".join(se.notes(sx)))

    def test_a_volume_query_that_fails_is_unknown_not_absent(self):
        run = engine(fail=lambda a: (1, "", "daemon error") if a[3:5] == ["volume", "ls"] else None)
        bad = self.bad(self.sweep(run))
        self.assertEqual({k: r for k, (r, _) in bad.items()}, {
            "every engine on this host can be asked": rh.UNKNOWN,
            "only ex-down mounts the volume ex-secret, read-only at /run/secrets/ex, as rendered": rh.UNKNOWN})

    def test_an_engine_that_cannot_list_is_unknown(self):
        run = engine(contexts=[("default", "unix:///var/run/docker.sock"), ("other", "unix:///x/docker.sock")],
                     fail=lambda a: (1, "", "cannot connect") if "--context" in a and "other" in a else None)
        self.assertOnly(self.sweep(run), "every engine on this host can be asked", rh.UNKNOWN)

    def test_a_socket_no_context_names_is_unknown(self):
        run = engine(contexts=[("desktop", "unix:///Users/op/.docker/run/docker.sock")],
                     by_context={"desktop": [runtime()]}, volumes=("desktop",))
        found = self.sweep(run, lstat_=lambda p: Id(1, 1, stat.S_IFSOCK | 0o660))
        self.assertOnly(found, "every engine on this host can be asked", rh.UNKNOWN)

    def test_no_contexts_at_all_is_one_unknown(self):
        run = engine(fail=lambda a: (1, "", "daemon down") if "context" in a else None)
        found = self.sweep(run)
        self.assertEqual([c.result for c in found], [rh.UNKNOWN])

    def test_on_macos_an_orb_that_cannot_be_asked_is_unknown(self):
        sx = exposure_sec()
        del sx["tools"]["orb"]
        d = full_doc()
        d[ss.SECTION] = sx
        spec_ = hs.load_spec(d)
        found = self.sweep(s=(spec_, spec_.secrets), platform="darwin")
        self.assertOnly(found, "no OrbStack machine", rh.UNKNOWN)

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

    def test_sshd_processes_and_backups_are_noted(self):
        sx = exposure_sec()
        sx["tools"].update({"sshd": "/usr/sbin/sshd", "ps": "/bin/ps", "tmutil": "/usr/bin/tmutil"})
        sx["exposure"]["backup_excluded"] = ["/Users/op/Library/Group Containers/x/data"]
        d = full_doc()
        d[ss.SECTION] = sx
        s = hs.load_spec(d).secrets

        def run(argv, **kw):
            if argv[0].endswith("sshd"):
                return rh.Proc(tuple(argv), 0, "port 22\npasswordauthentication no\ntrustedusercakeys none\n", "")
            if argv[0].endswith("/ps"):
                return rh.Proc(tuple(argv), 0, "/sbin/launchd\n/usr/local/bin/claude\nzsh\n", "")
            if argv[0].endswith("tmutil"):
                return rh.Proc(tuple(argv), 0, "[Excluded]    /Users/op/Library/Group Containers/x/data\n", "")
            return engine()(argv, **kw)
        orig = rh.run
        rh.run = run
        self.addCleanup(setattr, rh, "run", orig)
        text = "\n".join(se.notes(s))
        self.assertIn("passwordauthentication no; trustedusercakeys none", text)
        self.assertIn("agent CLIs running on this host outside containers: ['claude']", text)
        self.assertIn("[Excluded]", text)

    def test_missing_attestations_say_so(self):
        _, s = specs(attestations={})
        self.assertIn("attested native_agents: NOT RECORDED", se.notes(s))


if __name__ == "__main__":
    unittest.main()
