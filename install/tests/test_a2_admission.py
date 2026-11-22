"""Locks, the stop file, the budget read, the broker client, and the launcher
and S0 admission end to end on a staged runner host (a2fix.World).

The world's owner is this test's uid (`root_uid`), so every owner check
runs without root. Lock holders in another process are real subprocesses
holding a real `flock`.
"""

import copy
import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
import unittest

import a2fix
import a2_admit
import a2_args
import a2_budget
import a2_locks
import a2_stop
from a2_causes import Refusal

I = a2_args.Invocation


class Base(unittest.TestCase):
    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.w = a2fix.World(self.base)
        self.held = []
        self.addCleanup(self._close)

    def _close(self):
        for h in self.held:
            a2_locks.release(h)

    def refuses(self, cause, fn, *a, **kw):
        with self.assertRaises(Refusal) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.cause, cause)
        return cm.exception

    def holder(self, path):
        """A separate process holding an exclusive flock on `path`."""
        code = ("import fcntl,os,sys,time\n"
                "fd=os.open(sys.argv[1],os.O_RDONLY)\n"
                "fcntl.flock(fd,fcntl.LOCK_EX)\n"
                "sys.stdout.write('held\\n');sys.stdout.flush()\n"
                "time.sleep(60)\n")
        p = subprocess.Popen([sys.executable, "-I", "-c", code, path], stdout=subprocess.PIPE)
        self.assertEqual(p.stdout.readline(), b"held\n")
        self.addCleanup(p.stdout.close)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        return p


# ------------------------------------------------------------------ 5.3


class LockRootTest(Base):
    def check(self, **kw):
        site = self.w.site()
        args = dict(fs_type_of=site.fs_type_of, account_ids=site.account_ids)
        args.update(kw)
        hosts = kw.pop("hosts", self.w.hosts)
        args.pop("hosts", None)
        a2_locks.check_lock_root(hosts, args.pop("ident", "host-ident-0001"), os.getuid(), **args)

    def test_passes(self):
        self.check()

    def test_wrong_host_identity(self):
        self.refuses("RUNNER.LOCK_ROOT", self.check, ident="other-ident-0001")
        self.refuses("RUNNER.LOCK_ROOT", self.check, ident=None)

    def test_mode(self):
        os.chmod(self.w.root, 0o775)
        self.refuses("RUNNER.LOCK_ROOT", self.check)

    def test_owner(self):
        site = self.w.site()
        self.refuses("RUNNER.LOCK_ROOT", a2_locks.check_lock_root, self.w.hosts, "host-ident-0001",
                     os.getuid() + 1, fs_type_of=site.fs_type_of, account_ids=site.account_ids)

    def test_not_realpath(self):
        link = os.path.join(self.base, "link")
        os.symlink(self.w.root, link)
        h = copy.deepcopy(self.w.hosts)
        h["runner"]["lock_root"] = link
        self.refuses("RUNNER.LOCK_ROOT", self.check, hosts=h)

    def test_not_realpath_through_a_symlinked_parent(self):
        os.symlink(self.base, os.path.join(self.base, "via"))
        h = copy.deepcopy(self.w.hosts)
        h["runner"]["lock_root"] = os.path.join(self.base, "via", "locks")
        self.assertTrue(os.path.isdir(h["runner"]["lock_root"]))
        self.refuses("RUNNER.LOCK_ROOT", self.check, hosts=h)

    def test_parent_writable_by_an_account(self):
        me = os.getuid()
        self.refuses("RUNNER.LOCK_ROOT", self.check,
                     account_ids=lambda n: (me, {me}))

    def test_parent_world_writable(self):
        os.chmod(self.base, 0o757)
        self.refuses("RUNNER.LOCK_ROOT", self.check)

    def test_filesystem_not_on_allow_list(self):
        self.refuses("RUNNER.LOCK_ROOT", self.check, fs_type_of=lambda p: "nfs")
        self.refuses("RUNNER.LOCK_ROOT", self.check, fs_type_of=lambda p: None)

    def test_fs_type_reads_mountinfo(self):
        mi = os.path.join(self.base, "mountinfo")
        with open(mi, "w") as f:
            f.write("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                    "23 22 0:5 / /srv rw - nfs4 server:/x rw\n"
                    "24 22 0:6 / /srv2 rw shared:1 - xfs /dev/sdb rw\n")
        self.assertEqual(a2_locks.fs_type("/srv/locks", mi), "nfs4")
        self.assertEqual(a2_locks.fs_type("/srv2/l", mi), "xfs")
        self.assertEqual(a2_locks.fs_type("/srvx/l", mi), "ext4")
        self.assertIsNone(a2_locks.fs_type("/x", os.path.join(self.base, "absent")))


class TargetsTest(Base):
    def test_scope_and_destroy(self):
        h = self.w.hosts
        self.assertEqual([v["name"] for v in a2_locks.run_vms(h, I("install", "L2", {}), "loop")],
                         ["vm-a-t", "vm-b-t"])
        self.assertEqual([v["name"] for v in a2_locks.run_vms(h, I("install", "L3", {}), "l3")],
                         ["vm-a"])
        self.assertEqual(len(a2_locks.run_vms(h, I("destroy", None, {}), "l3")), 3)
        d = copy.deepcopy(h)
        d["destroy_deny"] = ["vm-a"]
        self.assertEqual([v["name"] for v in a2_locks.run_vms(d, I("destroy", None, {}), "l3")],
                         ["vm-a-t", "vm-b-t"])

    def test_destroy_refuses_an_unconfigured_or_malformed_deny_list(self):
        """Absent is UNCONFIGURED (6.2): RUNNER.DESTROY_DENY. A malformed list
        is refused by L3 first; run_vms checks again where destroy relies on it."""
        for bad in (None, ["vm-a", "vm-a"], ["nope"], [1], ("vm-a",)):
            with self.subTest(bad=bad):
                d = copy.deepcopy(self.w.hosts)
                if bad is None:
                    del d["destroy_deny"]
                else:
                    d["destroy_deny"] = bad
                e = self.refuses("RUNNER.DESTROY_DENY", a2_locks.run_vms, d, I("destroy", None, {}), "l3")
                self.assertEqual(e.rc, 2)
        # Other commands never read it.
        d = copy.deepcopy(self.w.hosts)
        del d["destroy_deny"]
        self.assertEqual(len(a2_locks.run_vms(d, I("install", "L2", {}), "loop")), 2)

    def test_destroy_without_deny_list_refuses_at_the_launcher_before_any_lock(self):
        l3 = a2fix.hosts_doc(self.w.root, loop_account="loop-runner", l3_account=a2fix.ME.pw_name)
        del l3["destroy_deny"]
        self.w.hosts = l3
        self.w.write_private()
        self.holder(a2_locks.lock_path(self.w.root, "hv"))
        import a2_admit
        self.refuses("RUNNER.DESTROY_DENY", a2_admit.launch, ["--destroy"], self.w.site())

    def test_sorted_by_utf8_and_duplicates_refuse(self):
        h = copy.deepcopy(self.w.hosts)
        t = a2_locks.targets(h, h["vms"])
        self.assertEqual(t, sorted(t, key=lambda s: s.encode()))
        self.assertIn("vm:300", t)
        h["hub"]["name"] = "vm-a"
        self.refuses("RUNNER.HOSTS_TARGETS", a2_locks.targets, h, h["vms"])

    def test_names_distinct_across_the_whole_file(self):
        h = copy.deepcopy(self.w.hosts)
        a2_locks.check_names_distinct(h)
        for mut in (lambda d: d["vms"][2].__setitem__("name", d["hub"]["name"]),
                    lambda d: d["vms"][2].__setitem__("name", d["hypervisor"]["name"]),
                    lambda d: d["hub"].__setitem__("name", d["hypervisor"]["name"])):
            d = copy.deepcopy(self.w.hosts)
            mut(d)
            self.refuses("RUNNER.HOSTS_TARGETS", a2_locks.check_names_distinct, d)

    def test_key(self):
        import hashlib
        self.assertEqual(a2_locks.target_key("hv"), hashlib.sha256(b"hv\n").hexdigest())

    def test_order_runner_lock_first_only_when_writing(self):
        o = a2_locks.lock_order(self.w.root, ["a", "b"], True)
        self.assertEqual(o[0][0], "runner.lock")
        o = a2_locks.lock_order(self.w.root, ["a", "b"], False)
        self.assertNotIn("runner.lock", [x[0] for x in o])


class AcquireTest(Base):
    def order(self, writes=True):
        vms = [v for v in self.w.hosts["vms"] if v["scope"] == "loop"]
        return a2_locks.lock_order(self.w.root, a2_locks.targets(self.w.hosts, vms), writes)

    def test_acquire_inheritable_and_exclusive(self):
        h = a2_locks.acquire(self.order(), os.getuid())
        self.held.append(h)
        self.assertTrue(all(os.get_inheritable(fd) for fd in h.values()))
        self.refuses("RUNNER.TARGET_LOCKED", a2_locks.acquire, self.order(), os.getuid())

    def test_all_or_nothing_and_names_target_not_holder(self):
        order = self.order()
        label, path = order[-1]
        self.holder(path)
        e = self.refuses("RUNNER.TARGET_LOCKED", a2_locks.acquire, order, os.getuid())
        self.assertEqual(e.detail, "target: " + label)
        # Nothing taken stayed held: every other lock is free.
        h = a2_locks.acquire(order[:-1], os.getuid())
        self.held.append(h)

    def test_missing_or_misowned_lock_file(self):
        order = self.order()
        os.chmod(order[1][1], 0o664)
        self.refuses("RUNNER.LOCK_ROOT", a2_locks.acquire, order, os.getuid())
        os.chmod(order[1][1], 0o644)
        self.refuses("RUNNER.LOCK_ROOT", a2_locks.acquire, order, os.getuid() + 1)
        os.unlink(order[1][1])
        self.refuses("RUNNER.LOCK_ROOT", a2_locks.acquire, order, os.getuid())

    def test_symlink_lock_file_refused(self):
        order = self.order()
        p = order[1][1]
        os.unlink(p)
        os.symlink(order[2][1], p)
        self.refuses("RUNNER.LOCK_ROOT", a2_locks.acquire, order, os.getuid())

    def test_destroy_vs_a_loop_vm_lock_only(self):
        """5.1a review test: a destroy whose targets include a loop VM
        refuses while a test process holds only that VM's name and
        vm:<vm_id> lock files, not the hypervisor's."""
        self.holder(a2_locks.lock_path(self.w.root, "vm-a-t"))
        self.holder(a2_locks.lock_path(self.w.root, "vm:300"))
        vms = a2_locks.run_vms(self.w.hosts, I("destroy", None, {}), "l3")
        order = a2_locks.lock_order(self.w.root, a2_locks.targets(self.w.hosts, vms), True)
        e = self.refuses("RUNNER.TARGET_LOCKED", a2_locks.acquire, order, os.getuid())
        self.assertIn(e.detail, ("target: vm-a-t", "target: vm:300"))


class FindHeldTest(Base):
    def order(self):
        vms = [v for v in self.w.hosts["vms"] if v["scope"] == "loop"]
        return a2_locks.lock_order(self.w.root, a2_locks.targets(self.w.hosts, vms), True)

    def test_held_by_this_description(self):
        h = a2_locks.acquire(self.order(), os.getuid())
        self.held.append(h)
        got = a2_locks.find_held(self.order(), os.getuid())
        self.assertEqual(set(got), set(h))
        self.assertEqual(a2_locks.custody_locks(self.order(), got, os.getuid()), "held")

    def test_open_but_not_locked_refuses(self):
        fds = {}
        for label, path in self.order():
            fds[label] = os.open(path, os.O_RDONLY)
        self.held.append(fds)
        self.refuses("RUNNER.ADMISSION", a2_locks.find_held, self.order(), os.getuid())

    def test_not_open_refuses(self):
        self.refuses("RUNNER.ADMISSION", a2_locks.find_held, self.order(), os.getuid())

    def test_one_missing_descriptor_refuses(self):
        order = self.order()
        h = a2_locks.acquire(order, os.getuid())
        self.held.append(h)
        os.close(h.pop(order[-1][0]))
        self.refuses("RUNNER.ADMISSION", a2_locks.find_held, order, os.getuid())

    def test_held_by_another_process_refuses(self):
        order = self.order()
        label, path = order[-1]
        fds = {}
        for lb, p in order[:-1]:
            fds[lb] = os.open(p, os.O_RDONLY)
            fcntl.flock(fds[lb], fcntl.LOCK_EX | fcntl.LOCK_NB)
        fds[label] = os.open(path, os.O_RDONLY)
        self.held.append(fds)
        self.holder(path)
        self.refuses("RUNNER.ADMISSION", a2_locks.find_held, order, os.getuid())

    def test_adopt_makes_held_fds_non_inheritable_and_closes_strays(self):
        order = self.order()
        h = a2_locks.acquire(order, os.getuid())
        self.held.append(h)
        stray = os.open(os.path.join(self.w.root, "runner.lock"), os.O_RDONLY)
        other = os.open(os.path.join(self.base, "private", "alpha2.lock"), os.O_RDONLY)
        self.addCleanup(lambda: os.close(other))
        dup = os.dup(h[order[1][0]])        # a second fd on a held lock file is a stray too
        got = a2_locks.find_held(order, os.getuid())
        a2_locks.adopt(got, self.w.root)
        self.assertTrue(all(not os.get_inheritable(fd) for fd in got.values()))
        for fd in (stray, dup):
            with self.assertRaises(OSError):
                os.fstat(fd)
        os.fstat(other)                      # outside the lock root: untouched
        self.assertEqual(a2_locks.custody_locks(order, got, os.getuid()), "held")

    def test_fd_dir_unreadable_refuses(self):
        self.refuses("RUNNER.ADMISSION", a2_locks.find_held, self.order(), os.getuid(),
                     os.path.join(self.base, "absent"))

    def test_custody_lost(self):
        order = self.order()
        h = a2_locks.acquire(order, os.getuid())
        self.held.append(h)
        fd = h[order[1][0]]
        os.close(fd)
        self.assertEqual(a2_locks.custody_locks(order, h, os.getuid()), "lost")

    def test_custody_inode_replaced(self):
        order = self.order()
        h = a2_locks.acquire(order, os.getuid())
        self.held.append(h)
        p = order[1][1]
        os.unlink(p)
        with open(p, "wb"):
            pass
        os.chmod(p, 0o644)
        self.assertEqual(a2_locks.custody_locks(order, h, os.getuid()), "lost")


# ----------------------------------------------------------- stop file


class StopTest(Base):
    def stop(self, *parts):
        return os.path.join(self.w.root, "stop.d", *parts)

    def test_unset(self):
        self.assertEqual(a2_stop.read(self.w.root), "unset")

    def test_permit_files_are_not_stops_while_regular(self):
        for n in ("permit.json", ".permit-next.json"):
            open(self.stop("monitor", n), "w").close()
        self.assertEqual(a2_stop.read(self.w.root), "unset")
        os.unlink(self.stop("monitor", "permit.json"))
        os.mkdir(self.stop("monitor", "permit.json"))
        self.assertEqual(a2_stop.read(self.w.root), "set")

    def test_each_setter_and_dotfiles(self):
        for s in ("operator", "controller", "monitor"):
            p = self.stop(s, ".x")
            open(p, "w").close()
            self.assertEqual(a2_stop.read(self.w.root), "set", s)
            os.unlink(p)

    def test_permit_name_under_another_setter_is_a_stop(self):
        open(self.stop("operator", "permit.json"), "w").close()
        self.assertEqual(a2_stop.read(self.w.root), "set")

    def test_extra_top_entry_missing_and_not_dir(self):
        open(self.stop("extra"), "w").close()
        self.assertEqual(a2_stop.read(self.w.root), "set")
        os.unlink(self.stop("extra"))
        os.rmdir(self.stop("controller"))
        self.assertEqual(a2_stop.read(self.w.root), "set")
        open(self.stop("controller"), "w").close()
        self.assertEqual(a2_stop.read(self.w.root), "set")
        shutil.rmtree(self.stop())
        self.assertEqual(a2_stop.read(self.w.root), "set")

    def test_unlistable_is_unobserved(self):
        if os.getuid() == 0:
            self.skipTest("root lists any directory")
        os.chmod(self.stop("monitor"), 0o000)
        self.addCleanup(os.chmod, self.stop("monitor"), 0o755)
        self.assertEqual(a2_stop.read(self.w.root), "UNOBSERVED")

    def test_applies(self):
        self.assertTrue(a2_stop.applies(I("install", "L2", {})))
        self.assertTrue(a2_stop.applies(I("destroy", None, {})))
        self.assertFalse(a2_stop.applies(I("install", "L3", {})))
        self.assertFalse(a2_stop.applies(I("install", None, {})))
        self.assertFalse(a2_stop.applies(I("verify", None, {})))


# -------------------------------------------------------------- budget


class BudgetReadTest(Base):
    RID = "20261116T010203Z-0a0b0c0d"

    def bd(self):
        return os.path.join(self.w.root, "budget.d")

    def unobserved(self):
        with self.assertRaises(a2_budget.Unobserved):
            a2_budget.read_budget(self.bd(), os.getuid())

    def test_reads_a_record(self):
        sha = a2fix.write_record(self.w, "loop", a2fix.record(self.RID))
        got = a2_budget.read_budget(self.bd(), os.getuid())
        self.assertEqual(got[self.RID][0], "loop")
        self.assertEqual(got[self.RID][2], sha)

    def test_tmp_names_ignored(self):
        a2fix.write_record(self.w, "loop", {"junk": 1}, name=".tmp-x")
        self.assertEqual(a2_budget.read_budget(self.bd(), os.getuid()), {})

    def test_rules(self):
        cases = [
            lambda: a2fix.write_record(self.w, "loop", a2fix.record(self.RID), name="other.json"),
            lambda: a2fix.write_record(self.w, "loop", a2fix.record(self.RID), mode=0o664),
            lambda: a2fix.write_record(self.w, "loop", dict(a2fix.record(self.RID), extra=1)),
            lambda: a2fix.write_record(self.w, "loop", dict(a2fix.record(self.RID), kind="stop")),
            lambda: a2fix.write_record(self.w, "loop", a2fix.record(self.RID),
                                       name="start-20261116T010203Z-ffffffff.json"),
            lambda: (a2fix.write_record(self.w, "loop", a2fix.record(self.RID)),
                     a2fix.write_record(self.w, "l3", a2fix.record(self.RID))),
            lambda: os.mkdir(os.path.join(self.bd(), "extra")),
            lambda: os.chmod(os.path.join(self.bd(), "l3"), 0o775),
            lambda: shutil.rmtree(os.path.join(self.bd(), "l3")),
            lambda: (a2fix.write_record(self.w, "loop", a2fix.record(self.RID)),
                     os.link(os.path.join(self.bd(), "loop", "start-" + self.RID + ".json"),
                             os.path.join(self.bd(), "loop", ".tmp-link"))),
        ]
        for i, mk in enumerate(cases):
            with self.subTest(i=i):
                shutil.rmtree(self.bd())
                os.mkdir(self.bd(), 0o755)
                for s in ("loop", "l3"):
                    os.mkdir(os.path.join(self.bd(), s), 0o755)
                    os.chmod(os.path.join(self.bd(), s), 0o755)
                mk()
                self.unobserved()

    def test_calendar_invalid_started_at_is_unobserved(self):
        a2fix.write_record(self.w, "loop", a2fix.record(self.RID, started="2026-13-45T99:99:99Z"))
        self.unobserved()

    def test_record_symlink_not_followed(self):
        real = a2fix.record(self.RID)
        a2fix.write_record(self.w, "loop", real, name=".tmp-real")
        os.symlink(".tmp-real", os.path.join(self.bd(), "loop", "start-" + self.RID + ".json"))
        self.unobserved()

    def test_record_read_to_eof(self):
        from unittest import mock
        a2fix.write_record(self.w, "loop", a2fix.record(self.RID))
        real_read = os.read
        with mock.patch.object(a2_budget.os, "read", lambda fd, n: real_read(fd, min(n, 5))):
            self.assertIn(self.RID, a2_budget.read_budget(self.bd(), os.getuid()))

    def test_owner(self):
        a2fix.write_record(self.w, "loop", a2fix.record(self.RID))
        with self.assertRaises(a2_budget.Unobserved):
            a2_budget.read_budget(self.bd(), os.getuid() + 1)


class StartRecordTest(Base):
    RID = "20261116T010203Z-0a0b0c0d"

    def check(self, rec_over=None, account="loop", inv=None, now=None, sub="loop"):
        rec = a2fix.record(self.RID, started="2026-11-16T01:02:03Z")
        rec.update(rec_over or {})
        a2fix.write_record(self.w, sub, rec)
        return a2_budget.check_start_record(
            os.path.join(self.w.root, "budget.d"), account, self.RID, inv or I("install", "L2", {}),
            a2fix.H64, a2fix.H64, "c" * 64,
            now=1794790923 + 10 if now is None else now, root_uid=os.getuid())

    def test_binds(self):
        import calendar
        self.assertEqual(calendar.timegm(time.strptime("2026-11-16T01:02:03Z", "%Y-%m-%dT%H:%M:%SZ")),
                         1794790923)
        self.assertEqual(len(self.check()), 64)

    def test_each_binding(self):
        for over, kw in [({"command": "destroy"}, {}), ({"loop": "L3"}, {}),
                         ({"lock_sha256": "d" * 64}, {}), ({"hosts_sha256": "d" * 64}, {}),
                         ({"installer_sha256": "d" * 64}, {}), ({}, {"account": "l3"}),
                         ({}, {"now": 1794790923 + 61}), ({}, {"now": 1794790923 - 1})]:
            with self.subTest(over=over, kw=kw):
                for s in ("loop", "l3"):
                    d = os.path.join(self.w.root, "budget.d", s)
                    for n in os.listdir(d):
                        os.unlink(os.path.join(d, n))
                self.refuses("RUNNER.ADMISSION", self.check, over, **kw)

    def test_missing_record_and_unobserved_read(self):
        self.refuses("RUNNER.ADMISSION", a2_budget.check_start_record,
                     os.path.join(self.w.root, "budget.d"), "loop", self.RID, I("install", "L2", {}),
                     a2fix.H64, a2fix.H64, "c" * 64, now=0, root_uid=os.getuid())
        os.mkdir(os.path.join(self.w.root, "budget.d", "junk"))
        self.refuses("PREFLIGHT.BUDGET", a2_budget.check_start_record,
                     os.path.join(self.w.root, "budget.d"), "loop", self.RID, I("install", "L2", {}),
                     a2fix.H64, a2fix.H64, "c" * 64, now=0, root_uid=os.getuid())


class BrokerClientTest(Base):
    def ask(self, **kw):
        return a2_budget.ask_broker(self.w.root, I("install", "L2", {}), a2fix.H64, a2fix.H64,
                                    "c" * 64, root_uid=kw.pop("root_uid", os.getuid()), **kw)

    def test_request_shape_and_answer(self):
        b = a2fix.FakeBroker(self.w)
        self.addCleanup(b.close)
        rid, sha = self.ask()
        self.assertEqual(b.requests[0], {"command": "install", "loop": "L2", "lock_sha256": a2fix.H64,
                                         "hosts_sha256": a2fix.H64, "installer_sha256": "c" * 64})
        self.assertIn(rid, a2_budget.read_budget(os.path.join(self.w.root, "budget.d"), os.getuid()))

    def test_unreachable(self):
        self.refuses("PREFLIGHT.BUDGET", self.ask)

    def test_not_a_socket(self):
        open(os.path.join(self.w.root, "budget.sock"), "w").close()
        self.refuses("PREFLIGHT.BUDGET", self.ask)

    def test_peer_not_root(self):
        b = a2fix.FakeBroker(self.w)
        self.addCleanup(b.close)
        os.lchown  # the socket owner check uses the same uid; give a different expected owner
        self.refuses("PREFLIGHT.BUDGET", self.ask, root_uid=os.getuid() + 1)

    def test_socket_owner_check_alone(self):
        import types
        sock_mode = 0o140755
        st = types.SimpleNamespace(st_mode=sock_mode, st_uid=0)
        self.assertTrue(a2_budget.socket_owner_ok(st, 0))
        self.assertFalse(a2_budget.socket_owner_ok(types.SimpleNamespace(st_mode=sock_mode, st_uid=5), 0))
        self.assertFalse(a2_budget.socket_owner_ok(types.SimpleNamespace(st_mode=0o100644, st_uid=0), 0))

    def test_peer_check_alone(self):
        import struct
        self.assertTrue(a2_budget.peer_ok(struct.pack("iII", 10, 0, 0), 0))
        self.assertFalse(a2_budget.peer_ok(struct.pack("iII", 10, 7, 0), 0))
        self.assertFalse(a2_budget.peer_ok(struct.pack("iII", 10, 2 ** 32 - 1, 0), 0))

    def test_socket_owner_check_is_applied(self):
        """With the peer check forced to pass, the socket-owner check alone
        must still refuse a socket not owned by root."""
        from unittest import mock
        b = a2fix.FakeBroker(self.w)
        self.addCleanup(b.close)
        with mock.patch.object(a2_budget, "peer_ok", lambda cred, uid: True):
            self.refuses("PREFLIGHT.BUDGET", self.ask, root_uid=os.getuid() + 1)

    def test_peer_check_is_applied(self):
        """With the socket-owner check forced to pass, the peer check alone
        must still refuse a peer that is not root."""
        from unittest import mock
        b = a2fix.FakeBroker(self.w)
        self.addCleanup(b.close)
        with mock.patch.object(a2_budget, "socket_owner_ok", lambda st, uid: True):
            self.refuses("PREFLIGHT.BUDGET", self.ask, root_uid=os.getuid() + 1)

    def test_hung(self):
        b = a2fix.FakeBroker(self.w, delay=3)
        self.addCleanup(b.close)
        t0 = time.monotonic()
        # A timeout after the send is a late answer: unknown outcome.
        self.refuses("RUNNER.NOT_STARTED", self.ask, bound_s=0.5)
        self.assertLess(time.monotonic() - t0, 2.5)

    def test_bad_answers(self):
        for ans in (b"", b"{}", b'{"run_id": "x", "sha256": "y"}', b"not json",
                    b'{"run_id": "20261116T010203Z-0a0b0c0d", "sha256": "y"}',
                    b'{"run_id": "20261116T010203Z-0a0b0c0d", "sha256": "' + b"a" * 64 + b'", "x": 1}',
                    b"x" * 5000):
            with self.subTest(ans=ans[:20]):
                b = a2fix.FakeBroker(self.w, answer=ans)
                try:
                    # Sent, then a lost or malformed answer: unknown outcome.
                    self.refuses("RUNNER.NOT_STARTED", self.ask)
                finally:
                    b.close()

    def test_explicit_refusal_is_budget(self):
        b = a2fix.FakeBroker(self.w, answer=b'{"refused": true}')
        self.addCleanup(b.close)
        self.refuses("PREFLIGHT.BUDGET", self.ask)

    def test_refusal_lookalikes_are_not_refusals(self):
        for ans in (b'{"refused": 1}', b'{"refused": false}', b'{"refused": true, "x": 1}'):
            with self.subTest(ans=ans):
                b = a2fix.FakeBroker(self.w, answer=ans)
                try:
                    self.refuses("RUNNER.NOT_STARTED", self.ask)
                finally:
                    b.close()

    def test_closed_after_publishing_is_not_started_and_the_record_counts(self):
        """A broker that publishes and then closes without an answer: the
        launcher cannot tell, so NOT_STARTED, and the record stays counted."""
        b = a2fix.FakeBroker(self.w, close_after_publish=True)
        self.addCleanup(b.close)
        self.refuses("RUNNER.NOT_STARTED", self.ask)
        self.assertEqual(len(a2_budget.read_budget(os.path.join(self.w.root, "budget.d"), os.getuid())), 1)

    def test_no_byte_sent_is_budget(self):
        """Before any byte is sent: unreachable, wrong owner, wrong peer."""
        self.refuses("PREFLIGHT.BUDGET", self.ask)
        b = a2fix.FakeBroker(self.w)
        self.addCleanup(b.close)
        self.refuses("PREFLIGHT.BUDGET", self.ask, root_uid=os.getuid() + 1)
        self.assertEqual(b.requests, [])

    def test_client_socket_is_close_on_exec(self):
        import socket
        from unittest import mock
        b = a2fix.FakeBroker(self.w)
        self.addCleanup(b.close)
        seen = []
        real = socket.socket

        def spy(*a, **k):
            s = real(*a, **k)
            seen.append(os.get_inheritable(s.fileno()))
            return s
        with mock.patch.object(a2_budget.socket, "socket", spy):
            self.ask()
        # The first socket made is the client's (the fake broker's accept
        # makes the later ones); none is inheritable.
        self.assertTrue(seen)
        self.assertFalse(seen[0])


# ------------------------------------------------- launcher and S0


class EndToEndTest(Base):
    """The launcher takes the locks, asks the broker and 'execs' (captured);
    S0 then admits in the same process, which still holds the descriptors
    exactly as an exec would have left them."""

    def launch_then_admit(self, argv, site=None, broker=True, sub="loop"):
        site = site or self.w.site()
        if broker:
            b = a2fix.FakeBroker(self.w, sub=sub)
            self.addCleanup(b.close)
        args, held, _wrote = a2_admit.prepare_launch(argv, site)
        self.held.append(held)
        self.assertEqual(args[:4], [site.interpreter, "-I", "-B", site.entry])
        self.assertEqual(args[4:6], ["--runner", "--run-id"])
        self.assertEqual(args[7:], argv)
        rid = args[6]
        c = a2_admit.admit(rid, args[7:], site)
        self.held.append(c.held)
        self.addCleanup(os.close, c.run_fd)
        return c, rid

    def test_loop_l2_admitted_with_broker_record(self):
        c, rid = self.launch_then_admit(["--loop", "L2"])
        self.assertEqual(c.run_id, rid)
        self.assertEqual(len(c.admission_sha), 64)
        self.assertTrue(os.path.isdir(os.path.join(self.w.home, "alpha2-work", "runs", rid, "receipts")))

    def test_non_writing_command_needs_no_broker(self):
        c, rid = self.launch_then_admit(["--verify"], broker=False)
        self.assertIsNone(c.admission_sha)
        self.assertNotIn("runner.lock", c.held)

    def test_second_admission_of_same_run_id_refuses(self):
        c, rid = self.launch_then_admit(["--loop", "L2"])
        self.refuses("RUNNER.RUN_DIR", a2_admit.admit, rid, ["--loop", "L2"], self.w.site())

    def test_failed_exec_after_the_broker_wrote_is_not_started_and_the_record_stays(self):
        b = a2fix.FakeBroker(self.w)
        self.addCleanup(b.close)
        def failing(path, args, env):
            raise OSError("exec failed")
        site = self.w.site(execve=failing)
        e = self.refuses("RUNNER.NOT_STARTED", a2_admit.launch, ["--loop", "L2"], site)
        self.assertEqual(e.rc, 2)
        self.assertTrue(e.detail.startswith("run id: "))
        # The fake broker stands in for the broker's side, the permit included.
        recs = a2_budget.read_budget(os.path.join(self.w.root, "budget.d"), os.getuid())
        self.assertEqual(len(recs), 1)
        (rid, (sub, rec, sha)), = recs.items()
        self.assertEqual((sub, rec["command"], rec["loop"]), ("loop", "install", "L2"))
        # Unchanged since publication: the sha the broker answered with.
        self.assertEqual(b.answers, [(rid, sha)])
        # The locks are released: every lock of that run can be taken again.
        vms = a2_locks.run_vms(self.w.hosts, I("install", "L2", {}), "loop")
        order = a2_locks.lock_order(self.w.root, a2_locks.targets(self.w.hosts, vms), True)
        a2_locks.release(a2_locks.acquire(order, os.getuid()))
        e = self.refuses("RUNNER.NOT_STARTED", a2_admit.launch, ["--verify"], self.w.site(execve=failing))
        self.assertEqual(e.rc, 2)

    def test_any_exec_exception_is_not_started(self):
        def failing(path, args, env):
            raise ValueError("embedded null byte")
        self.refuses("RUNNER.NOT_STARTED", a2_admit.launch, ["--verify"], self.w.site(execve=failing))
        a2_locks.release(a2_locks.acquire(a2_locks.lock_order(self.w.root, ["hv"], False), os.getuid()))

    def test_launch_execs_with_launch_env_and_a_returning_exec_releases(self):
        site = self.w.site()
        self.refuses("RUNNER.NOT_STARTED", a2_admit.launch, ["--verify"], site)
        path, args, env = site.exec_calls[0]
        self.assertEqual(path, site.interpreter)
        self.assertEqual(env, dict(site.environ))
        h = a2_locks.acquire(a2_locks.lock_order(self.w.root, ["hv"], False), os.getuid())
        a2_locks.release(h)

    def test_refusal_lines_pass_the_output_guard(self):
        """3.3: the reporter is the guarded writer. A held value in a
        refusal's detail is never printed; the report becomes
        RUNNER.OUTPUT_GUARD."""
        import io
        import a2_guard
        import a2_main
        self.holder(a2_locks.lock_path(self.w.root, "hv"))
        site = self.w.site()
        site.guard = a2_guard.OutputGuard()
        site.guard.hold(bytearray(b"target: hv"))
        site.out = io.StringIO()
        rc = a2_main.main(["--loop", "L2"], site.installer_sha, site.entry, site)
        text = site.out.getvalue()
        self.assertEqual(rc, 2)
        self.assertNotIn("target: hv", text)
        self.assertEqual(text.splitlines()[0], "CAUSE=RUNNER.OUTPUT_GUARD")

    def test_a_held_value_in_every_line_prints_nothing(self):
        import io
        import a2_guard
        import a2_main
        site = self.w.site(private_dir=None)
        site.guard = a2_guard.OutputGuard()
        site.guard.hold(bytearray(b"Look at"))
        site.out = io.StringIO()
        rc = a2_main.main(["--loop", "L2"], site.installer_sha, site.entry, site)
        self.assertEqual((rc, site.out.getvalue()), (2, ""))

    def test_an_l1_that_runs_s6_or_later_without_s3_is_refused_before_anything_runs(self):
        """Ruling W5-R13-L1-STAGESET-REQUIRED, through the launcher: the refusal comes before the private files are
        read, any lock is taken or the runner is executed, so no stage, S6 or later included, writes a receipt."""
        for argv in (["--only", "S6"], ["--only", "S6b"], ["--only", "S9"], ["--from", "S4"], ["--from", "S5"],
                     ["--from", "S6"], ["--from", "S10"]):
            with self.subTest(argv=argv):
                site = self.w.site()
                self.refuses("RUNNER.STAGE_SET", a2_admit.launch, argv, site)
                self.assertEqual(site.exec_calls, [])
                self.assertFalse(os.path.exists(os.path.join(self.w.home, "alpha2-work", "runs")) and any(
                    os.listdir(os.path.join(self.w.home, "alpha2-work", "runs"))))

    def test_launcher_refuses_while_another_run_holds_a_target(self):
        self.holder(a2_locks.lock_path(self.w.root, "hv"))
        self.refuses("RUNNER.TARGET_LOCKED", a2_admit.launch, ["--loop", "L2"], self.w.site())

    def test_launcher_refusals(self):
        w = self.w
        cases = [
            ("RUNNER.ENV", ["--loop", "L2"], dict(environ=dict(w.site().environ, X="1"))),
            ("RUNNER.ARGS", ["--loop", "L4"], {}),
            ("PREFLIGHT.PRIVATE_SOURCE", ["--loop", "L2"], dict(private_dir=None)),
            ("RUNNER.ACCOUNT", ["--loop", "L3"], {}),
            ("RUNNER.LOCK_ROOT", ["--loop", "L2"], dict(host_identity=lambda: "other-ident-01")),
            ("PREFLIGHT.HANDOFF", ["--loop", "L2"], dict(loop_tasks=lambda h: "UNOBSERVED")),
            ("PREFLIGHT.HANDOFF", ["--loop", "L2"], dict(loop_tasks=lambda h: "present")),
            ("PREFLIGHT.BUDGET", ["--loop", "L2"], dict(usage_path=None)),
            ("PREFLIGHT.BUDGET", ["--loop", "L2"], dict(usage_path="a", usage_read=lambda h: 80)),
            ("PREFLIGHT.BUDGET", ["--loop", "L2"], dict(usage_path="a", usage_read=lambda h: "UNOBSERVED")),
            ("PREFLIGHT.BUDGET", ["--loop", "L2"], dict(usage_path="a", usage_read=lambda h: True)),
        ]
        b = a2fix.FakeBroker(w)
        self.addCleanup(b.close)
        for cause, argv, over in cases:
            with self.subTest(cause=cause, over=sorted(over)):
                site = w.site(**over)
                self.refuses(cause, a2_admit.launch, argv, site)
                self.assertEqual(site.exec_calls, [])
                # A refusal holds no lock afterwards.
                h = a2_locks.acquire(a2_locks.lock_order(w.root, ["hv"], True), os.getuid())
                a2_locks.release(h)

    def test_usage_below_80_is_admitted_and_80_is_not(self):
        b = a2fix.FakeBroker(self.w)
        self.addCleanup(b.close)
        site = self.w.site(usage_path="a", usage_read=lambda h: 79)
        args, held, _wrote = a2_admit.prepare_launch(["--loop", "L2"], site)
        a2_locks.release(held)
        self.refuses("PREFLIGHT.BUDGET", a2_admit.prepare_launch, ["--loop", "L2"],
                     self.w.site(usage_path="a", usage_read=lambda h: 80))

    def test_broker_absent_refuses(self):
        self.refuses("PREFLIGHT.BUDGET", a2_admit.launch, ["--loop", "L2"], self.w.site())

    def test_stop_file_refuses_loop_run_but_not_l3(self):
        open(os.path.join(self.w.root, "stop.d", "controller", "stop"), "w").close()
        self.refuses("PREFLIGHT.HANDOFF", a2_admit.launch, ["--loop", "L2"], self.w.site())

    def test_l3_account_paths(self):
        l3 = a2fix.hosts_doc(self.w.root, loop_account="loop-runner", l3_account=a2fix.ME.pw_name)
        self.w.hosts = l3
        self.w.write_private()
        site = self.w.site()
        # The arm gate: closed, unobserved, or too little time left.
        for gate in ("closed", "UNOBSERVED", ("open", 10), ("closed", 100000)):
            with self.subTest(gate=gate):
                self.refuses("PREFLIGHT.HANDOFF", a2_admit.launch, ["--loop", "L3"],
                             self.w.site(arm_gate=lambda h, g=gate: g))
        self.refuses("PREFLIGHT.HANDOFF", a2_admit.launch, ["--loop", "L3"],
                     self.w.site(full_run_bound_s=None))
        self.refuses("RUNNER.ENV", a2_admit.launch, ["--loop", "L3"],
                     self.w.site(environ=dict(site.environ, SSH_AUTH_SOCK="/agent")))
        # A set stop file does not apply to the operator's run.
        open(os.path.join(self.w.root, "stop.d", "controller", "stop"), "w").close()
        c, rid = self.launch_then_admit(["--loop", "L3"], sub="l3")
        self.assertEqual(c.account, "l3")
        self.assertEqual(len(c.admission_sha), 64)

    def test_destroy_reads_stop_file_and_gate(self):
        l3 = a2fix.hosts_doc(self.w.root, loop_account="loop-runner", l3_account=a2fix.ME.pw_name)
        self.w.hosts = l3
        self.w.write_private()
        self.refuses("PREFLIGHT.HANDOFF", a2_admit.launch, ["--destroy"],
                     self.w.site(arm_gate=lambda h: "closed"))
        open(os.path.join(self.w.root, "stop.d", "operator", "stop"), "w").close()
        self.refuses("PREFLIGHT.HANDOFF", a2_admit.launch, ["--destroy"], self.w.site())

    def test_l3_vm_named_like_the_hub_refuses_a_loop_run(self):
        """The l3 entry is outside a loop run's scope; the file-wide rule
        still refuses it, at the launcher."""
        h = copy.deepcopy(self.w.hosts)
        h["vms"][2]["name"] = h["hub"]["name"]
        self.w.write_private(hosts_raw=a2fix.dumps(h))
        self.refuses("RUNNER.HOSTS_TARGETS", a2_admit.launch, ["--loop", "L2"], self.w.site())

    def test_malformed_gate_answer_is_handoff(self):
        l3 = a2fix.hosts_doc(self.w.root, loop_account="loop-runner", l3_account=a2fix.ME.pw_name)
        self.w.hosts = l3
        self.w.write_private()
        for gate in (("open",), ("open", None), ("open", True), ("open", -1), ["open", 99999],
                     ("open", 99999, 1), ("open", 1.5e9)):
            with self.subTest(gate=gate):
                self.refuses("PREFLIGHT.HANDOFF", a2_admit.launch, ["--loop", "L3"],
                             self.w.site(arm_gate=lambda h, g=gate: g))

    def test_private_file_must_be_regular_and_not_a_symlink(self):
        p = os.path.join(self.w.private, "alpha2.hosts")
        real = os.path.join(self.base, "hosts-real")
        os.rename(p, real)
        os.symlink(real, p)
        self.refuses("PREFLIGHT.PRIVATE_SOURCE", a2_admit.launch, ["--loop", "L2"], self.w.site())
        os.unlink(p)
        os.mkfifo(p, 0o600)
        self.refuses("PREFLIGHT.PRIVATE_SOURCE", a2_admit.launch, ["--loop", "L2"], self.w.site())

    def test_private_file_read_to_eof(self):
        """A file larger than one read is read whole: a padded but valid
        file still parses (a single short read would truncate it)."""
        from unittest import mock
        real_read = os.read
        with mock.patch.object(a2_admit.os, "read", lambda fd, n: real_read(fd, min(n, 7))):
            b = a2fix.FakeBroker(self.w)
            self.addCleanup(b.close)
            args, held, _ = a2_admit.prepare_launch(["--loop", "L2"], self.w.site())
            a2_locks.release(held)

    def test_leak_refusal_before_any_lock(self):
        self.w.write_private(hosts_raw=b'{"schema": "alpha2.hosts/1", "x": 1}')
        self.holder(a2_locks.lock_path(self.w.root, "hv"))
        e = self.refuses("PREFLIGHT.LEAK_HOSTS", a2_admit.launch, ["--loop", "L2"], self.w.site())
        self.assertEqual(e.detail, "check L2 at $#1")


class RunDirTest(Base):
    RID = "20261116T000000Z-00000001"

    def work(self, *p):
        return os.path.join(self.w.home, "alpha2-work", *p)

    def create(self, rid=None):
        import a2_rundir
        fd = a2_rundir.create_run_dir(self.w.home, rid or self.RID, os.getuid())
        self.addCleanup(os.close, fd)
        return fd

    def test_mint_and_create(self):
        import a2_private
        import a2_rundir
        rid = a2_rundir.mint_run_id(now=0, rand=lambda n: b"\x01" * n)
        self.assertEqual(rid, "19700101T000000Z-01010101")
        self.assertTrue(a2_private.matches("run_id", a2_rundir.mint_run_id()))
        fd = self.create(rid)
        self.assertEqual(os.fstat(fd).st_ino, os.stat(self.work("runs", rid)).st_ino)
        self.assertTrue(a2fix.is_mode(self.work("runs", rid), 0o700))
        self.assertTrue(os.path.isdir(self.work("runs", rid, "receipts")))

    def test_an_existing_run_dir_refuses_even_when_empty(self):
        os.mkdir(self.work("runs", self.RID), 0o700)
        os.chmod(self.work("runs", self.RID), 0o700)
        self.refuses("RUNNER.RUN_DIR", self.create)

    def test_bad_run_id_never_makes_a_path(self):
        self.refuses("RUNNER.RUN_DIR", self.create, "../x")

    def test_parents_must_preexist_and_nothing_is_created_above(self):
        shutil.rmtree(self.work())
        self.refuses("RUNNER.RUN_DIR", self.create)
        self.assertFalse(os.path.exists(self.work()))
        os.mkdir(self.work(), 0o700)
        self.refuses("RUNNER.RUN_DIR", self.create)
        self.assertFalse(os.path.exists(self.work("runs")))

    def test_symlinked_work_or_runs_refuses(self):
        real = os.path.join(self.base, "elsewhere")
        os.makedirs(os.path.join(real, "runs"), 0o700)
        os.chmod(real, 0o700)
        shutil.rmtree(self.work())
        os.symlink(real, self.work())
        self.refuses("RUNNER.RUN_DIR", self.create)
        self.assertEqual(os.listdir(os.path.join(real, "runs")), [])
        os.unlink(self.work())
        os.mkdir(self.work(), 0o700)
        os.symlink(os.path.join(real, "runs"), self.work("runs"))
        self.refuses("RUNNER.RUN_DIR", self.create)
        self.assertEqual(os.listdir(os.path.join(real, "runs")), [])

    def test_mode_owner_and_type_of_parents(self):
        os.chmod(self.work("runs"), 0o750)
        self.refuses("RUNNER.RUN_DIR", self.create)
        os.chmod(self.work("runs"), 0o700)
        os.chmod(self.work(), 0o755)
        self.refuses("RUNNER.RUN_DIR", self.create)
        os.chmod(self.work(), 0o700)
        import a2_rundir
        self.refuses("RUNNER.RUN_DIR", a2_rundir.create_run_dir, self.w.home, self.RID, os.getuid() + 1)
        shutil.rmtree(self.work("runs"))
        open(self.work("runs"), "w").close()
        self.refuses("RUNNER.RUN_DIR", self.create)

    def test_parent_swap_after_open_stays_in_the_pinned_directory(self):
        import a2_rundir
        runs_fd = a2_rundir.open_runs(self.w.home, os.getuid())
        self.addCleanup(os.close, runs_fd)
        os.rename(self.work("runs"), self.work("runs.old"))
        decoy = os.path.join(self.base, "decoy")
        os.mkdir(decoy, 0o700)
        os.symlink(decoy, self.work("runs"))
        run_fd = a2_rundir.create_in(runs_fd, self.RID, os.getuid())
        self.addCleanup(os.close, run_fd)
        self.assertTrue(os.path.isdir(self.work("runs.old", self.RID, "receipts")))
        self.assertEqual(os.listdir(decoy), [])

    def test_run_dir_replaced_before_receipts_is_not_followed(self):
        """receipts is made relative to the run directory's descriptor: a
        swap of the run directory's name just before receipts is created
        does not move receipts into the swapped-in target."""
        import a2_rundir
        runs_fd = a2_rundir.open_runs(self.w.home, os.getuid())
        self.addCleanup(os.close, runs_fd)
        real_mkdir = os.mkdir
        decoy = os.path.join(self.base, "decoy2")
        os.mkdir(decoy, 0o700)

        def swapping_mkdir(name, mode=0o777, *, dir_fd=None):
            if os.path.basename(name) == a2_rundir.RECEIPTS_NAME:
                os.rename(self.work("runs", self.RID), self.work("runs", "moved"))
                os.symlink(decoy, self.work("runs", self.RID))
            real_mkdir(name, mode, dir_fd=dir_fd)
        from unittest import mock
        with mock.patch.object(a2_rundir.os, "mkdir", swapping_mkdir):
            run_fd = a2_rundir.create_in(runs_fd, self.RID, os.getuid())
        self.addCleanup(os.close, run_fd)
        self.assertEqual(os.listdir(decoy), [])
        self.assertTrue(os.path.isdir(self.work("runs", "moved", "receipts")))


class DirectPathTest(Base):
    """5.1a review test: for each condition S0 re-checks, a process of the
    runner account that takes the lock files itself, calls the broker
    itself (for a target-writing command) and starts the runner with that
    condition failing is refused at S0, before the run directory exists."""

    brokers = []

    def direct(self, argv=("--loop", "L2"), broker=True, locks=True, account="loop", sub="loop"):
        site = self.w.site()
        inv = a2_args.parse(list(argv))
        vms = a2_locks.run_vms(self.w.hosts, inv, account)
        order = a2_locks.lock_order(self.w.root, a2_locks.targets(self.w.hosts, vms), inv.writes_target)
        if locks:
            self.held.append(a2_locks.acquire(order, os.getuid()))
        rid = "20261116T000000Z-00000000"
        if broker:
            b = a2fix.FakeBroker(self.w, sub=sub)
            self.addCleanup(b.close)
            self.brokers.append(b)
            with open(os.path.join(self.base, "private", "alpha2.lock"), "rb") as f:
                lock_sha = __import__("hashlib").sha256(f.read()).hexdigest()
            with open(os.path.join(self.base, "private", "alpha2.hosts"), "rb") as f:
                hosts_sha = __import__("hashlib").sha256(f.read()).hexdigest()
            rid, _ = a2_budget.ask_broker(self.w.root, inv, lock_sha, hosts_sha, site.installer_sha,
                                          root_uid=os.getuid())
            b.close()
        return rid, list(argv)

    def admit(self, rid, argv, **over):
        site = self.w.site(**over)
        return a2_admit.admit(rid, argv, site)

    def test_a_direct_start_with_everything_is_admitted(self):
        rid, argv = self.direct()
        c = self.admit(rid, argv)
        self.held.append(c.held)
        # Adopted: no child of the runner inherits a lock.
        self.assertTrue(c.held and all(not os.get_inheritable(fd) for fd in c.held.values()))
        os.close(c.run_fd)

    def test_each_condition_refuses_at_S0(self):
        cases = [
            ("RUNNER.ENV", dict(environ={"HOME": "/x", "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "",
                                         "TERM": "x"})),
            ("RUNNER.ACCOUNT", dict(geteuid=lambda: os.getuid() + 1)),
            ("RUNNER.LOCK_ROOT", dict(fs_type_of=lambda p: "nfs")),
            ("RUNNER.LOCK_ROOT", dict(host_identity=lambda: None)),
            ("PREFLIGHT.HANDOFF", dict(loop_tasks=lambda h: "present")),
            ("PREFLIGHT.BUDGET", dict(usage_path="a", usage_read=lambda h: 95)),
            ("PREFLIGHT.BUDGET", dict(usage_path=None)),
            ("RUNNER.ADMISSION", dict(installer_sha="d" * 64)),
            ("RUNNER.ADMISSION", dict(now=time.time() + 120)),
            ("PREFLIGHT.PRIVATE_SOURCE", dict(private_dir=None)),
        ]
        for cause, over in cases:
            with self.subTest(cause=cause, over=sorted(over)):
                self._close()
                self.held = []
                rid, argv = self.direct()
                self.refuses(cause, self.admit, rid, argv, **over)
                self.assertFalse(os.path.exists(os.path.join(self.w.home, "alpha2-work", "runs", rid)))

    def test_private_files_rechecked_at_S0(self):
        """L1 to L4 at S0: the files rewritten after the direct broker call."""
        cases = [
            ("PREFLIGHT.LEAK_LOCK", "alpha2.lock", b"{}"),
            ("PREFLIGHT.LEAK_HOSTS", "alpha2.hosts", b'{"schema": "alpha2.hosts/1", "x": 1}'),
        ]
        for cause, name, raw in cases:
            with self.subTest(cause=cause):
                self._close()
                self.held = []
                rid, argv = self.direct()
                p = os.path.join(self.w.private, name)
                with open(p, "rb") as f:
                    good = f.read()
                with open(p, "wb") as f:
                    f.write(raw)
                self.refuses(cause, self.admit, rid, argv)
                with open(p, "wb") as f:
                    f.write(good)

    def test_each_leak_check_at_S0_with_the_bad_bytes_admitted_by_the_broker(self):
        """The real direct path: the process asks the broker with the sha of
        the bytes IT chose, so the sha binding passes and only S0's own L1
        to L4 can refuse. One case per check per file; the detail's check
        number shows which check refused, so no case passes by failing at
        an earlier one."""
        lock = a2fix.lock_bytes()
        hosts = a2fix.dumps(self.w.hosts)
        d = copy.deepcopy(a2fix.LOCK)
        d["files"][0]["component"] = "nope"
        lock_l3 = a2fix.dumps(d)
        d = copy.deepcopy(a2fix.LOCK)
        d["vm_template"]["name"] = "glpat-x"
        lock_l4 = a2fix.dumps(d)
        h = copy.deepcopy(self.w.hosts)
        h["runner"]["l3_account"] = "Bad_Name"
        hosts_l3 = a2fix.dumps(h)
        h = copy.deepcopy(self.w.hosts)
        h["vms"][2]["ssh_alias"] = "glpat-x"
        hosts_l4 = a2fix.dumps(h)
        cases = [
            ("lock", "L1", lock.replace(b'"schema": "alpha2.lock/1"', b'"schema": "alpha2.lock/1", "schema": "alpha2.lock/1"'), hosts),
            ("lock", "L2", lock.replace(b'"d7_source": {', b'"extra": 1, "d7_source": {'), hosts),
            ("lock", "L3", lock_l3, hosts),
            ("lock", "L4", lock_l4, hosts),
            ("hosts", "L1", lock, hosts.replace(b'"schema": "alpha2.hosts/1"', b'"schema": "alpha2.hosts/1", "schema": "alpha2.hosts/1"')),
            ("hosts", "L2", lock, hosts.replace(b'"hub": {', b'"extra": 1, "hub": {')),
            ("hosts", "L3", lock, hosts_l3),
            ("hosts", "L4", lock, hosts_l4),
        ]
        for which, check, lraw, hraw in cases:
            with self.subTest(which=which, check=check):
                self._close()
                self.held = []
                self.w.write_private(lock_raw=lraw, hosts_raw=hraw)
                rid, argv = self.direct()          # the broker gets the bad bytes' shas
                e = self.refuses("PREFLIGHT.LEAK_" + which.upper(), self.admit, rid, argv)
                self.assertTrue(e.detail.startswith("check " + check + " at "), e.detail)
        self.w.write_private()

    def test_bytes_changed_after_the_broker_call_refuse_at_S0(self):
        for name in ("alpha2.lock", "alpha2.hosts"):
            with self.subTest(name=name):
                self._close()
                self.held = []
                rid, argv = self.direct()
                p = os.path.join(self.w.private, name)
                with open(p, "rb") as f:
                    good = f.read()
                with open(p, "wb") as f:
                    f.write(good + b"\n")   # still valid JSON, different sha
                self.refuses("RUNNER.ADMISSION", self.admit, rid, argv)
                with open(p, "wb") as f:
                    f.write(good)

    def test_lock_root_rechecked_at_S0(self):
        from unittest import mock
        me = os.getuid()
        for label, over, act, undo in [
            ("mode", {}, lambda: os.chmod(self.w.root, 0o775), lambda: os.chmod(self.w.root, 0o755)),
            ("parent", dict(account_ids=lambda n: (me, {me})), None, None),
            ("owner", dict(root_uid=me + 1), None, None),
        ]:
            with self.subTest(label=label):
                self._close()
                self.held = []
                rid, argv = self.direct()
                if act:
                    act()
                try:
                    self.refuses("RUNNER.LOCK_ROOT", self.admit, rid, argv, **over)
                finally:
                    if undo:
                        undo()
        self._close()
        self.held = []
        rid, argv = self.direct()
        root = self.w.root
        real = a2_locks._has_acl
        with mock.patch.object(a2_locks, "_has_acl", lambda p: p == root or real(p)):
            self.refuses("RUNNER.LOCK_ROOT", self.admit, rid, argv)

    def test_names_distinct_rechecked_at_S0(self):
        rid, argv = self.direct()
        h = copy.deepcopy(self.w.hosts)
        h["vms"][2]["name"] = h["hub"]["name"]
        self.w.write_private(hosts_raw=a2fix.dumps(h))
        self.refuses("RUNNER.HOSTS_TARGETS", self.admit, rid, argv)

    def test_stop_file_set_after_launch_refuses_at_S0(self):
        rid, argv = self.direct()
        open(os.path.join(self.w.root, "stop.d", "monitor", "stop"), "w").close()
        self.refuses("PREFLIGHT.HANDOFF", self.admit, rid, argv)

    def test_without_locks(self):
        rid, argv = self.direct(locks=False)
        self.refuses("RUNNER.ADMISSION", self.admit, rid, argv)

    def test_without_broker_record(self):
        rid, argv = self.direct(broker=False)
        self.refuses("RUNNER.ADMISSION", self.admit, rid, argv)

    def test_non_writing_needs_locks_but_no_record(self):
        rid, argv = self.direct(argv=("--verify",), broker=False)
        c = self.admit(rid, argv)
        self.held.append(c.held)
        os.close(c.run_fd)
        self.assertIsNone(c.admission_sha)

    def test_arm_gate_rechecked_at_S0(self):
        """The L3 install and destroy: a direct start with locks and a
        broker record, the gate closed, UNOBSERVED, or open with too little
        time for an install, refuses at S0."""
        l3 = a2fix.hosts_doc(self.w.root, loop_account="loop-runner", l3_account=a2fix.ME.pw_name)
        self.w.hosts = l3
        self.w.write_private()
        for argv, gates in ((("--loop", "L3"), ("closed", "UNOBSERVED", ("open", 10))),
                            (("--destroy",), ("closed", "UNOBSERVED"))):
            for gate in gates:
                with self.subTest(argv=argv, gate=gate):
                    self._close()
                    self.held = []
                    rid, a = self.direct(argv=argv, account="l3", sub="l3")
                    self.refuses("PREFLIGHT.HANDOFF", self.admit, rid, a,
                                 arm_gate=lambda h, g=gate: g)
        # And with the gate open, the same direct start is admitted.
        self._close()
        self.held = []
        rid, a = self.direct(argv=("--loop", "L3"), account="l3", sub="l3")
        c = self.admit(rid, a)
        self.held.append(c.held)
        os.close(c.run_fd)

    def test_account_rule_rechecked_at_S0(self):
        """The loop account starts an L3 install directly, with locks it
        took and a record the broker wrote in its own subdirectory: S0's
        account rule refuses it."""
        rid, argv = self.direct(argv=("--loop", "L3"))
        self.refuses("RUNNER.ACCOUNT", self.admit, rid, argv)

    def test_record_of_other_command_refuses(self):
        rid, _ = self.direct(argv=("--loop", "L2"))
        self.refuses("RUNNER.ADMISSION", self.admit, rid, ["--leak-run"])

    def test_bad_run_id_refuses(self):
        self.direct(argv=("--verify",), broker=False)
        for bad in ("../../x", "20261116T000000Z-0000000g"):
            self.refuses("RUNNER.ADMISSION", self.admit, bad, ["--verify"])
        self.assertEqual(os.listdir(os.path.join(self.w.home, "alpha2-work", "runs")), [])


class WritersPerStageSetTest(Base):
    """6.1/3.7 (ruling LOCK-WRITERS-PER-STAGE-SET): a lock may pin 0 to 2
    writers; admission refuses PREFLIGHT.LOCK, before any lock target is
    taken, unless every writer whose stage the run executes is pinned. Only
    an L1 run (--only/--from) can leave a writer's stage out."""

    def lock_with(self, uses):
        doc = copy.deepcopy(a2fix.LOCK)
        doc["writers"] = [w for w in doc["writers"] if w["use"] in uses]
        self.w.write_private(lock_raw=a2fix.dumps(doc))

    def admits(self, argv):
        c = a2_admit._common(argv, self.w.site())
        self.assertEqual(c.inv.command, "install")

    def test_without_writers_only_l1_runs_before_s6b_are_admitted(self):
        """Under RUNNER.STAGE_SET an L1 that reaches S6b or S7 also runs S3, so it runs both writers' stages: only an
        --only of S0 to S5 is admitted without writers."""
        self.lock_with(())
        for argv in (["--only", "S0"], ["--only", "S3"], ["--only", "S5"]):
            with self.subTest(argv=argv):
                self.admits(argv)
        for argv in (["--from", "S3"], ["--from", "S0"], ["--loop", "L2"], ["--leak-run"]):
            with self.subTest(argv=argv):
                e = self.refuses("PREFLIGHT.LOCK", a2_admit._common, argv, self.w.site())
                self.assertEqual(e.detail, "writers")

    def test_one_writer_is_never_enough_for_a_run_reaching_its_stages(self):
        """Each writer is tied to its own stage (WritersRequiredTest covers the function over every stage set). Every
        L1 that RUNNER.STAGE_SET admits and that reaches S6b or S7 runs both, so one pinned writer refuses it."""
        for one in (("hub_login",), ("api_key",)):
            with self.subTest(pinned=one):
                self.lock_with(one)
                self.refuses("PREFLIGHT.LOCK", a2_admit._common, ["--from", "S3"], self.w.site())
                self.admits(["--only", "S5"])

    def test_with_both_writers_every_run_passes_this_check(self):
        self.lock_with(("api_key", "hub_login"))
        for argv in (["--loop", "L2"], ["--from", "S0"], ["--from", "S3"], ["--only", "S5"]):
            with self.subTest(argv=argv):
                a2_admit._common(argv, self.w.site())

    def test_the_schema_takes_zero_to_two_unique_writers(self):
        import a2_private
        doc = copy.deepcopy(a2fix.LOCK)
        for writers in ([], doc["writers"][:1], doc["writers"]):
            with self.subTest(n=len(writers)):
                d = dict(doc, writers=writers)
                a2_private.check_lock(a2_private.parse(a2fix.dumps(d), "alpha2.lock/1"))
        for writers in (doc["writers"] + doc["writers"][:1], [doc["writers"][0], doc["writers"][0]]):
            with self.subTest(n=len(writers)):
                with self.assertRaises(a2_private.Invalid):
                    a2_private.check_lock(a2_private.parse(a2fix.dumps(dict(doc, writers=writers)),
                                                           "alpha2.lock/1"))


if __name__ == "__main__":
    unittest.main()
