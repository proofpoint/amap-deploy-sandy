"""The output guard (3.3), receipts (3.3), the manifest (6.3) and the SUMS
chain (5.4), on a run directory created the way S0 creates it."""

import hashlib
import io
import json
import os
import shutil
import unittest

import a2fix
import a2_guard
import a2_record
import a2_rundir
from a2_causes import Refusal

RID = "20261116T000000Z-0000abcd"
SHA = "c" * 64


class Base(unittest.TestCase):
    def setUp(self):
        self.base = a2fix.make_base()
        self.addCleanup(shutil.rmtree, self.base, True)
        self.w = a2fix.World(self.base)
        self.run_fd = a2_rundir.create_run_dir(self.w.home, RID, os.getuid())
        self.addCleanup(os.close, self.run_fd)
        self.guard = a2_guard.OutputGuard()
        self.run = a2_record.Run(self.run_fd, self.guard, RID, "install", "L2", SHA, a2fix.H64, a2fix.H64,
                                 now=1794790923)
        self.addCleanup(self.run.close)
        self.dir = os.path.join(self.w.home, "alpha2-work", "runs", RID)

    def refuses(self, cause, fn, *a, **kw):
        with self.assertRaises(Refusal) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.cause, cause)
        return cm.exception

    def read(self, *p):
        with open(os.path.join(self.dir, *p), "rb") as f:
            return f.read()


class WholeWriteTest(Base):
    """A stop inside a record write is taken once the write is complete:
    the file, its SUMS line and the manifest are all written first."""

    def setUp(self):
        import signal
        super().setUp()
        self.addCleanup(signal.pthread_sigmask, signal.SIG_SETMASK, signal.pthread_sigmask(signal.SIG_BLOCK, ()))
        self.taken = []

        def own(signum, frame):
            self.taken.append(signum)
            raise KeyboardInterrupt()
        self.addCleanup(signal.signal, signal.SIGTERM, signal.signal(signal.SIGTERM, own))

    def stop_after_writing(self, name):
        import signal
        real = a2_record._write_atomic
        sent = []

        def write(dir_fd, at, data):
            real(dir_fd, at, data)
            if at == name and not sent:
                sent.append(1)
                signal.raise_signal(signal.SIGTERM)
        a2_record._write_atomic = write
        self.addCleanup(setattr, a2_record, "_write_atomic", real)
        return sent

    def test_a_stop_after_the_receipt_file_waits_for_sums_and_manifest(self):
        import signal
        sent = self.stop_after_writing("S0--.txt")
        with self.assertRaises(KeyboardInterrupt):
            self.run.write_receipt("S0", None, "2026-11-16T00:00:00Z", "PASS", [("CUSTODY_LOCKS", "held")])
        self.assertEqual((sent, self.taken), ([1], [signal.SIGTERM]))
        self.assertEqual([st["receipt"] for st in self.run.stages], ["receipts/S0--.txt"])
        self.assertEqual(self.read("SUMS").decode().split()[-1], "receipts/S0--.txt")
        self.assertEqual([st["receipt"] for st in json.loads(self.read("manifest.json"))["stages"]],
                         ["receipts/S0--.txt"])

    def test_a_stop_after_the_final_manifest_file_waits_for_its_sums_line(self):
        import signal
        sent = self.stop_after_writing(a2_record.MANIFEST)
        with self.assertRaises(KeyboardInterrupt):
            self.run.write_manifest(final=True)
        self.assertEqual((sent, self.taken), ([1], [signal.SIGTERM]))
        self.assertTrue(self.run.final)
        self.assertEqual(self.read("SUMS").decode().split()[-1], a2_record.MANIFEST)


class GuardTest(unittest.TestCase):
    def test_refuses_a_held_value_and_writes_nothing(self):
        g = a2_guard.OutputGuard()
        v = bytearray(b"canary-s3cret")
        g.hold(v)
        out = io.StringIO()
        with self.assertRaises(Refusal) as cm:
            g.emit(out, "prefix canary-s3cret suffix")
        self.assertEqual(cm.exception.cause, "RUNNER.OUTPUT_GUARD")
        self.assertEqual(cm.exception.rc, 2)
        self.assertEqual(out.getvalue(), "")
        g.emit(out, "harmless")
        self.assertEqual(out.getvalue(), "harmless\n")

    def test_rc3_once_a_target_was_written(self):
        g = a2_guard.OutputGuard()
        g.hold(bytearray(b"canary"))
        g.wrote_target = True
        with self.assertRaises(Refusal) as cm:
            g.check(b"..canary..")
        self.assertEqual(cm.exception.rc, 3)

    def test_release_overwrites_the_values(self):
        g = a2_guard.OutputGuard()
        v = bytearray(b"canary")
        g.hold(v)
        g.release_all()
        self.assertEqual(v, bytearray(6))
        self.assertFalse(g.holding)
        g.check("canary")

    def test_hold_rejects_str_and_empty(self):
        g = a2_guard.OutputGuard()
        for bad in ("canary", b"canary", bytearray()):
            with self.assertRaises(ValueError):
                g.hold(bad)

    def test_fact_is_guarded_then_capped(self):
        g = a2_guard.OutputGuard()
        v = g.fact("x" * 5000)
        self.assertEqual(len(v), a2_guard.FACT_CAP)
        self.assertTrue(v.endswith(a2_guard.TRUNCATED))
        g.hold(bytearray(b"zz"))
        with self.assertRaises(Refusal):
            g.fact("a" * 6000 + "zz")


class ReceiptTest(Base):
    def write(self, **kw):
        args = dict(stage_id="S0", host=None, started="2026-11-16T00:00:00Z", result="PASS",
                    facts=[("CUSTODY_LOCKS", "held")])
        args.update(kw)
        return self.run.write_receipt(**args)

    def test_written_atomically_and_listed(self):
        path = self.write()
        self.assertEqual(path, "receipts/S0--.txt")
        data = self.read("receipts", "S0--.txt")
        self.assertTrue(data.endswith(b"STAGE-END S0 - rc=0\n"))
        self.assertEqual(sorted(os.listdir(os.path.join(self.dir, "receipts"))), ["S0--.txt"])
        sums = self.read("SUMS").decode()
        self.assertEqual(sums, "1 %s %s receipts/S0--.txt\n" % (hashlib.sha256(data).hexdigest(), "0" * 64))
        man = json.loads(self.read("manifest.json"))
        self.assertEqual(man["state"], "active")
        self.assertNotIn("ended", man)
        self.assertEqual(man["stages"], [{"stage": "S0", "host": "-", "receipt": "receipts/S0--.txt",
                                          "sha256": hashlib.sha256(data).hexdigest(), "rc": 0}])

    def test_failure_receipt_carries_the_fixed_sentence(self):
        self.write(result="FAIL", rc=2, cause="PREFLIGHT.HANDOFF")
        facts, _sid, _h, rc = a2_record.parse_receipt(self.read("receipts", "S0--.txt"))
        self.assertEqual(rc, 2)
        self.assertEqual(facts["CAUSE_TEXT"], a2_record.a2_causes.sentence("PREFLIGHT.HANDOFF"))

    def test_render_refuses_every_rule_break(self):
        bad = [
            dict(result="PASS", rc=2, cause=None),               # rc 2 needs FAIL and a cause
            dict(result="FAIL", rc=0, cause="PREFLIGHT.HANDOFF"), # rc 0 has no cause
            dict(result="MAYBE"),
            dict(facts=[("lower", "x")]),
            dict(facts=[("K", "line\nbreak")]),
            dict(facts=[("K", "café")]),
            dict(facts=[("RESULT", "PASS")]),                     # a repeated key
            dict(result="FAIL", rc=2, cause="VMS.NO_MARKER"),     # another stage's cause
        ]
        for kw in bad:
            with self.subTest(kw=kw):
                with self.assertRaises(ValueError):
                    self.write(**kw)
        self.assertEqual(os.listdir(os.path.join(self.dir, "receipts")), [])

    def test_a_receipt_is_never_rewritten(self):
        self.write()
        with self.assertRaises(ValueError):
            self.write()

    def test_control_bytes_refused_in_a_value(self):
        for ch in ("\r", "\x1b", "\x00", "\x7f", "\t"):
            with self.subTest(ch=repr(ch)):
                with self.assertRaises(ValueError):
                    self.write(facts=[("NOTE", "a" + ch + "b")])

    def test_guard_on_the_sums_line(self):
        """A held value that appears only in the SUMS line: the receipt is
        written, its SUMS line is not."""
        self.guard.hold(bytearray(b"receipts/S0--.txt"))
        self.refuses("RUNNER.OUTPUT_GUARD", self.write)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "SUMS")))

    def test_guard_on_the_manifest(self):
        self.guard.hold(bytearray(b"alpha2.run/1"))
        self.refuses("RUNNER.OUTPUT_GUARD", self.run.write_manifest)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "manifest.json")))

    def test_no_receipt_after_the_final_manifest(self):
        self.run.write_manifest(final=True)
        sums = self.read("SUMS")
        with self.assertRaises(ValueError):
            self.write()
        self.assertEqual(os.listdir(os.path.join(self.dir, "receipts")), [])
        self.assertEqual(self.read("SUMS"), sums)

    def test_held_value_never_reaches_a_receipt(self):
        self.guard.hold(bytearray(b"s3cret-v"))
        self.refuses("RUNNER.OUTPUT_GUARD", self.write, facts=[("NOTE", "has s3cret-v in it")])
        self.assertEqual(os.listdir(os.path.join(self.dir, "receipts")), [])


class ReaderTest(Base):
    def put(self, name, data):
        with open(os.path.join(self.dir, "receipts", name), "wb") as f:
            f.write(data)

    def good(self, **over):
        facts = [("RUN_ID", RID), ("COMMAND", "install"), ("LOOP", "L2"), ("INSTALLER_SHA", SHA),
                 ("LOCK_SHA", a2fix.H64), ("HOSTS_SHA", a2fix.H64), ("STAGE", "PREFLIGHT"), ("HOST", "-"),
                 ("STARTED", "2026-11-16T00:00:00Z"), ("ENDED", "2026-11-16T00:00:01Z"), ("RESULT", "PASS")]
        facts = [(k, over.get(k, v)) for k, v in facts]
        return "".join(k + "=" + v + "\n" for k, v in facts).encode() + b"STAGE-END S0 - rc=0\n"

    def test_reads_a_good_receipt(self):
        self.put("S0--.txt", self.good())
        self.assertEqual(self.run.read_receipt("S0", None)["RESULT"], "PASS")

    def test_missing(self):
        self.refuses("PREFLIGHT.PREDECESSOR_MISSING", self.run.read_receipt, "S0", None)

    def test_incomplete(self):
        g = self.good()
        cases = [
            g[:-len(b"STAGE-END S0 - rc=0\n")],                     # no end line
            g + b"X=1\n",                                           # end line not last
            g.replace(b"STAGE=PREFLIGHT", b"STAGE=VMS"),
            g.replace(b"RESULT=PASS\n", b"RESULT=PASS\nRESULT=PASS\n"),
            self.good(LOCK_SHA="d" * 64),
            self.good(RUN_ID="20261116T000000Z-00000000"),
            self.good(LOOP="L3"),
            g[:-1],                                                 # no final LF
        ]
        for i, data in enumerate(cases):
            with self.subTest(i=i):
                self.put("S0--.txt", data)
                self.refuses("PREFLIGHT.PREDECESSOR_INCOMPLETE", self.run.read_receipt, "S0", None)

    def test_installer_and_failed(self):
        self.put("S0--.txt", self.good(INSTALLER_SHA="d" * 64))
        self.refuses("PREFLIGHT.PREDECESSOR_INSTALLER", self.run.read_receipt, "S0", None)
        data = self.good(RESULT="FAIL").replace(b"STAGE-END S0 - rc=0", b"CAUSE=PREFLIGHT.HANDOFF\nCAUSE_TEXT=" +
                                                 a2_record.a2_causes.sentence("PREFLIGHT.HANDOFF").encode() +
                                                 b"\nSTAGE-END S0 - rc=2")
        self.put("S0--.txt", data)
        self.refuses("PREFLIGHT.PREDECESSOR_FAILED", self.run.read_receipt, "S0", None)

    def test_reader_refuses_control_bytes(self):
        self.put("S0--.txt", self.good(HOST="-").replace(b"RESULT=PASS", b"RESULT=PASS\nNOTE=a\x1bb"))
        self.refuses("PREFLIGHT.PREDECESSOR_INCOMPLETE", self.run.read_receipt, "S0", None)
        self.put("S0--.txt", self.good().replace(b"RESULT=PASS", b"NOTE=a\rb\nRESULT=PASS"))
        self.refuses("PREFLIGHT.PREDECESSOR_INCOMPLETE", self.run.read_receipt, "S0", None)

    def test_symlinked_receipt_is_incomplete(self):
        other = os.path.join(self.base, "elsewhere.txt")
        with open(other, "wb") as f:
            f.write(self.good())
        os.symlink(other, os.path.join(self.dir, "receipts", "S0--.txt"))
        self.refuses("PREFLIGHT.PREDECESSOR_INCOMPLETE", self.run.read_receipt, "S0", None)


class CheckReceiptTest(unittest.TestCase):
    """check_receipt on bytes that break exactly one rule each."""

    BASE = [("RUN_ID", RID), ("COMMAND", "install"), ("LOOP", "L2"), ("INSTALLER_SHA", SHA),
            ("LOCK_SHA", a2fix.H64), ("HOSTS_SHA", a2fix.H64), ("STAGE", "PREFLIGHT"), ("HOST", "-"),
            ("STARTED", "2026-11-16T00:00:00Z"), ("ENDED", "2026-11-16T00:00:01Z")]
    TEXT = a2_record.a2_causes.sentence("PREFLIGHT.HANDOFF")

    def data(self, extra, rc, drop=()):
        facts = [(k, v) for k, v in self.BASE if k not in drop] + extra
        return ("".join(k + "=" + v + "\n" for k, v in facts) + "STAGE-END S0 - rc=%d\n" % rc).encode()

    def bad(self, data):
        with self.assertRaises(ValueError):
            a2_record.check_receipt(data, "S0", None, "S0--.txt")

    def test_controls_pass(self):
        a2_record.check_receipt(self.data([("RESULT", "PASS")], 0), "S0", None, "S0--.txt")
        a2_record.check_receipt(self.data([("RESULT", "FAIL"), ("CAUSE", "PREFLIGHT.HANDOFF"),
                                           ("CAUSE_TEXT", self.TEXT)], 2), "S0", None, "S0--.txt")
        a2_record.check_receipt(self.data([("RESULT", "FAIL"), ("CAUSE", "RUNNER.CUSTODY"),
                                           ("CAUSE_TEXT", a2_record.a2_causes.sentence("RUNNER.CUSTODY"))], 3),
                                "S0", None, "S0--.txt")

    def test_rc0_with_a_cause(self):
        self.bad(self.data([("RESULT", "PASS"), ("CAUSE", "PREFLIGHT.HANDOFF"), ("CAUSE_TEXT", self.TEXT)], 0))

    def test_rc2_not_fail(self):
        self.bad(self.data([("RESULT", "PASS"), ("CAUSE", "PREFLIGHT.HANDOFF"), ("CAUSE_TEXT", self.TEXT)], 2))

    def test_another_stages_cause(self):
        self.bad(self.data([("RESULT", "FAIL"), ("CAUSE", "VMS.UNCLASSIFIED"),
                            ("CAUSE_TEXT", a2_record.a2_causes.sentence("VMS.UNCLASSIFIED"))], 2))

    def test_cause_text_not_the_sentence(self):
        self.bad(self.data([("RESULT", "FAIL"), ("CAUSE", "PREFLIGHT.HANDOFF"), ("CAUSE_TEXT", "Look.")], 2))

    def test_required_missing(self):
        for k in a2_record.REQUIRED:
            if k == "RESULT":
                continue
            with self.subTest(k=k):
                self.bad(self.data([("RESULT", "PASS")], 0, drop=(k,)))

    def test_repeated_key(self):
        self.bad(self.data([("RESULT", "PASS"), ("RESULT", "PASS")], 0))

    def test_render_refuses_an_injected_line(self):
        """A value carrying LF and a well-formed second fact: the reader
        would accept the result, so the writer must refuse it."""
        with self.assertRaises(ValueError):
            a2_record.render_receipt(self.BASE + [("NOTE", "x\nCUSTODY_LOCKS=held"), ("RESULT", "PASS")],
                                     "S0", None, 0)


def _rd(path):
    with open(path) as f:
        return f.read()


def _wr(path, text):
    with open(path, "w") as f:
        f.write(text)


def _touch(path, data=b""):
    with open(path, "wb") as f:
        f.write(data)


class SumsTest(Base):
    def finish(self):
        self.run.write_receipt("S0", None, "2026-11-16T00:00:00Z", "PASS", [])
        self.run.write_receipt("S2", "vm-a-t", "2026-11-16T00:00:02Z", "CHANGED", [])
        self.run.write_manifest(final=True)

    def test_a_finished_run_verifies(self):
        self.finish()
        sha = a2_record.verify_sums(self.run_fd)
        self.assertEqual(sha, hashlib.sha256(self.read("SUMS")).hexdigest())
        lines = self.read("SUMS").decode().splitlines()
        self.assertEqual([ln.split(" ")[3] for ln in lines],
                         ["receipts/S0--.txt", "receipts/S2-vm-a-t.txt", "manifest.json"])
        man = json.loads(self.read("manifest.json"))
        self.assertEqual(man["state"], "final")
        self.assertIn("ended", man)
        with self.assertRaises(ValueError):
            self.run.write_manifest(final=False)

    def test_an_active_manifest_is_unlisted_and_fails(self):
        self.run.write_receipt("S0", None, "2026-11-16T00:00:00Z", "PASS", [])
        self.refuses("RUNNER.SUMS", a2_record.verify_sums, self.run_fd)

    def test_every_break_fails(self):
        def edit_receipt():
            with open(os.path.join(self.dir, "receipts", "S0--.txt"), "ab") as f:
                f.write(b"X")

        def drop_line():
            p = os.path.join(self.dir, "SUMS")
            lines = _rd(p).splitlines(True)
            _wr(p, "".join(lines[1:]))

        def swap_lines():
            p = os.path.join(self.dir, "SUMS")
            lines = _rd(p).splitlines(True)
            _wr(p, lines[1] + lines[0] + "".join(lines[2:]))

        def extra_file():
            _touch(os.path.join(self.dir, "extra.txt"))

        def extra_receipt():
            _touch(os.path.join(self.dir, "receipts", "S3--.txt"))

        def remove_file():
            os.unlink(os.path.join(self.dir, "receipts", "S2-vm-a-t.txt"))

        def repeat_path():
            p = os.path.join(self.dir, "SUMS")
            s = _rd(p)
            _wr(p, s.replace("receipts/S2-vm-a-t.txt", "receipts/S0--.txt"))

        def bad_prev():
            p = os.path.join(self.dir, "SUMS")
            lines = _rd(p).splitlines(True)
            f = lines[1].split(" ")
            f[2] = "1" * 64
            lines[1] = " ".join(f)
            _wr(p, "".join(lines))

        def no_final_lf():
            p = os.path.join(self.dir, "SUMS")
            s = _rd(p)
            _wr(p, s[:-1])

        def dotdot_path():
            p = os.path.join(self.dir, "SUMS")
            s = _rd(p)
            _wr(p, s.replace("manifest.json", "../manifest.json"))

        def rechain(entries):
            """Write a SUMS whose chain is valid for these (path, digest) entries."""
            prev, out = "0" * 64, ""
            for n, (path, digest) in enumerate(entries, 1):
                ln = "%d %s %s %s\n" % (n, digest, prev, path)
                out += ln
                prev = hashlib.sha256(ln.encode()).hexdigest()
            _wr(os.path.join(self.dir, "SUMS"), out)

        def entries():
            return [(ln.split(" ")[3].rstrip("\n"), ln.split(" ")[1])
                    for ln in _rd(os.path.join(self.dir, "SUMS")).splitlines(True)]

        def last_number():
            p = os.path.join(self.dir, "SUMS")
            lines = _rd(p).splitlines(True)
            f = lines[-1].split(" ")
            f[0] = "9"
            lines[-1] = " ".join(f)
            _wr(p, "".join(lines))

        def repeat_same_file():
            e = entries()
            os.unlink(os.path.join(self.dir, "receipts", "S2-vm-a-t.txt"))
            rechain([e[0], e[0], e[2]])

        def listed_but_not_allowed():
            p = os.path.join(self.dir, "extra.txt")
            _touch(p, b"x")
            rechain(entries() + [("extra.txt", hashlib.sha256(b"x").hexdigest())])

        for i, brk in enumerate([edit_receipt, drop_line, swap_lines, extra_file, extra_receipt,
                                 remove_file, repeat_path, bad_prev, no_final_lf, dotdot_path,
                                 last_number, repeat_same_file, listed_but_not_allowed]):
            with self.subTest(brk=brk.__name__):
                for n in os.listdir(self.dir):
                    p = os.path.join(self.dir, n)
                    shutil.rmtree(p) if os.path.isdir(p) else os.unlink(p)
                os.mkdir(os.path.join(self.dir, "receipts"), 0o700)
                self.run.close()
                self.run = a2_record.Run(self.run_fd, self.guard, RID, "install", "L2", SHA,
                                         a2fix.H64, a2fix.H64)
                self.finish()
                a2_record.verify_sums(self.run_fd)
                brk()
                e = self.refuses("RUNNER.SUMS", a2_record.verify_sums, self.run_fd)
                self.assertEqual(e.rc, 4)


if __name__ == "__main__":
    unittest.main()
