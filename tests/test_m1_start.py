"""m1_start, the start wrapper: one positive case, then one negative case per
refusal rule, each planted alone. A refusal must name its own rule, exit 3,
and exec nothing. The records are small files whose sha the go text quotes,
built here; the A2a record carries the key=value fields the wrapper reads."""

import calendar
import contextlib
import hashlib
import io
import os
import tempfile
import time
import unittest

import m1_start as ms

BOOT = "0b9d6a3e-1c2f-4a5b-8d7e-112233445566"
IMAGE = "sha256:" + "d" * 64
RUN = ["/usr/bin/sudo", "-u", "#1001", "--", "/opt/amap/src/amap-router-local-hop/docker/run.sh", "--config",
       "/srv/data/sandy/features/amap/router.json", "--image", IMAGE, "--name", "amap-rl", "--group-add", "1002",
       "--detach"]


def utc(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


class Fixture(unittest.TestCase):

    def setUp(self):
        self.t = os.path.realpath(tempfile.mkdtemp())
        self.now = calendar.timegm(time.strptime("2026-10-30T18:00:00Z", "%Y-%m-%dT%H:%M:%SZ"))
        self.a2a_t = self.now - 60
        self.files = {}
        self.write("ctlr", b"ctlr record\n")
        self.write("psr", b"psr receipt\nresult PASS\n")
        self.write("harpf", b"har-pfv receipt\nresult PASS\n")
        self.write_a2a(ctlr=self.sha("ctlr"))
        self.order = "earlier"
        self.recheck = False
        self.go = self.default_go()
        self.execd = []

    def path(self, name):
        return os.path.join(self.t, name)

    def write(self, name, data):
        with open(self.path(name), "wb") as f:
            f.write(data)
        self.files[name] = data

    def write_a2a(self, ctlr, boot=BOOT, at=None):
        at = self.a2a_t if at is None else at
        self.write("a2a", f"A2A PASS vm=1 ctlr={ctlr} boot_id={boot} utc={utc(at)}\n".encode())

    def sha(self, name):
        return hashlib.sha256(self.files[name]).hexdigest()

    def default_go(self):
        return {"a2a": self.sha("a2a"), "boot_id": BOOT, "a2a_utc": utc(self.a2a_t), "ctlr": self.sha("ctlr"),
                "psr": self.sha("psr"), "harpf": self.sha("harpf")}

    def run_wrapper(self, run=None, go_text=None):
        text = go_text if go_text is not None else " ".join(f"{k}={v}" for k, v in self.go.items())
        with open(self.path("go"), "w") as f:
            f.write(text + "\n")
        argv = ["--go", self.path("go"), "--order", self.order, "--a2a", self.path("a2a"), "--ctlr",
                self.path("ctlr"), "--psr", self.path("psr"), "--harpf", self.path("harpf")]
        if self.recheck:
            argv += ["--psr-recheck", self.path("recheck")]
        argv += ["--"] + (run if run is not None else RUN)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = ms.main(argv, execv=lambda p, a: self.execd.append((p, a)), boot_id=lambda: BOOT,
                         now=lambda: self.now)
        return rc, err.getvalue()

    def refused(self, words, **kw):
        rc, err = self.run_wrapper(**kw)
        self.assertEqual(rc, ms.EXIT_REFUSED, err)
        self.assertIn("refused:", err)
        self.assertIn(words, err)
        self.assertIn("nothing was started", err)
        self.assertEqual(self.execd, [])


class AdmitTest(Fixture):

    def test_an_earlier_go_with_every_field_starts(self):
        rc, err = self.run_wrapper()
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.execd, [(RUN[0], RUN)])

    def test_a_later_go_with_a_passing_recheck_starts(self):
        self.order, self.recheck = "later", True
        self.write("recheck", b"psr recheck\nresult PASS\n")
        self.go["psr_recheck"] = self.sha("recheck")
        rc, err = self.run_wrapper()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.execd), 1)

    def test_a_later_go_with_no_recheck_starts(self):
        self.order = "later"
        rc, err = self.run_wrapper()
        self.assertEqual(rc, 0, err)


class HarpfTest(Fixture):

    def test_an_earlier_go_without_harpf_is_refused(self):
        del self.go["harpf"]
        self.refused("lacks harpf=")

    def test_a_later_go_without_harpf_is_refused(self):
        self.order = "later"
        del self.go["harpf"]
        self.refused("lacks harpf=")

    def test_a_harpf_that_is_not_the_admitted_hab_pfv_is_refused(self):
        self.go["harpf"] = "e" * 64
        self.refused("harpf= is not the sha256 of the harpf record")


class ShaTest(Fixture):

    def test_a_foreign_ctlr_is_refused(self):
        self.go["ctlr"] = "e" * 64
        self.refused("ctlr= is not the sha256 of the ctlr record")

    def test_a_foreign_psr_is_refused(self):
        self.go["psr"] = "e" * 64
        self.refused("psr= is not the sha256 of the psr record")

    def test_a_foreign_a2a_is_refused(self):
        self.go["a2a"] = "e" * 64
        self.refused("a2a= is not the sha256 of the a2a record")

    def test_a_psr_without_result_pass_is_refused(self):
        self.write("psr", b"psr receipt\nresult FAIL\n")
        self.go["psr"] = self.sha("psr")
        self.refused("does not carry `result PASS`")


class RecheckTest(Fixture):

    def test_psr_recheck_on_the_earlier_go_is_refused(self):
        self.recheck = True
        self.write("recheck", b"psr recheck\nresult PASS\n")
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("psr_recheck= on the earlier go")

    def test_psr_recheck_quoted_without_a_recheck_is_refused(self):
        self.order = "later"
        self.go["psr_recheck"] = "f" * 64
        self.refused("no PSR-RECHECK receipt is given")

    def test_a_recheck_that_ran_but_is_not_quoted_is_refused(self):
        self.order, self.recheck = "later", True
        self.write("recheck", b"psr recheck\nresult PASS\n")
        self.refused("does not quote psr_recheck=")

    def test_a_recheck_with_a_diff_is_refused(self):
        self.order, self.recheck = "later", True
        self.write("recheck", b"psr recheck\nDIFF d7 file\nresult PASS\n")
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("shows a DIFF")

    def test_a_foreign_psr_recheck_is_refused(self):
        self.order, self.recheck = "later", True
        self.write("recheck", b"psr recheck\nresult PASS\n")
        self.go["psr_recheck"] = "f" * 64
        self.refused("psr_recheck= is not the sha256")

    def test_a_recheck_without_result_pass_is_refused(self):
        self.order, self.recheck = "later", True
        self.write("recheck", b"psr recheck\n")
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("PSR-RECHECK receipt does not carry `result PASS`")


class CtlrTest(Fixture):

    def test_an_a2a_with_ctlr_none_is_refused(self):
        self.write_a2a(ctlr="none")
        self.go["a2a"] = self.sha("a2a")
        self.refused("ctlr=none")

    def test_an_a2a_ctlr_unequal_to_the_gos_is_refused(self):
        self.write_a2a(ctlr="9" * 64)
        self.go["a2a"] = self.sha("a2a")
        self.refused("the A2a record's ctlr= is not the go's ctlr=")

    def test_an_a2a_with_two_ctlr_fields_is_refused(self):
        self.write("a2a", self.files["a2a"].rstrip(b"\n") + b" ctlr=" + self.sha("ctlr").encode() + b"\n")
        self.go["a2a"] = self.sha("a2a")
        self.refused("2 ctlr= field(s), not exactly one")


class BootAndWindowTest(Fixture):

    def test_a_go_boot_id_other_than_a2as_is_refused(self):
        self.go["boot_id"] = "other"
        self.refused("boot_id= is not the A2a record's")

    def test_a_reboot_since_a2a_is_refused(self):
        self.write_a2a(ctlr=self.sha("ctlr"), boot="old-boot")
        self.go.update(a2a=self.sha("a2a"), boot_id="old-boot")
        self.refused("is not this machine's current boot")

    def test_an_a2a_older_than_w1_is_refused(self):
        self.a2a_t = self.now - ms.W1_S - 1
        self.write_a2a(ctlr=self.sha("ctlr"))
        self.go.update(a2a=self.sha("a2a"), a2a_utc=utc(self.a2a_t))
        self.refused("older than W1")

    def test_an_a2a_exactly_at_w1_starts(self):
        self.a2a_t = self.now - ms.W1_S
        self.write_a2a(ctlr=self.sha("ctlr"))
        self.go.update(a2a=self.sha("a2a"), a2a_utc=utc(self.a2a_t))
        rc, err = self.run_wrapper()
        self.assertEqual(rc, 0, err)

    def test_an_a2a_in_the_future_is_refused(self):
        self.a2a_t = self.now + 5
        self.write_a2a(ctlr=self.sha("ctlr"))
        self.go.update(a2a=self.sha("a2a"), a2a_utc=utc(self.a2a_t))
        self.refused("in the future")

    def test_a_go_utc_other_than_a2as_is_refused(self):
        self.go["a2a_utc"] = utc(self.a2a_t - 1)
        self.refused("a2a_utc= is not the A2a record's utc=")


class GoTextTest(Fixture):

    def test_an_unknown_field_is_refused(self):
        self.go["extra"] = "1"
        self.refused("unknown field(s) extra=")

    def test_a_repeated_field_is_refused(self):
        text = " ".join(f"{k}={v}" for k, v in self.go.items()) + f" ctlr={self.go['ctlr']}"
        self.refused("repeats ctlr=", go_text=text)

    def test_a_non_hex_sha_is_refused(self):
        self.go["psr"] = "PSR"
        self.refused("psr= is not 64 lowercase hex")


class ArgvTest(Fixture):

    def test_a_start_by_tag_is_refused(self):
        run = [a if a != IMAGE else "amap-router-local" for a in RUN]
        self.refused("not an image Id", run=run)

    def test_a_start_without_detach_is_refused(self):
        self.refused("ARGV has no --detach", run=[a for a in RUN if a != "--detach"])

    def test_a_relative_program_is_refused(self):
        self.refused("absolute program", run=["sudo"] + RUN[1:])


class UsageTest(Fixture):

    def test_missing_options_exit_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ms.main(["--go", "x", "--", "/bin/true"]), ms.EXIT_USAGE)

    def test_an_unknown_order_exits_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ms.main(["--go", "x", "--order", "first", "--a2a", "a", "--ctlr", "c", "--psr", "p",
                                      "--harpf", "h", "--", "/bin/true"]), ms.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
