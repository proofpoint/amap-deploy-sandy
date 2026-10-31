"""m1_start, the start wrapper: one positive case, then one negative case per
refusal rule, each planted alone. A refusal must name its own rule, exit 3,
and exec nothing. The records are small files whose sha the go text quotes,
built here. The A2a record follows ADM's specified line form (DS2 d8 §5), and
the PSR receipts NET's frozen PSR v1 grammar (PSR-GRAMMAR-v1); neither producer
has bytes yet, so these are the specified forms, not measured ones."""

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
SPEC = {"schema": "amap-m1-start-spec/1", "uid_1": 1001, "group_add": 1002,
        "config": "/srv/data/sandy/features/amap/router.json", "image": IMAGE, "name": "amap-rl"}


def psr_bytes(ctlr, recheck_of=None, diff=(), prewindow="PASS", result=None, users_x="-", tweak=None):
    """A receipt in NET's PSR v1 / PSR-RECHECK v1 grammar (PSR-GRAMMAR-v1 §1-§4,
    FROZEN; NET has no producer bytes yet, so this is the specified form).
    `diff` names items written DIFF, whose observed sha differs from their
    reference; `result` defaults to the §4 rule; `tweak(lines)` edits the line
    list before it is joined."""
    lines = ["PSR-RECHECK v1" if recheck_of else "PSR v1"]
    if recheck_of:
        lines.append(f"psr {recheck_of}")
    lines += [f"ctlr {ctlr}", "clone_head " + "2" * 40]
    for name in ms.PSR_ITEMS:
        lines.append(f"item {name} {('5' if name in diff else '3') * 64} {'3' * 64} "
                     f"{'DIFF' if name in diff else 'MATCH'}")
    derived = "PASS" if not diff and prewindow == "PASS" else "FAIL"
    lines += [f"users_x {users_x}", f"prewindow_acceptance {prewindow} {'4' * 64}", "at 2026-10-30T17:58:00Z",
              f"result {result or derived}", "DONE"]
    if tweak:
        lines = tweak(lines)
    return ("\n".join(lines) + "\n").encode()


def utc(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


class Fixture(unittest.TestCase):

    def setUp(self):
        self.t = os.path.realpath(tempfile.mkdtemp())
        self.now = calendar.timegm(time.strptime("2026-10-30T18:00:00Z", "%Y-%m-%dT%H:%M:%SZ"))
        self.a2a_t = self.now - 60
        self.files = {}
        self.write("ctlr", b"ctlr record\n")
        self.write("psr", psr_bytes(self.sha("ctlr")))
        self.write_spec(SPEC)
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
        self.write("a2a", (f"CHECK mount PASS ctlr=decoy\n"
                           f"VM-ADMIT A2a PASS host=H1 att=ATT-1 boot_id={boot} adm={'1' * 64} man={'2' * 64} "
                           f"ovl=none prov={'3' * 64} env=none exp=none d7={'4' * 64} dd={'5' * 64} ctlr={ctlr} "
                           f"utc={utc(at)}\n").encode())

    def write_spec(self, spec, mode=0o444):
        import json
        path = self.path("spec")
        if os.path.exists(path):
            os.chmod(path, 0o644)
            os.unlink(path)
        with open(path, "w") as f:
            json.dump(spec, f)
        os.chmod(path, mode)

    def write_recheck(self, **kw):
        self.write("recheck", psr_bytes(self.sha("ctlr"), recheck_of=self.sha("psr"), **kw))

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
                self.path("ctlr"), "--psr", self.path("psr"), "--harpf", self.path("harpf"), "--start-spec",
                self.path("spec")]
        if self.recheck:
            argv += ["--psr-recheck", self.path("recheck")]
        argv += ["--"] + (run if run is not None else RUN)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = ms.main(argv, execv=lambda p, a: self.execd.append((p, a)), boot_id=lambda: BOOT,
                         now=lambda: self.now, spec_owner=os.getuid())
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
        self.write_recheck()
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
        self.write("psr", psr_bytes(self.sha("ctlr"), prewindow="FAIL"))
        self.go["psr"] = self.sha("psr")
        self.refused("the PSR receipt's result is FAIL")


class RecheckTest(Fixture):

    def test_psr_recheck_on_the_earlier_go_is_refused(self):
        self.recheck = True
        self.write_recheck()
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("psr_recheck= on the earlier go")

    def test_psr_recheck_quoted_without_a_recheck_is_refused(self):
        self.order = "later"
        self.go["psr_recheck"] = "f" * 64
        self.refused("no PSR-RECHECK receipt is given")

    def test_a_recheck_that_ran_but_is_not_quoted_is_refused(self):
        self.order, self.recheck = "later", True
        self.write_recheck()
        self.refused("does not quote psr_recheck=")

    def test_a_recheck_with_a_diff_is_refused(self):
        self.order, self.recheck = "later", True
        self.write_recheck(diff=("vm2.delivered_domains_file",))
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("shows a DIFF")

    def test_a_foreign_psr_recheck_is_refused(self):
        self.order, self.recheck = "later", True
        self.write_recheck()
        self.go["psr_recheck"] = "f" * 64
        self.refused("psr_recheck= is not the sha256")

    def test_a_recheck_without_result_pass_is_refused(self):
        self.order, self.recheck = "later", True
        self.write_recheck(prewindow="FAIL")
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("the PSR-RECHECK receipt's result is FAIL")


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

    def test_an_a2a_whose_last_line_is_not_a2a_pass_is_refused(self):
        self.write("a2a", self.files["a2a"].replace(b"VM-ADMIT A2a PASS", b"VM-ADMIT A2a FAIL"))
        self.go["a2a"] = self.sha("a2a")
        self.refused("last line is not `VM-ADMIT A2a PASS")

    def test_an_a2b_line_is_refused(self):
        self.write("a2a", self.files["a2a"].replace(b"VM-ADMIT A2a PASS", b"VM-ADMIT A2b PASS"))
        self.go["a2a"] = self.sha("a2a")
        self.refused("last line is not `VM-ADMIT A2a PASS")

    def test_a_trailing_check_row_is_refused(self):
        self.write("a2a", self.files["a2a"] + b"CHECK late PASS\n")
        self.go["a2a"] = self.sha("a2a")
        self.refused("last line is not `VM-ADMIT A2a PASS")

    def test_a_ctlr_in_a_check_row_is_not_read(self):
        a2a = self.files["a2a"].replace(b"CHECK mount PASS ctlr=decoy", b"CHECK mount PASS ctlr=" +
                                        self.sha("ctlr").encode())
        a2a = a2a.replace(b" ctlr=" + self.sha("ctlr").encode() + b" utc=", b" ctlr=none utc=")
        self.write("a2a", a2a)
        self.go["a2a"] = self.sha("a2a")
        self.refused("ctlr=none")


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
    """ARGV must be exactly the fixed start the start spec builds."""

    def argv_refused(self, run):
        self.refused("ARGV is not the fixed start", run=run)

    def test_the_fixed_start_is_exactly_built_from_the_spec(self):
        self.assertEqual(ms.fixed_argv(SPEC), RUN)

    def test_another_program_is_refused(self):
        self.argv_refused(["/bin/sh"] + RUN[1:])

    def test_a_start_without_sudo_is_refused(self):
        self.argv_refused(RUN[4:])

    def test_sudo_without_u_is_refused(self):
        self.argv_refused([RUN[0]] + RUN[3:])

    def test_another_uid_is_refused(self):
        self.argv_refused([a if a != "#1001" else "#0" for a in RUN])

    def test_another_run_sh_is_refused(self):
        self.argv_refused([a if not a.endswith("run.sh") else "/tmp/run.sh" for a in RUN])

    def test_a_missing_flag_is_refused(self):
        for flag in ("--config", "--image", "--name", "--group-add"):
            with self.subTest(flag=flag):
                i = RUN.index(flag)
                self.argv_refused(RUN[:i] + RUN[i + 2:])

    def test_a_missing_detach_is_refused(self):
        self.argv_refused(RUN[:-1])

    def test_a_repeated_flag_is_refused(self):
        self.argv_refused(RUN[:-1] + ["--image", IMAGE, "--detach"])

    def test_an_extra_token_is_refused(self):
        self.argv_refused(RUN + ["--interval", "1"])

    def test_flags_out_of_order_are_refused(self):
        i, j = RUN.index("--config"), RUN.index("--image")
        run = RUN[:i] + RUN[j:j + 2] + RUN[i:i + 2] + RUN[j + 2:]
        self.argv_refused(run)

    def test_wrong_values_are_refused(self):
        for flag, bad in (("--config", "/srv/data/other.json"), ("--image", "sha256:" + "e" * 64),
                          ("--image", "amap-router-local"), ("--name", "other"), ("--group-add", "0")):
            with self.subTest(flag=flag, bad=bad):
                i = RUN.index(flag)
                self.argv_refused(RUN[:i + 1] + [bad] + RUN[i + 2:])

    def test_a_start_spec_that_is_not_sealed_is_refused(self):
        self.write_spec(SPEC, mode=0o644)
        self.refused("0644, not")

    def test_a_start_spec_owned_by_another_uid_is_refused(self):
        rc, err = None, None
        argv_owner = os.getuid() + 1
        with open(self.path("go"), "w") as f:
            f.write(" ".join(f"{k}={v}" for k, v in self.go.items()) + "\n")
        argv = ["--go", self.path("go"), "--order", self.order, "--a2a", self.path("a2a"), "--ctlr", self.path("ctlr"),
                "--psr", self.path("psr"), "--harpf", self.path("harpf"), "--start-spec", self.path("spec"), "--"] + RUN
        e = io.StringIO()
        with contextlib.redirect_stderr(e):
            rc = ms.main(argv, execv=lambda p, a: self.execd.append((p, a)), boot_id=lambda: BOOT,
                         now=lambda: self.now, spec_owner=argv_owner)
        self.assertEqual(rc, ms.EXIT_REFUSED)
        self.assertIn("a sealed overlay file", e.getvalue())
        self.assertEqual(self.execd, [])

    def test_a_linked_start_spec_is_refused(self):
        os.rename(self.path("spec"), self.path("spec.real"))
        os.symlink(self.path("spec.real"), self.path("spec"))
        self.refused("the start spec")

    def test_a_start_spec_with_another_key_is_refused(self):
        self.write_spec({**SPEC, "extra": 1})
        self.refused("the start spec must have exactly")

    def test_a_start_spec_with_a_tag_image_is_refused(self):
        self.write_spec({**SPEC, "image": "amap-router-local"})
        self.refused("is not an image Id")

    def test_a_start_spec_with_uid_0_is_refused(self):
        self.write_spec({**SPEC, "uid_1": 0})
        self.refused("uid_1 is not a positive integer")


class PsrGrammarTest(Fixture):
    """NET's PSR v1 / PSR-RECHECK v1 grammar: every malformed, missing, extra,
    reordered or contradictory receipt refuses."""

    def psr_refused(self, words, **kw):
        self.write("psr", psr_bytes(self.sha("ctlr"), **kw))
        self.go["psr"] = self.sha("psr")
        self.refused(words)

    def test_a_foreign_form_is_refused(self):
        self.write("psr", b"psr receipt\nresult PASS\n")
        self.go["psr"] = self.sha("psr")
        self.refused("lines, not 33")

    def test_a_wrong_version_is_refused(self):
        self.psr_refused("header is not `PSR v1`", tweak=lambda ls: ["PSR v2"] + ls[1:])

    def test_a_recheck_header_as_the_psr_is_refused(self):
        self.psr_refused("header is not `PSR v1`", tweak=lambda ls: ["PSR-RECHECK v1"] + ls[1:])

    def test_pass_with_a_diff_is_refused(self):
        self.psr_refused("disagrees with its items", diff=("hub.main.cf",), result="PASS")

    def test_pass_with_a_failed_prewindow_is_refused(self):
        self.psr_refused("disagrees with its items", prewindow="FAIL", result="PASS")

    def test_a_diff_item_fails_the_result(self):
        self.psr_refused("the PSR receipt's result is FAIL", diff=("vm1.delivered_domains_file",))

    def test_two_result_lines_are_refused(self):
        self.psr_refused("lines, not 33", tweak=lambda ls: ls[:-1] + ["result PASS", "DONE"])

    def test_pass_and_fail_lines_are_refused(self):
        self.psr_refused("lines, not 33", tweak=lambda ls: ls[:-2] + ["result FAIL", "result PASS", "DONE"])

    def test_an_unknown_row_is_refused(self):
        self.psr_refused("is not item", tweak=lambda ls: ls[:3] + ["item hub.extra " + "3" * 64 + " " + "3" * 64
                                                                   + " MATCH"] + ls[4:])

    def test_reordered_items_are_refused(self):
        self.psr_refused("is not item", tweak=lambda ls: ls[:3] + [ls[4], ls[3]] + ls[5:])

    def test_a_malformed_diff_token_is_refused(self):
        self.psr_refused("is not item", tweak=lambda ls: ls[:3] + [ls[3].replace("MATCH", "DIFFERENT")] + ls[4:])

    def test_a_missing_line_is_refused(self):
        self.psr_refused("lines, not 33", tweak=lambda ls: ls[:-2] + ls[-1:])

    def test_trailing_data_after_done_is_refused(self):
        self.psr_refused("lines, not 33", tweak=lambda ls: ls + ["junk"])

    def test_a_last_line_other_than_done_is_refused(self):
        self.psr_refused("does not end in DONE", tweak=lambda ls: ls[:-1] + ["END"])

    def test_a_crlf_receipt_is_refused(self):
        self.write("psr", psr_bytes(self.sha("ctlr")).replace(b"\n", b"\r\n"))
        self.go["psr"] = self.sha("psr")
        self.refused("end in exactly")

    def test_a_blank_line_is_refused(self):
        self.psr_refused("lines, not 33", tweak=lambda ls: ls[:5] + [""] + ls[5:])

    def test_a_psr_line_in_a_psr_is_refused(self):
        self.psr_refused("lines, not 33", tweak=lambda ls: ls[:1] + ["psr " + "9" * 64] + ls[1:])

    def test_unsorted_users_x_is_refused(self):
        self.psr_refused("not sorted and distinct",
                         users_x="router@m1vm2.hosts.internal,router@m1vm1.hosts.internal")

    def test_a_duplicate_users_x_login_is_refused(self):
        self.psr_refused("not sorted and distinct",
                         users_x="router@m1vm1.hosts.internal,router@m1vm1.hosts.internal")

    def test_two_sorted_users_x_logins_are_accepted(self):
        self.write("psr", psr_bytes(self.sha("ctlr"),
                                    users_x="router@m1vm1.hosts.internal,router@m1vm2.hosts.internal"))
        self.go["psr"] = self.sha("psr")
        rc, err = self.run_wrapper()
        self.assertEqual(rc, 0, err)

    def test_a_psr_ctlr_other_than_the_gos_is_refused(self):
        self.write("psr", psr_bytes("9" * 64))
        self.go["psr"] = self.sha("psr")
        self.refused("the PSR receipt's ctlr is not the go's ctlr=")

    def item(self, name, obs, ref, verdict):
        def tweak(ls):
            i = 3 + ms.PSR_ITEMS.index(name)
            return ls[:i] + [f"item {name} {obs} {ref} {verdict}"] + ls[i + 1:]
        return tweak

    def test_match_with_unequal_shas_is_refused(self):
        self.psr_refused("item hub.main.cf says MATCH, but its observed and reference shas are unequal",
                         tweak=self.item("hub.main.cf", "a" * 64, "b" * 64, "MATCH"))

    def test_every_item_says_match_with_unequal_shas_is_refused(self):
        def tweak(ls):
            for name in ms.PSR_ITEMS:
                ls = self.item(name, "a" * 64, "b" * 64, "MATCH")(ls)
            return ls
        self.psr_refused("says MATCH, but its observed and reference shas are unequal", tweak=tweak)

    def test_diff_with_equal_shas_is_refused(self):
        self.psr_refused("item hub.users_keys says DIFF, but its observed and reference shas are equal",
                         tweak=self.item("hub.users_keys", "3" * 64, "3" * 64, "DIFF"))

    def test_a_recheck_match_with_unequal_shas_is_refused(self):
        self.recheck, self.order = True, "later"
        self.write_recheck(tweak=lambda ls: ls[:4] + [f"item hub.main.cf {'a' * 64} {'b' * 64} MATCH"] + ls[5:])
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("PSR-RECHECK receipt's item hub.main.cf says MATCH")

    def test_a_render_not_referenced_to_its_clone_is_refused(self):
        for render, clone in ms.PSR_RENDER_REFS:
            with self.subTest(render=render):
                self.psr_refused(f"item {render} is not referenced to {clone}'s observed sha",
                                 tweak=self.item(render, "6" * 64, "6" * 64, "MATCH"))

    def test_a_render_referenced_to_another_clone_is_refused(self):
        def tweak(ls):
            ls = self.item("clone.delivered-domains.vm2", "7" * 64, "7" * 64, "MATCH")(ls)
            return self.item("vm1.delivered_domains_file", "7" * 64, "7" * 64, "MATCH")(ls)
        self.psr_refused("item vm1.delivered_domains_file is not referenced to clone.delivered-domains.vm1",
                         tweak=tweak)

    def test_distinct_shas_referenced_correctly_start(self):
        def tweak(ls):
            for n, name in enumerate(ms.PSR_ITEMS):
                ls = self.item(name, f"{n:064x}", f"{n:064x}", "MATCH")(ls)
            for render, clone in ms.PSR_RENDER_REFS:
                sha = f"{ms.PSR_ITEMS.index(clone):064x}"
                ls = self.item(render, sha, sha, "MATCH")(ls)
            return ls
        self.write("psr", psr_bytes(self.sha("ctlr"), tweak=tweak))
        self.go["psr"] = self.sha("psr")
        rc, err = self.run_wrapper()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.execd), 1)

    def test_a_recheck_of_another_psr_is_refused(self):
        self.order, self.recheck = "later", True
        self.write("recheck", psr_bytes(self.sha("ctlr"), recheck_of="9" * 64))
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("psr line is not the go's psr=")

    def test_a_recheck_with_a_psr_header_is_refused(self):
        self.order, self.recheck = "later", True
        self.write_recheck(tweak=lambda ls: ["PSR v1"] + ls[1:])
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("header is not `PSR-RECHECK v1`")

    def test_a_recheck_with_contradictory_result_is_refused(self):
        self.order, self.recheck = "later", True
        self.write_recheck(prewindow="FAIL", result="PASS")
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("disagrees with its items")

    def test_a_recheck_with_two_result_lines_is_refused(self):
        self.order, self.recheck = "later", True
        self.write_recheck(tweak=lambda ls: ls[:-1] + ["result PASS", "DONE"])
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("lines, not 34")

    def test_a_recheck_ctlr_other_than_the_gos_is_refused(self):
        self.order, self.recheck = "later", True
        self.write("recheck", psr_bytes("9" * 64, recheck_of=self.sha("psr")))
        self.go["psr_recheck"] = self.sha("recheck")
        self.refused("PSR-RECHECK receipt's ctlr is not the go's ctlr=")


class OpusOptionalTest(Fixture):

    def test_an_impossible_utc_is_refused_not_raised(self):
        bad = "2026-13-40T25:61:61Z"
        self.write_a2a(ctlr=self.sha("ctlr"))
        a2a = self.files["a2a"].replace(utc(self.a2a_t).encode(), bad.encode())
        self.write("a2a", a2a)
        self.go.update(a2a=self.sha("a2a"), a2a_utc=bad)
        self.refused("not a real UTC time")

    def test_an_unreadable_boot_id_names_its_source(self):
        with open(self.path("go"), "w") as f:
            f.write(" ".join(f"{k}={v}" for k, v in self.go.items()) + "\n")
        argv = ["--go", self.path("go"), "--order", self.order, "--a2a", self.path("a2a"), "--ctlr", self.path("ctlr"),
                "--psr", self.path("psr"), "--harpf", self.path("harpf"), "--start-spec", self.path("spec"), "--"] + RUN

        def broken():
            raise OSError(2, "No such file or directory")
        e = io.StringIO()
        with contextlib.redirect_stderr(e):
            rc = ms.main(argv, execv=lambda p, a: self.execd.append((p, a)), boot_id=broken, now=lambda: self.now,
                         spec_owner=os.getuid())
        self.assertEqual(rc, ms.EXIT_REFUSED)
        self.assertIn(ms.BOOT_ID, e.getvalue())


class CompleteReadTest(Fixture):
    """Both readers read to EOF however the bytes arrive, and refuse more than
    RECORD_MAX: a record and the start spec alike."""

    def short_reads(self):
        real = os.read
        self.addCleanup(setattr, os, "read", real)
        os.read = lambda fd, n: real(fd, min(n, 7))

    def test_short_reads_still_read_every_record_and_the_spec(self):
        self.short_reads()
        rc, err = self.run_wrapper()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.execd), 1)

    def test_a_spec_split_across_reads_is_read_whole(self):
        self.short_reads()
        self.assertEqual(ms.load_start_spec(self.path("spec"), owner=os.getuid()), SPEC)

    def test_an_oversized_start_spec_is_refused(self):
        import json
        doc = json.dumps(SPEC)[:-1] + ', "pad": "' + "x" * ms.RECORD_MAX + '"}'
        path = self.path("spec")
        os.chmod(path, 0o644)
        with open(path, "w") as f:
            f.write(doc)
        os.chmod(path, 0o444)
        self.refused(f"is larger than {ms.RECORD_MAX} bytes")

    def test_an_oversized_start_spec_is_refused_under_short_reads(self):
        path = self.path("spec")
        os.chmod(path, 0o644)
        with open(path, "wb") as f:
            f.write(b" " * (ms.RECORD_MAX + 1))
        os.chmod(path, 0o444)
        self.short_reads()
        with self.assertRaisesRegex(ms.Refused, "larger than"):
            ms.load_start_spec(path, owner=os.getuid())

    def test_an_oversized_record_is_refused_under_short_reads(self):
        self.write("harpf", b"x" * (ms.RECORD_MAX + 1))
        self.short_reads()
        with self.assertRaisesRegex(ms.Refused, "larger than"):
            ms.read_record(self.path("harpf"))

    def test_a_record_of_exactly_record_max_is_read(self):
        self.write("harpf", b"x" * ms.RECORD_MAX)
        self.short_reads()
        self.assertEqual(len(ms.read_record(self.path("harpf"))), ms.RECORD_MAX)

    def test_a_read_error_is_a_refusal(self):
        def fail(fd, n):
            raise OSError(5, "Input/output error")
        self.addCleanup(setattr, os, "read", os.read)
        os.read = fail
        self.refused("cannot be read (Input/output error)")


class UsageTest(Fixture):

    def test_missing_options_exit_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ms.main(["--go", "x", "--", "/bin/true"]), ms.EXIT_USAGE)

    def test_an_unknown_order_exits_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ms.main(["--go", "x", "--order", "first", "--a2a", "a", "--ctlr", "c", "--psr", "p",
                                      "--harpf", "h", "--start-spec", "s", "--", "/bin/true"]), ms.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
