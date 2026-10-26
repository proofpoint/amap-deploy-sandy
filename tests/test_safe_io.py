"""safe_io, and every install-path site that reads or writes through it.

The threat is a link planted where the deployment reads or writes its own
files: at a leaf, at the temporary name a write uses, or at a directory
between sandy's home and the leaf. Each test plants one, in a temporary
directory, and requires two things: the operation is refused by name, and
the file the link points at is neither read into the output nor written.
The decoding tests use a byte (0xff) whose value Python's own message would
print, and require that neither it nor its offset reaches the message.
"""

import json
import os
import shutil
import signal
import stat
import tempfile
import unittest
from pathlib import Path

import amap_sandy as prov
import connector_pin as cp
import fleet_policy as fp
import host_adapter as ha
import safe_io as sio

BAD_UTF8 = b'{"k": "\xff"}'


def _leaks_the_byte(message: str) -> bool:
    return any(s in message for s in ("0xff", "\\xff", "255", "position"))


class Tmp(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.d = Path(td.name)
        self.outside = self.d / "outside"
        self.outside.mkdir()
        self.secret = self.outside / "secret"
        self.secret.write_bytes(b"SECRET-BYTES\n")

    def secret_untouched(self):
        self.assertEqual(self.secret.read_bytes(), b"SECRET-BYTES\n")
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["secret"])


class Blocked(Exception):
    """Raised by the alarm: not an OSError, so no refusal can absorb it."""


def _raise_blocked(*_):
    raise Blocked("the open blocked")


class ReadLeafTest(Tmp):
    def test_a_regular_file_is_read(self):
        f = self.d / "f"
        f.write_bytes(b"abc")
        self.assertEqual(sio.read_leaf(f), b"abc")
        self.assertEqual(sio.read_text(f), "abc")

    def test_absent_is_file_not_found_and_a_refusal_is_not(self):
        with self.assertRaises(FileNotFoundError):
            sio.read_leaf(self.d / "nope")
        with self.assertRaises(FileNotFoundError):
            sio.read_leaf(self.d / "no-dir" / "nope")
        os.symlink(self.secret, self.d / "l")
        with self.assertRaises(sio.SafeIOError) as cm:
            sio.read_leaf(self.d / "l")
        self.assertNotIsInstance(cm.exception, FileNotFoundError)

    def test_a_link_at_the_leaf_is_not_followed(self):
        os.symlink(self.secret, self.d / "l")
        with self.assertRaises(sio.SafeIOError) as cm:
            sio.read_leaf(self.d / "l")
        self.assertIn("not followed", str(cm.exception))
        self.assertNotIn("SECRET", str(cm.exception))

    def test_a_link_at_every_directory_component_is_not_followed(self):
        """Each component from the top of the temporary tree down, one at a
        time: a live link and a dangling one."""
        chain = [self.d / "a", self.d / "a" / "b", self.d / "a" / "b" / "c"]
        for i, comp in enumerate(chain):
            for dangling in (False, True):
                with self.subTest(component=i, dangling=dangling):
                    root = Path(tempfile.mkdtemp(dir=self.d))
                    real = root / "real"
                    real.mkdir()
                    (real / "f").write_bytes(b"x")
                    parts = [root / "a", root / "a" / "b", root / "a" / "b" / "c"]
                    for p in parts[:i]:
                        p.mkdir()
                    os.symlink(root / "gone" if dangling else real, parts[i])
                    leaf = parts[-1] / "f" if i < len(parts) - 1 else parts[i] / "f"
                    with self.assertRaises(sio.SafeIOError) as cm:
                        sio.read_leaf(leaf)
                    self.assertIn("not followed", str(cm.exception))
                    self.assertIn(str(parts[i]), str(cm.exception))

    def test_a_directory_refuses(self):
        with self.assertRaises(sio.SafeIOError) as cm:
            sio.read_leaf(self.outside)
        self.assertIn("not a regular file", str(cm.exception))

    def test_a_fifo_refuses_without_blocking(self):
        f = self.d / "fifo"
        os.mkfifo(f)
        old = signal.signal(signal.SIGALRM, _raise_blocked)
        self.addCleanup(signal.signal, signal.SIGALRM, old)
        signal.alarm(5)
        try:
            with self.assertRaises(sio.SafeIOError) as cm:
                sio.read_leaf(f)
        finally:
            signal.alarm(0)
        self.assertIn("not a regular file", str(cm.exception))

    def test_a_second_hard_link_refuses(self):
        os.link(self.secret, self.d / "h")
        with self.assertRaises(sio.SafeIOError) as cm:
            sio.read_leaf(self.d / "h")
        self.assertIn("2 links", str(cm.exception))

    def test_bytes_past_the_bound_refuse(self):
        f = self.d / "big"
        f.write_bytes(b"x" * 11)
        self.assertEqual(sio.read_leaf(f, bound=11), b"x" * 11)
        with self.assertRaises(sio.SafeIOError):
            sio.read_leaf(f, bound=10)

    def test_a_decoding_failure_never_prints_the_byte(self):
        f = self.d / "bad"
        f.write_bytes(BAD_UTF8)
        with self.assertRaises(sio.SafeIOError) as cm:
            sio.read_text(f)
        self.assertFalse(_leaks_the_byte(str(cm.exception)), str(cm.exception))
        self.assertTrue(cm.exception.__suppress_context__, "the UnicodeDecodeError would print the byte in a traceback")

    def test_the_stat_is_the_descriptors(self):
        f = self.d / "x"
        f.write_bytes(b"")
        os.chmod(f, 0o751)
        self.assertEqual(stat.S_IMODE(sio.read_leaf_stat(f)[1].st_mode), 0o751)


class OpenDirTest(Tmp):
    def test_create_makes_every_missing_component(self):
        os.close(sio.open_dir(self.d / "a" / "b" / "c", create=True))
        self.assertTrue((self.d / "a" / "b" / "c").is_dir())

    def test_an_existing_tree_opens(self):
        os.close(sio.open_dir(self.outside))

    def test_a_linked_component_refuses_and_nothing_is_made_beneath_it(self):
        os.symlink(self.outside, self.d / "a")
        with self.assertRaises(sio.SafeIOError):
            sio.open_dir(self.d / "a" / "b", create=True)
        self.secret_untouched()

    def test_a_dangling_link_where_a_component_would_be_made_refuses(self):
        os.symlink(self.d / "absent", self.d / "a")
        with self.assertRaises(sio.SafeIOError):
            sio.open_dir(self.d / "a" / "b", create=True)
        self.assertFalse((self.d / "absent").exists())

    def test_a_file_in_the_way_refuses(self):
        (self.d / "a").write_text("")
        with self.assertRaises(sio.SafeIOError):
            sio.open_dir(self.d / "a" / "b", create=True)


class WriteLeafTest(Tmp):
    def test_a_write_lands_and_leaves_no_temporary(self):
        sio.write_leaf(self.d / "x" / "f", b"new")
        self.assertEqual((self.d / "x" / "f").read_bytes(), b"new")
        self.assertEqual(os.listdir(self.d / "x"), ["f"])

    def test_an_executable_is_exactly_0755_whatever_the_umask(self):
        """The legacy writer chmodded an executable to 0755 after writing, so
        the umask never reached it; a plain file was 0666 less the umask."""
        for umask, plain in ((0o022, 0o644), (0o077, 0o600), (0o027, 0o640)):
            with self.subTest(umask=oct(umask)):
                old = os.umask(umask)
                try:
                    sio.write_leaf(self.d / f"f{umask}", b"", executable=False)
                    sio.write_leaf(self.d / f"e{umask}", b"", executable=True)
                finally:
                    os.umask(old)
                self.assertEqual(stat.S_IMODE((self.d / f"f{umask}").stat().st_mode), plain)
                self.assertEqual(stat.S_IMODE((self.d / f"e{umask}").stat().st_mode), 0o755)

    def test_a_link_at_the_leaf_is_refused_not_replaced(self):
        os.symlink(self.secret, self.d / "f")
        with self.assertRaises(sio.SafeIOError):
            sio.write_leaf(self.d / "f", b"new")
        self.assertTrue((self.d / "f").is_symlink())
        self.secret_untouched()

    def test_a_link_at_a_directory_component_is_refused(self):
        os.symlink(self.outside, self.d / "sub")
        with self.assertRaises(sio.SafeIOError):
            sio.write_leaf(self.d / "sub" / "secret", b"new")
        self.secret_untouched()

    def test_a_planted_temporary_link_is_neither_followed_nor_removed(self):
        os.symlink(self.secret, self.d / ".f.tmp")
        sio.write_leaf(self.d / "f", b"new")
        self.assertEqual((self.d / "f").read_bytes(), b"new")
        self.assertTrue((self.d / ".f.tmp").is_symlink())
        self.secret_untouched()

    def test_an_object_at_the_temporary_name_refuses(self):
        real = sio.secrets.token_hex
        sio.secrets.token_hex = lambda n: "deadbeef"
        self.addCleanup(setattr, sio.secrets, "token_hex", real)
        os.symlink(self.secret, self.d / f".f.{os.getpid()}.deadbeef.tmp")
        with self.assertRaises(sio.SafeIOError):
            sio.write_leaf(self.d / "f", b"new")
        self.assertFalse((self.d / "f").exists())
        self.secret_untouched()

    def test_a_failed_write_removes_only_its_own_temporary(self):
        os.symlink(self.secret, self.d / ".f.tmp")
        real = os.replace

        def boom(*a, **k):
            raise OSError(5, "injected")
        os.replace = boom
        self.addCleanup(setattr, os, "replace", real)
        with self.assertRaises(OSError):
            sio.write_leaf(self.d / "f", b"new")
        os.replace = real
        self.assertEqual(sorted(os.listdir(self.d)), [".f.tmp", "outside"])
        self.secret_untouched()


class WriteFileSiteTest(Tmp):
    """`_write_file`: every install write (payload, stamp, manifest,
    router.json, activation records, plist, import batch)."""

    def test_a_link_at_the_leaf_refuses_and_its_target_is_untouched(self):
        os.symlink(self.secret, self.d / "f")
        with self.assertRaises(prov.ProvisionError) as cm:
            prov._write_file(self.d / "f", "new", dry_run=False, label="f")
        self.assertNotIn("SECRET", str(cm.exception))
        self.secret_untouched()

    def test_a_dry_run_refuses_the_link_too(self):
        os.symlink(self.secret, self.d / "f")
        with self.assertRaises(prov.ProvisionError):
            prov._write_file(self.d / "f", "new", dry_run=True, label="f")

    def test_a_non_utf8_leaf_is_refused_without_its_byte(self):
        (self.d / "f").write_bytes(BAD_UTF8)
        with self.assertRaises(prov.ProvisionError) as cm:
            prov._write_file(self.d / "f", "new", dry_run=False, label="f")
        self.assertFalse(_leaks_the_byte(str(cm.exception)), str(cm.exception))

    def test_a_linked_directory_component_refuses(self):
        os.symlink(self.outside, self.d / "sub")
        with self.assertRaises(prov.ProvisionError) as cm:
            prov._write_file(self.d / "sub" / "new", "x", dry_run=False, label="f")
        self.assertIn("not followed", str(cm.exception))
        self.secret_untouched()

    def test_the_write_itself_refuses_a_linked_directory_component(self):
        """The read before it refuses the same link; this removes the read
        (as a link planted between the two would) to reach the write."""
        os.symlink(self.outside, self.d / "sub")
        real = prov.sio.read_leaf_stat

        def absent(path, **_):
            raise FileNotFoundError(path)
        prov.sio.read_leaf_stat = absent
        self.addCleanup(setattr, prov.sio, "read_leaf_stat", real)
        with self.assertRaises(prov.ProvisionError) as cm:
            prov._write_file(self.d / "sub" / "new", "x", dry_run=False, label="f")
        self.assertIn("cannot write", str(cm.exception))
        self.secret_untouched()

    def test_the_executable_bit_is_read_from_the_descriptor(self):
        f = self.d / "f"
        f.write_text("same")
        os.chmod(f, 0o644)
        self.assertEqual(prov._write_file(f, "same", dry_run=False, label="f", executable=True), "updated f")
        self.assertTrue(f.stat().st_mode & 0o111)
        self.assertEqual(prov._write_file(f, "same", dry_run=False, label="f", executable=True), "f present")


class HomeSitesTest(Tmp):
    """The sites under sandy's home, each with one link planted."""

    def setUp(self):
        super().setUp()
        self.home = self.d / "sandy-home"
        self.root = prov.feature_root(self.home)
        self.root.mkdir(parents=True)

    def test_the_payload_refuses_a_linked_payload_directory(self):
        os.symlink(self.outside, prov.feature_payload_dir(self.home))
        with self.assertRaises(prov.ProvisionError):
            prov.install_feature_payload(self.home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False)
        self.secret_untouched()

    def test_the_payload_refuses_a_linked_feature_root(self):
        os.rename(self.root, self.outside / "amap")
        os.symlink(self.outside / "amap", self.root)
        with self.assertRaises(prov.ProvisionError):
            prov.install_feature_payload(self.home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False)
        self.assertEqual(os.listdir(self.outside / "amap"), [])

    def test_the_payload_refuses_a_linked_leaf(self):
        dest = prov.feature_payload_dir(self.home)
        dest.mkdir()
        os.symlink(self.secret, dest / prov.RELAY_WRAPPER_NAME)
        with self.assertRaises(prov.ProvisionError):
            prov.install_feature_payload(self.home, prov.DEFAULT_CONNECTOR_SRC, dry_run=False)
        self.secret_untouched()

    def test_the_payload_refuses_a_linked_source_rather_than_copy_through_it(self):
        src = self.d / "connector"
        src.mkdir()
        for name in (prov.DELIVERY_DAEMON_NAME, prov.DELIVERY_SUPPORT_NAME) + tuple(prov.CONNECTOR_BINARIES):
            (src / name).write_text("stand-in\n")
        os.unlink(src / prov.DELIVERY_DAEMON_NAME)
        os.symlink(self.secret, src / prov.DELIVERY_DAEMON_NAME)
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.install_feature_payload(self.home, src, dry_run=False)
        self.assertIn("payload source", str(cm.exception))
        dest = prov.feature_payload_dir(self.home) / prov.DELIVERY_DAEMON_NAME
        self.assertFalse(dest.exists())

    def test_the_manifest_refuses_a_link(self):
        os.symlink(self.secret, prov.feature_manifest_path(self.home))
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.install_manifest(self.home, fp.default_policy(), dry_run=False)
        self.assertIn("symlink", str(cm.exception))
        self.secret_untouched()

    def test_selected_json_refuses_a_link(self):
        os.symlink(self.secret, prov.feature_selected_path(self.home))
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.load_selected(self.home)
        self.assertIn("not followed", str(cm.exception))
        self.assertNotIn("SECRET", str(cm.exception))

    def test_selected_json_that_is_not_utf8_is_refused_without_its_byte(self):
        prov.feature_selected_path(self.home).write_bytes(BAD_UTF8)
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.load_selected(self.home)
        self.assertFalse(_leaks_the_byte(str(cm.exception)), str(cm.exception))

    def test_read_json_reports_a_link_as_unreadable(self):
        os.symlink(self.secret, self.d / "doc.json")
        got = prov._read_json(self.d / "doc.json")
        self.assertIsInstance(got, str)
        self.assertTrue(got.startswith("unreadable"), got)

    def test_read_json_reports_bad_utf8_without_its_byte(self):
        (self.d / "doc.json").write_bytes(BAD_UTF8)
        got = prov._read_json(self.d / "doc.json")
        self.assertTrue(got.startswith("unreadable"), got)
        self.assertFalse(_leaks_the_byte(got), got)

    def test_the_roster_directory_refuses_a_linked_feature_root(self):
        os.rename(self.root, self.outside / "amap")
        os.symlink(self.outside / "amap", self.root)
        with self.assertRaises(prov.ProvisionError):
            prov.install_roster_dir(self.home, dry_run=False)
        self.assertEqual(os.listdir(self.outside / "amap"), [])

    def test_a_roster_directory_reached_through_a_link_is_not_present(self):
        """The directory exists where the link points, so a pathname check
        would call it present; the walk refuses it."""
        os.rename(self.root, self.outside / "amap")
        (self.outside / "amap" / prov.feature_roster_dir(self.home).name).mkdir()
        os.symlink(self.outside / "amap", self.root)
        with self.assertRaises(prov.ProvisionError):
            prov.install_roster_dir(self.home, dry_run=False)

    def test_the_state_dir_refuses_a_linked_parent(self):
        os.symlink(self.outside, self.home / "linked")
        with self.assertRaises(prov.ProvisionError):
            prov.install_router_state_dir(self.home / "linked" / "state", dry_run=False)
        self.secret_untouched()

    def test_the_roster_directory_refuses_a_dangling_link_where_it_would_be_made(self):
        os.symlink(self.d / "absent", prov.feature_roster_dir(self.home))
        with self.assertRaises(prov.ProvisionError):
            prov.install_roster_dir(self.home, dry_run=False)
        self.assertFalse((self.d / "absent").exists())

    def test_the_identity_links_refuse_a_linked_directory(self):
        os.symlink(self.outside, prov.identity_links_dir(self.home))
        with self.assertRaises(OSError):
            prov.apply_identity_links(prov.identity_links_dir(self.home),
                                      [(prov.LINK_CREATE, "a", "/srv/example/identity/1", "")])
        self.secret_untouched()

    def test_the_router_inputs_refuse_a_link_before_the_router_reads_them(self):
        """The hop checks list `state_dir` and the router's loader reads
        `selected.json` and lists the instances directory, all by pathname;
        each is walked first."""
        state = self.home / "state"
        cases = (("state_dir", lambda: os.symlink(self.outside, state)),
                 ("instances", lambda: os.symlink(self.outside, prov.feature_instances_dir(self.home))),
                 ("selected.json", lambda: os.symlink(self.secret, prov.feature_selected_path(self.home))))
        for name, plant in cases:
            with self.subTest(name):
                plant()
                with self.assertRaises(sio.SafeIOError):
                    prov.walk_router_inputs(self.home, state)
                for p in (state, prov.feature_instances_dir(self.home), prov.feature_selected_path(self.home)):
                    if p.is_symlink():
                        p.unlink()
        prov.walk_router_inputs(self.home, state)  # every one absent

    HOP_KEYS = {"hop": {"root": "/r", "version_write": 1, "link": "L"}}

    def _hop_tree(self, state, *, evil=False):
        """A record tree in the shape hop_router.state_problems reads; with
        `evil`, every record disagrees with HOP_KEYS, so a consumer that
        reads one through a link reports something the real tree does not.
        Hidden identities and generations are included: pathlib's glob
        matches them."""
        root, link = ("/evil", "EVIL") if evil else ("/r", "L")
        for ident in ("id1", ".id2"):
            for gen in ("gen-1", "gen-.2"):
                for rec, body in (("transport/hop.json", {"hop_root": root, "version_write": 1}),
                                  ("ingress/link.json", {"link": link})):
                    f = state / ident / gen / rec
                    f.parent.mkdir(parents=True, exist_ok=True)
                    f.write_text(json.dumps(body))
            (state / ident / "generations.json").write_text("not json" if evil else '{"current": 1}')
        for gen in ("g1", ".g2", "g3"):
            f = state / "_runtime" / gen / "transport" / "hop.json"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps({"hop_root": root, "version_write": 9 if gen == "g3" else 1}))
        (state / "_runtime" / "generation.json").write_text('{"generation": "%s"}' % ("g3" if evil else "g1"))

    HOP_PLACES = ("_runtime", "_runtime/g1", "_runtime/.g2", "_runtime/g1/transport", "_runtime/g1/transport/hop.json",
                  "_runtime/.g2/transport/hop.json", "_runtime/generation.json",
                  "id1", ".id2", "id1/gen-1", "id1/gen-.2", ".id2/gen-1", "id1/gen-1/transport", "id1/gen-1/ingress",
                  "id1/gen-1/transport/hop.json", "id1/gen-1/ingress/link.json", ".id2/gen-.2/transport/hop.json",
                  "id1/generations.json", ".id2/generations.json")

    def test_the_hop_record_tree_refuses_a_link_at_each_place_the_hop_checks_read(self):
        """A STABLE link, planted before the walk, at every component
        state_problems lists or reads, hidden ones included. For each, the
        ACTUAL consumer is shown to reach through it (its report changes when
        the link points at a disagreeing copy), and the walk refuses it."""
        import hop_router as hp
        for rel in self.HOP_PLACES:
            with self.subTest(rel):
                base = Path(tempfile.mkdtemp(dir=self.d))
                state, evil = base / "state", base / "evil"
                self._hop_tree(state)
                self._hop_tree(evil, evil=True)
                prov.walk_router_inputs(self.home, state)
                real = hp.state_problems(str(state), self.HOP_KEYS)
                target = state / rel
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
                os.symlink(evil / rel, target)
                self.assertNotEqual(hp.state_problems(str(state), self.HOP_KEYS), real,
                                    f"the consumer does not reach {rel}, so this place proves nothing")
                with self.assertRaises(sio.SafeIOError) as cm:
                    prov.walk_router_inputs(self.home, state)
                self.assertIn(str(target), str(cm.exception))

    def test_a_hidden_link_in_state_dir_refuses(self):
        """Codex's witness: a hidden child linked to an outside tree, which
        pathlib's glob reaches and state_problems reads."""
        import hop_router as hp
        state, outside = self.home / "state", self.home / "elsewhere"
        state.mkdir()
        self._hop_tree(outside)
        os.symlink(outside / "id1", state / ".hidden")
        self.assertTrue(hp.state_problems(str(state), None), "the consumer reads the hidden link")
        with self.assertRaises(sio.SafeIOError) as cm:
            prov.walk_router_inputs(self.home, state)
        self.assertIn(".hidden", str(cm.exception))

    def test_the_hop_checks_list_nothing_outside_once_the_walk_passes(self):
        """The witness Codex built: a linked _runtime that hop_router would
        scandir. With the walk in front, the external call is not reached."""
        import hop_router as hp
        state = self.home / "state"
        state.mkdir()
        os.symlink(self.outside, state / "_runtime")
        with self.assertRaises(sio.SafeIOError):
            prov.walk_router_inputs(self.home, state)
        self.assertEqual(hp.state_problems(str(state), None), [], "the external check alone does not refuse")

    def test_render_router_walks_the_inputs_before_the_hop_checks(self):
        """run_render_router itself, with unrelated render preparation
        stubbed: a linked _runtime returns 2 before hop_router_keys runs."""
        import argparse
        state = self.home / "state"
        state.mkdir()
        os.symlink(self.outside, state / "_runtime")
        reached = []
        stubs = {"load_membership": lambda home, boxes: {},
                 "render_router_sibling": lambda *a, **k: {"_doc": {}, "_warnings": []},
                 "hop_router_keys": lambda *a, **k: reached.append("hop") or (None, [])}
        for name, fn in stubs.items():
            self.addCleanup(setattr, prov, name, getattr(prov, name))
            setattr(prov, name, fn)
        args = argparse.Namespace(state_dir=str(state), overlay=None, decommission_hop=False)
        import contextlib, io
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = prov.run_render_router(args, self.home, [], {}, apply=False)
        self.assertEqual(rc, 2)
        self.assertEqual(reached, [])
        self.assertIn("_runtime", err.getvalue())

    def test_an_empty_directory_create_refuses_a_parent_swapped_after_the_check(self):
        """The race the create walk exists for: the no-create walk finds the
        directory absent, then its parent is replaced by a link before the
        create. The create walk refuses and nothing is made outside."""
        parent = self.home / "p"
        parent.mkdir()
        real = sio.open_dir

        def swapping(path, *, create=False):
            if create:
                return real(path, create=create)
            try:
                return real(path, create=create)
            finally:
                if not parent.is_symlink():
                    os.rename(parent, self.d / "p-moved")
                    os.symlink(self.outside, parent)
        self.addCleanup(setattr, sio, "open_dir", real)
        sio.open_dir = swapping
        with self.assertRaises(prov.ProvisionError):
            prov._install_empty_dir(parent / "roster", "roster directory", "test", dry_run=False)
        self.secret_untouched()

    def test_the_servers_file_refuses_a_link(self):
        os.symlink(self.secret, self.d / "servers.json")
        with self.assertRaises(prov.ProvisionError) as cm:
            prov.load_servers(self.d / "servers.json")
        self.assertIn("not followed", str(cm.exception))


class SharedAndAdapterSitesTest(Tmp):
    def test_load_policy_refuses_a_link_rather_than_return_the_template(self):
        real = self.d / "feature.json"
        real.write_text(json.dumps({"feature": {}}))
        os.symlink(real, self.d / "linked.json")
        with self.assertRaises(fp.PolicyError):
            fp.load_policy(self.d / "linked.json")

    def test_load_policy_refuses_a_linked_directory_component(self):
        real = self.outside / "feature.json"
        real.write_text(json.dumps({"feature": {}}))
        os.symlink(self.outside, self.d / "linked")
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.d / "linked" / "feature.json")
        self.assertIn("symlink", str(cm.exception))
        self.assertTrue(str(cm.exception).startswith(f"{self.d / 'linked'} is a symlink"), str(cm.exception))

    def test_load_policy_under_a_missing_directory_is_the_template(self):
        doc = fp.load_policy(self.d / "no-dir" / "feature.json")
        self.assertEqual(doc[fp.SOURCE_KEY], fp.SOURCE_DEFAULT)

    def test_load_policy_reads_a_regular_file(self):
        (self.d / "feature.json").write_text(json.dumps({"feature": {"fleet_domain": "a.example.org"}}))
        self.assertNotEqual(fp.load_policy(self.d / "feature.json").get(fp.SOURCE_KEY), fp.SOURCE_DEFAULT)

    def test_load_policy_still_returns_the_template_for_an_absent_file(self):
        doc = fp.load_policy(self.d / "absent.json")
        self.assertEqual(doc[fp.SOURCE_KEY], fp.SOURCE_DEFAULT)

    def test_load_policy_refuses_a_second_hard_link(self):
        real = self.d / "feature.json"
        real.write_text(json.dumps({"feature": {}}))
        os.link(real, self.d / "h.json")
        with self.assertRaises(fp.PolicyError):
            fp.load_policy(real)

    def test_the_policy_reader_itself_never_follows_a_link(self):
        """The fstatat before it is the refusal an operator sees; this is
        the descriptor's own guard, for a link swapped in between the two."""
        real = self.d / "feature.json"
        real.write_text("{}")
        os.symlink(real, self.d / "linked.json")
        dfd = os.open(self.d, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, dfd)
        with self.assertRaises(OSError):
            fp._read_policy_text(dfd, "linked.json", self.d / "linked.json")

    def test_load_policy_reports_bad_utf8_without_its_byte(self):
        (self.d / "feature.json").write_bytes(BAD_UTF8)
        with self.assertRaises(fp.PolicyError) as cm:
            fp.load_policy(self.d / "feature.json")
        self.assertFalse(_leaks_the_byte(str(cm.exception)), str(cm.exception))

    def test_the_install_log_refuses_a_linked_directory_component(self):
        os.symlink(self.outside, self.d / "features")
        with self.assertRaises(OSError):
            cp.append_line(self.d / "features" / "amap" / "install.log", "x\n")
        self.secret_untouched()

    def test_the_install_log_refuses_a_fifo_without_blocking(self):
        os.mkfifo(self.d / "install.log")
        old = signal.signal(signal.SIGALRM, _raise_blocked)
        self.addCleanup(signal.signal, signal.SIGALRM, old)
        signal.alarm(5)
        try:
            with self.assertRaises(OSError):
                cp.append_line(self.d / "install.log", "x\n")
        finally:
            signal.alarm(0)

    def test_the_install_log_refuses_a_second_hard_link_and_its_alias_is_unchanged(self):
        alias = self.outside / "alias"
        alias.write_bytes(b"ALIAS\n")
        os.link(alias, self.d / "install.log")
        with self.assertRaises(OSError) as cm:
            cp.append_line(self.d / "install.log", "x\n")
        self.assertIn("2 links", str(cm.exception))
        self.assertEqual(alias.read_bytes(), b"ALIAS\n")

    def test_the_install_log_appends(self):
        cp.append_line(self.d / "a" / "install.log", "x\n")
        cp.append_line(self.d / "a" / "install.log", "y\n")
        self.assertEqual((self.d / "a" / "install.log").read_text(), "x\ny\n")

    def test_the_install_log_refuses_a_linked_leaf(self):
        os.symlink(self.secret, self.d / "install.log")
        with self.assertRaises(OSError):
            cp.append_line(self.d / "install.log", "x\n")
        self.secret_untouched()

    def test_the_overlay_refuses_a_link(self):
        os.symlink(self.secret, self.d / "overlay.json")
        with self.assertRaises(ha.OverlayError) as cm:
            ha.load_identifiers(self.d / "overlay.json")
        self.assertIn("not followed", str(cm.exception))
        self.assertNotIn("SECRET", str(cm.exception))

    def test_the_overlay_reports_bad_utf8_without_its_byte(self):
        (self.d / "overlay.json").write_bytes(BAD_UTF8)
        with self.assertRaises(ha.OverlayError) as cm:
            ha.load_identifiers(self.d / "overlay.json")
        self.assertFalse(_leaks_the_byte(str(cm.exception)), str(cm.exception))


if __name__ == "__main__":
    unittest.main()
