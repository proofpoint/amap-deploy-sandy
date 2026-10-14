"""hygiene_gate: the public/private hygiene gate, run for real against
scratch git repositories and scratch list directories.

Every name and fixture here is INVENTED (`zz-planted-host`, `zzplantedcorp`,
synthetic base64 lines). The private lists never enter this repository; the
tests build their own lists in a temporary directory, so a planted name is
found, a near miss is not, and each surface is read.
"""

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import hygiene_gate as hg

NAMES = """# invented entries
token zz-planted-host
word zzplantedcorp
regex zzslug-[0-9a-f]{8}
email zz\\.person@example\\.org
allow zz-planted-host\\.registry/[12]
+ zz-planted-host.registry/1
- zz-planted-host.registry/3
allow 1\\+zz@users\\.noreply\\.example\\.org
+ 1+zz@users.noreply.example.org
- 2+zz@users.noreply.example.org
"""

#: Synthetic high-entropy lines: base64 of fixed bytes, so they are eligible.
FIX_LINE = base64.b64encode(hashlib.sha256(b"fixture-one").digest() * 2).decode()
FIX_LINE2 = base64.b64encode(hashlib.sha256(b"fixture-two").digest() * 2).decode()
SIG_LINE = f'  "sig": "{FIX_LINE}",'
FIX_FILE = (f'{{\n{SIG_LINE}\n  "kind": "invented"\n}}\n').encode()


def fingerprints(files=(FIX_FILE,), lines=(SIG_LINE,)):
    return {"schema": hg.FINGERPRINT_SCHEMA, "gate_commit": "0" * 40, "source_sha256": "0" * 64,
            "files": sorted(hashlib.sha256(f).hexdigest() for f in files),
            "lines": sorted(hg.fingerprint_digest(l) for l in lines), "no_eligible_line": []}


ENV = {**hg.git_env(), "GIT_AUTHOR_NAME": "Test Author", "GIT_AUTHOR_EMAIL": "author@example.org",
       "GIT_COMMITTER_NAME": "Test Committer", "GIT_COMMITTER_EMAIL": "committer@example.org"}


class Repo:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True)
        self.git("init", "-q", "-b", "main")

    def git(self, *args, env=None, input=None):
        p = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, env={**ENV, **(env or {})},
                           input=input)
        if p.returncode:
            raise AssertionError(p.stderr.decode())
        return p.stdout.decode().strip()

    def commit(self, files=None, message="change", remove=(), env=None):
        for name, data in (files or {}).items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data if isinstance(data, bytes) else data.encode())
        for name in remove:
            self.git("rm", "-q", name)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message, env=env)
        return self.git("rev-parse", "HEAD")


class GateTest(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        self.lists = self.t / "lists"
        self.lists.mkdir()
        self.write_lists()
        self.repo = Repo(self.t / "repo")
        self.base = self.repo.commit({"README.md": "a clean public repository\n"}, "start")

    def write_lists(self, names=NAMES, allow="", fp=None):
        (self.lists / "names.txt").write_text(names)
        (self.lists / "allow.txt").write_text(allow)
        (self.lists / "fingerprints.json").write_text(json.dumps(fp or fingerprints()))

    def run_gate(self, *args, repo="public-repo"):
        said = []
        rc = hg.main(["scan", "--lists", str(self.lists), "--repo", repo, "--git", str(self.repo.root), *args],
                     out=said.append)
        return rc, "\n".join(said)

    def findings(self, out):
        return [l for l in out.splitlines() if l.startswith("FINDING")]

    def assert_found(self, args, *where):
        rc, out = self.run_gate(*args)
        self.assertEqual(rc, 1, out)
        for w in where:
            self.assertIn(w, out)
        return out

    def assert_clean(self, args):
        rc, out = self.run_gate(*args)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.findings(out), [])
        return out


class NamesFoundEverywhereTest(GateTest):
    def test_a_clean_tree_and_history_pass(self):
        self.assert_clean(["--tree", "HEAD", "--all-history", "--refs"])

    def test_a_tracked_file(self):
        self.repo.commit({"notes.md": "deploy to zz-planted-host tonight\n"})
        out = self.assert_found(["--tree", "HEAD"], "tree", "notes.md:1", "names.txt line 2")
        self.assertNotIn("zz-planted-host", out, "the entry's text is never printed without --show")

    def test_joined_by_separator_removal_and_case(self):
        self.repo.commit({"a.py": "HOST = 'ZZ_PLANTED.HOST'\n"})
        self.assert_found(["--tree", "HEAD"], "a.py:1")

    def test_a_commit_message_and_an_added_line(self):
        c = self.repo.commit({"b.txt": "x\nzz planted host\n"}, "reach zz-planted-host")
        out = self.assert_found([f"--range={self.base}..HEAD"], f"commit {c[:12]} message:1",
                                f"commit {c[:12]} b.txt:2")
        self.assertNotIn("b.txt:1", out)

    def test_an_author_email_and_a_personal_address(self):
        self.repo.commit({"c.txt": "c\n"}, env={"GIT_AUTHOR_EMAIL": "zz.person@example.org"})
        self.assert_found([f"--range={self.base}..HEAD"], "author", "names.txt line 5")

    def test_the_allowed_noreply_identity_is_clean_and_a_near_one_is_not(self):
        self.write_lists(NAMES + "token noreplyzz\n")
        self.repo.commit({"d.txt": "d\n"}, env={"GIT_AUTHOR_EMAIL": "1+zz@users.noreply.example.org",
                                                "GIT_AUTHOR_NAME": "Plain Name"})
        self.write_lists(NAMES.replace("email zz\\.person@example\\.org", "email [0-9]\\+zz@users\\.noreply\\.example\\.org"))
        out = self.assert_clean([f"--range={self.base}..HEAD"])
        self.assertIn("allow: names.txt line", out)
        self.repo.commit({"e.txt": "e\n"}, env={"GIT_AUTHOR_EMAIL": "2+zz@users.noreply.example.org"})
        self.assert_found([f"--range={self.base}..HEAD"], "author")

    def test_a_branch_name_a_tag_name_and_an_annotated_tag_message(self):
        self.repo.git("branch", "zz-planted-host-fix")
        self.assert_found(["--refs"], "ref refs/heads/zz-planted-host-fix")
        self.repo.git("branch", "-D", "zz-planted-host-fix")
        self.repo.git("tag", "-a", "v1", "-m", "release for zzplantedcorp")
        self.assert_found(["--refs"], "tag refs/tags/v1 message:1")

    def test_a_path_name_added_renamed_and_deleted(self):
        c1 = self.repo.commit({"conf/zz-planted-host.yml": "a: 1\n"})
        self.assert_found(["--tree", "HEAD"], "path name")
        c2 = self.repo.commit(remove=["conf/zz-planted-host.yml"])
        self.assert_clean(["--tree", "HEAD"])
        out = self.assert_found([f"--range={self.base}..HEAD"], f"commit {c1[:12]} conf/zz-planted-host.yml path name",
                                f"commit {c2[:12]} conf/zz-planted-host.yml path name")
        self.repo.commit({"x/plain.txt": "same body\n"})
        self.repo.git("mv", "x/plain.txt", "x/zzplantedcorp.txt")
        c4 = self.repo.commit(message="rename")
        self.assert_found([f"--range={c4}~1..{c4}"], "x/zzplantedcorp.txt path name")

    def test_a_name_committed_then_deleted_is_found_in_history(self):
        self.repo.commit({"old.txt": "zz-planted-host\n"})
        self.repo.commit(remove=["old.txt"])
        self.assert_clean(["--tree", "HEAD"])
        self.assert_found(["--all-history"], "old.txt:1")

    def test_a_merges_added_lines_are_its_own_resolution_only(self):
        """A line a merge brings in from a side branch is the side commit's;
        a line the merge itself writes (its resolution) is the merge's."""
        self.repo.git("checkout", "-q", "-b", "side")
        side = self.repo.commit({"m.txt": "one\nzz-planted-host side\n"}, "side")
        self.repo.git("checkout", "-q", "main")
        self.repo.commit({"other.txt": "o\n"}, "main")
        self.repo.git("merge", "-q", "--no-ff", "side", "-m", "merge")
        merge = self.repo.git("rev-parse", "HEAD")
        out = self.assert_found([f"--range={self.base}..HEAD"], f"commit {side[:12]} m.txt:2")
        self.assertNotIn(f"commit {merge[:12]} m.txt", out)
        # A conflict resolved by the merge with a new line.
        self.repo.git("checkout", "-q", "-b", "side2")
        self.repo.commit({"k.txt": "side version\n"}, "s2")
        self.repo.git("checkout", "-q", "main")
        self.repo.commit({"k.txt": "main version\n"}, "m2")
        subprocess.run(["git", "-C", str(self.repo.root), "merge", "-q", "side2"], capture_output=True, env=ENV)
        (self.repo.root / "k.txt").write_text("resolved for zzplantedcorp\n")
        self.repo.git("add", "k.txt")
        self.repo.git("commit", "-q", "--no-edit")
        m2 = self.repo.git("rev-parse", "HEAD")
        self.assert_found([f"--range={m2}~1..{m2}"], f"commit {m2[:12]} k.txt:1")

    def test_text_from_a_file(self):
        body = self.t / "body.md"
        body.write_text("Summary\n\nTested on zzplantedcorp's host.\n")
        self.assert_found(["--text", str(body)], f"text {body}:3")

    def test_a_long_line_is_scanned_for_regexes(self):
        self.repo.commit({"long.txt": "x" * (hg.MAX_LINE + 100) + " zzslug-0123abcd\n"})
        self.assert_found(["--tree", "HEAD"], "long.txt:1", "names.txt line 4")


class NegativeTest(GateTest):
    def test_a_near_word_is_not_a_word_match(self):
        self.repo.commit({"w.txt": "notzzplantedcorpus\n"})
        self.assert_clean(["--tree", "HEAD"])
        self.repo.commit({"w.txt": "(zzplantedcorp)\n"})
        self.assert_found(["--tree", "HEAD"], "w.txt:1")

    def test_an_allow_masked_schema_id_is_clean_and_counted(self):
        self.repo.commit({"s.json": '{"schema": "zz-planted-host.registry/1"}\n'})
        out = self.assert_clean(["--tree", "HEAD"])
        self.assertIn("allow: names.txt line 6 masked 1 span(s)", out)
        self.repo.commit({"s.json": '{"schema": "zz-planted-host.registry/3"}\n'})
        self.assert_found(["--tree", "HEAD"], "s.json:1")

    def test_a_base64_blob_that_is_no_fixture_is_clean(self):
        self.repo.commit({"blob.txt": FIX_LINE2 + "\n"})
        self.assert_clean(["--tree", "HEAD"])


class UnicodeTest(GateTest):
    """A character whose lower case is longer than itself (U+0130 becomes
    two) must not shift later matches onto the wrong source characters."""

    def scan(self, text):
        p = self.t / "u.txt"
        p.write_text(text, encoding="utf-8")
        return self.run_gate("--text", str(p))

    def test_a_word_after_a_two_character_lowercasing_letter_is_found(self):
        for text in ("\u0130 see zzplantedcorp now", "\u0130\u0130\u0130\u0130 zzplantedcorp",
                     "\u0130" * 40 + " (zzplantedcorp) " + "\u0130" * 40):
            with self.subTest(text=text[:12]):
                rc, out = self.scan(text + "\n")
                self.assertEqual(rc, 1, out)
                self.assertIn("names.txt line 3", out)

    def test_a_word_directly_followed_by_such_a_letter_is_unbounded(self):
        rc, out = self.scan("zzplantedcorp\u0130 and \u0130zzplantedcorp\n")
        self.assertEqual(rc, 0, out)

    def test_sharp_s_and_ligatures_keep_their_place(self):
        rc, out = self.scan("stra\u00dfe \ufb03 \u1e9e zzplantedcorp\n")
        self.assertEqual(rc, 1, out)
        self.assertIn("names.txt line 3", out)

    def test_an_internal_error_is_cannot_run_never_a_traceback(self):
        orig = hg.Matcher.text
        self.addCleanup(setattr, hg.Matcher, "text", orig)

        def boom(self, *a, **k):
            raise IndexError("x")
        hg.Matcher.text = boom
        rc, out = self.scan("anything\n")
        self.assertEqual(rc, 2)
        self.assertIn("CANNOT RUN: internal error IndexError", out)


class FixtureTest(GateTest):
    def test_a_whole_file_copy_under_another_name(self):
        self.repo.commit({"vendored/copy.json": FIX_FILE})
        self.assert_found(["--tree", "HEAD"], "vendored/copy.json: s5-r4 fixture file")

    def test_one_eligible_line_pasted(self):
        self.repo.commit({"t/test_x.py": f"SIG = (\n{SIG_LINE}\n)\n"})
        out = self.assert_found(["--tree", "HEAD"], "t/test_x.py:2: s5-r4 fixture line")
        self.assertNotIn(FIX_LINE, out)

    def test_a_binary_copy_is_found_by_its_file_hash(self):
        binary = b"\0\1\2" + FIX_FILE
        self.write_lists(fp=fingerprints(files=(FIX_FILE, binary)))
        self.repo.commit({"b.bin": binary})
        self.assert_found(["--tree", "HEAD"], "b.bin: s5-r4 fixture file")

    def test_a_fixture_line_in_history(self):
        self.repo.commit({"p.txt": SIG_LINE + "\n"})
        self.repo.commit(remove=["p.txt"])
        self.assert_found(["--all-history"], "p.txt:1: s5-r4 fixture line")

    def test_a_reformatted_copy_is_not_caught(self):
        """The recorded limit: a fixture re-wrapped line by line."""
        wrapped = "\n".join(FIX_LINE[i:i + 16] for i in range(0, len(FIX_LINE), 16))
        self.repo.commit({"r.txt": wrapped + "\n"})
        self.assert_clean(["--tree", "HEAD"])


class ExceptionsTest(GateTest):
    def digest(self, line):
        return hashlib.sha256(line.encode()).hexdigest()

    def test_a_commit_exception_masks_that_commit_only(self):
        c = self.repo.commit({"h.txt": "zz-planted-host\n"}, "accepted")
        self.write_lists(allow=f"commit public-repo {c} accepted history (no rewrite)\n")
        out = self.assert_clean([f"--range={self.base}..HEAD"])
        self.assertIn("exceptions: commit applied", out)
        self.repo.commit({"h2.txt": "zz-planted-host\n"}, "again")
        self.assert_found([f"--range={self.base}..HEAD"], "h2.txt:1")

    def test_a_commit_exception_is_for_its_repository_only(self):
        c = self.repo.commit({"h.txt": "zz-planted-host\n"})
        self.write_lists(allow=f"commit other-repo {c} elsewhere\n")
        self.assert_found([f"--range={self.base}..HEAD"], "h.txt:1")

    def test_a_tree_exception_masks_only_its_own_commits_tree(self):
        line = "the skeleton names zz-planted-host"
        c = self.repo.commit({"doc/s.md": line + "\n"})
        self.write_lists(allow=f"tree public-repo {c} doc/s.md {self.digest(line)} retained ref head\n")
        self.assert_clean(["--tree", c])
        self.repo.commit({"unrelated.txt": "u\n"})
        self.assert_found(["--tree", "HEAD"], "doc/s.md:1")

    def test_a_path_exception_masks_that_line_at_that_path(self):
        line = "seen zz-planted-host once"
        self.repo.commit({"p/q.md": line + "\n", "p/r.md": line + "\n"})
        self.write_lists(allow=f"path public-repo p/q.md {self.digest(line)} reviewed\n")
        out = self.assert_found(["--tree", "HEAD"], "p/r.md:1")
        self.assertNotIn("p/q.md", out)

    def test_unused_commit_and_tree_exceptions_are_listed(self):
        self.write_lists(allow=f"commit public-repo {'a' * 40} gone\ntree public-repo {'b' * 40} x {'c' * 64} gone\n")
        out = self.assert_clean(["--tree", "HEAD"])
        self.assertIn("allow.txt line 1 (commit) matched nothing", out)
        self.assertIn("allow.txt line 2 (tree) matched nothing", out)


class CannotRunTest(GateTest):
    def refused(self, names=NAMES, allow="", fp=None, args=("--tree", "HEAD")):
        self.write_lists(names, allow, fp)
        rc, out = self.run_gate(*args)
        self.assertEqual(rc, 2, out)
        self.assertIn("CANNOT RUN", out)
        return out

    def test_a_missing_list(self):
        (self.lists / "allow.txt").unlink()
        rc, out = self.run_gate("--tree", "HEAD")
        self.assertEqual(rc, 2, out)

    def test_an_empty_or_malformed_list(self):
        self.refused(names="# nothing\n")
        self.refused(names="host zz-planted-host\n")
        self.refused(allow="commit public-repo abc reason\n")
        self.refused(fp={"schema": hg.FINGERPRINT_SCHEMA, "files": [], "lines": []})
        (self.lists / "fingerprints.json").write_text("{")
        rc, _ = self.run_gate("--tree", "HEAD")
        self.assertEqual(rc, 2)

    def test_a_short_token_or_a_generic_label(self):
        self.assertIn("shorter than", self.refused(names="token zz-ab\n"))
        self.assertIn("generic label", self.refused(names="token Local.Host\n"))

    def test_an_unsafe_or_long_regex(self):
        self.assertIn("quantifier", self.refused(names="regex (a+)+b\n"))
        self.assertIn("longer than", self.refused(names="regex " + "a" * (hg.MAX_REGEX + 1) + "\n"))
        self.assertIn("compile", self.refused(names="regex (unclosed\n"))

    def test_an_allow_entry_without_or_failing_its_examples(self):
        self.refused(names="token zzplantedcorp\nallow abc[0-9]\n+ abc1\n")
        self.refused(names="token zzplantedcorp\nallow abc[0-9]\n+ abcx\n- abd1\n")
        self.refused(names="token zzplantedcorp\nallow abc[0-9]\n+ abc1\n- abc2\n")

    def test_no_fingerprints_is_explicit_never_a_silent_skip(self):
        """Without the flag, a missing fingerprints.json cannot run; with it,
        names are still matched, no fixture is, the output says so, and the
        digest differs from a run with fingerprints."""
        self.repo.commit({"copy.json": FIX_FILE, "n.txt": "zz-planted-host\n"})
        with_fp = hg.load_lists(str(self.lists)).digest
        (self.lists / "fingerprints.json").unlink()
        rc, out = self.run_gate("--tree", "HEAD")
        self.assertEqual(rc, 2, out)
        rc, out = self.run_gate("--tree", "HEAD", "--no-fingerprints")
        self.assertEqual(rc, 1, out)
        self.assertIn("n.txt:1", out)
        self.assertNotIn("fixture", out.replace("no fixture content", ""))
        self.assertIn("fingerprints: not used (--no-fingerprints)", out)
        self.assertNotEqual(hg.load_lists(str(self.lists), False).digest, with_fp)

    def test_a_shallow_clone(self):
        self.repo.commit({"more.txt": "m\n"})
        shallow = self.t / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{self.repo.root}", str(shallow)],
                       check=True, env=ENV, capture_output=True)
        said = []
        rc = hg.main(["scan", "--lists", str(self.lists), "--repo", "r", "--git", str(shallow), "--all-history"],
                     out=said.append)
        self.assertEqual(rc, 2)
        self.assertIn("shallow", "\n".join(said))

    def test_a_git_failure(self):
        rc, out = self.run_gate("--tree", "no-such-rev")
        self.assertEqual(rc, 2, out)


class FingerprintBuildTest(unittest.TestCase):
    """The builder against a scratch source repository bundled like the
    private delivery: every input is bound by a source record."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        src = Repo(self.t / "src")
        prose = "This fixture describes an invented case in plain words only.\n"
        src.commit({"spec/profile.md": "an invented profile\n", "fixtures/a.json": FIX_FILE,
                    "fixtures/b/prose.txt": prose, "fixtures/c.bin": b"\0binary\1"}, "s")
        src.git("tag", "-a", "s5-r4", "-m", "invented tag")
        self.commit = src.git("rev-parse", "HEAD")
        self.bundle = self.t / "s.bundle"
        src.git("bundle", "create", str(self.bundle), "refs/tags/s5-r4")
        self.public = Repo(self.t / "pub")
        self.public.commit({"README.md": "public\n"})
        self.record = {
            "bundle": {"filename": "s.bundle", "sha256": hashlib.sha256(self.bundle.read_bytes()).hexdigest()},
            "commit": self.commit, "tag": "s5-r4",
            "profile": {"path": "spec/profile.md", "sha256": hashlib.sha256(b"an invented profile\n").hexdigest()},
            "fixture_root": {"path": "fixtures", "tree": src.git("rev-parse", f"{self.commit}:fixtures")},
            "fixture_count": 3}
        self.src = src

    def build(self, record=None, public=None):
        p = self.t / "source.json"
        p.write_text(json.dumps(record or self.record))
        out = self.t / "fp.json"
        said = []
        args = ["fingerprint", "--source", str(p), "--bundle", str(self.bundle), "--out", str(out)]
        for c in public or [self.public.root]:
            args += ["--public", str(c)]
        rc = hg.main(args, out=said.append)
        return rc, "\n".join(said), out

    def test_the_build_is_deterministic_and_lists_files_without_an_eligible_line(self):
        rc, said, out = self.build()
        self.assertEqual(rc, 0, said)
        first = out.read_bytes()
        rc, said, out = self.build()
        self.assertEqual(out.read_bytes(), first)
        doc = json.loads(first)
        self.assertEqual(doc["no_eligible_line"], ["b/prose.txt", "c.bin"])
        self.assertEqual(doc["lines"], [hg.fingerprint_digest(SIG_LINE)])
        self.assertEqual(len(doc["files"]), 3)
        self.assertNotIn(FIX_LINE.encode(), first)

    def test_each_mismatch_against_the_record_refuses(self):
        for key, value in (("bundle", {"filename": "s.bundle", "sha256": "0" * 64}), ("commit", "1" * 40),
                           ("profile", {"path": "spec/profile.md", "sha256": "0" * 64}),
                           ("profile", {"path": "spec/missing.md", "sha256": "0" * 64}),
                           ("fixture_root", {"path": "fixtures", "tree": "2" * 40}), ("fixture_count", 2)):
            with self.subTest(key=key, value=value):
                rc, said, out = self.build(dict(self.record, **{key: value}))
                self.assertEqual(rc, 2, said)
                self.assertFalse(out.exists())

    def test_a_missing_or_malformed_record_refuses(self):
        rec = dict(self.record)
        del rec["fixture_count"]
        rc, said, _ = self.build(rec)
        self.assertEqual(rc, 2, said)

    def test_a_fixture_line_already_public_is_a_finding_not_a_dropped_line(self):
        self.public.commit({"leak.txt": SIG_LINE + "\n"})
        rc, said, out = self.build()
        self.assertEqual(rc, 1, said)
        self.assertIn("leak.txt", said)
        self.assertFalse(out.exists())

    def test_the_expanded_source_is_removed(self):
        before = set(os.listdir(tempfile.gettempdir()))
        self.build()
        self.build(dict(self.record, commit="1" * 40))
        after = {n for n in os.listdir(tempfile.gettempdir()) if n.startswith("hygiene-fp-")}
        self.assertEqual(after - before, set())


class EligibilityTest(unittest.TestCase):
    def test_prose_of_any_length_is_not_eligible(self):
        self.assertFalse(hg.eligible("This is a long line of ordinary English prose with no secrets at all."))
        self.assertFalse(hg.eligible("internationalization internationalization internationalization"))

    def test_keys_digests_and_base64_are(self):
        self.assertTrue(hg.eligible(f'  "sig": "{FIX_LINE}",'))
        self.assertTrue(hg.eligible("digest = " + hashlib.sha256(b"x").hexdigest()))

    def test_an_rfc8032_vector_line_is_never_eligible(self):
        self.assertFalse(hg.eligible("SECRET KEY: " + hg.RFC8032_VECTORS[0]))
        self.assertFalse(hg.eligible("sig " + hg.RFC8032_VECTORS[2].upper()))

    def test_short_lines_are_not(self):
        self.assertFalse(hg.eligible(FIX_LINE[:30]))


class HookTest(GateTest):
    def test_the_hook_blocks_a_finding_and_a_missing_list(self):
        said = []
        rc = hg.main(["install-hook", "--lists", str(self.lists), "--repo", "public-repo",
                      "--git", str(self.repo.root)], out=said.append)
        self.assertEqual(rc, 0, said)
        hook = self.repo.root / ".git" / "hooks" / "pre-push"
        self.assertTrue(os.access(hook, os.X_OK))
        remote = self.t / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, env=ENV)
        self.repo.git("remote", "add", "o", str(remote))
        self.repo.git("push", "-q", "o", "main")          # clean: allowed
        self.repo.commit({"n.txt": "zz-planted-host\n"})
        p = subprocess.run(["git", "-C", str(self.repo.root), "push", "-q", "o", "main"], capture_output=True,
                           env=ENV)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"push blocked", p.stderr)
        self.repo.commit({"n.txt": "clean again\n"})       # history still holds it
        (self.lists / "names.txt").unlink()
        p = subprocess.run(["git", "-C", str(self.repo.root), "push", "-q", "o", "main"], capture_output=True,
                           env=ENV)
        self.assertNotEqual(p.returncode, 0, "a missing list blocks too")
        rc = hg.main(["install-hook", "--lists", str(self.lists), "--repo", "x", "--git", str(self.repo.root)],
                     out=said.append)
        self.assertEqual(rc, 2, "an existing hook is never overwritten")


class ConstantsTest(unittest.TestCase):
    def test_the_bounds_are_the_reviewed_values(self):
        self.assertEqual((hg.MIN_TOKEN, hg.MAX_REGEX, hg.MAX_LINE), (6, 200, 4096))
        self.assertEqual((hg.ELIGIBLE_LEN, hg.RUN_LEN, hg.RUN_CLASSES, hg.RUN_ENTROPY), (32, 20, 4, 3.5))


if __name__ == "__main__":
    unittest.main()
