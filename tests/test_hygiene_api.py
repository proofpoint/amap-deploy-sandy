"""hygiene_api: the scheduled run, against a fake GitHub API on localhost,
a second local server standing in for the storage host that downloads
redirect to, and bare git repositories served by path.

Every name, token and fixture is INVENTED. The API's shapes are the
documented REST ones the code reads (a listing is a JSON array, or an object
holding `workflow_runs` or `artifacts`; pagination is the `Link` header).
"""

import http.server
import io
import json
import os
import subprocess
import threading
import time
import unittest
import zipfile
from pathlib import Path

import hygiene_api as ha
import hygiene_gate as hg
from test_hygiene_gate import ENV, FIX_FILE, NAMES, Repo, fingerprints

TOKEN = "zz-test-token-0123456789"
PRIVATE_TOKEN = "zz-meta-token-9876543210"


class Server:
    """One local HTTP/1.0 server; `routes` maps a path (with its query) to a
    handler(h) that writes the whole response."""

    def __init__(self):
        self.routes = {}
        self.posts = {}
        self.auth = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):
                outer.auth.append((self.path, self.headers.get("Authorization")))
                fn = outer.routes.get(self.path)
                if fn is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                try:
                    fn(self)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_POST(self):
                outer.auth.append((self.path, self.headers.get("Authorization")))
                data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                fn = outer.posts.get(self.path)
                if fn is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                fn(self, json.loads(data))

            def log_message(self, *a):
                pass
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def body(data, status=200, headers=None, length=True):
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()

    def fn(h):
        h.send_response(status)
        for k, v in (headers or {}).items():
            h.send_header(k, v)
        if length:
            h.send_header("Content-Length", str(len(raw)))
        h.end_headers()
        h.wfile.write(raw)
    return fn


def sequence(*handlers):
    """A route that answers with each handler in turn, then the last again."""
    calls = []

    def fn(h, *a):
        calls.append(1)
        handlers[min(len(calls), len(handlers)) - 1](h, *a)
    fn.calls = calls
    return fn


def edits(*diffs):
    def fn(h, query):
        doc = {"data": {"repository": {"issueOrPullRequest": {"userContentEdits": {
            "nodes": [{"diff": d} for d in diffs], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}}
        body(doc)(h)
    return fn


def redirect(to):
    def fn(h):
        h.send_response(302)
        h.send_header("Location", to)
        h.send_header("Content-Length", "0")
        h.end_headers()
    return fn


def zipped(members):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return b.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        import tempfile
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.t = Path(td.name)
        self.api = Server()
        self.store = Server()
        self.addCleanup(self.api.close)
        self.addCleanup(self.store.close)
        self.budget = ha.Budget()
        self.http = ha.Http(self.api.url, TOKEN, self.budget)

    def patch(self, **values):
        for k, v in values.items():
            self.addCleanup(setattr, ha, k, getattr(ha, k))
            setattr(ha, k, v)


class BoundedReadTest(Base):
    """§4a's witnesses: each shortfall is a LIMIT, never a short clean read."""

    def stream(self, path):
        got = []
        self.http.stream(self.api.url + path, got.append)
        return b"".join(got)

    def test_a_declared_length_over_the_cap_is_refused_before_reading(self):
        self.patch(MAX_OBJECT=1000)
        self.api.routes["/big"] = body(b"x" * 2000)
        with self.assertRaisesRegex(ha.Limit, "oversize"):
            self.stream("/big")

    def test_an_oversize_declared_length_is_refused_without_waiting_for_the_body(self):
        """The server declares more than the cap and then sends nothing: the
        refusal comes from the header, not from a read that would stall."""
        self.patch(MAX_OBJECT=1000, IO_TIMEOUT=5)

        def silent(h):
            h.send_response(200)
            h.send_header("Content-Length", "999999")
            h.end_headers()
            h.wfile.flush()
            time.sleep(8)
        self.api.routes["/silent"] = silent
        start = time.monotonic()
        with self.assertRaisesRegex(ha.Limit, "oversize"):
            self.stream("/silent")
        self.assertLess(time.monotonic() - start, 3)

    def test_an_undeclared_stream_over_the_cap_is_cut_off(self):
        self.patch(MAX_OBJECT=1000, CHUNK=100)
        self.api.routes["/big"] = body(b"x" * 5000, length=False)
        with self.assertRaisesRegex(ha.Limit, "oversize"):
            self.stream("/big")

    def test_a_body_cut_short_is_truncated(self):
        def short(h):
            h.send_response(200)
            h.send_header("Content-Length", "1000")
            h.end_headers()
            h.wfile.write(b"x" * 10)
        self.api.routes["/short"] = short
        with self.assertRaisesRegex(ha.Limit, "truncated"):
            self.stream("/short")

    def test_a_listing_whose_next_outlives_the_page_bound_is_incomplete(self):
        self.patch(MAX_PAGES=2)
        for i in range(1, 4):
            nxt = f'<{self.api.url}/l{i + 1}?per_page=100>; rel="next"'
            path = "/l?per_page=100" if i == 1 else f"/l{i}?per_page=100"
            self.api.routes[path] = body([{"n": i}], headers={"Link": nxt})
        with self.assertRaisesRegex(ha.Limit, "incomplete listing"):
            list(self.http.listing("/l"))
        self.patch(MAX_PAGES=3)
        self.api.routes["/l3?per_page=100"] = body([{"n": 3}])
        self.assertEqual([d["n"] for d in self.http.listing("/l")], [1, 2, 3])

    def test_a_server_that_stalls_past_the_read_timeout(self):
        self.patch(IO_TIMEOUT=0.3)

        def stall(h):
            h.send_response(200)
            h.send_header("Content-Length", "10")
            h.end_headers()
            h.wfile.flush()
            time.sleep(1.5)
        self.api.routes["/stall"] = stall
        with self.assertRaisesRegex(ha.Limit, "timeout|truncated"):
            self.stream("/stall")

    def test_a_zip_member_that_decompresses_past_its_cap(self):
        self.patch(MAX_MEMBER=1000)
        self.api.routes["/z"] = body(zipped({"log.txt": b"a" * 5000}))
        m = hg.Matcher(hg.Lists(hg.parse_names(NAMES), [], set(), set(), "d"), "r")
        with self.assertRaisesRegex(ha.Limit, "oversize"):
            ha.scan_zip(m, self.http, self.api.url + "/z", "log 1", [], "r")

    def test_a_nested_archive_is_a_named_limit(self):
        self.api.routes["/z"] = body(zipped({"inner.zip": b"PK", "ok.txt": b"fine\n"}))
        m = hg.Matcher(hg.Lists(hg.parse_names(NAMES), [], set(), set(), "d"), "r")
        limits = []
        ha.scan_zip(m, self.http, self.api.url + "/z", "artifact 7", limits, "r")
        self.assertEqual(limits, ["LIMIT: r artifact 7 inner.zip: nested archive"])

    def test_the_run_budget_charges_decompressed_bytes_too(self):
        data = zipped({"log.txt": b"a" * 20000})
        self.assertLess(len(data), 1000)
        self.patch(MAX_RUN=len(data) + 5000)
        self.api.routes["/z"] = body(data)
        m = hg.Matcher(hg.Lists(hg.parse_names(NAMES), [], set(), set(), "d"), "r")
        with self.assertRaisesRegex(ha.Limit, "run budget"):
            ha.scan_zip(m, self.http, self.api.url + "/z", "log 1", [], "r")

    def test_the_bounds_are_the_reviewed_values(self):
        self.assertEqual((ha.CHUNK, ha.MAX_OBJECT, ha.MAX_MEMBER, ha.MAX_ARCHIVE, ha.MAX_RUN),
                         (64 << 10, 50 << 20, 50 << 20, 200 << 20, 2 << 30))
        self.assertEqual((ha.PER_PAGE, ha.MAX_PAGES, ha.IO_TIMEOUT, ha.OBJECT_TIMEOUT), (100, 50, 30, 300))


class LongLineTest(Base):
    """A streamed line longer than MAX_CARRY is scanned in overlapping
    pieces, so a name is never split between two of them."""

    def test_a_name_across_the_carry_boundary_is_found_once(self):
        self.patch(MAX_CARRY=4096)
        lists = hg.Lists(hg.parse_names(NAMES), [], set(), set(), "d")
        # 4096 - 300 puts the name wholly inside the overlap, so two pieces
        # both hold it: it must still be reported once.
        for pad in (4096 - 2, 4096, 4096 - 7, 4096 * 3 - 5, 4096 - 300):
            with self.subTest(pad=pad):
                m = hg.Matcher(lists, "r")
                lines = ha.Lines(m, hg.Where("text", "r", path="log"))
                data = b"x" * pad + b" zz" + b"-planted-host y" + b"z" * 5000 + b"\nnext\n"
                for i in range(0, len(data), 700):   # in chunks: the line goes through the carry
                    lines.feed(data[i:i + 700])
                lines.finish()
                self.assertEqual([(f.where.lineno, f.entry) for f in m.findings], [(1, 2)])
                self.assertEqual(lines.n, 2)

    def test_lines_after_a_long_line_are_whole_lines_again(self):
        """After a long line, a fixture line and a repeated name are each
        found on their own line."""
        from test_hygiene_gate import SIG_LINE
        self.patch(MAX_CARRY=4096)
        lists = hg.Lists(hg.parse_names(NAMES), [], set(), {hg.fingerprint_digest(SIG_LINE)}, "d")
        m = hg.Matcher(lists, "r")
        lines = ha.Lines(m, hg.Where("text", "r", path="log"))
        data = b"zz-planted-host " + b"x" * 9000 + b"\n" + SIG_LINE.encode() + b"\nzz-planted-host\n"
        for i in range(0, len(data), 1000):       # in chunks, so the long line goes through the carry
            lines.feed(data[i:i + 1000])
        lines.finish()
        self.assertEqual([(f.where.lineno, f.what) for f in m.findings],
                         [(1, "name"), (2, "fixture line"), (3, "name")])


class TokenTest(Base):
    def test_the_token_goes_to_the_api_host_and_not_across_a_redirect(self):
        self.api.routes["/repos/o/r/actions/runs/1/logs"] = redirect(self.store.url + "/blob/1")
        self.store.routes["/blob/1"] = body(zipped({"x.txt": b"x\n"}))
        m = hg.Matcher(hg.Lists(hg.parse_names(NAMES), [], set(), set(), "d"), "r")
        ha.scan_zip(m, self.http, self.api.url + "/repos/o/r/actions/runs/1/logs", "log 1", [], "r")
        self.assertEqual(self.api.auth, [("/repos/o/r/actions/runs/1/logs", f"Bearer {TOKEN}")])
        self.assertEqual(self.store.auth, [("/blob/1", None)])

    def test_a_public_403_or_404_is_a_limit_not_a_skip(self):
        self.api.routes["/x?per_page=100"] = body({"message": "nope"}, status=403)
        with self.assertRaisesRegex(ha.Limit, "HTTP 403"):
            list(self.http.listing("/x"))
        with self.assertRaisesRegex(ha.Limit, "HTTP 404"):
            list(self.http.listing("/missing"))


class FleetTest(Base):
    def files(self, repos, rule):
        (self.t / "repos.txt").write_text(repos)
        (self.t / "rule.txt").write_text(rule)
        return ha.load_fleet(str(self.t / "repos.txt"), str(self.t / "rule.txt"))

    def org(self, *repos):
        self.api.routes["/orgs/o/repos?type=public&per_page=100"] = body(
            [{"name": n, "visibility": "public", "private": False, "topics": list(t)} for n, t in repos])

    def resolve(self, fleet, private_token=PRIVATE_TOKEN):
        return ha.resolve_fleet(self.http, "o", fleet, private_token)

    def private(self, name, visibility="private", status=200):
        self.api.routes[f"/repos/o/{name}"] = body({"name": name, "visibility": visibility}, status=status)

    def test_an_unrelated_public_repository_is_skipped_and_counted(self):
        f = self.files("zzfleet-a public\nzzfleet-p private\n", "prefix zzfleet-\n")
        self.org(("zzfleet-a", ()), ("unrelated-tool", ()), ("other", ("misc",)))
        self.private("zzfleet-p")
        v = self.resolve(f)
        self.assertEqual((v.public, v.findings, v.skipped), (["zzfleet-a"], [], 2))

    def test_an_unlisted_public_repository_matching_the_rule_is_a_finding(self):
        f = self.files("zzfleet-a public\n", "prefix zzfleet-\ntopic zz-fleet\n")
        self.org(("zzfleet-a", ()), ("zzfleet-new", ()), ("odd-name", ("zz-fleet",)))
        v = self.resolve(f)
        self.assertEqual(len(v.findings), 2)
        self.assertIn("zzfleet-new", v.findings[1] + v.findings[0])
        self.assertIn("odd-name", v.findings[0] + v.findings[1])

    def test_drift_cannot_run(self):
        cases = [
            ("zzfleet-a public\nother public\n", [("zzfleet-a", ()), ("other", ())], "does not match"),
            ("zzfleet-a public\n", [], "does not show it"),
            ("zzfleet-a public\nzzfleet-p private\n", [("zzfleet-a", ()), ("zzfleet-p", ())], "and it is public"),
        ]
        for repos, org, words in cases:
            with self.subTest(words=words):
                f = self.files(repos, "prefix zzfleet-\n")
                self.org(*org)
                with self.assertRaisesRegex(hg.CannotRun, words):
                    self.resolve(f)

    def test_a_private_repository_whose_visibility_cannot_be_read_or_differs(self):
        f = self.files("zzfleet-a public\nzzfleet-p private\n", "prefix zzfleet-\n")
        self.org(("zzfleet-a", ()))
        with self.assertRaisesRegex(hg.CannotRun, "cannot be read"):
            self.resolve(f)                            # 404: no route
        self.private("zzfleet-p", status=403)
        with self.assertRaisesRegex(hg.CannotRun, "cannot be read"):
            self.resolve(f)
        self.private("zzfleet-p", visibility="internal")
        with self.assertRaisesRegex(hg.CannotRun, "reads internal"):
            self.resolve(f)
        with self.assertRaisesRegex(hg.CannotRun, "no private metadata credential"):
            self.resolve(f, private_token=None)
        self.private("zzfleet-p")
        self.assertEqual(self.resolve(f).public, ["zzfleet-a"])
        priv = [a for p, a in self.api.auth if p == "/repos/o/zzfleet-p"]
        self.assertEqual(set(priv), {f"Bearer {PRIVATE_TOKEN}"}, "only the metadata token reads private rows")


class RunTest(Base):
    """run_ci end to end: one public fleet repository, mirrored from a bare
    repository by path, its API surfaces served by the fake."""

    def setUp(self):
        super().setUp()
        self.lists = self.t / "lists"
        self.lists.mkdir()
        (self.lists / "names.txt").write_text(NAMES)
        (self.lists / "allow.txt").write_text("")
        (self.lists / "fingerprints.json").write_text(json.dumps(fingerprints()))
        (self.t / "repos.txt").write_text("zzfleet-a public\n")
        (self.t / "rule.txt").write_text("prefix zzfleet-\n")
        self.work = self.t / "work"
        self.work.mkdir()
        self.src = Repo(self.t / "src")
        self.clean = self.src.commit({"README.md": "clean\n"}, "start")
        self.publish()
        self.api.routes["/orgs/o/repos?type=public&per_page=100"] = body(
            [{"name": "zzfleet-a", "visibility": "public", "private": False, "topics": []}])
        self.api.routes["/repos/o/zzfleet-a"] = body({"name": "zzfleet-a", "visibility": "public",
                                                       "default_branch": "main", "has_wiki": False})
        for path in ("pulls?state=all", "issues?state=all", "issues/comments", "pulls/comments", "comments",
                     "releases"):
            self.api.routes[f"/repos/o/zzfleet-a/{path}{'&' if '?' in path else '?'}per_page=100"] = body([])
        self.api.routes["/repos/o/zzfleet-a/actions/runs?per_page=100"] = body({"workflow_runs": []})
        self.api.routes["/repos/o/zzfleet-a/actions/artifacts?per_page=100"] = body({"artifacts": []})
        self.api.posts["/graphql"] = edits()
        self.open_pulls([])

    def publish(self):
        bare = self.t / "git" / "o" / "zzfleet-a.git"
        if not bare.exists():
            bare.parent.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True, env=ENV)
            self.src.git("remote", "add", "pub", str(bare))
        self.src.git("push", "-q", "--force", "pub", "+refs/heads/*:refs/heads/*")

    def open_pulls(self, shas):
        self.api.routes["/repos/o/zzfleet-a/pulls?state=open&per_page=100"] = body(
            [{"number": i + 1, "head": {"sha": s}} for i, s in enumerate(shas)])

    def run_ci(self, **kw):
        said = []
        os.environ["ZZ_TEST_TOKEN"] = TOKEN
        self.addCleanup(os.environ.pop, "ZZ_TEST_TOKEN", None)
        args = ["ci", "--lists", str(self.lists), "--owner", "o", "--repos", str(self.t / "repos.txt"),
                "--fleet-rule", str(self.t / "rule.txt"), "--workdir", str(self.work), "--api", self.api.url,
                "--git-base", f"file://{self.t / 'git'}", "--token-env", "ZZ_TEST_TOKEN",
                "--verdicts", str(self.t / "verdicts.json")]
        for k, v in kw.items():
            args += [f"--{k}", v]
        rc = hg.main(args, out=said.append)
        verdicts = json.loads((self.t / "verdicts.json").read_text()) if (self.t / "verdicts.json").exists() else None
        return rc, "\n".join(said), verdicts

    def test_a_clean_fleet_passes_with_a_success_verdict(self):
        rc, out, v = self.run_ci()
        self.assertEqual(rc, 0, out)
        self.assertEqual(v, [{"repo": "zzfleet-a", "sha": self.clean, "state": "success"}])
        self.assertIn("skipped 0 public repositories", out)

    def issue(self, number, body_text, stamp="2026-10-14T10:00:00Z", pull=True):
        item = {"number": number, "title": "t", "body": body_text, "updated_at": stamp}
        if pull:
            item["pull_request"] = {}
        return item

    def test_a_name_in_a_pull_request_body_is_red_but_never_a_failed_verdict(self):
        self.api.routes["/repos/o/zzfleet-a/issues?state=all&per_page=100"] = body(
            [self.issue(3, "for zzplantedcorp")])
        self.api.routes["/repos/o/zzfleet-a/issues/3"] = body(self.issue(3, "for zzplantedcorp"))
        rc, out, v = self.run_ci()
        self.assertEqual(rc, 1, out)
        self.assertIn("text pull #3", out)
        self.assertEqual([x["state"] for x in v], ["success"])

    def test_a_name_in_a_commit_fails_every_head_that_reaches_it(self):
        self.src.git("checkout", "-q", "-b", "feature")
        bad = self.src.commit({"n.txt": "zz-planted-host\n"}, "x")
        self.src.commit({"n.txt": "cleaned\n"}, "y")
        self.publish()
        self.open_pulls([self.src.git("rev-parse", "HEAD")])
        rc, out, v = self.run_ci()
        self.assertEqual(rc, 1, out)
        states = {x["sha"]: x["state"] for x in v}
        self.assertEqual(states[self.clean], "success")
        self.assertEqual(states[self.src.git("rev-parse", "HEAD")], "failure")
        self.assertIn(bad[:12], out)

    def test_a_branch_name_is_red_but_not_a_failed_verdict(self):
        self.src.git("branch", "zz-planted-host-wip")
        self.publish()
        rc, out, v = self.run_ci()
        self.assertEqual(rc, 1, out)
        self.assertEqual([x["state"] for x in v], ["success"])

    def test_a_retained_body_revision_is_read(self):
        """Text added and then edited away is still in the body's revisions."""
        self.api.routes["/repos/o/zzfleet-a/issues?state=all&per_page=100"] = body(
            [self.issue(4, "now clean", pull=False)])
        self.api.routes["/repos/o/zzfleet-a/issues/4"] = body(self.issue(4, "now clean", pull=False))
        self.api.posts["/graphql"] = edits("- was for zzplantedcorp\n+ now clean")
        rc, out, _v = self.run_ci()
        self.assertEqual(rc, 1, out)
        self.assertIn("text revision #4/1", out)

    def test_an_object_edited_between_listing_and_read_is_read_again_then_a_limit(self):
        listed = self.issue(5, "clean", stamp="T1", pull=False)
        self.api.routes["/repos/o/zzfleet-a/issues?state=all&per_page=100"] = body([listed])
        self.api.routes["/repos/o/zzfleet-a/issues/5"] = sequence(
            body(self.issue(5, "edited to zzplantedcorp", stamp="T2", pull=False)),
            body(self.issue(5, "edited again", stamp="T3", pull=False)))
        rc, out, _v = self.run_ci()
        self.assertIn("text issue #5", out, "the newer read is scanned")
        self.assertIn("LIMIT: zzfleet-a issue #5: still changing", out)
        self.assertEqual(rc, 1, out)

    def test_an_object_read_once_and_unchanged_is_not_read_again(self):
        cache = str(self.t / "cache.json")
        self.api.routes["/repos/o/zzfleet-a/issues?state=all&per_page=100"] = body(
            [self.issue(6, "fine", pull=False)])
        read = sequence(body(self.issue(6, "fine", pull=False)))
        self.api.routes["/repos/o/zzfleet-a/issues/6"] = read
        self.assertEqual(self.run_ci(cache=cache)[0], 0)
        self.assertEqual(self.run_ci(cache=cache)[0], 0)
        self.assertEqual(len(read.calls), 1)

    def test_a_run_whose_read_failed_is_read_again_next_time(self):
        cache = str(self.t / "cache.json")
        self.api.routes["/repos/o/zzfleet-a/actions/runs?per_page=100"] = body(
            {"workflow_runs": [{"id": 5, "status": "completed"}]})
        self.api.routes["/repos/o/zzfleet-a/actions/runs/5/logs"] = body({}, status=500)
        rc, out, _ = self.run_ci(cache=cache)
        self.assertEqual(rc, 2, out)
        self.api.routes["/repos/o/zzfleet-a/actions/runs/5/logs"] = body(zipped({"s.txt": b"zz-planted-host\n"}))
        rc, out, _ = self.run_ci(cache=cache)
        self.assertEqual(rc, 1, out)
        self.assertIn("text log 5 s.txt:1", out)

    def test_a_nested_archive_stays_a_limit_on_later_runs(self):
        cache = str(self.t / "cache.json")
        self.api.routes["/repos/o/zzfleet-a/actions/artifacts?per_page=100"] = body(
            {"artifacts": [{"id": 8, "name": "a", "expired": False,
                            "archive_download_url": f"{self.api.url}/repos/o/zzfleet-a/actions/artifacts/8/zip"}]})
        self.api.routes["/repos/o/zzfleet-a/actions/artifacts/8/zip"] = body(zipped({"inner.zip": b"PK"}))
        for _ in range(2):
            rc, out, _ = self.run_ci(cache=cache)
            self.assertEqual(rc, 2, out)
            self.assertIn("inner.zip: nested archive", out)

    def test_a_wiki_mirror_that_cannot_be_refreshed_is_a_limit_not_a_stale_scan(self):
        wiki = Repo(self.t / "wsrc")
        wiki.commit({"Home.md": "welcome\n"})
        bare = self.t / "git" / "o" / "zzfleet-a.wiki.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(wiki.root), str(bare)], check=True, env=ENV,
                       capture_output=True)
        self.api.routes["/repos/o/zzfleet-a"] = body({"name": "zzfleet-a", "visibility": "public",
                                                       "default_branch": "main", "has_wiki": True})
        rc, out, _ = self.run_ci()
        self.assertEqual(rc, 0, out)
        import shutil
        shutil.rmtree(bare)
        rc, out, _ = self.run_ci()
        self.assertEqual(rc, 2, out)
        self.assertIn("LIMIT: zzfleet-a wiki all: could not be refreshed", out)

    def test_a_limit_alone_exits_2_and_still_hands_over_the_verdicts(self):
        self.api.routes["/repos/o/zzfleet-a/releases?per_page=100"] = body({"x": 1}, status=500)
        rc, out, v = self.run_ci()
        self.assertEqual(rc, 2, out)
        self.assertIn("LIMIT: zzfleet-a releases listing: HTTP 500", out)
        self.assertEqual([x["state"] for x in v], ["success"])

    def test_a_fixture_in_an_artifact_and_a_name_in_a_log(self):
        self.api.routes["/repos/o/zzfleet-a/actions/runs?per_page=100"] = body(
            {"workflow_runs": [{"id": 5, "status": "completed"}]})
        self.api.routes["/repos/o/zzfleet-a/actions/runs/5/logs"] = redirect(self.store.url + "/l5")
        self.store.routes["/l5"] = body(zipped({"job/1_step.txt": b"echo zz-planted-host\n"}))
        self.api.routes["/repos/o/zzfleet-a/actions/artifacts?per_page=100"] = body(
            {"artifacts": [{"id": 9, "name": "out", "expired": False,
                            "archive_download_url": f"{self.api.url}/repos/o/zzfleet-a/actions/artifacts/9/zip"}]})
        self.api.routes["/repos/o/zzfleet-a/actions/artifacts/9/zip"] = redirect(self.store.url + "/a9")
        self.store.routes["/a9"] = body(zipped({"copy.json": FIX_FILE}))
        rc, out, v = self.run_ci()
        self.assertEqual(rc, 1, out)
        self.assertIn("text log 5 job/1_step.txt:1: private name", out)
        self.assertIn("text artifact 9 copy.json: s5-r4 fixture file", out)
        self.assertTrue(all(a is None for _p, a in self.store.auth))

    def test_a_release_assets_bytes_are_hashed(self):
        self.api.routes["/repos/o/zzfleet-a/releases?per_page=100"] = body(
            [{"id": 2, "name": "v1", "tag_name": "v1", "body": "notes",
              "assets": [{"id": 4, "name": "data.json", "browser_download_url": self.store.url + "/as4"}]}])
        self.store.routes["/as4"] = body(FIX_FILE)
        rc, out, _v = self.run_ci()
        self.assertEqual(rc, 1, out)
        self.assertIn("text asset 4: s5-r4 fixture file", out)

    def test_discussions_enabled_are_a_named_limit(self):
        self.api.routes["/repos/o/zzfleet-a"] = body({"name": "zzfleet-a", "visibility": "public",
                                                       "default_branch": "main", "has_discussions": True})
        rc, out, _v = self.run_ci()
        self.assertEqual(rc, 2, out)
        self.assertIn("discussions", out)

    def test_the_token_never_reaches_an_argument_or_the_output(self):
        seen = []
        real_run, real_popen = subprocess.run, subprocess.Popen

        def run(args, *a, **k):
            seen.append(" ".join(map(str, args)))
            return real_run(args, *a, **k)

        class Popen(real_popen):
            def __init__(self, args, *a, **k):
                seen.append(" ".join(map(str, args)))
                super().__init__(args, *a, **k)
        self.addCleanup(setattr, subprocess, "run", real_run)
        self.addCleanup(setattr, subprocess, "Popen", real_popen)
        subprocess.run, subprocess.Popen = run, Popen
        rc, out, v = self.run_ci()
        self.assertEqual(rc, 0, out)
        self.assertTrue(seen)
        self.assertFalse(any(TOKEN in s for s in seen))
        self.assertNotIn(TOKEN, out)
        self.assertNotIn(TOKEN, (self.t / "verdicts.json").read_text())
        self.assertTrue(any(a == f"Bearer {TOKEN}" for _p, a in self.api.auth))

    def test_the_cache_skips_commits_already_scanned_and_resets_on_a_list_change(self):
        cache = str(self.t / "cache.json")
        rc, out, _ = self.run_ci(cache=cache)
        self.assertEqual(rc, 0, out)
        first = json.loads(Path(cache).read_text())
        self.assertIn(self.clean, first["repos"]["zzfleet-a"]["commits"])
        rc, out, _ = self.run_ci(cache=cache)
        self.assertIn("incremental", out)
        (self.lists / "names.txt").write_text(NAMES + "token zzanotherhost\n")
        rc, out, _ = self.run_ci(cache=cache)
        self.assertNotIn("incremental", out)


class VerdictSchemaTest(unittest.TestCase):
    def test_the_status_jobs_check_refuses_every_deviation(self):
        good = {"repo": "zzfleet-a", "sha": "a" * 40, "state": "success"}
        self.assertEqual(ha.check_verdicts([good], ["zzfleet-a"]), [good])
        for bad in (dict(good, extra=1), dict(good, sha="abc"), dict(good, repo="other"),
                    dict(good, state="pending"), {k: good[k] for k in ("repo", "sha")}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    ha.check_verdicts([bad], ["zzfleet-a"])
        with self.assertRaises(ValueError):
            ha.check_verdicts({"repo": "zzfleet-a"}, ["zzfleet-a"])


if __name__ == "__main__":
    unittest.main()
