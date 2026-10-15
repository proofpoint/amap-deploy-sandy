"""A fake filesystem for the closure walk: entries with an owner and mode,
links with their TEXTUAL targets, and directories that cannot be listed. Its
lstat, stat, readlink, realpath and walk resolve paths the way the kernel
does (".." after a link is taken from where the link led), so the writer's
walk can be driven through shapes a test user cannot make on disk: other
owners, and links in root's own directories. Every lstat is counted."""

import errno
import os
import stat
import types

D, F, L = stat.S_IFDIR | 0o755, stat.S_IFREG | 0o644, stat.S_IFLNK | 0o777
MAX_HOPS = 40


class FakeFS:
    def __init__(self, entries, links=None, unreadable=()):
        self.entries = dict(entries)
        self.links = dict(links or {})
        for p in self.links:
            self.entries.setdefault(p, (0, L))
        self.unreadable = set(unreadable)
        self.lstats = 0

    def _walk_path(self, path, follow_last):
        """`path` resolved; FileNotFoundError when a component is absent, and
        OSError(ELOOP) when the links go round."""
        comps = [c for c in path.split("/")]
        todo = [c for c in comps if c not in ("", ".")]
        cur, hops = "/", 0
        while todo:
            c = todo.pop(0)
            if c == "..":
                cur = os.path.dirname(cur)
                continue
            nxt = cur.rstrip("/") + "/" + c
            if nxt not in self.entries:
                raise FileNotFoundError(errno.ENOENT, "No such file or directory", path)
            if nxt in self.links and (todo or follow_last):
                hops += 1
                if hops > MAX_HOPS:
                    raise OSError(errno.ELOOP, "Too many levels of symbolic links", path)
                t = self.links[nxt]
                rest = [x for x in t.split("/") if x not in ("", ".")]
                todo = rest + todo
                if t.startswith("/"):
                    cur = "/"
                continue
            if todo and not stat.S_ISDIR(self.entries[nxt][1]):
                raise NotADirectoryError(errno.ENOTDIR, "Not a directory", path)
            cur = nxt
        return cur

    def kw(self, **more):
        return dict(lstat=self.lstat, walk=self.walk, realpath=self.realpath, readlink=self.readlink,
                    stat_=self.stat, **more)

    def lstat(self, p):
        self.lstats += 1
        real = self._walk_path(p, follow_last=False)
        uid, mode = self.entries[real]
        return types.SimpleNamespace(st_uid=uid, st_mode=mode)

    def stat(self, p):
        real = self._walk_path(p, follow_last=True)
        uid, mode = self.entries[real]
        return types.SimpleNamespace(st_uid=uid, st_mode=mode)

    def readlink(self, p):
        real = self._walk_path(p, follow_last=False)
        if real not in self.links:
            raise OSError(errno.EINVAL, "Invalid argument", p)
        return self.links[real]

    def realpath(self, p):
        """os.path.realpath's non-strict answer: as far as it resolves, then
        the rest as spelled; the path itself when the links go round."""
        comps = [c for c in p.split("/") if c not in ("", ".")]
        for i in range(len(comps), -1, -1):
            head = "/" + "/".join(comps[:i])
            try:
                real = self._walk_path(head, follow_last=True)
            except FileNotFoundError:
                continue
            except OSError:
                return os.path.normpath(p)
            rest = comps[i:]
            out = real
            for c in rest:
                out = os.path.dirname(out) if c == ".." else out.rstrip("/") + "/" + c
            return out
        return os.path.normpath(p)

    def walk(self, top, onerror=None):
        """os.walk without following links: `top`'s names, then each real
        subdirectory's, spelled under `top`."""
        try:
            real = self._walk_path(top, follow_last=True)
        except OSError as e:
            if onerror:
                onerror(e)
            return
        if real in self.unreadable:
            if onerror:
                onerror(PermissionError(errno.EACCES, "Permission denied", top))
            return
        kids = sorted(p for p in self.entries if p != real and os.path.dirname(p) == real)
        dirs = [os.path.basename(k) for k in kids if stat.S_ISDIR(self.entries[k][1])]
        files = [os.path.basename(k) for k in kids if not stat.S_ISDIR(self.entries[k][1])]
        yield top, dirs, files
        for d in dirs:
            yield from self.walk(os.path.join(top, d), onerror)


def tree(*dirs, **over):
    """Root's directories `dirs` (and every directory above each), then `over`."""
    t = {"/": (0, D)}
    for d in dirs:
        parts = d.strip("/").split("/")
        for i in range(1, len(parts) + 1):
            t["/" + "/".join(parts[:i])] = (0, D)
    t.update(over)
    return t
