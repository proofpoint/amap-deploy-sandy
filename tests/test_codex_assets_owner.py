"""Owner controls for publication, early refusal and the immutable EEXIST path."""
from pathlib import Path
import os
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest import mock
import codex_assets as assets

HERE = Path(__file__).resolve().parents[1]


class OwnerControls(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(dir=HERE)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dfd = assets.open_dir(self.root)
        self.addCleanup(os.close, self.dfd)

    def test_differing_immutable_file_refuses_before_any_temporary_write(self):
        target = self.root / 'retained'
        target.write_bytes(b'retained bytes')
        created = []
        real = os.open
        def observed(name, flags, *args, **kwargs):
            if flags & os.O_CREAT:
                created.append(str(name))
            return real(name, flags, *args, **kwargs)
        with mock.patch.object(assets.os, 'open', side_effect=observed):
            with self.assertRaisesRegex(assets.AssetError, 'immutable protected asset differs'):
                assets.place_at(self.dfd, target.name, b'new bytes', target)
        self.assertEqual(target.read_bytes(), b'retained bytes')
        self.assertEqual([p.name for p in self.root.iterdir()], ['retained'])
        self.assertEqual(created, [], 'known immutable conflict must refuse before creating or writing a temp')

    def test_equal_concurrent_winner_is_reread_without_a_second_link(self):
        target = self.root / 'winner'
        real_link = os.link
        def winner(src, dst, **kwargs):
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=kwargs['dst_dir_fd'])
            try:
                os.write(fd, b'same bytes')
                os.fsync(fd)
            finally:
                os.close(fd)
            return real_link(src, dst, **kwargs)
        with mock.patch.object(assets.os, 'link', side_effect=winner):
            assets.place_at(self.dfd, target.name, b'same bytes', target)
        self.assertEqual(assets.read_at(self.dfd, target.name, target), b'same bytes')
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual([p.name for p in self.root.iterdir()], ['winner'])

    def test_new_file_is_synced_at_exact_mode_before_publication_then_directory_synced(self):
        target = self.root / 'published'
        events = []
        real_sync, real_link = os.fsync, os.link
        def sync(fd):
            info = os.fstat(fd)
            events.append(('dirsync' if stat.S_ISDIR(info.st_mode) else 'filesync', stat.S_IMODE(info.st_mode)))
            return real_sync(fd)
        def link(src, dst, **kwargs):
            events.append(('publish', None))
            return real_link(src, dst, **kwargs)
        with mock.patch.object(assets.os, 'fsync', side_effect=sync), mock.patch.object(assets.os, 'link', side_effect=link):
            assets.place_at(self.dfd, target.name, b'new bytes', target)
        self.assertEqual(target.read_bytes(), b'new bytes')
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        self.assertEqual(events[0], ('filesync', 0o644))
        self.assertEqual(events[1], ('publish', None))
        self.assertEqual(events[-1][0], 'dirsync')
        self.assertEqual([p.name for p in self.root.iterdir()], ['published'])
