"""The writer's trusted-exec (ROOT-BOOTSTRAP d3.1 §4): what it refuses, in
what order, and how it discovers what a command loads, on synthetic images
built here byte by byte (Mach-O for macOS's dyld, ELF for Linux's loader)."""

import errno
import os
import struct
import subprocess
import sys
import tempfile
import unittest

import host_steps as hs

ARM64 = 0x0100000C
X86_64 = 0x01000007


def _pad(b, n=8):
    return b + b"\0" * ((-len(b)) % n)


def lc_dylib(cmd, name):
    body = _pad(name.encode() + b"\0")
    return struct.pack("<6I", cmd, 24 + len(body), 24, 0, 0, 0) + body


def lc_str(cmd, text):
    body = _pad(text.encode() + b"\0")
    return struct.pack("<3I", cmd, 12 + len(body), 12) + body


def lc_inert(cmd=0x1B, size=24):
    return struct.pack("<2I", cmd, size) + b"\0" * (size - 8)


def macho(*cmds, cpu=ARM64):
    blob = b"".join(cmds)
    return struct.pack("<4s7I", b"\xcf\xfa\xed\xfe", cpu, 0, 6, len(cmds), len(blob), 0, 0) + blob


def fat(*slices):
    head = struct.pack(">2I", 0xCAFEBABE, len(slices))
    off = 4096
    entries, body = b"", b""
    for cpu, data in slices:
        entries += struct.pack(">5I", cpu, 0, off + len(body), len(data), 12)
        body += data
    return _pad(head + entries, 4096) + body


class Tmp(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.d = t.name

    def put(self, rel, data=b"", mode=0o755):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        os.chmod(p, mode)
        return p


class MachOReaderTest(Tmp):
    def test_dylib_and_rpath_commands_are_read_and_inert_ones_passed(self):
        data = macho(lc_inert(), lc_dylib(hs.LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"),
                     lc_dylib(hs.LC_LOAD_UPWARD_DYLIB, "/usr/lib/libz.1.dylib"), lc_str(hs.LC_RPATH, "@loader_path/../lib"),
                     lc_str(hs.LC_LOAD_DYLINKER, hs.DYLD))
        try:
            got = hs.macho_load_commands(data, "arm64")
        except hs.Tooling as e:
            self.fail(f"a load command dyld reads was refused as unknown: {e}")
        self.assertEqual(got, [
            (hs.LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib"), (hs.LC_LOAD_UPWARD_DYLIB, "/usr/lib/libz.1.dylib"),
            (hs.LC_RPATH, "@loader_path/../lib"), (hs.LC_LOAD_DYLINKER, hs.DYLD)])

    def test_the_named_benign_list_is_d3_3s_and_every_further_type_is_separate(self):
        """d3.3 §4.3: SEGMENT_64, SYMTAB, DYSYMTAB, UUID, BUILD_VERSION,
        SOURCE_VERSION, MAIN, FUNCTION_STARTS, DATA_IN_CODE, CODE_SIGNATURE,
        DYLD_INFO_ONLY, DYLD_EXPORTS_TRIE, DYLD_CHAINED_FIXUPS, NOTE,
        LINKER_OPTION; anything further is its own reasoned group, and
        LC_DYLD_ENVIRONMENT is in none."""
        self.assertEqual(hs._MACHO_BENIGN_NAMED, {0x19, 0x2, 0xB, 0x1B, 0x32, 0x2A, 0x80000028, 0x26, 0x29, 0x1D,
                                                  0x80000022, 0x80000033, 0x80000034, 0x31, 0x2D})
        self.assertFalse(hs._MACHO_BENIGN_NAMED & hs._MACHO_BENIGN_FURTHER)
        self.assertNotIn(hs.LC_DYLD_ENVIRONMENT, hs._MACHO_INERT)
        self.assertFalse(set(hs._DYLIB_COMMANDS) & hs._MACHO_INERT, "a load is read, never passed as inert")

    def test_dyld_environment_an_unknown_command_and_another_loader_refuse(self):
        for cmds, why in (((lc_str(hs.LC_DYLD_ENVIRONMENT, "DYLD_INSERT_LIBRARIES=/x"),), "0x27"),
                          ((lc_inert(0x99),), "0x99"),
                          ((lc_str(hs.LC_LOAD_DYLINKER, "/tmp/dyld"),), "loader other than")):
            with self.subTest(why=why):
                with self.assertRaisesRegex(hs.Tooling, why):
                    hs.macho_load_commands(macho(*cmds), "arm64")

    def test_a_fat_file_is_read_for_the_running_architecture_only(self):
        arm = macho(lc_dylib(hs.LC_LOAD_DYLIB, "/usr/lib/a.dylib"))
        intel = macho(lc_dylib(hs.LC_LOAD_DYLIB, "/usr/lib/b.dylib"), cpu=X86_64)
        both = fat((X86_64, intel), (ARM64, arm))
        self.assertEqual(hs.macho_load_commands(both, "arm64"), [(hs.LC_LOAD_DYLIB, "/usr/lib/a.dylib")])
        self.assertEqual(hs.macho_load_commands(both, "x86_64"), [(hs.LC_LOAD_DYLIB, "/usr/lib/b.dylib")])
        with self.assertRaisesRegex(hs.Tooling, "no slice"):
            hs.macho_load_commands(fat((X86_64, intel)), "arm64")
        with self.assertRaisesRegex(hs.Tooling, "another architecture"):
            hs.macho_load_commands(intel, "arm64")

    def test_a_truncated_or_non_ascii_command_refuses(self):
        good = macho(lc_dylib(hs.LC_LOAD_DYLIB, "/usr/lib/a.dylib"))
        with self.assertRaises(hs.Tooling):
            hs.macho_load_commands(good[:-8], "arm64")
        with self.assertRaisesRegex(hs.Tooling, "not ASCII"):
            hs.macho_load_commands(macho(lc_dylib(hs.LC_LOAD_DYLIB, "/usr/lib/é.dylib")), "arm64")

    def test_rpath_resolution_follows_dyld_and_returns_every_searched_directory(self):
        """The binary's own rpath first, then those inherited; the first that
        exists wins; each earlier candidate's directory is searched too."""
        lib = self.put("fw/Versions/3.9/lib/libpy.dylib", b"")
        exe = self.put("fw/Versions/3.9/bin/python3",
                       macho(lc_dylib(hs.LC_LOAD_DYLIB, "@rpath/libpy.dylib"), lc_str(hs.LC_RPATH, "@loader_path/../nolib"),
                             lc_str(hs.LC_RPATH, "@loader_path/../lib")))
        libs, weak, searched, own = hs.macho_libraries(exe, exe, arch="arm64")
        bin_ = os.path.join(self.d, "fw/Versions/3.9/bin")
        self.assertEqual(libs, [bin_ + "/../lib/libpy.dylib"])
        self.assertEqual(os.path.realpath(libs[0]), os.path.realpath(lib))
        self.assertEqual(searched, sorted([bin_ + "/../nolib", bin_ + "/../lib"]))

    def test_a_dot_dot_after_a_directory_link_is_the_kernels_never_collapsed(self):
        """Codex d3 A2: @loader_path/../lib from an image reached through
        jump -> real/a/b is real/a/lib, not the lexical sibling of jump; a
        decoy where normpath would land is never named."""
        real = self.put("real/a/lib/libq.dylib", b"")
        decoy = self.put("lib/libq.dylib", b"")
        self.put("real/a/b/x", macho(lc_dylib(hs.LC_LOAD_DYLIB, "@loader_path/../lib/libq.dylib")))
        os.symlink(os.path.join(self.d, "real/a/b"), os.path.join(self.d, "jump"))
        x = os.path.join(self.d, "jump/x")
        libs, _, _, _ = hs.macho_libraries(x, x, arch="arm64")
        self.assertEqual(libs, [os.path.join(self.d, "jump/../lib/libq.dylib")])
        self.assertEqual(os.path.realpath(libs[0]), os.path.realpath(real))
        self.assertNotEqual(os.path.realpath(libs[0]), os.path.realpath(decoy))

    def test_an_inherited_rpath_resolves_a_dependency_with_none_of_its_own(self):
        lib = self.put("main/lib/libdep.dylib", b"")
        mod = self.put("mods/m.so", macho(lc_dylib(hs.LC_LOAD_DYLIB, "@rpath/libdep.dylib")))
        libs, _, _, _ = hs.macho_libraries(mod, mod, inherited=(os.path.join(self.d, "main/lib"),), arch="arm64")
        self.assertEqual(libs, [lib])
        with self.assertRaisesRegex(hs.Tooling, "no rpath"):
            hs.macho_libraries(mod, mod, arch="arm64")

    def test_executable_path_is_the_main_executables_directory(self):
        lib = self.put("bin/libx.dylib", b"")
        mod = self.put("mods/m.so", macho(lc_dylib(hs.LC_LOAD_DYLIB, "@executable_path/libx.dylib")))
        main = self.put("bin/python3", b"")
        self.assertEqual(hs.macho_libraries(mod, main, arch="arm64")[0], [lib])

    def test_an_absent_weak_dependency_is_a_would_be_place_not_a_library(self):
        exe = self.put("bin/x", macho(lc_dylib(hs.LC_LOAD_WEAK_DYLIB, "/opt/absent/libw.dylib")))
        libs, weak, _, _ = hs.macho_libraries(exe, exe, arch="arm64")
        self.assertEqual((libs, weak), ([], ["/opt/absent/libw.dylib"]))


def elf64(runpath=None, interp=None):
    """A minimal little-endian ELF64 with an optional PT_INTERP and a dynamic
    section naming DT_RUNPATH from its string table."""
    phnum = 1 + (interp is not None) + (runpath is not None)
    ph_at, data_at = 64, 64 + 56 * phnum
    strtab = b"\0" + (runpath.encode() + b"\0" if runpath else b"")
    interp_b = (interp.encode() + b"\0") if interp else b""
    strtab_at = data_at
    interp_at = strtab_at + len(strtab)
    dyn_at = interp_at + len(interp_b)
    dyn = struct.pack("<qQ", 5, strtab_at) + (struct.pack("<qQ", 29, 1) if runpath else b"") + struct.pack("<qQ", 0, 0)
    total = dyn_at + len(dyn)
    head = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9 + struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0, ph_at, 0, 0, 64, 56,
                                                                     phnum, 0, 0, 0)
    phs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)
    if interp is not None:
        phs += struct.pack("<IIQQQQQQ", 3, 4, interp_at, interp_at, interp_at, len(interp_b), len(interp_b), 1)
    if runpath is not None:
        phs += struct.pack("<IIQQQQQQ", 2, 6, dyn_at, dyn_at, dyn_at, len(dyn), len(dyn), 8)
    return head + phs + strtab + interp_b + dyn


class ElfDiscoveryTest(Tmp):
    def test_pt_interp_and_runpath_are_read_without_running_anything(self):
        p = self.put("lib/x.so", elf64(runpath="$ORIGIN/../lib2:/opt/rp", interp="/lib/ld-test.so.1"))
        self.assertEqual(hs.elf_dynamic(p), ("/lib/ld-test.so.1", ["$ORIGIN/../lib2", "/opt/rp"]))

    def test_the_anchors_own_shell_names_its_loader(self):
        interp, _ = hs.elf_dynamic(hs.ANCHOR_SHELL)
        self.assertTrue(interp and interp.startswith("/"))

    def test_a_binary_under_another_loader_is_refused_before_listing(self):
        calls = []
        p = self.put("bin/x", elf64(interp="/tmp/evil-ld.so"))
        with self.assertRaisesRegex(hs.Tooling, "not the anchor's loader"):
            hs._elf_closure([p], run=lambda *a, **k: calls.append(a))
        self.assertEqual(calls, [])

    def test_runpath_candidates_are_returned_with_origin_expanded(self):
        loader, _ = hs.elf_dynamic(hs.ANCHOR_SHELL)
        p = self.put("app/bin/x", elf64(runpath="$ORIGIN/../lib:/opt/rp", interp=loader))
        ok = subprocess.CompletedProcess([], 0, b"\tlinux-vdso.so.1 (0x1)\n\t" + loader.encode() + b" (0x2)\n", b"")
        libs, searched = hs._elf_closure([p], run=lambda *a, **k: ok)
        self.assertEqual(searched, sorted([os.path.join(self.d, "app/bin") + "/../lib", "/opt/rp"]),
                         "joined textually: a .. after a link is the kernel's")

    def test_a_static_elf_runs_no_loader_and_links_nothing(self):
        """RE N5, option (a): no PT_INTERP and no DT_NEEDED is judged by its
        file rule and route alone."""
        calls = []
        p = self.put("bin/static", elf64())
        self.assertEqual(hs._elf_closure([p], run=lambda *a, **k: calls.append(a)), ([], []))
        self.assertEqual(calls, [])

    @unittest.skipUnless(os.path.exists("/usr/bin/gcc") and sys.platform.startswith("linux"), "needs gcc on Linux")
    def test_the_loaders_list_mode_runs_no_constructor_and_reports_failure(self):
        """On this platform: --list maps a library whose constructor would
        leave a sentinel, and the sentinel is absent; a real run leaves it.
        A missing dependency fails the listing, which is refused."""
        sentinel = os.path.join(self.d, "ctor-ran")
        src = self.put("ctor.c", ('#include <fcntl.h>\n#include <unistd.h>\n__attribute__((constructor)) static void r(void)'
                                  ' { int fd = open("%s", O_CREAT | O_WRONLY, 0644); if (fd >= 0) close(fd); }\n'
                                  'int marker(void) { return 1; }\n' % sentinel).encode(), 0o644)
        main = self.put("main.c", b"int marker(void);\nint main(void) { return marker() - 1; }\n", 0o644)
        lib, prog = os.path.join(self.d, "libctor.so"), os.path.join(self.d, "prog")
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", lib, src], check=True)
        subprocess.run(["gcc", "-o", prog, main, "-L" + self.d, "-lctor", "-Wl,-rpath,$ORIGIN"], check=True)
        libs, searched = hs._elf_closure([prog])
        self.assertIn(lib, libs)
        self.assertIn(self.d, searched)
        self.assertFalse(os.path.exists(sentinel), "the list mode ran the library's constructor")
        subprocess.run([prog], check=True)
        self.assertTrue(os.path.exists(sentinel), "the control: a real run does")
        os.rename(lib, lib + ".gone")
        with self.assertRaises(hs.Tooling):
            hs._elf_closure([prog])

    @unittest.skipUnless(os.path.exists("/usr/bin/gcc") and sys.platform.startswith("linux"), "needs gcc on Linux")
    def test_the_loaders_list_mode_runs_no_ifunc_resolver(self):
        """Opus d3.1 2(c): an IFUNC resolver runs at relocation; the list
        mode must not relocate. Its sentinel stays absent; a real run makes it."""
        sentinel = os.path.join(self.d, "ifunc-ran")
        src = self.put("ifunc.c", ('#include <fcntl.h>\n#include <unistd.h>\nstatic int impl(void) { return 1; }\n'
                                   'static void *resolve(void) { int fd = open("%s", O_CREAT | O_WRONLY, 0644);'
                                   ' if (fd >= 0) close(fd); return (void *)impl; }\n'
                                   'int marker(void) __attribute__((ifunc("resolve")));\n' % sentinel).encode(), 0o644)
        main = self.put("main.c", b"int marker(void);\nint main(void) { return marker() - 1; }\n", 0o644)
        lib, prog = os.path.join(self.d, "libifunc.so"), os.path.join(self.d, "prog")
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", lib, src], check=True)
        subprocess.run(["gcc", "-o", prog, main, "-L" + self.d, "-lifunc", "-Wl,-rpath,$ORIGIN"], check=True)
        libs, _ = hs._elf_closure([prog])
        self.assertIn(lib, libs)
        self.assertFalse(os.path.exists(sentinel), "the list mode ran the IFUNC resolver")
        subprocess.run([prog], check=True)
        self.assertTrue(os.path.exists(sentinel), "the control: a real run does")

    def test_a_runpath_with_another_token_refuses(self):
        loader, _ = hs.elf_dynamic(hs.ANCHOR_SHELL)
        p = self.put("bin/x", elf64(runpath="$LIB/x", interp=loader))
        ok = subprocess.CompletedProcess([], 0, b"\t" + loader.encode() + b" (0x2)\n", b"")
        with self.assertRaisesRegex(hs.Tooling, "does not judge"):
            hs._elf_closure([p], run=lambda *a, **k: ok)


GCC = os.path.exists("/usr/bin/gcc") and sys.platform.startswith("linux")


def missing_dependency(test):
    """liby.so with DT_NEEDED on libx.so, then libx.so removed: the case
    d3.3 §3.6b requires to FAIL under both list forms."""
    x = test.put("x.c", b"int x(void) { return 1; }\n", 0o644)
    y = test.put("y.c", b"int x(void);\nint y(void) { return x(); }\n", 0o644)
    libx, liby = os.path.join(test.d, "libx.so"), os.path.join(test.d, "liby.so")
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", libx, x], check=True)
    subprocess.run(["gcc", "-shared", "-fPIC", "-o", liby, y, "-L" + test.d, "-lx"], check=True)
    os.unlink(libx)
    return liby


class ListModeTest(Tmp):
    """d3.3 §3.6b's parser: every line one of three forms, tab first; a lone
    `statically linked` is empty; stderr, a non-zero rc or any other line
    refuses."""

    OK = b"\tlinux-vdso.so.1 (0x0000ffff981db000)\n\tlibc.so.6 => /lib/libc.so.6 (0x0000ffff97f70000)\n" \
         b"\t/lib/ld-linux-aarch64.so.1 (0x0000ffff98190000)\n"

    def test_the_three_forms_and_both_vdso_forms_pass(self):
        self.assertEqual(hs.list_mode_libraries("b", self.OK, b"", 0), ["/lib/libc.so.6", "/lib/ld-linux-aarch64.so.1"])
        old = b"\tlinux-vdso.so.1 =>  (0x00007ffd)\n\tlibc.so.6 => /lib/libc.so.6 (0x1)\n"
        self.assertEqual(hs.list_mode_libraries("b", old, b"", 0), ["/lib/libc.so.6"], "older glibc's vdso form")

    def test_a_lone_statically_linked_is_empty_and_only_alone(self):
        self.assertEqual(hs.list_mode_libraries("m.so", b"\tstatically linked\n", b"", 0), [])
        with self.assertRaisesRegex(hs.Tooling, "outside the list mode's forms"):
            hs.list_mode_libraries("m.so", b"\tstatically linked\n" + self.OK, b"", 0)

    def test_every_other_line_refuses(self):
        for bad in (b"\tlibx.so => not found\n", b"libc.so.6 => /lib/libc.so.6 (0x1)\n", b"\tlibc.so.6 => /lib/libc.so.6\n",
                    b"\t/lib/x.so (0xZZ)\n", b"\t/tmp/pt => /lib/ld.so (0x1)\n", b"\tlib c.so => /lib/c.so (0x1)\n",
                    b"\tsomething else\n", b"", b"\t/lib/x\xc3\xa9.so (0x1)\n"):
            with self.subTest(line=bad):
                with self.assertRaises(hs.Tooling):
                    hs.list_mode_libraries("b", self.OK + bad, b"", 0) if bad else hs.list_mode_libraries("b", b"", b"", 0)

    def test_stderr_or_a_non_zero_rc_refuses(self):
        with self.assertRaisesRegex(hs.Tooling, "error stream"):
            hs.list_mode_libraries("b", self.OK, b"warning\n", 0)
        with self.assertRaisesRegex(hs.Tooling, "exit 127"):
            hs.list_mode_libraries("b", self.OK, b"", 127)

    def test_the_interpreter_line_is_found_by_its_text_anywhere(self):
        mid = b"\t/lib/ld.so (0x2)\n\tlibc.so.6 => /lib/libc.so.6 (0x1)\n"
        self.assertEqual(hs.list_mode_libraries("py", mid, b"", 0, loader="/lib/ld.so"), ["/lib/ld.so", "/lib/libc.so.6"])
        with self.assertRaisesRegex(hs.Tooling, "did not list itself"):
            hs.list_mode_libraries("py", b"\tlibc.so.6 => /lib/libc.so.6 (0x1)\n", b"", 0, loader="/lib/ld.so")

    def test_the_trace_form_is_chosen_below_glibc_2_33(self):
        for v, want in (("glibc 2.32", True), ("glibc 2.33", False), ("glibc 2.41", False), (None, False),
                        ("musl 1.2", False), ("glibc x.y", False)):
            with self.subTest(v=v):
                self.assertIs(hs._trace_form(confstr=lambda name, v=v: v), want)
        seen = []
        hs._elf_closure([sys.executable], run=lambda argv, **k: (seen.append((argv, k["env"])),
                        subprocess.CompletedProcess(argv, 0, b"\tstatically linked\n", b""))[1], trace=True)
        self.assertEqual(seen[0][1], {"LD_TRACE_LOADED_OBJECTS": "1"})
        self.assertNotIn("--list", seen[0][0])

    @unittest.skipUnless(GCC, "needs gcc on Linux")
    def test_a_missing_dependency_fails_under_each_form_on_the_real_loader(self):
        liby = missing_dependency(self)
        for trace, why in ((False, "cannot list .* \\(exit [1-9]"), (True, "outside the list mode's forms.*not found")):
            with self.subTest(trace=trace):
                with self.assertRaisesRegex(hs.Tooling, why):
                    hs._elf_closure([liby], trace=trace)

    @unittest.skipUnless(GCC, "needs gcc on Linux")
    def test_a_library_with_no_dt_needed_passes_as_statically_linked(self):
        src = self.put("z.c", b"int z(void) { return 0; }\n", 0o644)
        libz = os.path.join(self.d, "libz0.so")
        subprocess.run(["gcc", "-shared", "-fPIC", "-nostdlib", "-o", libz, src], check=True)
        loader, _ = hs.elf_dynamic(hs.ANCHOR_SHELL)
        for trace in (False, True):
            with self.subTest(trace=trace):
                p = subprocess.run([loader, libz] if trace else [loader, "--list", libz], capture_output=True,
                                   env={"LD_TRACE_LOADED_OBJECTS": "1"} if trace else {})
                self.assertEqual(p.stdout, b"\tstatically linked\n", "the real loader's own form")
                self.assertEqual(hs.list_mode_libraries(libz, p.stdout, p.stderr, p.returncode), [])


class AllowlistTest(Tmp):
    """d3.3 §4.1: argv[0] is the own interpreter in its exact vector or a
    recorded tool; so is every --also tool. Nothing is discovered or exec'd
    before the refusal."""

    def setUp(self):
        super().setUp()
        FlowTest.stub(self)

    def run_it(self, argv, also=(), tools=()):
        ran = []
        hs.trusted_exec(argv, also, platform="linux", execv=lambda *a: ran.append(a), tools=tools)
        return ran

    def test_an_unrecorded_argv0_or_also_tool_refuses(self):
        with self.assertRaisesRegex(hs.Tooling, "not a tool the document records"):
            self.run_it(["/usr/bin/docker", "ps"], tools=["/usr/bin/install"])
        with self.assertRaisesRegex(hs.Tooling, "/opt/x/docker is not a tool"):
            self.run_it(["/usr/bin/docker", "ps"], also=["/opt/x/docker"], tools=["/usr/bin/docker"])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.run_it(["/usr/bin/docker", "ps"], tools=["/usr/bin/docker"]),
                         [("/usr/bin/docker", ["/usr/bin/docker", "ps"])])

    def test_the_own_interpreter_needs_no_record_but_only_as_its_vector(self):
        self.addCleanup(setattr, sys, "argv", sys.argv)
        own = self.put("libexec/host_steps.py", b"print(1)\n", 0o644)
        sys.argv = [own]
        self.assertEqual(len(self.run_it([sys.executable, "-I", "-S", "-B", own, "noop"])), 1)

    def test_the_main_entry_carries_tool_into_the_allowlist(self):
        self.addCleanup(setattr, hs, "trusted_exec", hs.trusted_exec)
        got = []
        hs.trusted_exec = lambda rest, also, shas, tools=(): got.append((rest, also, tools))
        hs._trusted_exec_main(["trusted-exec", "--tool", "/usr/bin/docker", "--also", "/usr/bin/docker", "--",
                               "/usr/bin/docker", "ps"])
        self.assertEqual(got, [(["/usr/bin/docker", "ps"], ["/usr/bin/docker"], ["/usr/bin/docker"])])


class BindTest(Tmp):
    def test_a_hashbang_file_refuses(self):
        p = self.put("bin/script", b"#!/bin/sh\necho\n")
        with self.assertRaisesRegex(hs.Tooling, "#! script"):
            hs._bound([p])

    def test_a_shell_refuses_under_any_flags(self):
        for argv in (["/bin/sh", "-c", "id"], ["/bin/sh", "-ec", "id"], ["/bin/sh", "/tmp/script"], ["/bin/bash"]):
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(hs.Tooling, "is a shell"):
                    hs._bound(argv)

    def test_an_exec_wrapper_refuses_by_name_and_by_what_it_resolves_to(self):
        """Opus d3.3 N2: a recorded `env` or `timeout` would pass any
        allowlist of recorded tools; it is refused all the same."""
        for name in ("env", "timeout", "xargs", "nice", "nohup", "setsid", "stdbuf", "flock", "find", "chroot",
                     "runuser", "perl", "busybox"):
            with self.subTest(name=name):
                p = self.put(f"bin/{name}", b"\x7fELF", 0o755)
                with self.assertRaisesRegex(hs.Tooling, "execs a program from its arguments|is a shell"):
                    hs._bound([p, "/usr/bin/docker", "ps"])
        os.symlink(os.path.join(self.d, "bin/env"), os.path.join(self.d, "bin/docker"))
        with self.assertRaisesRegex(hs.Tooling, "execs a program from its arguments"):
            hs._bound([os.path.join(self.d, "bin/docker"), "ps"])
        hs._bound([self.put("bin2/docker", b"\x7fELF", 0o755), "ps"])

    def test_the_interpreter_runs_only_its_own_writer(self):
        own = self.put("libexec/host_steps.py", b"print(1)\n", 0o644)
        other = self.put("libexec/other.py", b"print(2)\n", 0o644)
        self.addCleanup(setattr, sys, "argv", sys.argv)
        sys.argv = [own]
        hs._bound([sys.executable, "-I", "-S", "-B", own, "lock"])
        for argv in ([sys.executable, "-I", "-S", "-B", other, "lock"], [sys.executable, "-c", "print(3)"],
                     [sys.executable, "-m", "http.server"], [sys.executable, "-I"], [sys.executable, "-I", "-S", own, "x"],
                     [sys.executable, "-I", "-S", "-B", "-c", own, "x"], [sys.executable, "-I", "-S", "-B", own]):
            with self.subTest(argv=argv[1:]):
                with self.assertRaises(hs.Tooling):
                    hs._bound(argv)


class OrderTest(unittest.TestCase):
    """The file rule comes before any library discovery: ldd or the loader's
    list mode may run code of the target, so they see only a judged one."""

    def test_an_operator_owned_tool_is_refused_and_nothing_is_discovered(self):
        calls = []
        for name, fn in (("_trusted_tool", self.refuse), ("_bound", lambda argv: None),
                         ("exec_closure", lambda *a, **k: calls.append(a)),
                         ("_elf_closure", lambda *a, **k: calls.append(a))):
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, fn)
        with self.assertRaisesRegex(hs.Tooling, "operator's"):
            hs.trusted_exec(["/opt/op/docker", "ps"], platform="linux", execv=lambda *a: calls.append(a),
                            tools=["/opt/op/docker"])
        self.assertEqual(calls, [])

    @staticmethod
    def refuse(p):
        raise hs.Tooling(f"{p} is the operator's")

    def test_sudo_is_refused_anywhere(self):
        for argv, also in ((["/usr/bin/sudo", "-n", "/usr/bin/docker"], ()), (["/usr/bin/docker"], ("/usr/bin/sudo",))):
            with self.subTest(argv=argv, also=also):
                with self.assertRaisesRegex(hs.Tooling, "never holds sudo"):
                    hs.trusted_exec(argv, also, platform="linux", execv=lambda *a: None)

    def test_ld_so_preload_present_refuses(self):
        with tempfile.NamedTemporaryFile() as f:
            self.addCleanup(setattr, hs, "LD_SO_PRELOAD", hs.LD_SO_PRELOAD)
            hs.LD_SO_PRELOAD = f.name
            with self.assertRaisesRegex(hs.Tooling, "ld.so.preload|maps it into every process"):
                hs.trusted_exec(["/bin/true"], platform="linux", execv=lambda *a: None)


class FlowTest(unittest.TestCase):
    """trusted_exec end to end, each refusal on its own path: what the
    host's real files cannot show (a route problem, a closure problem, an
    ACL) is put in by replacing the one judge that finds it, and the row
    asserts that nothing is discovered after a refusal and nothing execs."""

    def stub(self, **over):
        self.calls = []
        fns = {"_trusted_tool": lambda p: p, "_bound": lambda argv: None,
               "exec_closure": lambda py, reals, spelled, platform=None: (self.calls.append("discover"),
                                                                          {hs.REQUIRED: [py], hs.LIBRARIES: [],
                                                                           hs.OPTIONAL: []})[1],
               "closure_problems": lambda c, platform=None, seen=None: [],
               "acl_problems": lambda paths, platform=None: [],
               "loader_dirs": lambda platform=None: ["/etc/ld.so.cache", "/etc/ld.so.conf"]}
        fns.update(over)
        for name, fn in fns.items():
            self.addCleanup(setattr, hs, name, getattr(hs, name))
            setattr(hs, name, fn)

    def go(self, argv=("/usr/bin/docker", "ps"), **kw):
        ran = []
        try:
            kw.setdefault("tools", [argv[0]] + list(kw.get("also", ())))
            hs.trusted_exec(list(argv), platform=kw.pop("platform", "linux"), execv=lambda *a: ran.append(a), **kw)
        finally:
            self.ran = ran

    def test_the_whole_path_judged_then_execd(self):
        self.stub()
        self.go()
        self.assertEqual((self.calls, self.ran), (["discover"], [("/usr/bin/docker", ["/usr/bin/docker", "ps"])]))

    def test_a_shell_never_reaches_the_tools_or_the_exec(self):
        """_bound inside trusted_exec, on this host's real /bin/sh: the
        route and closure would pass, so only the bind refuses it."""
        self.stub(_bound=hs._bound)
        with self.assertRaisesRegex(hs.Tooling, "is a shell"):
            self.go(["/bin/sh", "-c", "id"])
        self.assertEqual((self.calls, self.ran), ([], []))

    def test_a_tools_route_problem_refuses_before_any_discovery(self):
        def judge(c, platform=None, seen=None):
            return ["/opt/op is the operator's"] if c == ["/usr/bin/docker"] else []
        self.stub(closure_problems=judge)
        with self.assertRaisesRegex(hs.Tooling, "route is not root's alone"):
            self.go()
        self.assertEqual((self.calls, self.ran), ([], []))

    def test_a_client_other_than_the_pinned_one_refuses(self):
        """On this host's real /usr/bin/true, whose bytes are not all zeros' hash."""
        self.stub()
        with self.assertRaisesRegex(hs.Tooling, "not the client the document pins"):
            self.go(["/usr/bin/true"], shas={"/usr/bin/true": "0" * 64})
        self.assertEqual((self.calls, self.ran), ([], []))

    def test_a_closure_problem_refuses_the_exec(self):
        def judge(c, platform=None, seen=None):
            return ["/usr/lib/libz.so is writable by others"] if isinstance(c, dict) else []
        self.stub(closure_problems=judge)
        with self.assertRaisesRegex(hs.Tooling, "closure is not root's alone: /usr/lib/libz.so"):
            self.go()
        self.assertEqual((self.calls, self.ran), (["discover"], []))

    def test_an_acl_on_anything_judged_refuses_the_exec(self):
        def judge(c, platform=None, seen=None):
            if seen is not None:
                seen.extend(["/usr/lib", "/usr/lib/libz.so"])
            return []
        got = []
        self.stub(closure_problems=judge,
                  acl_problems=lambda paths, platform=None: (got.append(paths), ["/usr/lib/libz.so carries an ACL"])[1])
        with self.assertRaisesRegex(hs.Tooling, "libz.so carries an ACL"):
            self.go()
        self.assertEqual((got, self.ran), ([["/usr/lib", "/usr/lib/libz.so"]], []))

    def test_the_loaders_directories_are_judged_on_linux_and_on_darwin_only_on_fall_through(self):
        seen = []

        def judge(c, platform=None, seen_=None, **kw):
            if isinstance(c, dict):
                seen.append(list(c[hs.OPTIONAL]))
            return []
        self.stub(closure_problems=lambda c, platform=None, seen=None: judge(c))
        self.go()
        self.assertEqual(seen, [["/etc/ld.so.cache", "/etc/ld.so.conf"]])
        seen.clear()
        self.go(platform="darwin")
        self.assertEqual(seen, [[]], "every install name on disk: no fall-through, no fallback directories")


class AclTest(unittest.TestCase):
    def test_linux_acl_xattrs_refuse_and_a_filesystem_without_them_does_not(self):
        def lx(p, follow_symlinks=False):
            if p == "/acl":
                return ["system.posix_acl_access"]
            if p == "/noxattr":
                raise OSError(errno.ENOTSUP, "Operation not supported")
            if p == "/denied":
                raise OSError(errno.EACCES, "Permission denied")
            return []
        self.assertEqual(hs.acl_problems(["/clean", "/noxattr"], platform="linux", listxattr=lx), [])
        bad = hs.acl_problems(["/acl", "/denied"], platform="linux", listxattr=lx)
        self.assertEqual(len(bad), 2)

    def test_darwin_acl_lines_name_their_entry_even_under_at(self):
        out = (b"drwxr-xr-x@ 3 0  0  96 Oct 1 00:00 /fw/a\n"
               b" 0: group:everyone deny delete\n"
               b"-rw-r--r--  1 0  0  10 Oct 1 00:00 /fw/b\n")
        run = lambda *a, **k: subprocess.CompletedProcess([], 0, out, b"")
        self.assertEqual(hs.acl_problems(["/fw/a", "/fw/b"], platform="darwin", run=run), ["/fw/a carries an ACL"])


class LoaderConfigTest(unittest.TestCase):
    def test_ld_so_conf_includes_and_directories_are_all_listed(self):
        files = {"/etc/ld.so.conf": "include /etc/ld.so.conf.d/*.conf\n# a comment\n/opt/lib\n",
                 "/etc/ld.so.conf.d/a.conf": "/usr/local/lib\n"}
        def read(p):
            if p not in files:
                raise FileNotFoundError(p)
            return files[p]
        got = hs.loader_dirs("linux", read=read, glob_=lambda pat: ["/etc/ld.so.conf.d/a.conf"])
        for p in ("/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ld.so.conf.d/a.conf", "/opt/lib",
                  "/usr/local/lib"):
            self.assertIn(p, got)

    def test_darwin_names_the_dyld_fallbacks(self):
        self.assertEqual(set(hs.loader_dirs("darwin")), set(hs.DYLD_FALLBACK_DIRS))


if __name__ == "__main__":
    unittest.main()
