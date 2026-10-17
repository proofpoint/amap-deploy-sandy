"""d3.3 §3.6b's line grammar, as fixtures both halves are held to: the sh
half (root-trust.sh's _rt_libs) and the Python half
(host_steps.list_mode_libraries). `{lib}` stands for a library path each
half can accept; each line follows one good line."""

LINES = [
    ("\tlinux-vdso.so.1 (0x0000ffff981db000)", True),
    ("\tlinux-gate.so.1 (0x1)", True),
    ("\tlinux-vdso.so.1 =>  (0x00007ffd)", True),
    ("\tlinux-vdso.so.1 (0xgarbage)", False),
    ("\tlinux-gate.so.1 (0x)", False),
    ("\tlinux-vdso.so.1 (0x1) extra (0x2)", False),
    ("\tlinux-vdso.so.1 => (0x1)", False),
    ("\tlinux-vdso.so.1", False),
    ("\tlinux-vdso.so.1 ff)", False),
    ("\tlinux-gate.so.1 =>  ff)", False),
    ("linux-vdso.so.1 (0x1)", False),
    ("\tlibc.so.6 => {lib} (0x1)", True),
    ("\t{lib} (0x2)", True),
    ("\tlibc.so.6 => {lib} (0x1) extra (0x2)", False),
    ("\t{lib} (0xZZ)", False),
    ("\t{lib} (0x)", False),
    ("\tlibx.so => not found", False),
    ("\tlib c.so => {lib} (0x1)", False),
    ("\t/tmp/pt => {lib} (0x1)", False),
    ("\tlibc.so.6 => {lib}", False),
    ("{lib} (0x1)", False),
    ("\tsomething else", False),
]
