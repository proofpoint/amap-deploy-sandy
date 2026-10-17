"""The live engine route's trust gate (secret_setup.live_docker), held open
for rows about what the engine answers, through a stubbed rh.run. The gate's
own rows, where it refuses, are test_root_tool_trust's."""

import secret_setup as ss


def open_gate(test):
    """Hold the gate open for `test`, and close it when the test ends."""
    ss._GATE.append((None, None))
    test.addCleanup(ss._GATE.pop)
