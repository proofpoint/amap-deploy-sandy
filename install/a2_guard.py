"""The output guard (section 3.3): the one writer every line of a run
passes through.

While S1 holds any value, the guard refuses a line that contains a held
value. It writes nothing for that line, and the stage exits with
`RUNNER.OUTPUT_GUARD`. The held values live in memory only, as
bytearrays the guard never converts to `str`.
"""

from a2_causes import Refusal

#: A fact from a target or a child is capped (3.3).
FACT_CAP = 4096
TRUNCATED = "...[truncated]"


class OutputGuard:
    def __init__(self):
        self._held = []
        self.wrote_target = False

    def hold(self, value):
        """Hold a value S1 read. `value` is a bytearray; the guard keeps the
        same object, so S1's clear (overwrite) clears it here too."""
        if not isinstance(value, bytearray) or not value:
            raise ValueError("held values are non-empty bytearrays")
        self._held.append(value)

    def release_all(self):
        for v in self._held:
            for i in range(len(v)):
                v[i] = 0
        self._held = []

    @property
    def holding(self):
        return bool(self._held)

    def check(self, data):
        """Refuse bytes that contain any held value. Returns `data`."""
        if isinstance(data, str):
            raw = data.encode("utf-8", "surrogateescape")
        else:
            raw = bytes(data)
        for v in self._held:
            if bytes(v) and bytes(v) in raw:
                raise Refusal("RUNNER.OUTPUT_GUARD", rc=3 if self.wrote_target else None)
        return data

    def emit(self, stream, line):
        """Write one line (without its LF) to a text stream, or nothing."""
        self.check(line)
        stream.write(line + "\n")
        stream.flush()

    def fact(self, value):
        """A value from a target or a child: guarded, then capped."""
        self.check(value)
        if len(value) > FACT_CAP:
            value = value[:FACT_CAP - len(TRUNCATED)] + TRUNCATED
        return value
