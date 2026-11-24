"""RE's REAL outputs at fc542edc (RE's answer to W13 d2, section 3), each line as RE sent it, with RE's own
placeholders kept: <T> for its scratch directory, <path> for the plugin path, <HOP_LINK>. S1 is RE's obs.info call with
relay.py's exact argument set and placeholder values, not a live start; B1-B3, R1, R3, L1, L4, V6, V7 and the six
hub-status writes H1-H6 are real (H1-H3 and H5 in flight, complete false; H4 and H6 final, complete true)."""

B1 = (b'{"ts": "2026-11-22T18:08:30.511823+00:00", "component": "relay", "level": "warning", "event": "hub_s'
      b'ession_backoff", "cls": "hub_unreachable", "stage": "connect", "code": null, "delay_s": 30.0}')
B2 = (b'{"ts": "2026-11-22T18:08:31.518874+00:00", "component": "relay", "level": "warning", "event": "hub_s'
      b'ession_backoff", "cls": "tls_failed", "stage": "ehlo", "code": null, "delay_s": 30.0}')
B3 = (b'{"ts": "2026-11-22T18:08:32.532223+00:00", "component": "relay", "level": "warning", "event": "hub_s'
      b'ession_backoff", "cls": "temporary", "stage": "starttls", "code": 454, "delay_s": 30.0}')
S1 = (b'{"ts": "2026-11-22T18:08:33.516285+00:00", "component": "relay", "level": "info", "event": "startup"'
      b', "role": "hub", "link": "<HOP_LINK>", "plugin_sha256": "0000000000000000000000000000000000000000000'
      b'000000000000000000000", "plugin_api": "[3, 5]", "interval": 5.0, "control": "off"}')
R1 = (b'{"ts": "2026-11-22T18:08:47.085464+00:00", "component": "relay", "level": "error", "event": "config_'
      b'error", "error_class": "ConfigRefused", "knob": "IMAP_HOST", "detail": "is required for the hub inbo'
      b'und start"}')
R3 = (b'{"ts": "2026-11-22T18:08:47.742564+00:00", "component": "relay", "level": "error", "event": "secret_'
      b'unavailable", "path": "<S>/t/nope", "rule": "missing", "exit": 5}')
L1 = (b'outcome_ledger: initialised <T>/ledger')
L4 = (b'outcome_ledger: LedgerUnavailable: not_private: <T>/wide must be owned by uid 1000 with mode 0700 (f'
      b'ound uid 1000, mode 0o750)')
V6 = (b'{"claimed_unstarted": [], "claimed_unstarted_complete": true, "claimed_unstarted_truncated": false, '
      b'"complete": true, "held": [], "held_complete": true, "held_truncated": false, "ledger": {"available"'
      b': true}, "pending": [], "pending_age_s": 3600, "pending_complete": true, "pending_truncated": false}')
V7 = (b'{"claimed_unstarted": null, "claimed_unstarted_complete": null, "claimed_unstarted_truncated": null,'
      b' "complete": false, "held": null, "held_complete": null, "held_truncated": null, "ledger": {"availab'
      b'le": false, "reason": "not_private"}, "pending": null, "pending_age_s": 3600, "pending_complete": nu'
      b'll, "pending_truncated": null}')
H1 = (b'{"complete":false,"interval_s":5.0,"process_started_ts":"2026-11-22T18:08:03.614363Z","progress":1,"'
      b'pumps":1,"started_at":"2026-11-22T18:08:03Z","started_ts":"2026-11-22T18:08:03Z","transport_plugin":'
      b'{"path":"<path>","sha256":"2aca9e214a8cca789bd081d43a04de776dc9eb6844f6c3b180d148e01b7dd893"},"v":1}')
H2 = (b'{"complete":false,"interval_s":5.0,"process_started_ts":"2026-11-22T18:08:03.614363Z","progress":2,"'
      b'pumps":1,"started_at":"2026-11-22T18:08:03Z","started_ts":"2026-11-22T18:08:03Z","transport_plugin":'
      b'{"path":"<path>","sha256":"2aca9e214a8cca789bd081d43a04de776dc9eb6844f6c3b180d148e01b7dd893"},"v":1}')
H3 = (b'{"complete":false,"interval_s":5.0,"process_started_ts":"2026-11-22T18:08:03.614363Z","progress":3,"'
      b'pumps":1,"started_at":"2026-11-22T18:08:03Z","started_ts":"2026-11-22T18:08:03Z","transport_plugin":'
      b'{"path":"<path>","sha256":"2aca9e214a8cca789bd081d43a04de776dc9eb6844f6c3b180d148e01b7dd893"},"v":1}')
H4 = (b'{"archive":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"frontier":"absent"'
      b',"kept":0,"removed":0}},"complete":true,"interval_s":5.0,"logical_ids":{},"policy_reloaded":true,"pr'
      b'ocess_started_ts":"2026-11-22T18:08:03.614363Z","progress":3,"pumps":1,"registry":null,"started_ts":'
      b'"2026-11-22T18:08:03Z","transport_plugin":{"path":"<path>","sha256":"2aca9e214a8cca789bd081d43a04de7'
      b'76dc9eb6844f6c3b180d148e01b7dd893"},"trees":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbb'
      b'bbbbbbbbbbb":{"held":{},"reason":null,"state":null}},"v":1,"written_at":"2026-11-22T18:08:03Z"}')
H5 = (b'{"complete":false,"interval_s":5.0,"process_started_ts":"2026-11-22T18:08:03.614363Z","progress":4,"'
      b'pumps":2,"started_at":"2026-11-22T18:08:03Z","started_ts":"2026-11-22T18:08:03Z","transport_plugin":'
      b'{"path":"<path>","sha256":"2aca9e214a8cca789bd081d43a04de776dc9eb6844f6c3b180d148e01b7dd893"},"v":1}')
H6 = (b'{"archive":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"frontier":"absent"'
      b',"kept":0,"removed":0}},"complete":true,"interval_s":5.0,"logical_ids":{},"policy_reloaded":true,"pr'
      b'ocess_started_ts":"2026-11-22T18:08:03.614363Z","progress":4,"pumps":2,"registry":null,"started_ts":'
      b'"2026-11-22T18:08:03Z","transport_plugin":{"path":"<path>","sha256":"2aca9e214a8cca789bd081d43a04de7'
      b'76dc9eb6844f6c3b180d148e01b7dd893"},"trees":{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbb'
      b'bbbbbbbbbbb":{"held":{},"reason":null,"state":null}},"v":1,"written_at":"2026-11-22T18:08:03Z"}')
