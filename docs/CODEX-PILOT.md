# Dedicated Codex pilot adapter

`codex_pilot.py` adds a reviewed two-endpoint pilot to an existing single-Claude
fleet. It requires Python 3.11+, the connector's launcher-control v1 contract,
Sandy protected submounts and managed_exec.py, and the router configurable outcome
IDs change. Existing installations without the pilot registry retain their CLI
behavior. There is no automatic PR merge or deployment.

```bash
python3 codex_pilot.py --sandy /absolute/sandy inventory
python3 codex_pilot.py --sandy /absolute/sandy prepare \
  --codex-workspace /actual/new/workspace --claude-workspace /actual/existing/workspace \
  --codex-src /absolute/amap-connector-codex --sandy-src /absolute/sandy-source \
  --router-src /absolute/router-source --router-container existing-router-name \
  --model available-model --output /private/pilot/plan.json
python3 codex_pilot.py --plan /private/pilot/plan.json runbook --output /private/pilot/HOST-RUNBOOK.md
```

Provision the fresh Codex namespace normally first, keep it outside AMAP selection,
and authenticate the pinned CLI in that sandbox. Both chosen containers must be
running for read-only preparation. Do not hand-create Sandy sandbox directories.
Before fleet apply, review the source/preimage hashes, all emitted files and the
exact generated commands. Source drift or host manifest drift causes apply to
refuse. Runtime inventory accepts the existing router run.sh network/user contract;
custom runtime configurations require explicit engineering review.

The plan freezes current membership, mail peers and old-to-old task edges, adding
only C↔B task edges. No future member automatically joins. Router state_dir remains
unchanged. The common feature holds mounts/tool payload; unchanged Claude endpoints
receive their relay through an explicitly selected Claude-only feature. The chosen
Claude peer uses the common immutable relay payload under a host guard instead of
a feature entry. Stop/recreate that peer to positively terminate its old relay
before starting the new host service. Other existing Claude containers can retain
their old relay until normal recreation; verify them through their existing checks.

Host services keep the journal, canonical guards and binding records outside agent
and router mounts. A root runtime helper drops the child to the actual agent UID;
exact container and daemon IDs are recorded before remote spawn. Missing bindings
are unknown until stop commits a revocation. Unknown cleanup holds ownership.
Codex auth/thread state lives in a per-namespace runtime home outside router-mounted
instance roots; its configuration is a read-only file child. Exact three-server MCP
allowlists are also supplied to thread start/resume and checked against the actual
registry before inference. No engine socket or model-writable host controls.

Follow generated commands in order: apply, scoped sandbox restart, rebuild/replace
the recorded router with retained state, wait for first sight, isolation-probe,
doctor --probe, services, verify, roundtrip/check-roundtrip for each direction.
`apply` writes reviewed files and rollback preimages but starts no services.
Legacy verify reports the whole-fleet gate UNKNOWN until its external observations
are retained; it cannot turn a two-endpoint check into a healthy fleet.
The legacy installer refuses install/router-config/fleet-domain/teardown while the
pilot registry is active to prevent clobbering the mixed deployment.

`verify` checks rendered files and both runtime endpoints, reporting FAIL/UNKNOWN
without treating missing observations as success. It deliberately reports
`rollout_ready: false`: it does not replace live inference, fleet health, policy
admission, tool traces, restart or round-trip evidence. `check-roundtrip` checks two
accepted runtime submissions, correlation and attachment marker/hash; attachment
reads, final consumption and idle polls still require actual trace observations.
Its zero exit code covers only those checked router artifacts.

Roundtrip prepares a private nonce fixture and evidence directory. Codex-initiated
runs enqueue on the existing controller; Claude-initiated runs print an instruction
for the existing Claude session. A prepared ID cannot be queued twice. No direct
spool injection satisfies the demonstration.

For rollback, stop both services and positively clean their exact executions,
then run `rollback`. It takes both private controller locks, refuses changed target
files and restores only saved manifests/configs. Runtime homes, journals, spools,
router state and source payload snapshots remain. Recreate the affected endpoints,
restore exactly one Claude activation, and replace the router with the restored
configuration. Never use fleet teardown or remove uncertainty records to recover.

The new canonical connector repository is proofpoint/amap-connector-codex; it
has not yet been created. Prepare records per-file SHA-256 source/dependency
locks for the reviewed local connector artifact. A Git pin and connector PR
must be established after repository creation before the final source release.
The existing Claude/router sibling pins are retained rather than replaced.
