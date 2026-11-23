# ALPHA-2 installer: stage contract, formats and check lists

Status: DRAFT for review (W1). It is normative once it is reviewed and approved
by sha (decision E7 (a)). Later changes are reviewed as diffs against this file.

This file is the installer's public contract. It holds the rules every
stage follows, the cause names, the formats of the three private files, the
`--verify` check list, and the leak check those private files get at S0. It
holds no values: hosts, domains, key ids, VM ids, image ids and pins live in
the private files, and every example here uses `example.org` and
`<placeholders>`.

Words: MUST, MUST NOT, SHOULD and MAY are used in their RFC 2119 sense.
`[OPEN <id>]` marks a slot that waits on a named decision or owner answer.

## 1. Sources and decisions

This contract restates, and does not change, sections a.2, a.3, a.4, a.6,
a.11 and b.9 of the ALPHA-2 installer proposal. Where this file and the
proposal disagree before approval, the proposal governs and the difference
is a finding. It applies these decisions:

| Decision | Effect here |
|---|---|
| E5 (a) | A component change arrives through its own reviewed PR and is pinned in `alpha2.lock` (section 6.1). Nothing here pins a component any other way. |
| E6 (b) | S3 and S6b CHECK the hub and write nothing to it. The installer holds no hub write path. The operator resets and sets the router logins before every fresh run (section 3.6). Here "hub" is the `l3` scope's `hub` (6.2); hub-t (`hub_loop`) is one of the loop's throwaway test VMs (E1), restored only as 3.6 states (E3). |
| E7 (a) | One review per stage against this contract. The installer is approved by its sha, and each green run by the sha of its receipt SUMS (section 5.4). |
| E14 (a) | S2 applies: it starts NET's reviewed program and creates the VMs if absent. |
| E16 (a) | `alpha2.lock` and `alpha2.hosts` live in the private overlay repository; run manifests live there or on the runner host. Only code and the formats below are public. S0 leak-checks both files (section 8). |
| E12 (C), L3 target VMs (A), Q0b (iii) | One runner host runs every run: L1, L2, the L2-leak run and the final run (L3). One `alpha2.hosts` names the targets, with separate VM entries: the loop's test VMs, and the real VMs that the final run rebuilds from bare (E1, E2). The loop never touches the real VMs. Two runner accounts: the loop runs only as the loop runner account, and the final run only as the L3 runner account, started by the operator through a reviewed `sudo` line. The target locks of 5.3 exclude any two runs (one key per target, one for the hypervisor), every supported invocation starts through one launcher and every route is admitted by S0 before a target write (5.1a), every target-writing run's S0 requires the hypervisor to report no loop task, an `L3` or bare `install` and a `destroy` also need the hypervisor's L3 arm gate open, and each run reads custody back at every stage boundary (section 5.3b). |
| E19 | The stop file `stop.d`, the loop's kill switch, and its setters (section 5.3b); and the loop's budget, 12 L2 runs a day counted from durable start records, and no run at 80% or more of its account's 7-day usage (section 5.3c). |
| E20 | After a PASS, S10 prints an access line for each VM for use from the runner host; S0 rehearses that route read-only (`PREFLIGHT.OPERATOR_ROUTE`). |
| A2-16 | The runner host does not sleep; S0 checks that its sleep is disabled (section 5.3a). |
| Apply credentials (A) | Decided: the apply path's access is by scoped keys with forced commands. The loop key belongs to the loop runner account; the L3 key belongs to the L3 runner account, and the loop runner account cannot read it. An `L3` or bare `install` and a `destroy` need the hypervisor's L3 arm gate open. Because an `L3` or bare `install` runs only as the L3 runner account (5.3b), the loop cannot start one, inside an armed window or outside it: the armed-window exposure is closed by identity, not by time. The key inventory, forced commands, custody paths and checks are [OPEN: apply credentials design, NET] (section 9a). |
| E13 | Decided (c): the autonomous-agent residual is accepted for ALPHA-2; nothing is built. The brakes for an L2 run are the router stop, de-enrolment, the cross-host `task_deny`, and the 7-day reply window (section 9). The RL per-run reply-depth check is a per-run evidence item for L2 and L3 runs [OPEN: RL reply-depth check] (section 5.5). |
| E18 | D3 is blocked until A2-05, A2-08 and A2-14 land. A2-15 may be accepted as INFERRED, by name, only if it is the last one outstanding (section 9). |
| Lock-denial and budget-scope residuals | Accepted by the operator. (a) Lock and permit denial: a runner account can hold a lock the other's run needs, including from a process outside the launcher, or spend the current path (b) permit, so that run refuses. That is availability only and fail-closed, on a local filesystem: a held lock or a spent permit never admits a run. Recovery: on a `RUNNER.TARGET_LOCKED` the operator did not expect, the operator, as root, finds the holder with `lslocks` and stops that account's processes; a spent permit is recovered by the monitor's next permit (5.3 step 4, 5.3c, section 9). (b) Budget scope: the E19 budget governs runs of the reviewed installer, not a runner account acting with its own key; only that key's forced program (9a) bounds such a process (5.1a). No lock broker replaces direct `flock`. |
| E26 | The twelve residuals are accepted: R1 to R4, R6, R7, R10, and N1 to N5. N4 is the A2-07 wedge until RE's fix lands; N5 is the PR #513 fleet pause (section 9, D3). |
| E23 | Decided 2026-11-15T04:59:02Z: the registry program joins the ALPHA-2 tag list, and the private overlay is tagged privately; the lock pins both. The registry program is a `components[]` entry, and the overlay is pinned by `overlay` (section 6.1). |
| E24 | Decided 2026-11-15T04:59:58Z: tag names as in plan section 11, `alpha2-rcN` at each lock change, plus a final tag on the green fresh (L3) run. Every tag in one lock is the same `alpha2-rcN` (section 6.1); the final tag is D5's (section 9) [OPEN: final tag name]. |
| E25 | Settled by E11 (a′), decided 2026-11-15T14:01:57Z (`--destroy` is added now and uses the L3 key, never the loop key), and by the second round of the apply-key questions, decided 2026-11-15T14:06:36Z (the L3 arm gate, and `destroy` limited to the pinned VMs). `--destroy`'s VM scope is the `vms[]` entries of `alpha2.hosts` that are not on the runner-side list `destroy_deny` (section 6.2), and only those that carry the installer's marker inside an armed window and are not on the L3 forced program's own hard deny list (section 9a); never the hub (E6 (b)). Its own confirmation is the arm gate the operator sets for each sitting, with the `--destroy` line frozen at D3 (5.3b). The real VMs are rebuilt from bare by the final run (L3 target VMs (A), decided 2026-11-15T14:22:59Z). |
| ALPHA2-IMAGE-BUILD-PIN (D) | Decided 2026-11-20T17:07:58Z: the sandy agent sandbox images are built on each VM as usual (`sandy --build-only` in S7) and their ids are RECORDED in S7's receipt for information only: no `images[]` row, no check, no refusal on the value. The router's and the relay end's images stay `images[]` pins (section 6.1). Accepted trade-off: an L3 image may differ from the loop's |
| ALPHA2-L3-ID-REMINT (A) | Decided 2026-11-20T17:09:05Z: every bare L3 mints new router and agent ids, on four conditions: (1) no ALPHA-2 state lives off a VM's own disk (every RE state directory and its volume on the VM; verify V15); (2) `min_sender_age_s` is 0 on both VMs, rendered by S6, which checks the two are equal; (3) S8 refuses a clock skew over 2 s between the VMs before start; (4) at each bare L3 start the operator empties the rebuilt hosts' router mailboxes and lets queued hub mail drain (section 9, U2) |

What this draft ADDS beyond the proposal, for the reviewer to accept or
change (the proposal sets the requirement; the shape below is this draft's):

| Added | Section |
|---|---|
| The predecessor graph (the proposal gives the order and the dependencies in prose) | 2 |
| The receipt grammar, its required facts and the `RESULT` values | 3.3 |
| `<STAGE>.UNCLASSIFIED` and its fail-closed exit rule | 3.4 |
| The stub rule in the test list | 3.8 |
| The cause-name grammar, every name outside a.6's `VERIFY.*` list, and the fixed sentences | 4, 4.7 |
| The run directory layout, run id, the target-lock algorithm, the stop file and the loop's budget, the sleep check, SUMS bytes and eligibility | 5 |
| All three private file formats, as normative schemas, and the manifest lifecycle | 6 |
| The S0 leak checks L1 to L8 | 8 |

## 2. Stages

Twelve stages, in this order. NAME is the stage's name exactly as a.4 writes
it, and it is the `<STAGE>` half of every cause the stage emits (section 4).

| Id | NAME | Owner | With | Writes to | Predecessors |
|---|---|---|---|---|---|
| S0 | `PREFLIGHT` | DS | controller, NET | nothing on any target; on the runner host, the run directory and the fetched commits in the work directory | none |
| S1 | `CREDENTIALS` | DS | sandy | nothing; the values are held in the runner's memory (section 3.7) | S0 |
| S2 | `VMS` | NET | DS | the hypervisor, through NET's reviewed program (E14 (a)) | S0 |
| S3 | `HUB-CHECK` | NET | RE | nothing (E6 (b)) | S0 |
| S4 | `IMAGES` | DS | RL, HOP, RE | each VM | S2 |
| S5 | `KEYS` | DS | RL | each VM; only the public key and its id come back | S4 |
| S6 | `CONFIG` | DS | RL, RE, HOP | each VM; nothing is started | S3, S5 |
| S6b | `HUB-LOGIN` | DS (VM writer), NET | RE | the VM end only: RE's secret file on each VM | S1, S6 |
| S7 | `AGENTS` | DS | sandy, the sandbox-image owner, connector | each VM; each agent is left stopped | S1, S6 |
| S8 | `START` | DS | RL, RE, HOP | each VM | S6b, S7 |
| S9 | `VERIFY` | controller | RL, RE, HOP, DS, NET, connector | nothing, except the agent processing proof in a full install run (section 7.2) | S8 |
| S10 | `SUMMARY` | DS | controller | the run directory only | every stage the run ran |

The predecessor column is this draft's reading of a.4's dependencies: S6
needs the hub facts of S3 and the peer key of S5; S6b and S7 need S1's
values and S6's secret volume, writer and owners; S8 needs both writers done.
S1's receipt carries facts only, never a value; its values reach S6b and S7
in memory, inside one run.

## 3. The contract (every stage, every owner)

### 3.1 Entry points

Each stage provides exactly three entry points.

| Entry point | Rule |
|---|---|
| `plan` | Read-only. Prints the desired state, the observed state and the difference. Runs every refusal check the stage has. A fact it could not observe is printed as `UNOBSERVED` with the reason, never as a pass. |
| `apply` | Runs `plan` first. Refuses (exit 2) if anything it depends on is not in its expected state. Writes only what differs. After writing, re-observes and requires the desired state. On a failure after a write, restores what it changed where a restore is defined, and reports the final observed state either way (exit 3). |
| `verify` | Read-only. Used by `--verify` and by the next stage as its precondition. |

"Read-only" means: no write on any target host, no write to either private
file, and no write on the runner host outside the run directory.

### 3.2 Inputs and the environment

A stage reads exactly these, and nothing else:

1. `alpha2.lock` (section 6.1), as the in-memory copy S0 read (section 8);
2. `alpha2.hosts` (section 6.2), likewise;
3. the receipts of its predecessors (section 2), from the current run directory, or, in an L1 run only, read in place from the verified `source_run` directory under the provenance rule of section 3.3;
4. for S1 only, the values entered at its one no-echo prompt; for S6b and
   S7 only, the corresponding values S1 holds in memory (section 3.7).

The launch line (section 5.1) passes exactly three variables through,
`HOME`, `SSH_AUTH_SOCK` and `TERM`, and sets `PATH` to `/usr/bin:/bin`. These
are the runner's: `HOME` locates the work directory, `SSH_AUTH_SOCK` carries
the operator's own ssh access (empty for the L3 runner account, 5.3b), and `TERM` serves the no-echo prompt. A stage
MUST NOT read any of them as an input.

A stage MUST refuse (exit 2) a predecessor receipt whose `INSTALLER_SHA` fact
differs from its own installer sha. The one exception (K8) is a verified
source-run predecessor in an L1 run, under the provenance rule of section
3.3; a receipt written by the current run never has it. The cause is
`<STAGE>.PREDECESSOR_INSTALLER`.

### 3.3 Receipt

A receipt is a text file, one per stage per host, written to the run directory.

```
receipt     = *fact-line end-line
fact-line   = KEY "=" VALUE LF
KEY         = [A-Z][A-Z0-9_]{0,63}
VALUE       = *( %x21-7E / SP )        ; printable ASCII, no LF, no control bytes
end-line    = "STAGE-END" SP stage-id SP ( host-name / "-" ) SP "rc=" rc LF
stage-id    = "S0" / "S1" / "S2" / "S3" / "S4" / "S5" / "S6" / "S6b" / "S7" / "S8" / "S9" / "S10"
host-name   = the section 6 `name` pattern
rc          = "0" / "2" / "3" / "4"
```

The receipt's pathname is exactly `receipts/<stage-id>-<host-name or ->.txt`. The file ends in LF and has no other bytes.

- The end line is the LAST line and appears exactly once. A receipt without
  it is not a receipt, and the next stage refuses it (`<STAGE>.PREDECESSOR_INCOMPLETE`).
- Every receipt carries at least `RUN_ID`, `COMMAND`, `LOOP` (`-` for null),
  `INSTALLER_SHA`, `LOCK_SHA`, `HOSTS_SHA`, `STAGE`, `HOST` (or `-`),
  `STARTED` and `ENDED` (UTC, `YYYY-MM-DDTHH:MM:SSZ`), and `RESULT`.
- `STAGE` equals the section 2 NAME paired with the end line's `stage-id`;
  `HOST` equals the end line's host; the pathname is the one above.
- `INSTALLER_SHA`, `LOCK_SHA` and `HOSTS_SHA` are lowercase 64-hex sha256
  values and equal the bytes the stage used. `RUN_ID`, `COMMAND` and `LOOP`
  equal the manifest's `run_id`, `command` and `loop`.
- `RESULT` is one of `CHANGED` (apply wrote and re-observed the desired
  state), `ALREADY` (already in the desired state; nothing written),
  `PLANNED` (`--dry-run`), `PASS` (a read-only verify), or `FAIL`.
- For rc 0, `RESULT` is one of `CHANGED`, `ALREADY`, `PLANNED`, `PASS`, and
  `CAUSE` and `CAUSE_TEXT` are absent. For rc 2, 3 or 4, `RESULT` is `FAIL`,
  and exactly one `CAUSE=<STAGE>.<NAME>` fact and one `CAUSE_TEXT=` fact are
  present.
- A KEY appears at most once.
- A receipt is finalized atomically (written to a temp file, fsynced, renamed
  into place) before its SUMS line is appended (section 5.4).

A reader refuses a receipt (`<STAGE>.PREDECESSOR_INCOMPLETE`) if:
- a KEY repeats;
- its `STAGE` or `HOST` facts, its end line, or its file name disagree with the predecessor it expected;
- its `LOCK_SHA` or `HOSTS_SHA` differ from the manifest;
- any other rule of this section fails.

Any mismatch is an incomplete or failed predecessor, never accepted.

**Source-run provenance.** A receipt written by the current run always equals the current manifest's RUN_ID, COMMAND, LOOP and INSTALLER_SHA. In an L1 `--only`/`--from` run, a missing local predecessor may be read in place from the one `source_run` directory only after that source's final manifest and SUMS verify: the source manifest must be `final`, and its `SUMS` sha must equal `source_run.sums_sha256`. Its RUN_ID, COMMAND, LOOP and INSTALLER_SHA must equal the source manifest; its LOCK_SHA and HOSTS_SHA must also equal the current manifest. It is never copied or rewritten into the current run. The sole K8 relaxation is that a verified source predecessor's INSTALLER_SHA may differ from the current manifest. Current-run receipts never receive that relaxation. Every other rule of this section applies unchanged.

**What a receipt, a stage and a check MUST NOT print**, anywhere (receipt,
stdout, stderr, log):

- a secret, a seed, a password, an API key, or a hash, length, prefix or any other part of any of them;
- a container's environment, the `Env` field of a `docker inspect`, or any
  process environment (the API key reaches each sandbox as a value by design,
  so any such listing carries it).

**Output guard (fail closed).** Every line a run writes (receipt, manifest, SUMS, summary, stdout, stderr, log, and child output relayed from a target) passes through one writer in the runner. While S1 holds any value, that writer refuses a line that contains a held value. When it refuses, it writes nothing for that line and the stage exits with `RUNNER.OUTPUT_GUARD` (exit 3 if the stage had written, else 2). The guard holds the values in memory only. It is part of the S1 review, with a negative test in which a stage tries to print the canary. [OPEN: S1 review] whether the guard keeps its in-memory copy until the run ends (so S8 to S10, including S9's processing proof with the real key, stay guarded; the on-screen hold time then says so), or S8 to S10 rely on fixed filters only.

`CAUSE_TEXT` is the fixed sentence for that cause from section 4.7, never text formatted from an exception, a child's output or an input value.

A fact whose value comes from a target or a child process (for example kept stderr) carries a fixed-filter result, or is passed through the output guard and capped at 4096 bytes. An over-long value is truncated and marked, and is never a reason to skip the guard.

Every argv value is matched in full against a section 6 pattern (`--add-agent <host>`: `name`; `--id`: `name`; `--check-roundtrip <nonce>`: `^[A-Za-z0-9]{8,64}$`; `--only`/`--from`: a stage id) before it is used or recorded. A mismatch is `RUNNER.ARGS` (exit 2), and the cause sentence does not echo the argument.

A check that must compare a container's environment with a file emits only
counts, or named non-secret keys through a fixed filter, never values. The
filter is a committed list of key names, reviewed with the stage.

### 3.4 Exit codes

| rc | Meaning |
|---|---|
| 0 | Pass, or already in state. |
| 2 | Refused before any write. |
| 3 | Failed after a write. The receipt says what state was left. |
| 4 | `verify` failed. |

No other exit code is permitted. A stage that cannot classify its own failure exits 2 only if it can show it issued no write (it failed before its first write call). Otherwise it exits 3, and its receipt records the final observed state, or `UNOBSERVED`. The cause is `<STAGE>.UNCLASSIFIED`, which is itself a review finding when it appears. A write, for this rule, is any write by the run: on a target, to a private file, or anywhere in the work directory (the fetched commits and the run directory). The start record is the broker's write in `budget.d`, not the run's, so `RUNNER.NOT_STARTED` (5.1a), which fetches nothing and ends before any run directory exists, exits 2. A cause that S0 names (sections 4.3 and 4.4) exits 2 although S0 has already written in the work directory (its run directory, its record and the fetched commits): those are S0's own bookkeeping, and S0 writes nothing to a target or a private file. `<STAGE>.UNCLASSIFIED` keeps the rule above.

### 3.5 Runtime identity

- Every image readback and every config read is done as the uid and gid that
  will run it (K1, K10).
- Every one-shot run of a pinned image sets its entrypoint explicitly (K2).
  A one-shot that relies on an image's default entrypoint to forward its
  arguments is a contract breach: an entrypoint that drops an argument
  returns the wrong output with rc 0, and nothing downstream can tell.

### 3.6 The hub (E6 (b))

In this section "the hub" is the `l3` scope's `hub` (6.2). hub-t, the loop's `hub_loop`, is one of the three
throwaway test VMs of E1, and the loop identity holds restore, start, stop and status on exactly those VMs (E3). The
only writes to it are S2's, under the E3 loop identity: its power state (start, stop) and the rollback to its pinned
snapshot, restoring it as a member of `loop_restore_set`; nothing else in the installer, and no program it calls,
writes to hub-t. S3 checks hub-t read-only, as it does the
hub, for a loop-scope run.

- S3 `HUB-CHECK` is read-only: the hub facts record against the pinned
  inventory commit and against what RE's reader expects; the group's render
  compared with the live hub; the default group's bytes recorded. Its apply
  path (E6 (a)) is not built.
- S6b `HUB-LOGIN` writes only the VM end: RE's secret file on each VM, 0400,
  owned by RE's uid and the hop gid. The value is the mailbox credential the
  operator typed at S1's prompt. The stage then proves the login from RE's
  own probe result, by account name.
- The installer contains no code path that writes to the hub, and calls no other program in a mode that can. S3's `apply` is defined as its `verify`: it writes nothing and returns `ALREADY` or a cause. The runner invokes NET's program for S0's hub probe, S3 and S9 only with read-only verbs, and passes it no E6 mode. The NET commit pinned in `alpha2.lock` is reviewed, at that commit, to show that no entry point reachable from the runner's interface writes to the hub. A review that finds a reachable hub write fails the stage.
- **Before every fresh run** (L3 and every bare start), the operator runs
  NET's reviewed text that resets and sets the two router logins, outside the
  installer, and then types the two mailbox credentials at S1's one prompt.
  This is an operator touch (section 9), not a stage.
- `--destroy` MUST NOT touch the hub (E6 (b), decided). It deletes, through NET's program, only VMs that carry the installer's marker. The login reset stays the operator's pre-run touch. `--destroy`'s VM scope is settled as E25 records in section 1, and a.2's "resets the router logins" is recorded as a finding superseded by E6 (b).

### 3.7 The secret path (S1, and the writers in S6b and S7)

These rules are a.4's S1 row and a.11, restated as checkable statements. Each
is a negative test of the S1 review; each MUST be shown to fail closed.

1. S1 sets its own core-dump limit to zero, and that of every child that
   handles a secret (a per-process limit, no sudo), and refuses if it cannot.
   The writer on each VM sets its own core-dump limit to zero before it reads stdin, and exits without reading if it cannot. The negative test runs it where setting the limit fails.
2. One prompt, no echo. The prompt reads from the controlling terminal with echo turned off, and checks that echo is off before it reads. If stdin is not a terminal, or echo cannot be turned off, S1 refuses (`CREDENTIALS.NO_ECHO`, exit 2) and never falls back to an echoing read. A library fallback that warns and echoes (for example `getpass`'s `GetPassWarning` path) is a contract breach. The terminal state is restored on every exit path. `--dry-run` never prompts. A re-run prompts again, once. Negative test: run S1 with stdin not a terminal; it must exit 2 with no read.
3. Each value is checked for form. A form failure names only which form rule failed, never the value, its length or any part of it. The API key is checked live by one authenticated request, made by the installer's own process over TLS with certificate and hostname verification on, to the one endpoint named in the installer's code [OPEN: endpoint]. The key travels in a request header that is never forwarded on a redirect. Redirects are not followed: any non-2xx answer is `CREDENTIALS.KEY_NOT_LIVE`. The key is never in an argument list or a child process. Neither the response body nor the exception text is printed or recorded. The cause sentence is the fixed text of 4.7. If the API exposes expiry, S1 warns when expiry meets the reviewed near-expiry threshold; the threshold is fixed by the S1 review, not guessed by the stage.

   3a. The stub live check exists only behind the flag `--leak-run`. That flag sets `"loop": "L2-leak"`, feeds the prompt's values to the two writers, stops after the last secret writer, and runs no S8 or S9; after the last secret writer and the leak scan, S10 writes a `NOT ELIGIBLE: L2-leak` summary and the runner finalizes manifest and SUMS. A run with `"loop": "L2-leak"` is never an approval identity (5.4). No other input, file key or environment variable selects the stub.
4. The values are held in the runner's memory from the prompt until their
   writers have run, then cleared: held in a `bytearray`, never converted to `str`, and overwritten after the last writer (best effort, stated in the S1 review). The hold time is stated on screen. Only S7's writer (the API key) and S6b's writer (the mailbox credential) receive a value; no other stage does. The prompt binds each mailbox credential to one `vms[].name`. Each VM's S6b writer receives exactly that VM's credential and no other value. S7's writer on each VM receives only the API key. The binding is recorded in S1's receipt by VM name only.
5. The writer is a committed file, never generated at run time.
6. The writer checks every return code, writes in a full-write loop to a
   0600 temp file in a 0700 directory, fsyncs, renames atomically, and removes
   the temp on any failure.
7. The bytes hashed are the bytes executed. On each VM, one fixed bootstrap (committed in the installer and pinned through `install/MANIFEST`) is run by the VM's absolute interpreter in a cleaned environment (`env -i`, `-I`), as `python3 -I -S -c <its bytes>`, so no bootstrap or writer file exists on the VM. The runner reads the writer's bytes from its checkout, refuses unless they match the `writers[]` sha from `alpha2.lock`, and sends them first on stdin. The bootstrap reads them once into memory, hashes those bytes itself (no external hasher), compares them with the `writers[]` sha passed as an argument, and only on a match writes `READY` and executes the in-memory bytes. The runner sends the value only after `READY`. On a mismatch the bootstrap exits without `READY`, the value is never sent, and the cause is `<STAGE>.PIN`. Hashing on the runner host, or hashing in one process and executing in another, does not meet this rule. Negative test: a writer altered by one byte on the VM gets no value and the stage exits 2. The mode decides the value: `write` and `rotate` send a non-empty value, `finish` and `restore` send none, and any other pairing refuses before the route is used. After the writer returns, the bootstrap prints `RC <n>`; a session without it failed in the bootstrap and is `<STAGE>.UNCLASSIFIED` (3). The whole session runs under one deadline. Stated residual: `READY` is a line on the login account's shell; that account can `sudo -n` and is root-equivalent, so "never before `READY`" holds while that shell is trusted. The login shell is POSIX sh family (a VM base requirement).
8. The check of which credential is in force follows sandy's grammar: the
   last duplicate wins.
9. Interpreters are invoked by absolute path, in a cleaned environment. The
   value is handed over on stdin only, never as an argument, never in an
   exported variable.
10. S7 and `--rotate-key` check that a start is possible before any stop, and
    define the recovery start. The environment variables sandy needs come
    from sandy's owner, with file and line, before S7 is written
    [OPEN: sandy's list, a.12].
11. The per-key approval in the pre-seed is treated as a secret: written by
    the reviewed writer from the value on stdin, never read back, never in a
    receipt.
12. The leak run and the live-key check never share a run: there are two L2
    forms, as a.11 sets out (`"loop": "L2"` and `"loop": "L2-leak"`).

For every run (5.3c), the API key of these rules is the loop account's setup token; rule 3's live check and the API-key shape of section 8 L4 concern that token's form [OPEN: endpoint]. Where the live check can read the account the token belongs to, S1 also shows that it is the loop account; otherwise that rests on the operator's entry, and the S1 review says which.

S1 gets its own dual review (Codex and Opus).

### 3.8 Tests owed by every stage

- A fake-host run, and a mutant run in which every check has a negative test
  that makes it fail. The packages committed under `alpha/packages/` carry
  this form.
- Fixtures captured from real live output (A2-11, K15, K9). A fixture states
  in its header where and when it was captured.
- A stub that stands in for a tool models that tool's real argument handling,
  including what it drops. A stub that accepts any argv proves nothing about
  the call.

### 3.9 K answers

This contract has no K answers of its own. Each stage's review cover answers
K1 to K19 for that stage, as b.8 lays out. The owner answers K7, K15, K16 and
K19 with file and line or a fixture sha; the "With" owners of section 2 are
the source for K7.

## 4. Cause names

### 4.1 Form

```
cause-line  = "CAUSE=" STAGE "." NAME
STAGE       = a NAME from section 2 exactly as written there, or RUNNER
              ; [A-Z][A-Z0-9-]*  e.g. PREFLIGHT, HUB-CHECK, HUB-LOGIN
NAME        = [A-Z][A-Z0-9_]{1,82}
```

**One spelling, decided here:** the `STAGE` part is a.4's stage name
verbatim, hyphens included (`HUB-CHECK.GROUP_ABSENT`, `HUB-LOGIN.PROBE`); the
`NAME` part uses underscores only. A stage therefore has one name everywhere
(map, receipts, causes), and the dot is the only separator a reader splits on.

Every non-zero exit prints exactly one cause line and one sentence. The
cause names are part of the reviewed contract: a stage that emits a name not
in this list fails its review, and a name is added only by a diff to this file.

### 4.2 Names every stage carries

**The write rule (every cause of a stage that writes, this table's and 4.4's):** a stage's cause exits 2 before
the stage's first write and 3 after it, keeping its name. Exit 2 from any stage therefore always means the stage
wrote nothing, which later stages and the operator rely on. "Write" is 3.4's: any write by the stage, a write through
the VM layer included (a root placement, a secret, or a command the stage declared as writing). S0 and S1, and the
runner's own causes, write nothing to a target and keep their exits. The Exit column below is the exit BEFORE a
write.

| NAME | Exit | When |
|---|---|---|
| `LOCK` | 2 (3 after a write) | `alpha2.lock` unreadable, or fails its schema (section 6.1) |
| `HOSTS` | 2 (3 after a write) | `alpha2.hosts` unreadable, or fails its schema (section 6.2) |
| `PREDECESSOR_MISSING` | 2 | A predecessor's receipt is absent from the run directory |
| `PREDECESSOR_INCOMPLETE` | 2 | A predecessor's receipt has no valid end line |
| `PREDECESSOR_FAILED` | 2 | A predecessor's end line has rc other than 0 |
| `PREDECESSOR_INSTALLER` | 2 | A predecessor was written by a different installer sha, outside the one K8 relaxation (section 3.3) |
| `PIN` | 2 (3 after a write) | A file, image or commit does not match its pin in `alpha2.lock` |
| `TARGET_ACCESS` | 2 (3 after a write) | The route to a VM (ssh to its `ssh_alias`, with the host key S2 pinned) failed, timed out, or is not configured. After the stage's first write, on any VM, it exits 3 under the write rule, because a VM may have changed |
| `EXISTS_DIFFERENT` | 2 (3 after a write) | A key or file the stage would create already exists and differs from what the run expects; it is never regenerated or replaced |
| `INTERPRETER` | 2 (3 after a write) | A VM's `python3` is older than the release a component the stage runs there requires (S6: RL's floor, 3.11) |
| `CLOCK` | 2 | The run scope's hub clock (`hub_for_scope`, 6.2: hub-t in the loop scope) is more than the allowed skew (60 s) from the runner's, or could not be read (S3, NET's; read-only) |
| `HUB_NAME` | 2 | The run scope's hub name is not a host key of the pinned network inventory (6.2); S3 is read-only, so it never follows a write of its own |
| `HUB_HOSTNAME` | 2 | The run's S3 receipt has no `HUB_HOSTNAME` fact, or it is not a lowercase DNS name of at most 253 characters (S6, ruling W7-S6-HUB-HOSTNAME: the hub MTA's own hostname, S6's `hub_fqdn`, read before S6's first write) |
| `ROUTER_REFUSED` | 2 (3 after a write) | RL's `peers` verb, run over the router.json the stage placed, exits non-zero (S6) |
| `PEER_STORE` | 2 (3 after a write) | RL's peer store is not `ready` with admission `open` and exactly its three artefacts, or `peer-store init --never-admitted` failed or left it otherwise; never retried or repaired (S6) |
| `REGISTRY` | 2 (3 after a write) | The registry program (E23) refuses the router's import, or its read-back by key does not match the apply and the placed host.json; never repaired (S6) |
| `CLOCK_SKEW` | 2 | The two VMs' clocks, each read once and bracketed by the runner's clock, differ by more than 2 s after both read errors are added, or a clock could not be read (S8, before anything starts; decision ALPHA2-L3-ID-REMINT, condition 3) |
| `TRUSTDIR_MOUNTED` | 2 (3 after a write) | A running agent sandbox has a bind mount whose source, resolved on the VM, is a router or relay trust directory or the plugin's root path, is inside one, or is a directory above one (S8, ruling RE-TRUSTDIR-MOUNT-CHECK-OWNER); the router's container binds a relay trust path (every path of the relay account's group, the env-file's directory, or the directories of the hub's two config files); or a container S8 started or checks binds a docker socket or a directory above one, adds the docker group by name or gid, or is privileged |
| `TRUSTDIR_UNREAD` | 2 (3 after a write) | A trust path S8 derives from S6's env-file and the agent account's home (the five files S6 placed included) lies outside its allowed root: the relay home for the relay account's paths, the agent home or the plugin's directory for the rest. Or a derived trust path (each relay path resolved as the relay account, the rest as the agent account), or a bind source of an agent sandbox or of the router's container (resolved as the agent account), is missing, malformed or not its own realpath; a bind source has no root rule, and check_trust judges what it covers. Or S6's env-file is not readable as KEY=value lines, or names a key the relay must not be given (S6's ABSENT keys); or `getent group docker` as the agent account gives no single docker line; or the mount table or host config of a running sandbox, the router's container or the relay's container could not be read, or holds a mount type or bind source the check cannot judge. Absent is never read as empty (S8) |
| `CONFIG_CHANGED` | 2 (3 after a write) | A file S6 placed no longer hashes to S6's receipt, the plugin or its directory has another owner or mode, the env-file or its directory is not the agent account's own at 0600 and 0700, router.json and the env-file name different hop or registry paths, either names another plugin path than S6's, or the relay ledger directory is gone or not reachable as the relay account (the relay account's stat of it fails) (S8, read only) |
| `RUNNING` | 2 (3 after a write) | A container named amap-rl or amap-re already exists on the VM, running or stopped, or the relay ledger is already initialised; the recovery is a VM restore (S8) |
| `LEDGER_UNUSABLE` | 2 (3 after a write) | Before S8 starts anything on the VM, the relay ledger directory, stat'ed as the relay account, is not that account's 0700 directory, or RE's read-only ledger check reports a state other than uninitialised, or gives no report S8 can parse (S8) |
| `RL_REFUSED` | 3 | The router container S8 started exited, is restarting or has restarted, its start script refused, its `docker inspect` failed or gave no well-formed state, start time or container id, or it wrote no first poll of its own within 60 s of starting (S8) |
| `NOT_ADMITTING` | 3 | The router's first poll of its own breaks one of S8's six admission conditions: its instances, registry, peer-store admission, delegation key, classification or loaded transport plugin (S8) |
| `RE_REFUSED` | 3 | The relay's one-shot ledger init fails or leaves the ledger not available, the env-file names a forbidden key or a malformed mount path, or the relay container refuses to start, cannot be inspected or its logs read, exits, or fails one of its health witnesses (S8) |
| `PLACED_DIFFERENT` | 2 (3 after a write) | A file the stage places is already there with other bytes, mode or type, or a directory the stage owns exactly holds a name it does not place; nothing is ever replaced (S6, vm_place; S6's transport plugin through the root bootstrap, placed only where absent; an agent's registry batch in S7) |
| `OWNER` | 2 (3 after a write) | A path the stage creates or uses exists with another owner, group or mode, or a directory above it is not trusted; it is never repaired. A never-replaced file the root bootstrap places (S6's transport plugin) with another owner or mode refuses `PLACED_DIFFERENT` instead |
| `NOT_RESTORED` | 3 | A write failed and the restore did not reach the prior state |
| `UNCLASSIFIED` | 3, or 2 only when no write can be shown | Section 3.4 |

### 4.3 Runner names

| Cause | Exit | When |
|---|---|---|
| `RUNNER.ENV` | 2 | A variable outside `HOME`, `SSH_AUTH_SOCK`, `TERM` and `PATH` is set, or `PATH` is not `/usr/bin:/bin`; or `HOME` is not the home directory the account database gives for the run's kernel account; or, for the L3 runner account, `SSH_AUTH_SOCK` is not empty |
| `RUNNER.TARGET_LOCKED` | 2 | Another run on this runner host holds the lock for one of this run's targets; the message names the target (section 5.3) |
| `RUNNER.RUN_DIR` | 2 | The run directory exists or cannot be created, or the work directory or its `runs` is not as section 5.2 requires |
| `RUNNER.SUMS` | 4 | The SUMS chain does not verify (section 5.4) |
| `RUNNER.OUTPUT_GUARD` | 2 or 3 | The output guard refused a line (section 3.3) |
| `RUNNER.HOSTS_TARGETS` | 2 | Two targets in `alpha2.hosts` share a name (section 5.3) |
| `RUNNER.LOCK_ROOT` | 2 | The runner host or the lock root differs from `runner` in `alpha2.hosts`, or the lock root or a lock file is not owned and moded as section 5.3 requires (section 5.3) |
| `RUNNER.CUSTODY` | 2 or 3 | The custody read-back at a stage boundary, or before a first target write, is not what section 5.3b requires; exit 3 if the run has written to a target, else 2 |
| `RUNNER.ARGS` | 2 | An argv value does not match its pattern (section 3.3) |
| `RUNNER.STAGE_SET` | 2 | An L1 (`--only`, `--from`) whose stage set includes S6 or a later stage but not S3: it would skip every hub check (ruling W5-R13-L1-STAGESET-REQUIRED). Refused at argument parsing, before any file is read or any stage runs |
| `RUNNER.ADMISSION` | 2 | The runner does not hold the locks of its run or, for a command that can write to a target, a valid broker record of its own account, or they do not bind it to this run (section 5.1a) |
| `RUNNER.DESTROY_DENY` | 2 | A `destroy` whose `alpha2.hosts` has no `destroy_deny` (section 6.2): the hard deny list is UNCONFIGURED |
| `RUNNER.NOT_STARTED` | 2 | No runner was started after a start record may have been published: the launcher's exec of the runner failed in any way (5.1a step 5), or the broker was sent a request and its answer was lost, late or malformed (5.3c). The record, if written, stays counted |
| `RUNNER.ACCOUNT` | 2 | The run's account, read from the kernel, is not one of the two runner accounts, or is not the one its command needs (section 5.3b) |

### 4.4 S0 `PREFLIGHT`: the hoisted refusals

S0 runs every refusal that needs no earlier write, for all later stages,
before anything changes (K12 across the run). One name per refusal, from
a.4's S0 row:

| Cause | When |
|---|---|
| `PREFLIGHT.MAC_TOOLS` | A required tool on the runner host is absent or not at its recorded version |
| `PREFLIGHT.INTERPRETER` | The interpreter's or the installer's hash differs from the lock (the launch line is fixed text) |
| `PREFLIGHT.NET_RUNTIME` | NET's runtime on the runner host is absent or cannot run offline |
| `PREFLIGHT.LEAK_LOCK` | Section 8 refuses `alpha2.lock` |
| `PREFLIGHT.LEAK_HOSTS` | Section 8 refuses `alpha2.hosts` |
| `PREFLIGHT.PRIVATE_SOURCE` | Either file does not come from the private overlay checkout, or that checkout's working tree is not exactly the tree of the commit `overlay.tag` peels to, or a file's bytes differ from that tree, or that commit does not meet the lock's `overlay` pin (section 6.1) |
| `PREFLIGHT.REPO_ACCESS` | The read-only access probe to a pinned repository fails |
| `PREFLIGHT.FETCH` | A pinned commit could not be fetched into the work directory, or the fetch did not produce that commit, or a pinned tag, as fetched and peeled, is not its pinned commit (section 6.1) |
| `PREFLIGHT.TARGET_ACCESS` | The read-only access probe to a target (the hypervisor, the run's own hub by `hub_for_scope` (6.2), each VM that exists) fails |
| `PREFLIGHT.HUB_READ` | The read-only checks of the run's own hub (`hub_for_scope`, 6.2) fail, including the render comparison |
| `PREFLIGHT.OPERATOR_ROUTE` | The operator's ssh route from the runner host to a VM (E20) fails its read-only rehearsal |
| `PREFLIGHT.LIVE_DEPLOY` | The run directory is the runner host's live deploy |
| `PREFLIGHT.KEEP_AWAKE` | The runner host's sleep is not shown disabled (A2-16, section 5.3a) |
| `PREFLIGHT.SURVEY` | Before L3 or a bare install: an `l3` target differs from the bare start state (E2: each `l3` VM absent; the hub as b.4 records). Before an L1, L2 or L2-leak run: a member of the loop's snapshot set is not at its pinned base snapshot (6.2 `loop_snapshots`: the snaptime differs, the snapshot is not the current parent or not the only one), or the read cannot be made |
| `PREFLIGHT.HANDOFF` | The stop file is set or `UNOBSERVED` for a command it applies to; or, for a command that can write to a target, the hypervisor does not report itself free of loop tasks; or an `L3` or bare `install`, or a `destroy`, does not read the hypervisor's L3 arm gate open, or for an `install` with too little time left in it (section 5.3b) |
| `PREFLIGHT.BUDGET` | A run that can write to a target: for an L2 run, the day's count of L2 runs is 12; for any such run, the loop's account usage is at 80% or more or cannot be shown below it, or the broker refused to write its start record, or `budget.d` could not be read (section 5.3c) |

All exit 2. The target lock is the runner's (`RUNNER.TARGET_LOCKED`).

### 4.5 `--verify` names

These are a.6's names, plus `VERIFY.RE_STATE_OFF_VM` (V15, ALPHA2-L3-ID-REMINT condition 1).

`VERIFY.RL_FORM`, `VERIFY.RL_REGISTRY`, `VERIFY.RL_DELEGATION`,
`VERIFY.PEERSTORE_CLOSED`, `VERIFY.RL_NO_VERIFY_SIGNAL`,
`VERIFY.PLUGIN_MISMATCH`, `VERIFY.RE_DOWN`, `VERIFY.RE_HELD`,
`VERIFY.RE_POLL_FAILED`, `VERIFY.RE_PUMP_FAILED`, `VERIFY.RE_AUTH_FAILED`,
`VERIFY.RE_NOT_PROGRESSING`, `VERIFY.HOP_LAYOUT`, `VERIFY.HOP_TREE_UNREADABLE`,
`VERIFY.HUB_LOGIN`, `VERIFY.HUBENV`, `VERIFY.D7`, `VERIFY.AGENT_<id>_<WHAT>`,
`VERIFY.OPERATOR_ROUTE`, `VERIFY.HOST`, `VERIFY.RE_STATE_OFF_VM`.

`VERIFY.AGENT_<id>_<WHAT>`: `<id>` is the agent's id from `alpha2.hosts`,
upper-cased with every character outside `[A-Z0-9]` replaced by `_`; `<WHAT>`
is one of `WORKSPACE`, `REGISTRY`, `SECRET_FILE`, `CONNECTOR_PIN`, `IMAGE`.

### 4.6 Stage-specific names

Each stage's own names are added by that stage's review, as a diff to this
section. Until then a stage has only the names in 4.2. Names a.4 already
requires are listed; the rest is a slot.

| Stage | Names |
|---|---|
| S1 `CREDENTIALS` | `CREDENTIALS.CORE_LIMIT` (rule 1 of 3.7), `CREDENTIALS.NO_ECHO` (rule 2), `CREDENTIALS.FORM`, `CREDENTIALS.KEY_NOT_LIVE` (rule 3), `CREDENTIALS.LEAK_LOCK`, `CREDENTIALS.LEAK_HOSTS` (section 8 L5); [stage review] |
| S2 `VMS` | `VMS.NO_MARKER` (a VM of that name exists without the installer's marker); [stage review] |
| S3 `HUB-CHECK` | `HUB-CHECK.CLOCK` (L1, L2 and L2-leak: hub-t's clock, read by S3 as its first hub check over the bound route, after S2's restore where the run has one, is more than 60 s from the runner's midpoint, or unread; NET's), `HUB-CHECK.HUB_NAME` (the run scope's hub name, `hub_for_scope(hosts, scope)["name"]`, is not a host key of the pinned network inventory; NET's S3 check, 6.2); [stage review] |
| S4 `IMAGES` | `IMAGES.FINGERPRINT` (router fingerprint not EXACT); [stage review] |
| S5 `KEYS` | `KEYS.EXISTS_DIFFERENT` (a re-run never regenerates a key); [stage review] |
| S6 `CONFIG` | `CONFIG.HOSTS` (an account or the hop group named in `alpha2.hosts` is missing on the VM, the relay account is root or the agent's uid, or an account lacks the hop group), `CONFIG.INTERPRETER` (the VM's python3 is older than RL's floor), `CONFIG.OWNER` (a path S6 lays out, including the hop intakes the bootstrap makes, is never repaired), `CONFIG.HUB_HOSTNAME` (S3's `HUB_HOSTNAME` fact, which S6 renders as RE's `SMTP_HOST`, `IMAP_HOST` and the prefix template's `hub_fqdn`, is missing or malformed), `CONFIG.ROUTER_REFUSED` (RL's `peers` over the placed router.json exits non-zero), `CONFIG.PEER_STORE` (RL's peer store is not ready with admission open after a never-admitted init, or an existing one is not), `CONFIG.REGISTRY` (the registry program refuses the router's import, or the read-back by key disagrees with the apply or host.json), `CONFIG.PLACED_DIFFERENT` (a placed file is already there and differs, or an exactly-owned directory holds an extra name); S6's recovery is a VM restore (S2), never a re-run: router.json and d7.json carry the run id, so a later run on a VM that was not restored refuses `CONFIG.PLACED_DIFFERENT`; [stage review] |
| S6b `HUB-LOGIN` | `HUB-LOGIN.PROBE` (RE's probe does not show the login by account name); [stage review] |
| S7 `AGENTS` | Each S7 cause exits 2 before S7's first write and 3 after, keeping its name (3.4; stage-wide, so a later VM's causes follow an earlier VM's writes); every VM's S6 receipt is read before the first write. `AGENTS.NO_START_PATH` (rule 10 of 3.7), `AGENTS.ADD_AGENT_AMBIGUOUS` (`--add-agent` does not select exactly one `agents[]` entry for the host; the detail is a count, never an id), `AGENTS.CONFIG_NOT_PLACED` (a run VM's S6 receipt does not say `CONFIG` `PLACED` with both shas, checked for every run VM before any VM contact; or, on the VM, router.json and feature.json do not re-hash to its `ROUTER_JSON_SHA` and `FEATURE_JSON_SHA`), `AGENTS.VM_ACCESS` (the VM cannot be reached as its agent account, or that account's `HOME` is not absolute, is `/`, starts with `//` or is not in normal form), `AGENTS.WRITER` (the credential writer or its bootstrap refused or failed), `AGENTS.PIN` with detail `sandy schema` (PROPOSED, W8 r6: after install, the installed sandy's `--print-schema` does not answer the capabilities S6 rendered for, `a2_sandy_caps`), `AGENTS.PIN` with detail `connector` (a connector file of S6's payload is missing from the connector's tree at the lock's commit, read as S6 reads it, or does not re-hash to it; the lock pins the connector by commit, with no files[] row per file), `AGENTS.IMAGE_BUILD` (sandy's build of the sandbox image failed), `AGENTS.SLUG_UNOBSERVED` (the sandbox name cannot be read from sandy's state), `AGENTS.SLUG_TOO_LONG` (PROPOSED, W8 r7: an agent's sandbox name `agent-<id>-<8 hex>` does not pass the agent registry's slug rule, `a2_agent_registry`; decided from `alpha2.hosts` before any VM contact; exit 2), `AGENTS.REGISTRY` (the agent registry (`a2_agent_registry`, through `a2_vm.bind`) refused the agent's import, or its read-back does not match), `AGENTS.ROTATE_LEFTOVER` (a previous credential file from a rotation is present), `AGENTS.SECRETS_TEMP_LEFTOVER` (a writer temporary from an interrupted write is present), `AGENTS.ROTATE_UNDONE` (exit 3: a rotation's new credential did not take, and the previous one was restored and started), `AGENTS.ROTATE_UNSUPPORTED` (PROPOSED, W8 r4: `--rotate-key` in ALPHA-2; refused before any VM contact or write; exit 2) |
| S8 `START` | `START.CONFIG_CHANGED` (step 2: a file S6 placed, the plugin's or the env-file's owner or mode, the hop and registry paths of router.json and the env-file, or either naming another plugin path; step 4: the relay ledger directory gone), `START.CLOCK_SKEW`, `START.RUNNING` (step 4: an amap-rl or amap-re container exists, or the ledger is initialised), `START.LEDGER_UNUSABLE` (step 4: the ledger directory's owner, mode or type, any other ledger state, or no parsable report), `START.TRUSTDIR_MOUNTED`, `START.TRUSTDIR_UNREAD`, `START.RL_REFUSED` (step 5: run.sh refused, the container is not running or restarted, its inspect failed or gave no well-formed state, start time or id, or no first poll of its own within 60 s), `START.NOT_ADMITTING` (step 5: the first poll breaks one of the six admission conditions), `START.RE_REFUSED` (step 6: the ledger init failed, or the ledger is not available after it; step 7: the env-file names a forbidden key or a malformed mount path, RE's start refused, its inspect or logs failed, its container stopped running, or one of its three witnesses failed); step 8's start causes follow with its code; [stage review] |
| S9 `VERIFY` | the `VERIFY.*` names of 4.5; `VERIFY.PROCESSING_<id>` (section 7.2); [stage review] |
| S10 `SUMMARY` | [stage review] |

### 4.7 Cause sentences

Each cause name's sentence is fixed text committed with this contract; a
stage review adds a name and its sentence together. `CAUSE_TEXT`
is that sentence, byte for byte, with `<STAGE>` replaced by the stage's NAME
and nothing else substituted. A sentence names what to look at; it never
carries a value.

| Cause | Sentence |
|---|---|
| `<STAGE>.LOCK` | Look at alpha2.lock: it is unreadable, fails its schema, or changed since S0 read it. |
| `<STAGE>.HOSTS` | Look at alpha2.hosts: it is unreadable, fails its schema, or changed since S0 read it. |
| `<STAGE>.PREDECESSOR_MISSING` | Look at the run directory: a predecessor stage has no receipt. |
| `<STAGE>.PREDECESSOR_INCOMPLETE` | Look at the predecessor receipt: it is unfinished, malformed, or not bound to this run. |
| `<STAGE>.PREDECESSOR_FAILED` | Look at the predecessor receipt: its stage did not pass. |
| `<STAGE>.PREDECESSOR_INSTALLER` | Look at the predecessor receipt: a different installer wrote it. |
| `<STAGE>.PIN` | Look at the pin in alpha2.lock and the file, image or commit it names: they differ. |
| `<STAGE>.TARGET_ACCESS` | Look at the VM named in the receipt: the route to it failed, timed out, or is not configured. |
| `<STAGE>.EXISTS_DIFFERENT` | Look at the router key on the VM named in the receipt: a key is already there, and the router.json there names another. |
| `<STAGE>.INTERPRETER` | Look at the VM named in the receipt: its python3 is older than the release the stage requires. |
| `<STAGE>.CLOCK` | Look at the run scope's hub clock: it differs from this machine's by more than the allowed skew, or could not be read. |
| `<STAGE>.HUB_NAME` | Look at alpha2.hosts: the run's hub name is not a host key of the pinned inventory. |
| `<STAGE>.HUB_HOSTNAME` | Look at this run's S3 receipt: its HUB_HOSTNAME fact, the hub's mail server hostname, is missing or malformed. |
| `<STAGE>.ROUTER_REFUSED` | Look at router.json on the VM named in the receipt: the router's own check of it failed. |
| `<STAGE>.PEER_STORE` | Look at the router's peer store on the VM named in the receipt: it is not ready with admission open, or its initialisation failed; it is never retried or repaired. |
| `<STAGE>.REGISTRY` | Look at the router's registry entry on the VM named in the receipt: the registry program refused it, or its read-back does not match. |
| `<STAGE>.CLOCK_SKEW` | Look at the clocks of the run's two VMs: they differ by more than 2 s, or one could not be read; nothing was started. |
| `<STAGE>.TRUSTDIR_MOUNTED` | Look at the containers' mounts on the VM named in the receipt: a mount makes a router or relay trust directory, or the plugin's root path, visible inside a sandbox or the router's container, or a container S8 started or checks can reach the docker daemon (its socket, the docker group, or privileged). |
| `<STAGE>.TRUSTDIR_UNREAD` | Look at the VM named in the receipt: a router or relay trust path S8 derives from S6's env-file and the agent home (the files S6 placed included) lies outside its allowed root (the relay home for the relay's paths, the agent home or the plugin's directory for the rest); or such a path, or a bind source of an agent sandbox or of the router's container, is missing, malformed or not its own path (a symlink in it) when its owning account resolves it; or S6's env-file could not be read or names a key the relay must not be given, or the docker group could not be read, or a container's mount table or host config could not be read or holds a mount the check cannot judge; the trust directories could not be shown clear. |
| `<STAGE>.CONFIG_CHANGED` | Look at what S6 placed on the VM named in the receipt: a file no longer matches S6's receipt, the plugin's or the env-file's owner or mode moved, router.json and the env-file name different paths or another plugin path, or the relay ledger directory is gone or not reachable as the relay account; nothing was started on that VM. |
| `<STAGE>.RUNNING` | Look at the VM named in the receipt: a router or relay container of this installer already exists there, or the relay ledger is already initialised; restore the VM, never re-run onto it. |
| `<STAGE>.RL_REFUSED` | Look at the router on the VM named in the receipt: its start script refused, its container could not be inspected, or it exited, restarted or never polled, and the script's error or the container's logs name the reason; a started container was stopped, not removed. |
| `<STAGE>.NOT_ADMITTING` | Look at the router's status on the VM named in the receipt: its first poll broke one of the six admission conditions; it was stopped, not removed. |
| `<STAGE>.LEDGER_UNUSABLE` | Look at the relay ledger directory on the VM named in the receipt: it is not the relay account's own 0700 directory (its owner, mode or type), or RE's own read-only check reports it unusable or gave no report S8 could read; nothing was started on that VM. |
| `<STAGE>.RE_REFUSED` | Look at the relay on the VM named in the receipt: its one-shot ledger init failed (a failed init leaves no container and no logs), or its container refused or never became healthy, and that container's logs name the reason; a started container was stopped, not removed. |
| `<STAGE>.PLACED_DIFFERENT` | Look at the directory on the VM named in the receipt: a file the stage places is there and differs, or the directory holds a name the stage does not place; nothing is ever replaced. |
| `<STAGE>.OWNER` | Look at the path on the VM named in the receipt: it, or a directory above it, has another owner, group or mode than the stage requires; it is never repaired. |
| `<STAGE>.NOT_RESTORED` | Look at the receipt's final observed state: a write failed and the restore did not complete. |
| `<STAGE>.UNCLASSIFIED` | Look at the receipt's final observed state: this stage failed in a way it does not name. |
| `RUNNER.ENV` | Look at the launch line: the environment holds a variable it does not allow. |
| `RUNNER.ARGS` | Look at the command's arguments: one does not match its pattern. |
| `RUNNER.STAGE_SET` | Look at the command's arguments: an L1 that runs S6 or a later stage must also run S3. |
| `RUNNER.ROTATE_UNSUPPORTED` | Look at the command: --rotate-key is disabled in this release. |
| `RUNNER.HOSTS_TARGETS` | Look at alpha2.hosts: two targets share a name. |
| `RUNNER.LOCK_ROOT` | Look at the runner entry in alpha2.hosts and the lock root: this host or its lock root is not the one named there, or the lock root or a lock file is missing or not owned and moded as required. |
| `RUNNER.TARGET_LOCKED` | Look at the target named in the message: another run holds its lock. |
| `RUNNER.CUSTODY` | Look at the custody facts in the receipt: lock, placement or the stop file changed at a stage boundary. |
| `RUNNER.RUN_DIR` | Look at the work directory: the run directory exists or cannot be created. |
| `RUNNER.SUMS` | Look at SUMS in the run directory: the chain does not verify. |
| `RUNNER.OUTPUT_GUARD` | Look at the stage that was writing: it tried to print a held value. |
| `RUNNER.ADMISSION` | Look at how the run was started: without the held locks of this run or, for a command that can write to a target, its broker record, or with ones that do not bind it. |
| `RUNNER.ACCOUNT` | Look at the account the run was started as: it is not the runner account this command needs. |
| `RUNNER.DESTROY_DENY` | Look at alpha2.hosts: destroy needs its destroy_deny list. |
| `RUNNER.NOT_STARTED` | Look at budget.d and the launcher's exec of the runner: no runner started, and a start record written for it stays counted. |
| `PREFLIGHT.MAC_TOOLS` | Look at the runner host's tools: one is missing or not at its recorded version. |
| `PREFLIGHT.INTERPRETER` | Look at the interpreter and the installer files: a hash differs from alpha2.lock. |
| `PREFLIGHT.NET_RUNTIME` | Look at NET's runtime on the runner host: it is missing or cannot run offline. |
| `PREFLIGHT.LEAK_LOCK` | Look at alpha2.lock: it fails the leak check named in the receipt. |
| `PREFLIGHT.LEAK_HOSTS` | Look at alpha2.hosts: it fails the leak check named in the receipt. |
| `PREFLIGHT.PRIVATE_SOURCE` | Look at the private overlay checkout: a file is not from it, its working tree is not exactly the tagged commit's tree, a file's bytes differ from that tree, or the tagged commit does not meet the lock's overlay pin. |
| `PREFLIGHT.REPO_ACCESS` | Look at access to the repository named in the receipt. |
| `PREFLIGHT.FETCH` | Look at the work directory: a pinned commit was not fetched, or its pinned tag is not that commit. |
| `PREFLIGHT.TARGET_ACCESS` | Look at access to the target named in the receipt. |
| `PREFLIGHT.HUB_READ` | Look at the hub's read-only checks in the receipt. |
| `PREFLIGHT.OPERATOR_ROUTE` | Look at the operator's ssh route from the runner host to the target named in the receipt. |
| `PREFLIGHT.LIVE_DEPLOY` | Look at the work directory: it is the runner host's live deploy. |
| `PREFLIGHT.KEEP_AWAKE` | Look at the runner host's sleep settings: sleep is not shown disabled. |
| `PREFLIGHT.SURVEY` | Look at the survey in the receipt: an l3 target differs from the bare start state, or a loop target is not at its pinned snapshot. |
| `PREFLIGHT.HANDOFF` | Look at the stop file, the hypervisor's loop tasks and, for an L3 or bare install or a destroy, the hypervisor's L3 arm gate: one does not allow this run. |
| `PREFLIGHT.BUDGET` | Look at the loop's budget: the day's runs are used up, its account usage is not shown below the limit, the broker refused the start record, or budget.d could not be read. |
| `CREDENTIALS.CORE_LIMIT` | Look at the core-dump limit: it could not be set to zero. |
| `CREDENTIALS.NO_ECHO` | Look at the terminal: the prompt could not read without echo. |
| `CREDENTIALS.FORM` | Look at the value named by its form rule in the receipt: it is not well formed. |
| `CREDENTIALS.KEY_NOT_LIVE` | Look at the API key: the live check did not accept it. |
| `CREDENTIALS.LEAK_LOCK` | Look at alpha2.lock: it contains a value entered at the prompt. |
| `CREDENTIALS.LEAK_HOSTS` | Look at alpha2.hosts: it contains a value entered at the prompt. |
| `AGENTS.NO_START_PATH` | Look at the agent's start path named in the receipt: sandy's approvals, the credential or the sandbox image would not let it start. |
| `AGENTS.ADD_AGENT_AMBIGUOUS` | Look at alpha2.hosts: the agents named for this host do not pick exactly one agent to add. |
| `AGENTS.CONFIG_NOT_PLACED` | Look at S6's receipt for this VM and the VM's amap feature files: they are not placed, or differ from what S6 recorded. |
| `AGENTS.VM_ACCESS` | Look at access to the VM named in the receipt. |
| `AGENTS.WRITER` | Look at the credential writer on the VM: it refused or failed. |
| `AGENTS.IMAGE_BUILD` | Look at sandy's sandbox image build on the VM: it did not finish. |
| `AGENTS.SLUG_UNOBSERVED` | Look at sandy's state for the workspace: the sandbox name could not be read. |
| `AGENTS.SLUG_TOO_LONG` | Look at alpha2.hosts: an agent's id makes a sandbox name longer than the agent registry accepts. |
| `AGENTS.REGISTRY` | Look at the agent's registry entry on the VM named in the receipt: the registry program refused its import, or its read-back does not match. |
| `AGENTS.ROTATE_LEFTOVER` | Look at the VM's sandy secrets directory: a previous credential file is left from a rotation. |
| `AGENTS.SECRETS_TEMP_LEFTOVER` | Look at the VM's sandy secrets directory: a temporary credential file is left from an interrupted write. |
| `AGENTS.ROTATE_UNDONE` | Look at the rotation in the receipt: the new credential did not take, and the old one is back in force. |
| `AGENTS.ROTATE_UNSUPPORTED` | Look at the ALPHA-2 scope: key rotation is not supported in this release; rotate by hand. |

Sentences for the `VERIFY.*` names and for every other stage-specific name in
4.6 are added by that stage's review (S9 for `VERIFY.*`); until then those
names are not usable.

## 5. The runner

### 5.1 Launch line

The one line the operator's shell on the runner host runs (a.2, PROPOSED there; frozen with the
installer at D3):

```
/usr/bin/env -i HOME="$HOME" SSH_AUTH_SOCK="$SSH_AUTH_SOCK" TERM="$TERM" PATH=/usr/bin:/bin /usr/bin/python3 -I -B <installer checkout>/install/alpha2_install.py [flags]
```

The launch line starts the launcher (5.1a). Before the first stage, the
runner on every route, and first the launcher for a supported invocation,
refuse any other environment (`RUNNER.ENV`),
and the runner records the variable NAMES, never their values, in the run
manifest.

| Flags | Command | Writes |
|---|---|---|
| (none) | `install` | yes: S0 to S10 in order |
| `--dry-run` | `dry-run` | every stage's `plan`; only the run directory on the runner host |
| `--verify` | `verify` | only the run directory |
| `--verify --canary` | `canary` | one round trip between stand-in agents (E10); outside section 7's read-only list |
| `--add-agent <host> [--id <id>]` | `add-agent` | yes |
| `--rotate-key` | `rotate-key` | none in ALPHA-2: refused with `AGENTS.ROTATE_UNSUPPORTED` before any VM contact (PROPOSED, W8 r4); section 3.7 after ALPHA-2 |
| `--check-roundtrip <nonce>` | `check-roundtrip` | only the run directory |
| `--only <stage>`, `--from <stage>` | `install`, with `"loop": "L1"` | as the stages run; a stage set that includes S6 or later but not S3 is `RUNNER.STAGE_SET` |
| `--leak-run` | `install`, with `"loop": "L2-leak"` | the leak run of a.11: section 3.7 rule 3a; stops after the last secret writer |
| `--loop L2` or `--loop L3` | `install`, without `--only`, `--from` or `--leak-run` | records the loop in the manifest; apart from 5.3b (an L3 run targets the real VMs, runs only as the L3 runner account, does not read the stop file, and needs the hypervisor's L3 arm gate open) and 5.3c (the L2 count), it changes no behaviour; given together with `--only`, `--from` or `--leak-run`, or twice, it is `RUNNER.ARGS` |
| `--destroy` | `destroy` | deletes, through NET's program, only VMs in the pinned set that carry the installer's marker, inside an armed window, never one on either hard deny list (`destroy_deny`, 6.2, and the forced program's own, 9a), and never the hub (3.6, 9a; E25, section 1) |

Every supported invocation, the operator's and the loop's, starts through the launcher (5.1a). Every route, supported or not, must pass S0's admission (5.1a), and every run runs S0 first. The
commands that can write to a target, every command except `dry-run`,
`verify` and `check-roundtrip`, also have a broker record before the
runner starts; for a supported invocation the launcher obtains it from the
budget broker (5.3c), and S0 verifies it.

### 5.1a The launcher

The launch line starts the launcher, the installer's supported entry point.
It refuses early; S0 is the admission authority (below). The admitting
process of a run is the process that reads the private files, takes the
run's locks and, for a command that can write to a target, obtains its
broker record, before the runner starts; for a supported invocation it is
the launcher. For every command, in this order, the launcher:

1. refuses any other environment (`RUNNER.ENV`), reads `alpha2.lock` and
   `alpha2.hosts` once, and runs L1 to L4 on them (section 8);
2. reads its account from the kernel and refuses one its command does not
   allow (`RUNNER.ACCOUNT`, 5.3b); and, for an `install` whose `loop` is `L3`
   or `null`, and for `destroy`, reads the hypervisor's L3 arm gate (5.3b)
   before it takes any lock;
3. takes the locks of 5.3 (`runner.lock` first, for a command that can
   write to a target); for a command that writes no target, it mints the run
   id itself;
4. for a command that can write to a target, refuses while the stop file
   applies and is set (5.3b), reads through the S2 probe that the hypervisor reports no loop task (5.3b), and refuses with `PREFLIGHT.HANDOFF` otherwise, and then performs the admission of 5.3c, which
   ends with the start record published and fsynced by the budget broker;
5. execs the runner by absolute path under the launch line's environment,
   passing the run id the broker returned (5.3c), or that step 3 minted,
   with every lock descriptor kept open across the exec
   (5.3 step 5). If the exec fails in any way, the launcher releases its
   locks and refuses with `RUNNER.NOT_STARTED` (exit 2). For a command that
   can write to a target, the broker has published the run's start record,
   which stays counted and, under path (b), its permit spent (5.3c), and the
   terminal names the run id. No run directory exists.

A refusal in steps 1 to 4 is printed to the terminal only and leaves no run
directory, like the leak refusals of section 8.

**The runner is bound to its admission.** A runner that does not hold the
locks of its run, or, for a command that can write to a target, a valid broker record of its own account
bound to that run, refuses with `RUNNER.ADMISSION`, however it was started. Before it creates the run directory, S0
checks that the runner holds every lock descriptor of 5.3 for its run, the
lock set that `alpha2.hosts` and the command decide (5.3 step 1; custody
step 1, 5.3b). S0 reads its account from the kernel, as the launcher does, and refuses with `RUNNER.ACCOUNT` by the same rule (5.3b). Under path (a) of 5.3c, S0 reads the usage again and refuses with `PREFLIGHT.BUDGET` at 80% or more, or when it cannot be read.

**S0 is the admission authority; the launcher refuses early.** S0 re-checks
every condition the launcher checks, on its own reads, before any target
write: the environment (`RUNNER.ENV`); the account; 5.3 step 0, the lock
root's owner, mode and filesystem type included; L1 to L4 on both private
files; the stop file, the hypervisor's loop tasks and the L3 arm gate with
its remaining time (5.3b); and, under path (a), the usage. The count and the
permit are applied by the broker when it writes the record (5.3c), and S0
checks that record. A run that reaches S0 by any route therefore passes
every limit the launcher applies, or refuses. This binds the governed
installer, the reviewed bytes S0 checks by sha (`PREFLIGHT.INTERPRETER`,
`installer_sha256`). A process of a runner account that does not run the
installer is not governed by the budget at all; it is bounded by its key's
forced program (9a), which no admission step can widen or narrow. For a command that can write to a target, S0 also checks that the subdirectory of `budget.d` for its own account (`loop` or `l3`) holds the start record named by that run id, read under the rules of 5.3c, whose `command` and `loop` equal its own, and whose
`lock_sha256` and `hosts_sha256` equal the sha256 of the two files it reads.
The run directory for that run id must not exist (`RUNNER.RUN_DIR`), so one
start record admits one run. For such a command, S0 also refuses with `RUNNER.ADMISSION` a start record whose `started_at` is more than 60 seconds before the runner host's UTC clock when S0 begins, or is after it. The record's `installer_sha256` must equal the runner's own `INSTALLER_SHA`; the launcher is one of the installer files approved by sha at D3. S0 verifies the start record; it never
publishes one. S0 records the start record's sha256 in its receipt as
`ADMISSION_SHA`.

The launcher's review tests include, at least: a runner started directly
without the held locks of its run, or, for a command that can write to a target, without a valid broker
record of its own account, refuses with `RUNNER.ADMISSION`; a runner whose
inherited lock descriptor was closed across the exec refuses with
`RUNNER.ADMISSION` (Python opens descriptors non-inheritable by default, so
the launcher makes each lock descriptor inheritable explicitly); and, for a command that can write to a target, a failed
exec leaves its start record counted and its permit spent. They also include a direct-path test: for each condition S0 re-checks, a process of the runner account that takes the lock files itself, calls the broker itself for a command that can write to a target, and execs the runner with that condition failing is refused at S0, before any target write. And a `destroy` whose targets include a `loop` VM refuses with `RUNNER.TARGET_LOCKED` while a test process holds only that VM's `name` and `vm:<vm_id>` lock files, not the hypervisor's.

### 5.2 Run directory

Each run gets a new directory under the work directory in `HOME`, never reused:

```
<work>/runs/<run-id>/
  manifest.json            section 6.3
  receipts/<stage-id>-<host or ->.txt
  SUMS                     section 5.4
  summary.txt              S10
```

`<run-id>` is `YYYYMMDDTHHMMSSZ-<8 hex>`. The work directory is outside every
sandbox mount, and is not the runner host's live deploy (`PREFLIGHT.LIVE_DEPLOY`).

`<work>` and `<work>/runs` exist before the first run of each runner account
(section 9, D2): real directories, not symlinks, owned by that account, mode
0700. The runner creates neither. It opens `<work>` by its fixed path under
the account's `HOME`, then `runs` relative to the `<work>` descriptor, each
without following a symlink, checks each, and creates `<run-id>` and its
`receipts` relative to the opened `runs` directory, never through a path
resolved again. Anything else is
`RUNNER.RUN_DIR`.

### 5.3 Target locks

One kernel lock per TARGET name, by this algorithm:

0. The admitting process (5.1a; the launcher, for a supported invocation)
   verifies `runner.host_id` and `runner.lock_root` from `alpha2.hosts`
   (section 6.2) before it acquires any lock, and S0 verifies them again: the host's
   identity, read as the S0 review fixes, equals `runner.host_id`, and the
   realpath of `runner.lock_root` equals that string and is an existing
   directory owned by root with mode 0755, and no parent of it is writable by
   either runner account. Either difference refuses with `RUNNER.LOCK_ROOT`.
   Both runner accounts use that one lock root; `HOME` does not select it.
1. The targets are `hypervisor.name`, `hub.name`, the `name` of every VM of
   the run (6.2, 5.3b; for `destroy`, every `vms[]` entry of either scope not on the hard deny list `destroy_deny`, decided from `alpha2.hosts` alone; a `destroy` whose `alpha2.hosts` has no `destroy_deny` refuses with `RUNNER.DESTROY_DENY` before any lock), and `vm:<vm_id>` for each of them, and, for a run with any `loop` VM, `hub_loop.name` and `vm:<hub_loop.vm_id>` (the loop restores hub-t with its VMs), from the
   in-memory `alpha2.hosts`
   after that file has passed L1 to L4 (section 8); no name is hashed or used
   before then. A duplicated target refuses the run (`RUNNER.HOSTS_TARGETS`).
   The targets are sorted by UTF-8 byte order.
2. Each target's key is the lowercase hex sha256 of the target's UTF-8 bytes
   followed by one LF. Its lock path is `<runner.lock_root>/<target-key>.lock`.
3. Before the run directory is created, the admitting process opens each lock file in
   that order read-only (`O_RDONLY|O_NOFOLLOW`, never creating it) and takes a
   non-blocking exclusive advisory lock (`flock`) on each, all or nothing. If
   any lock is held, it releases what it took and refuses with
   `RUNNER.TARGET_LOCKED`; the message names the target, never a holder. A
   lock file that is missing, is not a regular file, or is not owned by root
   with mode 0644 refuses with `RUNNER.LOCK_ROOT`.
   3a. A run that can write to a target also takes, first and with the same all-or-nothing rule, a non-blocking exclusive `flock` on the fixed file `<runner.lock_root>/runner.lock`, and keeps it with its target locks. The budget read, the permit check and the start-record write of 5.3c happen only while it is held.
4. The lock files are created once by the operator (D2b), one per target
   key and one `runner.lock`, owned by root with mode 0644, in the root-owned
   lock root. Neither runner account can create, write, replace or remove
   one; both can open one read-only and `flock` it, so a run of either
   account excludes a run of the other. The admitting process writes nothing
   in a lock file. A runner account can still hold a lock, which is the exclusion
   itself: a held lock refuses the other run (`RUNNER.TARGET_LOCKED`), and
   never admits it. The lock root is on a local filesystem of the runner host (not NFS or CIFS, where an exclusive lock on a read-only descriptor fails); the admitting process, and again S0, check the filesystem type against an allow-list of local types that the S0 review names, and refuse with `RUNNER.LOCK_ROOT` otherwise. Holding a lock lets one account deny the other's run, including by a process that admits no run and holds a lock indefinitely. That is fail-closed and availability only: a held lock never admits a run, and no account can spoof, replace or release another's lock. This residual is accepted by the operator (section 1, lock-denial and budget-scope residuals), and direct `flock` stays. On `RUNNER.TARGET_LOCKED` that it did not expect, the operator, as root, finds the holder with `lslocks` and stops that account's processes.
5. The descriptors are opened without close-on-exec, and the runner inherits
   them across the admitting process's exec (the launcher's, for a supported
   invocation); they are never closed and taken again.
   The runner keeps them until the final `SUMS` line and the summary are
   written. Release happens only by explicit close on every normal exit, or
   by the kernel when the process dies. Every child that can touch a target is started so that it dies with the runner (Linux `PR_SET_PDEATHSIG`, or its own process group that the runner kills on every exit path), and every remote command runs under a bound the stage review states.
6. No command unlinks, breaks or removes a lock file. A lock file whose lock
   is not held is reusable whatever it contains; its presence alone never
   means "held".

These locks are local to the runner host. They exclude a second run on the
same host that names the same target. Every run runs on the one runner host
and reads the one `alpha2.hosts` (5.3b), so these locks are the exclusion
between any two runs, of either runner account, the final run (L3) and the
loop's runs included. One file means one key per target, and one key for
the hypervisor, which every run takes.

### 5.3b One runner host: the final run, the stop file and custody

Every run, that is L1, L2, the L2-leak run and the final run (L3), runs on
the one runner host that `runner` names in the one `alpha2.hosts` (6.2,
E12 (C)). S0 reads `alpha2.hosts` only from the one absolute path fixed in the installer's code at the S0 review, inside the private overlay checkout, and refuses a hosts file named any other way (`PREFLIGHT.PRIVATE_SOURCE`). The launcher reads it by the same rule.

**Two VM scopes.** Each `vms[]` entry has a `scope` (6.2): `loop` for the
loop's test VMs, `l3` for the real VMs that the final run rebuilds from bare
(E1, E2). A command run as the L3 runner account acts only on the `l3`
VMs, except `destroy`, which acts on VMs of either scope within the limits
of 9a; a command run as the loop runner account acts only on the `loop` VMs
and on `hub_loop` (hub-t), which it restores with them as `loop_restore_set` (E1, E3; 3.6)
(the two accounts, below). The loop never touches an `l3` VM: no command run
as the loop runner account names one, and its key's forced program refuses them
([OPEN: apply credentials design, NET]). A run's VMs are the entries of its
scope; for `destroy`, they are every `vms[]` entry of either scope not on the hard deny list `destroy_deny` (6.2), decided from `alpha2.hosts` alone before any lock, and its lock targets (5.3 step 1) and its placement check (custody step 2) cover all of them, all or nothing. `destroy` deletes no VM that is not one of its locked entries; 9a's runtime limits (marker, armed window) then narrow what it deletes, never what it locks. Wherever this contract says a VM or an agent of `alpha2.hosts`, it
means one of the run's.

No key or agent socket that the loop runner account can read is authorized on an `l3` VM. The L3 run installs on each `l3` VM only access keys held under the L3 runner account's home (or the operator's own, E20), never a key shared with `loop` VMs. NET's host verifier proves, as the loop runner account, that an ssh to each `l3` VM's address is refused, before D4 and again after the final run's PASS.

**Two runner accounts (Q0b (iii)).** Two accounts on the runner host run the
installer, both named in `runner` (6.2): the loop runner account and the L3
runner account. S0 on every route, and first the launcher for a supported invocation, read the account from the kernel (real and
effective uid, never the environment) and refuses with `RUNNER.ACCOUNT`
unless it is one of the two, and unless:
- an `install` whose `loop` is `L3` or `null` runs as the L3 runner account;
- an `install` whose `loop` is `L1`, `L2` or `L2-leak` runs as the loop
  runner account;
- `destroy` runs as the L3 runner account.
The operator starts the final run as the L3 runner account through the reviewed line `sudo -u <L3 runner account> -H -- /usr/bin/env -i HOME=<the L3 runner account's home> SSH_AUTH_SOCK= TERM="$TERM" PATH=/usr/bin:/bin /usr/bin/python3 -I -B <installer checkout>/install/alpha2_install.py --loop L3`. `HOME` is a literal fixed with the line, never the operator's `$HOME`, and `SSH_AUTH_SOCK` is empty: the L3 run reaches its targets only with the L3 key (9a), never through the operator's agent. `destroy` runs through the matching line with `--destroy` in place of `--loop L3`. The exact text of both lines is fixed with the launch line at D3 [OPEN: D3 launch paths]. The L3 key belongs to the L3 runner account, and
the loop runner account cannot read it (9a). Because an `L3` or bare
`install` runs only as the L3 runner account, the loop cannot start one,
inside an armed window or outside it.

**Integrity of what the L3 runner account runs.** The launcher, the
installer checkout and the interpreter it runs, `alpha2.hosts`,
`alpha2.lock`, and every other file an L3 run reads are owned by root or by
the L3 runner account, and neither they nor any parent directory is
writable by the loop runner account. Once D3 freezes the paths, NET's host
verifier proves this while running as the loop runner account: a write test
is refused on each path and on each parent. Until then the paths are
[OPEN: D3 launch paths]. D4 does not start without that proof (section 9).
The loop runner account also has no sudo rule, no access to the container runtime socket, and no group, ACL or capability that reaches the L3 runner account's files. The L3 run's installer checkout is its own copy, frozen at D3, and is not the loop's working checkout. `alpha2.hosts` and `alpha2.lock` at their one fixed path are likewise not writable by the loop runner account, so a change to them during the loop goes through the operator.

Exclusion between any two runs is the target locks of 5.3. One file gives
each target one spelling, so each target has one key, and the hypervisor
has one lock that every run takes. A run holds its locks from before
its runner starts (for a supported invocation, the launcher takes them, 5.1a) until its final `SUMS` line, so no other run can write to a target between two of its
stages.

**Hypervisor identity.** S0 reads the hypervisor's identity back through its
read-only probe ([OPEN: S2 review]) and records it as `HYPERVISOR_ID` (the
`host_id` pattern). The placement read-back below is made on that identity.

**Leftover loop tasks.** Every command that can write to a target, an
`install` whose `loop` is `L3` or `null` included, refuses at S0 on every
route, and first at the launcher for a supported invocation (5.1a step 4),
with `PREFLIGHT.HANDOFF` unless, with its 5.3 locks held, it reads through the
same probe that the hypervisor reports no task in progress under the loop
identity (E3, D2). A report that cannot be read is `UNOBSERVED` and refuses.
The locks already exclude a live run; this check covers a task that a
killed run left in progress on the hypervisor.

**The L3 arm gate (apply credentials A).** An `install` whose `loop` is
`L3` or `null` is the operator's run. It refuses with `PREFLIGHT.HANDOFF`,
at S0 on every route, and first at the launcher before it takes any lock for
a supported invocation, unless the
hypervisor's L3 arm gate reads open and, for an `install`, the gate's
remaining time is at least the bound the S2 review states for a full run.
`destroy` also refuses with `PREFLIGHT.HANDOFF` at S0 on every route, and
first at the launcher for a supported invocation, unless the gate reads open; unlike the operator's run, it still reads the
stop file. The L3 forced program refuses every verb outside the armed
window, which is the third check of the gate (9a). The gate is the hypervisor's L3 arm
file: a root-owned file that the operator sets in an admin session of their
own and that expires after a bounded time (about four hours). It is read
through NET's read-only probe, whose verb is [OPEN: S2 review]. A gate that
is absent, expired or cannot be read is not open; a read that cannot be made
is `UNOBSERVED` and refuses. No key or account of the loop identity can create, extend or change the arm file: no forced program offers such a verb, and the loop identity has no other route to the hypervisor's root. [OPEN: apply credentials design, NET] shows this, and the S2 review checks it.

**The stop file (E19).** The stop file is the loop's kill switch. It applies
to every command that can write to a target, that is, every command except
`dry-run`, `verify` and `check-roundtrip`, with one exception: an `install`
whose `loop` is `L3` or `null` does not read it, and needs the L3 arm gate
instead. Every other command reads the stop file whichever account runs it. The stop file is a
directory `stop.d` in the lock root (5.3), with one subdirectory per setter
role: `operator`, `controller` and `monitor`. It is set when any of those
subdirectories holds an entry (names beginning with a dot included), or when
`stop.d` holds any entry other than the three subdirectories. The only
entries that are not stops are the monitor's usage permit,
`stop.d/monitor/permit.json`, and its replacement file
`stop.d/monitor/.permit-next.json`, each only while it is a regular file
(5.3c, path (b)). `stop.d` or a subdirectory that is missing or cannot be
read also counts as set (fail closed). A read-back that returns no explicit
listing of all three subdirectories is `UNOBSERVED`; an empty output never
reads as unset.

A run the stop file applies to refuses at S0 with `PREFLIGHT.HANDOFF` while
it is set. Once the run has passed S0, it stops at its next stage boundary
when the stop file is set (custody, below). The runner never sets or clears
the stop file, and writes nothing in `stop.d`.

A setter sets its stop by adding a file to its own subdirectory, and clears
its part by removing that file. The controller and the monitor each reach
only their own subdirectory, through a read-write bind mount into their
sandbox that the operator sets up once (section 9).
The monitor's stop authority has this scope:

- it writes only in its own subdirectory, `stop.d/monitor` (its stop file
  and, under path (b) of 5.3c, its permit), and never removes or edits
  another setter's file;
- it sets a stop only on a measured safety condition, quoted in the stop
  file: a leak in a run's output, a lock or placement violation, a runner
  acting outside this contract, or the usage limit of 5.3c reached with no
  stop set;
- it reports every set and every clear to the operator and the controller in
  the same step, with the evidence;
- it clears only its own stop file, and only once the condition is measured
  gone, or on the operator's word.

Until the D2b mount exists, the monitor cannot write in `stop.d`, and this
authority has no effect.

**Custody is measured, never assumed (K19: lock and placement).** The
runner, not a stage and not the operator, reads custody back at every stage
boundary: at S0 once the locks are taken, and again before each later stage
starts, S1 to S10. A command whose target writes are not inside S1 to S10
reads custody back again immediately before its first target write. It
reads back:

1. Lock: for every target, and for `runner.lock` where 5.3 step 3a takes it, the descriptor it holds from 5.3 is still open; a
   non-blocking exclusive `flock` on it still succeeds; and the inode at the
   lock path is the descriptor's inode, still owned by root with mode 0644.
2. Placement, through the hypervisor's read-only probe (the one
   `PREFLIGHT.TARGET_ACCESS` uses), on the hypervisor whose measured
   identity is the `HYPERVISOR_ID` S0 recorded: for each `vms[]` entry, the
   object at its `vm_id`, if any, has its `name`, and that `name`, if present
   on the hypervisor, is at its `vm_id` and nowhere else. Presence is
   checked against the expected set for the stage. S0 records what it
   observed as `PLACEMENT_BASELINE`: the sha256 of one line per entry,
   `name SP vm_id SP present-or-absent LF`, sorted by name. Before S2 has
   ended with rc 0 in this run (or in its verified source run, 3.3), an
   entry may be absent only if the baseline recorded it absent. After that,
   every entry must be present. A command that runs no S2 expects the
   presence S0 recorded, except that `destroy` expects each VM it has
   deleted to be absent. Missing, extra (a second object with an entry's
   name), moved, or on a different identity is `differs`; an answer that
   cannot be read is `UNOBSERVED`.
3. Stop, for a command the stop file applies to: the stop file, read as S0
   read it. It must be unset.

The receipt of S0 and of each later stage carries the read-back as facts.
A stage with one receipt per host carries the same values in each:

- `CUSTODY_LOCKS`: `held`, `lost` or `UNOBSERVED`;
- `CUSTODY_PLACEMENT`: `match`, `differs` or `UNOBSERVED`;
- `CUSTODY_STOP`: `set`, `unset` or `UNOBSERVED`, or `-` when step 3 does
  not apply.

Any answer other than `held`, `match` and `unset` (or `-` where it applies)
is a mismatch. A read-back that could not be made is `UNOBSERVED`, and that
is a mismatch too, never a pass. On a mismatch the stage does not start: the
runner writes that stage's receipt with `RESULT=FAIL` and stops the run. At
S0 a set or `UNOBSERVED` stop file is `PREFLIGHT.HANDOFF`. Every other
mismatch, at any boundary, is `RUNNER.CUSTODY`. This is also how the stop
file stops a run in progress: once the stop file is set, that run stops at
its next stage boundary. That stop is the expected exit for a drain
(`RUNNER.CUSTODY`, rc 3 once the run has written), not an incident.

### 5.3c The loop's budget (E19)

Every run that can write to a target, the final run (L3) included, runs on
the loop's own subscription account, through a setup token. At most 12 L2
runs (`loop` `L2` or `L2-leak`) start per UTC day. They are counted from the
durable start records below whose `loop` is `L2` or `L2-leak` and whose
`started_at` falls on that UTC day, including the records in every
`budget.d.<utc>` set aside (section 9), never from an in-memory
counter. A count that cannot be made refuses. No run that can write to a
target starts while that account's 7-day usage is at or above 80%. Which of
two paths measures usage is [OPEN: usage read-back measured]:

- (a) The runner reads the account's usage before each run without a
  person present. A usage read that cannot be made counts as 80% or more.
- (b) If usage cannot be read that way, launches default to stopped. The
  monitor grants a launch window by writing a permit, `permit.json`, in its
  own `stop.d/monitor`: a closed record with `kind` `permit`, `permit_id`
  (`^[0-9a-f]{32}$`, new for every permit), `observed_percent` (an integer
  from 0 to 79), `observed_at` and
  `expires_at` (`utc`, with `expires_at` no more than 60 minutes after
  `observed_at`). The permit is current only while the runner host's
  UTC clock is at or after `observed_at` and before `expires_at`. A permit
  that is missing, unreadable, malformed or not current counts as 80% or
  more. A permit grants one launch only: the run it admits records its
  `permit_id` in its start record, and a permit whose `permit_id` appears in
  any start record, in `budget.d` or in any `budget.d.<utc>` set aside
  (section 9), grants nothing. The monitor writes each new permit from a
  fresh reading below 80%; the expiry stays as an extra limit, never as
  leave for a second launch. When a reading shows 80% or more, or the monitor cannot make a reading (treated as 80% or more), the monitor first sets its stop (a file in `stop.d/monitor` other than `permit.json`) and then removes `permit.json`. It writes no permit while its stop is set, and it clears its stop only after a reading below 80%. A run in progress that the stop file applies to therefore stops at its next stage boundary (5.3b). `permit.json` is not a stop entry
  (5.3b). The monitor writes a new permit as `.permit-next.json` in `stop.d/monitor`, fsyncs it, and renames it over `permit.json`. `.permit-next.json` is not a stop entry either. Either name that is not a regular file is a stop entry. A permit read while it is being replaced, or a `.permit-next.json` read as a permit, grants nothing. A permit is written only from a reading of the loop runner's subscription account (above), never of another account; who reads that account and how the reading reaches the monitor are [OPEN: usage read-back measured]. Until a reading reaches it, the monitor writes no permit, and no run that can write to a target starts.

**Start records.** Every run that can write to a target has one start
record in a directory `budget.d` in the lock root, beside `stop.d`.
`budget.d` holds one subdirectory per runner account, `loop` and `l3`.
`budget.d`, both subdirectories and every record in them are owned by root
(directories 0755, records 0644), so neither runner account can create,
rewrite, rename or remove a record, in its own subdirectory or the other's.

**The budget broker.** Records are written only by the budget broker: a
root-owned program on the runner host, reached over a local Unix socket at a
fixed path in the lock root [OPEN: budget broker, DS]. The broker identifies
its caller from the kernel (`SO_PEERCRED`), refuses any caller that is not
one of the two runner accounts, and writes only in the caller's own
subdirectory. For each request, in one step under its own lock, it:
1. reads every record in `budget.d` and in every `budget.d.<utc>`, by the
   read rules below, and refuses if the read is `UNOBSERVED`;
2. refuses an `install` with `loop` `L2` or `L2-leak` once the day's count is
   12;
3. under path (b), reads `stop.d/monitor/permit.json` itself and refuses
   unless that permit is current and its `permit_id` is named in no record;
4. otherwise mints the `run_id` itself (the `run_id` pattern, its time part
   from its own clock), sets `started_at` from the same clock, publishes the
   record under the publication rule below, and returns the `run_id` and the
   record's sha256. A caller never chooses a `run_id`.
The broker never edits or removes a record. A request it cannot complete
refuses. The launcher and the runner only read `budget.d`. Under path (a),
the broker does not read usage; S0 reads it (5.1a).

A request carries exactly `command`, `loop`, `lock_sha256`, `hosts_sha256` and `installer_sha256`; the broker refuses a request with any other key, and sets `kind` (the constant `start`), `run_id`, `started_at` and `permit_id` itself. It refuses a request whose `command` writes no target (`dry-run`, `verify`, `check-roundtrip`). Before it publishes, the broker validates the record it built against the record schema below. It refuses a `command` or `loop` that the caller's account may not run (5.3b), and refuses if the `run_id` it minted is already named by any record in `budget.d` or in any `budget.d.<utc>`. It opens `permit.json` with `O_NOFOLLOW|O_NONBLOCK`, accepts only a regular file of bounded size, and otherwise treats the permit as not current. It runs in the runner host's initial user namespace, identifies its caller by the uid of `SO_PEERCRED` only (never the pid), authorises on the credentials captured at connect and ignores `SCM_CREDENTIALS`, and serves one request for each connection. The socket is in the lock root, owned by root, and the launcher checks before it sends a request that the socket and the peer's `SO_PEERCRED` uid are root. The broker answers with an explicit refusal only before it has placed any record under its final name. A failure after that point is never answered as a refusal: the broker closes the connection without an answer, which the launcher maps to `RUNNER.NOT_STARTED`. The boundary between the two causes is whether any byte of the request was sent. Before any is sent (a socket that cannot be reached or fails its owner or peer check), and on a well-formed explicit refusal from the broker, which establishes that no record was published, the launcher refuses with `PREFLIGHT.BUDGET`. Once any byte of the request has been sent, any timeout, including one past the answer bound the broker review states, and any lost, late or malformed answer, has an unknown outcome: the launcher refuses with `RUNNER.NOT_STARTED`, whether or not the record was published, and the run counts if it was. The launcher's broker socket is close-on-exec and is not inherited by the runner. The broker also refuses a request beyond a per-account ceiling of records per UTC day that the broker review states, so that direct calls cannot grow `budget.d` without bound.

**Publication.** A start record is one file holding one JSON object, written to a temporary file whose name begins with `.tmp-`, fsynced, and then placed under its final name by an operation that fails if that name exists (`link(2)` followed by unlinking the temporary file, or `renameat2` with `RENAME_NOREPLACE`; a plain `rename` replaces and is not allowed). The directory is then fsynced. A record counts as written only once all of these have returned success. The final name is `start-<run_id>.json`. Readers ignore names beginning with `.tmp-`. Records are only added, never edited or removed.

**Record schema.** A start record is closed (section 8 L1 to L3 apply) and
has exactly these keys, all required: `kind`, the constant `start`;
`run_id`, the `run_id` pattern, equal to the `<run_id>` in its file name;
`command`, an enum of the commands of 5.1; `loop`, enum `L1`, `L2`,
`L2-leak`, `L3`, or `-` for `null`; `started_at`, `utc`; `lock_sha256` and
`hosts_sha256`, each `sha256`, of the two files the admitting process read
(the launcher, for a supported invocation); `installer_sha256`, `sha256`, of
the installer the admitting process runs; and
`permit_id`, `^[0-9a-f]{32}$`, or `-` for a run no permit admitted.

**A read of `budget.d`** lists every name in both subdirectories and reads
every record. The count is `UNOBSERVED`, and refuses, when `budget.d` holds
any name other than the two subdirectories, when a name in a subdirectory
that does not begin with `.tmp-` is not of the form `start-<run_id>.json` or
is not a regular file, or when a record does not parse, breaks its schema,
or disagrees with its name, or when one `run_id` names a record in both subdirectories, or when a record is not a regular file owned by root with mode 0644 and one link. A `budget.d`, or a subdirectory of it, that is missing, is not a directory, is not owned by root with mode 0755, has an ACL or group write, or cannot be listed is `UNOBSERVED`. Neither the broker, the launcher nor the runner creates it.

A `budget.d.<utc>` (section 9) is read by the same rules, except that an entry that fails them is not `UNOBSERVED`. It counts as one `L2` start on the UTC day of its name's `run_id` (or of `<utc>` if the name does not parse), and under path (b) any permit that was current at `<utc>` (`observed_at <= <utc> < expires_at`) grants nothing. Every `budget.d.<utc>` is read, whatever its day; the count keeps only records whose `started_at` falls on the day being counted. `<utc>` is the `utc` pattern (the section 9 operator line renames with `date -u +%Y-%m-%dT%H:%M:%SZ`, under `flock <lock_root>/budget.d`); a `budget.d.*` name that is not that pattern, a `<utc>` that is not a real date, a set-aside that cannot be listed, or a `loop` or `l3` inside one that is not a directory refuses, because its count cannot be made; a missing subdirectory counts nothing, and any other name at its top counts as one `L2` start on the set-aside's day. The per-account ceiling of start records per UTC day is 32, counted in the live `budget.d` only.

**Admission, before launch.** For a supported invocation, the launcher
(5.1a) enforces both limits before the runner exists. While it holds `runner.lock` and the target locks
of 5.3 (which include the hypervisor, so two admissions never count at
once), it refuses with `PREFLIGHT.BUDGET` any run that can write to a target
at 80% or more by path (a), and then asks the broker to admit the run. A
broker refusal (the day's count, the permit of path (b), or an `UNOBSERVED`
read) is `PREFLIGHT.BUDGET`. On the broker's success the run's start record
is published and fsynced, which spends the permit, and only then does the
launcher exec the runner, with no gap in the locks (5.3 step 5). A runner account that calls the broker without the launcher, and then starts the runner itself with locks it took itself, gains no run that the launcher would refuse. The broker applies the count and the permit. S0 re-checks the account (5.1a), the stop file, the hypervisor's loop tasks and the arm gate (5.3b). Under path (a), S0 also reads the account's usage again, and refuses with `PREFLIGHT.BUDGET` at 80% or more or when the read cannot be made. An extra record only uses up budget. A runner account can also deny the other's run through the broker, by spending the current path (b) permit. That is fail-closed and availability only, and the monitor's next permit recovers it. It falls under the same operator acceptance as the lock-denial residual (section 1, 5.3 step 4). The start record is the charge: a run is
counted from the moment it is written, whether or not the exec succeeds or
the run passes. A failed exec consumes the start and the permit (fail
closed); so does a runner that dies before it creates its run directory,
because a start record older than 60 seconds admits no runner (5.1a). A
start-record write whose outcome is unknown refuses with
`RUNNER.NOT_STARTED`, and the run counts if the record was written. An admitting process that ends before its start record is written has started no runner and has written nothing to any target, and is not a run for the budget. The loop starts every run through this launcher. A start of a command that can write to a target without the held locks and a valid broker record of its own account refuses (`RUNNER.ADMISSION`, 5.1a); a start that has both still passes S0's admission, and so every limit above. S0 verifies the start record and never writes one.

### 5.3a Sleep (A2-16)

The runner host does not sleep (E12 (C)). S0 reads, through a read-only
probe of the runner host's power settings, that sleep is disabled, and
refuses with `PREFLIGHT.KEEP_AWAKE` otherwise. A probe that cannot be read
refuses too. The probe is [OPEN: sleep probe measured]. If the S0 review
finds no read-only probe, the cause is removed and the fact is recorded in
section 1 instead.

### 5.4 SUMS chain

`SUMS` has one line per file, in the order the files were finalized: every receipt, then `manifest.json` in its final state (section 6.3), then `summary.txt`.

```
sums-line = n SP file-digest SP prev-digest SP path LF
n         = "1" / %x31-39 *DIGIT          ; base 10, no leading zero, consecutive from 1
file-digest, prev-digest = 64 lowercase hex
path      = receipt-path / "manifest.json" / "summary.txt"
```

- Lines are ASCII, exactly four fields separated by one SP, each terminated by
  one LF. The final `SUMS` file has no other bytes.
- `prev-digest` is the sha256 of the complete preceding line including its
  LF, or 64 zeros on line 1.
- `receipt-path` is exactly the pathname form of section 3.3. It contains no
  `..`, and every path occurs once.
- Each file is finalized atomically (temp, fsync, rename) before its line is
  appended, and `SUMS` is fsynced after each append.
- `RUNNER.SUMS` is emitted when any line fails to recompute or to parse, a
  number is missing, a path repeats, or a listed file is absent. A file in
  the run directory that `SUMS` does not list, other than `SUMS` itself, also
  fails verification.
- No file in the run directory contains the sha of `SUMS`. S10 prints that
  sha to the terminal after `SUMS` is final (section 5.5).

The run's identity for approval (E7 (a)) is the sha256 of the final `SUMS` file. A SUMS sha is ELIGIBLE for approval only if the verifier, reading the run directory and the `alpha2.hosts` bytes whose sha256 equals the manifest's `hosts_sha256` (and nothing else), finds all of the following:
- the last two lines of `SUMS` are `manifest.json` and then `summary.txt`, and the receipt lines are exactly the manifest's `stages[]`, in order, with equal digests;
- `manifest.json` has `command` `install` and `loop` either `null` or `L3`;
- `manifest.json` has `source_run` `null` and `state` `final`;
- every stage S0 to S10 has a receipt for every host it applies to in `alpha2.hosts`, each with `rc=0` and `RESULT` in `CHANGED`, `ALREADY` or `PASS`, and no `UNOBSERVED` fact;
- every receipt's `INSTALLER_SHA`, `LOCK_SHA` and `HOSTS_SHA` equal the manifest's;
- S9 includes the processing proof (7.2).

A `dry-run`, `verify`, `canary`, `L1`, `L2-leak`, or `--only`/`--from` run is never eligible, whatever its rc. S10's summary prints `ELIGIBLE` or `NOT ELIGIBLE: <reason>`.

An `--only`/`--from` run names, by run id, the earlier run directory it takes predecessors from. It verifies that run's `SUMS` first and records the source run id and that SUMS sha in its own manifest.

### 5.5 S10 `SUMMARY`

One PASS/FAIL block; each stage, host and rc, with the first cause if any;
the run directory; the lock sha; the agent addresses; the
exact ssh line or host alias for each VM, for use from the runner host (E20); the three operator steps and
the round-trip prompt with a fresh nonce filled in; and the word INFERRED
beside anything not proven, and `ELIGIBLE` or `NOT ELIGIBLE: <reason>`
(section 5.4). For an L2 or L3 run it also prints the RL per-run reply-depth
check as a per-run evidence item (E13) [OPEN: RL reply-depth check]. Until the slot is filled it prints `UNMEASURED`, and it does not change `ELIGIBLE`. It prints no fact a receipt may not carry. `summary.txt` is
the last file in `SUMS`; the SUMS sha itself is printed to the terminal only,
after `SUMS` is final, because a file inside the chain cannot carry the
chain's own hash.

## 6. Formats of the private files

These schemas are NORMATIVE. All three
files are JSON (RFC 8259), UTF-8 without a BOM, parsed with duplicate keys
refused and no `NaN`/`Infinity` (section 8 L1). Every object is CLOSED: a
key not listed for that object is refused (L2). The examples are
illustrations; the tables govern.

Table columns: **Req** is `R` (required) or `O` (optional; when absent the
rule in the last column applies). **Type** is a JSON type. **Value** is a
pattern from 6.0, a constant or an enum; a string MUST match it in full
(L3). Every array listed `≥1` is non-empty; `unique` means no two items
share that key's value.

### 6.0 Patterns

| Name | Pattern |
|---|---|
| `sha256` | `^[0-9a-f]{64}$` |
| `commit` | `^[0-9a-f]{40}$` |
| `image_id` | `^sha256:[0-9a-f]{64}$` |
| `name` | `^[a-z][a-z0-9-]{0,62}$` |
| `vm_id` | `^[0-9]{1,9}$` |
| `domain` | `^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$` |
| `repo_url` | the regex in the fenced block below this table. No password, no query, no fragment. `git@` is the only userinfo allowed |
| `relpath` | `^[A-Za-z0-9._-]{1,100}(/[A-Za-z0-9._-]{1,100}){0,15}$`, with no segment equal to `.` or `..` |
| `abspath` | `^/[A-Za-z0-9._+-]{1,100}(/[A-Za-z0-9._+-]{1,100}){0,15}$`, with no segment equal to `.` or `..` |
| `plugin_api` | `^[0-9]{1,4}\.[0-9]{1,4}$` |
| `py_version` | `^3\.[0-9]{1,2}\.[0-9]{1,3}$` |
| `utc` | `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$` |
| `run_id` | `^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$` |
| `rc_tag` | `^alpha2-rc[1-9][0-9]{0,3}$` |
| `host_id` | `^[A-Za-z0-9-]{8,64}$` |
| `stage_id` | one of `S0`, `S1`, `S2`, `S3`, `S4`, `S5`, `S6`, `S6b`, `S7`, `S8`, `S9`, `S10` |
| `receipt_path` | `receipts/<stage_id>-<name or ->.txt`, exactly as section 3.3 |

`repo_url`, as raw regex bytes (the `|` is alternation):

```regex
^(ssh://git@[a-z0-9.-]{1,253}(:[0-9]{1,5})?/[A-Za-z0-9._/-]{1,200}|https://[a-z0-9.-]{1,253}/[A-Za-z0-9._/-]{1,200})$
```

No pattern in a table cell contains a `|`; any regex that needs one is given in a fenced block.

### 6.1 `alpha2.lock`

The only place a pin lives (A2-10). Written by reviewed changes only (E5 (a));
never by a run.

```json
{
  "schema": "alpha2.lock/1",
  "installer": { "repo": "<repo_url>", "commit": "<commit>",
                 "entry": "install/alpha2_install.py", "sha256": "<sha256 of install/MANIFEST>" },
  "interpreter": { "path": "/usr/bin/python3", "sha256": "<sha256>",
                   "resolved_path": "<abspath>", "resolved_sha256": "<sha256>", "version": "<py_version>" },
  "overlay": { "repo": "<repo_url>", "commit": "<commit>", "tag": "<rc_tag>" },
  "components": [ { "name": "<name>", "repo": "<repo_url>", "commit": "<commit>", "tag": "<rc_tag>" } ],
  "images": [ { "name": "<name>", "built_from": "<component name>", "image_id": "<image_id>" } ],
  "files": [ { "path": "<relpath>", "component": "<component name>", "sha256": "<sha256>" } ],
  "writers": [ { "use": "api_key", "path": "<relpath>", "sha256": "<sha256>" },
               { "use": "hub_login", "path": "<relpath>", "sha256": "<sha256>" } ],
  "plugin": { "sha256": "<sha256>", "plugin_api": "<plugin_api>" },
  "d7_source": { "sha256": "<sha256>" },
  "vm_template": { "name": "<name>" },
  "hub_login": { "local": "<login_part>", "domain": "<login_domain>" },
  "registry_program": { "package": "<pkg_name>", "config_schema": "<iface_token>",
                        "adapter_interface": "<iface_token>", "component": "<name>" }
}
```

**Root**

| Key | Req | Type | Value | Rule |
|---|---|---|---|---|
| `schema` | R | string | constant `alpha2.lock/1` | Another token is refused, never read with this meaning |
| `installer` | R | object | below | |
| `interpreter` | R | object | below | |
| `components` | R | array ≥1 | objects below | `name` unique; every `tag`, and `overlay.tag`, the same (E24) |
| `images` | R | array ≥1 | objects below | `name` unique |
| `files` | R | array ≥1 | objects below | `path` unique within one `component` |
| `writers` | R | array of 0 to 2 | objects below | `use` unique. A run needs each writer whose stage is in its stage set (S6b `hub_login`, S7 `api_key`): only an L1 run (`--only`, `--from`) may need fewer than both; S0's admission refuses `PREFLIGHT.LOCK` otherwise |
| `plugin` | R | object | below | |
| `d7_source` | R | object | below | |
| `vm_template` | R | object | below | |
| `hub_login` | R | object | below | The hub login's two private names (W7-HUB-LOGIN-IN-LOCK) |
| `registry_program` | R | object | below | The registry program's four private names (W7-REGISTRY-NAME-IN-LOCK, W7-PRIVATE-COMPONENT-LOOKUP) |
| `overlay` | R | object | below | The private overlay's pin (E23) |

**`installer`**: `repo` R string `repo_url`; `commit` R string `commit`;
`entry` R string constant `install/alpha2_install.py`; `sha256` R string
`sha256`. `INSTALLER_SHA` is the sha256 of a committed file
`install/MANIFEST`. That file lists every file of the installer (runner,
stages, writers, bootstrap) with its sha256, and its own sha is
`installer.sha256`. The entry file loads no code except through one loader
that hashes each module's bytes in memory, compares them with
`install/MANIFEST`, and executes those same bytes. A mismatch, or a module
not listed, is `PREFLIGHT.INTERPRETER` at S0 and `<STAGE>.PIN` later. S0 also
refuses an `<installer checkout>` that is not clean at `installer.commit`.

**`interpreter`**: `path` R string constant `/usr/bin/python3`; `sha256` R
string `sha256`; `resolved_path` R string `abspath`; `resolved_sha256` R
string `sha256`; `version` R string `py_version`. S0 hashes the launch path
and the fully resolved interpreter binary. It finds that binary outside the
interpreter under test (fixed absolute tools, captured in the D2 profile)
and compares both shas and the version with the lock. A shim pinned alone is
not a pin.

**`components[]`**: `name` R string `name`; `repo` R string `repo_url`;
`commit` R string `commit`; `tag` R string `rc_tag`. One entry per component
repository (router, relay end, hop, connectors, the registry program (E23),
this repo). Each lock change takes the next `alpha2-rcN`, and every `tag` in
one lock is that one tag (E24). S0 fetches each pinned commit and refuses
with `PREFLIGHT.FETCH` unless the tag, an annotated tag read from the refs
the remote fetch returned (never a tag created in the work directory),
peeled to a commit, is exactly that commit. A tag never selects a commit:
`commit` pins, and the tag is checked against it. For an L1, L2 or L2-leak run
(E24 B) a component is pinned by commit only: S0 fetches the remote's branches
and tags into a fresh bare repository and refuses with `PREFLIGHT.FETCH` unless
the pinned commit is reachable from one of them; the tag rule applies to every
other run. The overlay's tag below is checked in every run.

**`overlay`**: `repo` R string `repo_url`; `commit` R string `commit`; `tag`
R string `rc_tag`, equal to every `components[].tag`. The private overlay
holds `alpha2.lock` itself, so the lock cannot pin the commit that adds it.
The lock pins two overlay commits (E23):

- `overlay.commit` is the commit that carries `alpha2.hosts` and every other
  overlay file as this lock was written against them;
- `overlay.tag`, a private annotated tag in the overlay, is placed after the
  commit that contains this lock, on that commit. The lock holds only the
  tag's name, so this is not circular.

S0 reads `overlay.tag` as components' tags are read: the annotated tag ref
returned by a fetch from the private overlay's remote (`overlay.repo`), never
a tag created in the local checkout.

S0 refuses with `PREFLIGHT.PRIVATE_SOURCE` unless all of these hold for T, the
commit `overlay.tag` peels to, read in the installer's own fresh bare
repository (section 8 L6 records T). S0 runs no git command in the private
checkout and reads nothing under its `.git`: its owner is another account,
and git would run that account's configuration in the runner's environment.

1. `overlay.tag` is an annotated tag as the remote fetch returned it, and the
   checkout's working tree, walked without git and without following a
   symlink, is EXACTLY T's tree: every path, mode (100644, or 100755 when the
   owner may execute) and byte, and nothing more, with the top-level `.git`
   skipped by name. An ignored file, a symlink, a FIFO, a missing file or a
   changed byte refuses; a directory deeper than 32 levels, more than 1024
   directories, more than 4096 files or a file over 16 MiB refuses. A tracked
   path that is not valid UTF-8 never passes, and the overlay tracks no
   executable (the reviewed publication makes every file 0640);
2. T is `overlay.commit` or descends from it;
3. the tree comparison of `overlay.commit` with T, recursive and with
   rename and copy detection off (as `git diff-tree --no-renames -r`), has
   no entries, or exactly one entry, whose path is `alpha2.lock`. Any other
   entry refuses, a mode-only change to `alpha2.hosts` and a submodule
   (gitlink) included;
4. `alpha2.lock` at T is a regular blob with mode 100644. Adding it is
   the only change of type allowed; a symlink (120000) or gitlink (160000)
   at that path refuses.

`alpha2.hosts` and every other overlay file are therefore pinned exactly by
`overlay.commit`; a change to any of them needs a new `overlay.commit`, which
is a lock change, which takes the next `alpha2-rcN` (E24).

**`images[]`**: `name` R string `name`; `built_from` R string `name`, which
MUST name an entry of `components[]`; `image_id` R string `image_id`, what a
readback as the runtime uid must return (section 3.5).

**`files[]`**: `path` R string `relpath`; `component` R string `name`, which
MUST name an entry of `components[]`; `sha256` R string `sha256`. Each
reviewed text the installer runs, including `alpha/packages/*`, every
per-stage script and the VM bootstrap of 3.7 rule 7; checked at use, not
only at S0.

**`writers[]`**: `use` R string enum `api_key`, `hub_login`; `path` R string
`relpath`; `sha256` R string `sha256`. Checked by the VM bootstrap on the
bytes it executes (3.7 rule 7).

**`plugin`**: `sha256` R string `sha256`; `plugin_api` R string `plugin_api`.
`VERIFY.PLUGIN_MISMATCH` compares against it. Exactly one `files[]` row has this `sha256` (W7-PRIVATE-COMPONENT-LOOKUP);
none, or more than one, is L3 at `$.plugin.sha256`. S6 reads the plugin by that row's component and path, through the
VM layer's pinned-file read, and places it root-owned 0444 at the plugin path.

**`d7_source`**: `sha256` R string `sha256`. `VERIFY.D7` derives the placed
digest's expectation from it.

**`hub_login`**: `local` R string `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`; `domain` R string, one or more such labels
joined by `.`. Both are private identifiers: the installer pins each by sha256 (the same pins as this repository's
hub renderer) and refuses a value whose sha differs (L3, at `$.hub_login.local` or `$.hub_login.domain`). They are
the same for every hub. S6 writes each VM's hub login as `<local>@<host>.<domain>`, with `<host>` the VM's
`fleet_host` (6.2).

**`registry_program`**: `package` R string `^[a-z_][a-z0-9_]{0,63}$`, the registry program's (E23) Python package;
`config_schema` and `adapter_interface` R strings `^[a-z0-9]([a-z0-9.-]{0,62}[a-z0-9])?/[1-9][0-9]{0,3}$`, its
host.json schema token and its adapter interface token; `component` R string `name`, the `components[]` entry that
holds the program, which must name exactly one. All four are private identifiers: the installer pins each by
sha256 (the values at the program's pinned commit) and refuses a value whose sha differs (L3, at
`$.registry_program.<key>`; a component naming no entry, or two, is L3 at `$.registry_program.component`). S6 places
`component`'s tree under `package` and runs `<package>.opverbs` and `<package>` from the program's placed tree
(`.a2-registry-code` in the agent account's home), writes `config_schema` into host.json, and sends
`adapter_interface` with the read-back.

**`vm_template`**: `name` R string `name`. The pin form is **[OPEN: NET
(W4)]**; until a key and pattern for it are assigned here, no other key is
allowed (L2) and S2's review is blocked on it.

### 6.2 `alpha2.hosts`

Names the targets. W19 makes the reviewed texts read hosts, domains and key
ids from this file instead of their literals.

```json
{
  "schema": "alpha2.hosts/1",
  "runner": { "host_id": "<host_id>", "lock_root": "<abspath>",
              "loop_account": "<name>", "l3_account": "<name>" },
  "hypervisor": { "name": "<name>", "ssh_alias": "<name>" },
  "hub": { "name": "<name>", "domain": "<domain>" },
  "hub_loop": { "name": "<name>", "domain": "<domain>", "vm_id": "<vm_id>" },
  "loop_snapshots": [ { "vm": "<vm name or hub_loop.name>", "snaptime": "<snaptime>" } ],
  "vms": [ { "name": "<name>", "scope": "loop", "vm_id": "<vm_id>", "fleet_domain": "<domain>",
             "ssh_alias": "<name>",
             "agent_account": "<name>", "relay_account": "<name>", "hop_group": "<name>",
             "router": { "slug": "<slug>", "stable_key": "<abspath>" } } ],
  "agents": [ { "id": "<name>", "vm": "<vm name>", "connector": "<component name>" } ],
  "destroy_deny": [ "<vm name>" ]
}
```

**Root**

| Key | Req | Type | Value | Rule |
|---|---|---|---|---|
| `schema` | R | string | constant `alpha2.hosts/1` | |
| `runner` | R | object | below | The one runner host for every run; its locks are local to that host (5.3, 5.3b) |
| `hypervisor` | R | object | below | |
| `hub` | R | object | below | The `l3` scope's hub. Checked by S0 and S3 only (E6 (b)) |
| `hub_loop` | R | object | below | The `loop` scope's hub, hub-t, a VM on the hypervisor and never a `vms[]` entry (E1). Its `domain` differs from `hub.domain` |
| `loop_snapshots` | R | array | objects below | `vm` unique; the `vm` values are exactly `loop_restore_set` (below), else L3 |
| `vms` | R | array ≥1 | objects below | `name`, `vm_id`, `fleet_domain`, `ssh_alias` each unique |
| `agents` | R | array ≥1 | objects below | `id` unique |
| `destroy_deny` | O | array | strings `name`, each naming a `vms[]` entry | Unique. `destroy`'s hard deny list (5.3, 5.3b, 9a). ABSENT is UNCONFIGURED: `destroy` refuses with `RUNNER.DESTROY_DENY`, and no other command reads it. `[]` is configured and protects no entry. The operator authors it with the rest of the file |

Across the file, `hypervisor.name`, `hub.name`, `hub_loop.name` and every `vms[].name` are
pairwise distinct, and so is every `vm:<vm_id>`, `hub_loop`'s included; they are the lock targets of 5.3.

`loop_restore_set` is the sorted names of every `vms[]` entry of scope `loop`, and `hub_loop.name`: the one set the
loop restores together, that S0 checks and that D2a pins (installer function `a2_private.loop_restore_set`; S2's
restore and NET's checks call it, and nothing keeps a second list). The hub a run uses is
`a2_private.hub_for_scope(hosts, scope)`, with `scope` `"loop"` for an L1, L2 or L2-leak run and `"l3"` otherwise:
`hub_loop` and `hub` respectively. S0 passes that scope to every probe slot (`probe(hosts, scope)`), so NET's hub
and target probes read the run's own hub. hub-t's two lock targets (`hub_loop.name`, `vm:<hub_loop.vm_id>`) are
targets of `alpha2.hosts` like any other, so D2b's lock files include them before the first run on this layout.

**`runner`**: `host_id` R string `host_id`, the runner host's machine identity, read as the S0 review fixes [OPEN: S0 review: the identity source]; `lock_root` R string `abspath`, the one lock root (5.3); `loop_account` R string `name`, the loop runner account; `l3_account` R string `name`, the L3 runner account, different from `loop_account` (5.3b).

**`hypervisor`**: `name` R string `name`; `ssh_alias` R string `name`. S0's
access probe and S2's target.

**`hub`**: `name` R string `name`; `domain` R string `domain`.

**`hub_loop`**: `name` R string `name`; `domain` R string `domain`; `vm_id` R string `vm_id`.

Each of `hub.name` and `hub_loop.name` is EXACTLY the host key of that hub in the network inventory pinned by the
lock (the key S3's render reads). The installer cannot see the inventory; S3 checks the key, its address and its
host entries against the pinned inventory (NET's S3 checks, `HUB-CHECK.*`).

**`loop_snapshots[]`**: `vm` R string `name`; `snaptime` R string `^[1-9][0-9]{0,11}$`, the base snapshot's PVE
`snaptime` in epoch seconds. S0 compares it, as an integer, with the read of NET's read-only `snapshots` verb. A
re-baseline is a new overlay commit and tag (D2a), never a runtime write.

**`vms[]`**: `name` R string `name`; `scope` R string enum `loop`, `l3`, the runs that act on it (5.3b), with at least one entry of each; `vm_id` R string `vm_id`; `fleet_domain`
R string `domain`; `ssh_alias` R string `name`
(the operator route from the runner host, E20). The host key is NOT here: S2 captures it into the
installer's pinned known_hosts and records that file's sha in its receipt,
because a rebuilt VM has a new host key; later stages and `--verify` pin
against S2's receipt. `router` and the accounts are defined in the next paragraph.

**`vms[]`, the accounts and the router (W7)**: `agent_account` R string `name`, the account sandy, the agents and
the VM's router run as; `relay_account` R string `name`, the relay end's container account, never `agent_account`;
`hop_group` R string `name`, the group both are in (the hop root's group); `router` R object {`slug` R string
`^[a-z0-9][a-z0-9-]{0,62}$`, `stable_key` R string `abspath`}: the router's instance name and its registry key
on the VM (unique across the file). The logical id is never authored: S6 reads it back from the registry. The router's delegation key id is never authored either: it is `router.slug` + `-k1` (S5). Each `fleet_domain` is exactly `<host>.internal`: one label of `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, then `.internal`, lower-case, and never the hub login's domain (held by its sha256 pin, 6.1). RE's own domain (`HUB_OWN_DOMAIN`) is that domain, and the hub's mailbox and router login for the VM are named by `<host>`, so S6 derives both and nothing about the mailbox account is authored. Any of these broken is L3. On each VM, its
router slug and the `agents[].id` of the agents on that VM have pairwise distinct skeletons, and every router slug has a skeleton distinct from every other router slug's (NFC, casefold, 0 to o, 1 and i to l, 5 to s,
then `-`, `_` and `.` dropped), and no slug is `postmaster` or `abuse`; any of these broken is L3.

**`agents[]`**: `id` R string `name`; `vm` R string `name`, which MUST name
an entry of `vms[]`; `connector` R string `name`, which MUST name an entry of
`components[]` in `alpha2.lock`. The workspace is derived (`~/dev/agent-<id>`,
a.4 S7), never stored.

Neither private file holds a secret, a seed, a password, an API key or a hash
of any of them. Section 8 enforces it.

### 6.3 Run manifest (`manifest.json`)

Written by the runner, one per run, in the run directory.

```json
{
  "schema": "alpha2.run/1",
  "state": "final",
  "run_id": "<run_id>",
  "command": "install",
  "loop": null,
  "source_run": null,
  "installer_sha256": "<sha256>",
  "lock_sha256": "<sha256>",
  "hosts_sha256": "<sha256>",
  "started": "<utc>",
  "ended": "<utc>",
  "env_names": ["HOME", "PATH", "SSH_AUTH_SOCK", "TERM"],
  "stages": [ { "stage": "<stage_id>", "host": "<name or ->", "receipt": "<receipt_path>",
                "sha256": "<sha256>", "rc": 0 } ]
}
```

**Root**

| Key | Req | Type | Value | Rule |
|---|---|---|---|---|
| `schema` | R | string | constant `alpha2.run/1` | |
| `state` | R | string | enum `active`, `final` | Lifecycle below |
| `run_id` | R | string | `run_id` | Equals the run directory's name and every receipt's `RUN_ID` |
| `command` | R | string | enum `install`, `dry-run`, `verify`, `canary`, `add-agent`, `rotate-key`, `check-roundtrip`, `destroy` | Per 5.1 |
| `loop` | R | string or null | enum `L1`, `L2`, `L2-leak`, `L3`, or `null` | `L1` exactly when `--only`/`--from` was given; `L2-leak` exactly when `--leak-run` was given |
| `source_run` | R | object or null | below | Non-null exactly when `--only` or `--from` was given |
| `installer_sha256` | R | string | `sha256` | Equals the `INSTALLER_SHA` of every receipt written by this run. A verified source-run predecessor may differ (section 3.3, the one K8 relaxation) |
| `lock_sha256` | R | string | `sha256` | Equals every receipt's `LOCK_SHA` |
| `hosts_sha256` | R | string | `sha256` | Equals every receipt's `HOSTS_SHA` |
| `started` | R | string | `utc` | |
| `ended` | R when `final`; ABSENT when `active` | string | `utc` | |
| `env_names` | R | array of exactly 4 | the strings `HOME`, `PATH`, `SSH_AUTH_SOCK`, `TERM`, sorted, each once | Names only, never values |
| `stages` | R | array (may be empty while `active`) | objects below | (`stage`, `host`) unique; order = the order the receipts were finalized |

**`source_run`**: `run_id` R string `run_id`; `sums_sha256` R string `sha256`.
The earlier run whose `SUMS` this run verified before taking its predecessors
(5.4).

**`stages[]`**: `stage` R string `stage_id`; `host` R string `name` or the
constant `-`; `receipt` R string `receipt_path`, consistent with `stage` and
`host`; `sha256` R string `sha256`, equal to that receipt's line in `SUMS`;
`rc` R integer enum `0`, `2`, `3`, `4`, equal to the receipt's end line.

**Lifecycle.** The runner writes the manifest with `state` `active` and no
`ended` before S0, and rewrites it atomically (temp, fsync, rename) as
receipts are finalized. After the last stage it writes it once more with
`state` `final` and `ended` set, atomically, and only then appends its line
to `SUMS` (5.4). An `active` manifest is never in `SUMS`; a manifest listed in
`SUMS` MUST be `final`, and a run directory whose manifest is `active` is an
unfinished run, never eligible. The manifest carries no SUMS sha (5.4).

## 7. `--verify` and S9

### 7.1 The read-only check list

`--verify` and S9 run the same code. It writes nothing on any target. It runs
every group, fails with the cause of the FIRST failed group, and still prints
the result of every group. Environment checks emit only counts or named
non-secret keys (section 3.3).

| # | Group | Check | Cause |
|---|---|---|---|
| V1 | RL process | Container running by its expected name and image id from the lock; primary gid 2100 in `/proc/<pid>/status` | `VERIFY.RL_FORM` |
| V2 | RL registry | `status --json`: registry state ok, held empty, every agent in `alpha2.hosts` drained | `VERIFY.RL_REGISTRY` |
| V3 | RL delegation | Own key id and the peer's key in the key table; the peer's key equals the public key the other VM printed in S5, measured directly; peer store admission open | `VERIFY.RL_DELEGATION`, `VERIFY.PEERSTORE_CLOSED` |
| V4 | RL signature evidence | The verified-signed counter or log line exists (zero is allowed before the first round trip; absence is not) | `VERIFY.RL_NO_VERIFY_SIGNAL` |
| V5 | Plugin | The plugin file sha in the RL and RE images equals the lock; RL's activation line names the same sha and PLUGIN_API | `VERIFY.PLUGIN_MISMATCH` |
| V6 | RE process | Unit active, container running, no restarts. Necessary, never sufficient. | `VERIFY.RE_DOWN` |
| V7 | RE failure events | None of the captured failure event names in the last N minutes (N from RE; at least two poll periods) | `VERIFY.RE_HELD`, `VERIFY.RE_POLL_FAILED`, `VERIFY.RE_PUMP_FAILED`, `VERIFY.RE_AUTH_FAILED` |
| V8 | RE progress | A delivery success line is on record after a round trip; the idle-poll marker once A2-14 provides it | `VERIFY.RE_NOT_PROGRESSING` |
| V9 | Hop layout | `down/` beside `up/` for every agent; no RE hold event for that agent in the window. Needs a positive control on a healthy live host before review. | `VERIFY.HOP_LAYOUT`, `VERIFY.RE_HELD` |
| V10 | Hop tree | Modes and groups as RE reads them; each group-readable file OPENED as 2102:2100 (a stat is not enough) | `VERIFY.HOP_TREE_UNREADABLE` |
| V11 | Hub link | Probe unit ok and fresh; `hub.env` has exactly one allowlist line and carriage on; the running container's environment has the same COUNT of those two keys; placed D7 digest equals the digest derived from the pinned source | `VERIFY.HUB_LOGIN`, `VERIFY.HUBENV`, `VERIFY.D7` |
| V12 | Agents | Workspace present; registry entry active; secret file present with its mode (content never read); connector at its pin; sandbox image present. Prints every agent and who may task it, from RL's own output, else labelled INFERRED | `VERIFY.AGENT_<id>_<WHAT>` |
| V13 | Operator route | The operator's ssh route from the runner host reaches each VM and shows the host key pinned by S2's receipt, read-only | `VERIFY.OPERATOR_ROUTE` |
| V14 | Host | No SSH agent socket inside the RL or RE container; capability waiver rows exactly as recorded | `VERIFY.HOST` |
| V15 | RE state on the VM | Every RE state directory (inbound state, relay ledger, mailbox root) and any volume behind it is on the VM's own disk: the RE container's mounts read back, and none has a source on nfs, cifs, 9p, virtiofs or sshfs, or a volume whose driver is not `local` (ALPHA2-L3-ID-REMINT condition 1) | `VERIFY.RE_STATE_OFF_VM` |

Rules for the check list:

- The event names in V7 come from a captured live RE log, not typed from
  memory; the fixture is part of the stage's review.
- V7 is windowed, never "zero since start".
- A group whose fact cannot be read is a failure of that group with its
  cause, never a pass.

### 7.2 The agent processing proof (S9, full install only; E21)

Not part of `--verify`. In a full `install` run, and only then, S9 starts
each agent unattended through a login shell, as the operator will start it;
one signed test message from the other VM must be processed and answered;
the agent is stopped again. A failure is `VERIFY.PROCESSING_<id>` (the `<id>`
rule of 4.5). A setting read back is not a substitute for this proof (A2-01).

## 8. S0 leak check of the private files

S0 refuses to start a run unless both private files, `alpha2.lock` and `alpha2.hosts`, pass every check below.
A failure is `PREFLIGHT.LEAK_LOCK` or `PREFLIGHT.LEAK_HOSTS`, and the
receipt names the check number and the JSON path, never the value.

| # | Check | Why |
|---|---|---|
| L1 | The file is valid UTF-8 without a BOM and parses as JSON with duplicate keys REFUSED (a parser hook, not the default last-wins), with no `NaN`/`Infinity`, and its `schema` token is the one section 6 names | A duplicate key hides a value from every later check |
| L2 | Every object is closed: every key is one section 6 names. A refusal names the check number and the JSON path of the PARENT object plus the unknown key's ordinal position, never the unknown key's text | An unknown key, or its name, is where a pasted secret lands |
| L3 | Every value has its type and matches, in full, the pattern or enum the field table assigns it. A string field with no assigned pattern is a contract defect, and the field is refused until one is assigned | A pattern-checked field cannot carry free text |
| L4 | Neither any parsed string nor the raw file bytes match a deny pattern: a PEM or OpenSSH private key header; an API key shape [OPEN: the shapes, from the S1 review]; the token shapes `ghp_`, `github_pat_` and `glpat-`; URL userinfo with a password (`://[^/@]*:[^/@]*@`) | Defence in depth behind L2 and L3; the raw pass catches an escaped form |
| L5 | No string, and no raw byte sequence of the file, equals or contains a value S1 holds, compared in memory only. S0 runs before S1, so S1 runs this check on the in-memory bytes S0 checked, after the prompt and before any writer receives a value. A failure there is `CREDENTIALS.LEAK_LOCK` or `CREDENTIALS.LEAK_HOSTS` (exit 2), and no writer runs. In the `L2-leak` run the value is the canary | The direct test, per a.11 |
| L6 | The private overlay checkout's working tree is exactly the tree of T, the commit `overlay.tag` peels to, which meets the lock's `overlay` pin (section 6.1); and the exact bytes S0 read for the file, hashed as a git blob with no filter applied, equal the blob id of the file's path in T's tree (`PREFLIGHT.PRIVATE_SOURCE` otherwise). No git runs in the checkout, so no index flag or configured filter is consulted. The receipt records T | A run is reproducible only from a committed file |
| L7 | The file's mode allows no access by others, and its realpath is not under any root in a committed deny list of sandbox mount roots (the list is part of the S0 review) | E3: identity never in a sandbox mount |
| L8 | Receipts carry the file's sha256 only, never its content | The public run record must not carry the values |

The leak check (L1 to L4) runs before the runner or any stage uses either file's values, including the lock targets of 5.3.

The admitting process (the launcher, for a supported invocation, 5.1a) reads each private file once, before the target locks of 5.3, and runs L1 to L4 on both in-memory files before it derives any lock target. The runner reads each file once again at S0, runs L1 to L4 on those bytes, and keeps them in memory; for a command that can write to a target, their sha256 must equal the start record's (5.1a). On a failure it refuses with `PREFLIGHT.LEAK_LOCK` or `PREFLIGHT.LEAK_HOSTS`, printed to the terminal only (check number and JSON path, never a value), and it creates no lock file and no run directory. S0 records these results in its receipt and runs L6 to L8. Every stage reads that in-memory copy, never the path. Any stage that does touch the path re-hashes the file and refuses on a mismatch with the manifest's `lock_sha256` or `hosts_sha256` (`<STAGE>.LOCK` or `<STAGE>.HOSTS`). A check that passed on one set of bytes never vouches for another.

## 9. Operator touches outside the installer (b.9)

| # | Touch | Relation to the stages |
|---|---|---|
| — | Before every fresh run (L3 and every bare start): NET's reviewed text resets and sets the two router logins (E6 (b)) | Precondition of S3 and S6b; S3 checks it, S6b proves the login |
| U1 | Before every L3 run: NET's reviewed `empty-host-mailbox`, bound to the run's scope by `hub_for_scope` and `--hosts-sha`, refuses while any mail is queued for the hosts' domains and otherwise empties their router mailboxes. "Drain" means no queued mail remains when the step completes; mail that will not clear is a separately reviewed operator step | S3's `mailbox-count` check proves it inside the run (`HUB-CHECK.MAILBOX_NOT_EMPTY`). L2 and L2-leak need no U1: hub-t is restored with the loop's snapshot set (section 9, D2a) |
| U2 | At the start of each bare L3, before the launcher: the same invocation as U1 for that run (ALPHA2-L3-ID-REMINT condition 4) | As U1 |
| — | The operator sets its stop in the E19 stop file before the final run, so that the loop drains, and clears it only after that run's S10 has printed its SUMS sha | The loop refuses while it is set, and a loop run in progress stops at its next stage boundary; the final run does not read it, and its locks keep the loop out while it runs (5.3b) |
| — | The brakes for an L2 run (E13): the router stop, de-enrolment, the cross-host `task_deny`, and the 7-day reply window | Named in the L2 runbook text; available throughout every L2 run. |
| D2 | One setup sitting on the runner host: the profile capture; test credentials entered once; a dry attach on a test VM with the test key; plus, per E20 and E3, the one ssh include line and the loop-identity install, and the L3 runner account with its key (9a); for each runner account, its work directory and `runs` (5.2) | Before the first L2 |
| D2a | Hypervisor setup with NET: test network, test VMs built by S2, the stand-in hub (`hub_loop`, hub-t), snapshots. The test VMs and their snapshots are created by the L3 key inside an armed window (9a). The snapshot set is `loop_restore_set`, taken QUIESCENT (RE stopped on every agent VM, no RE journal or held records, hub-t's mailbox count 0, each recorded in the D2a receipt), with hub-t's certificate valid until at least 2027-01-01 (NET checks it). Its snaptimes go into `alpha2.hosts`' `loop_snapshots` by an overlay commit and tag; every L2 and L2-leak restores the whole set, never a part (RE: hub-t alone skips mail, agents alone replay it) | Before the first L2 |
| D2b | One-time: the operator creates the lock root (root, 0755), one lock file per target key of `alpha2.hosts` and `runner.lock` (each root, 0644, 5.3 step 4), `stop.d` with one subdirectory per setter role, each readable (r-x) by both runner accounts and writable by neither, and `budget.d` with its `loop` and `l3` subdirectories (all root, 0755, with no ACL and no group write, 5.3c), and installs the budget broker and its socket (5.3c). The operator binds only `stop.d/controller` and `stop.d/monitor` read-write into the controller's and the monitor's sandboxes. No runner account can write in the lock root, in `budget.d` or in either of its subdirectories. A change to `alpha2.hosts` that adds a target needs its lock file created the same way before the next run. Neither `budget.d` nor the lock root is in any sandbox mount. The S0 review checks that only the broker writes in `budget.d`, and only start records, and that neither the launcher nor the runner writes in `stop.d`. Both sandboxes run on the runner host, because a bind mount cannot cross hosts | Before the first L2; not per run (5.3b, 5.3c) |
| — | A `budget.d` read that is `UNOBSERVED` because of a record: the operator measures that no run is active and the 5.3 locks are free, renames `budget.d` whole to `budget.d.<utc>` (it never edits or removes a record), and creates a new `budget.d` with empty `loop` and `l3` subdirectories, owned as D2b states. A `RUNNER.TARGET_LOCKED` the operator did not expect: as root, find the holder with `lslocks` and stop that account's processes (5.3 step 4) | Lets runs count their budget again (5.3c). The day's count and the permit check of 5.3c also read every `budget.d.<utc>` |
| — | Adopting the VMs that predate the installer's marker: a reviewed operator step gives them the marker | Before `--destroy` retires them (9a) |
| D3 | The installer approved by sha, with the dual verdict, green L2 receipts, drift list and residual risks (the twelve accepted residuals of E26: R1 to R4, R6, R7, R10, N1 to N5); the launch line and the L3 `sudo` line, and the matching line for `--destroy`, frozen, with their paths (5.3b). Blocked until A2-05, A2-08 and A2-14 land; A2-15 may be accepted as INFERRED, by name, only if it is the last one outstanding (E18) | Fixes `alpha2.lock`'s `installer` and `interpreter` |
| D4 | The final run, as the L3 runner account: one command, one credential prompt, three steps, the round-trip prompt. Precondition: NET's host verifier has proved, as the loop runner account, the integrity of what the L3 runner account runs, and that no loop-readable key reaches an `l3` VM (5.3b) | One `install` run, approved by its SUMS sha |
| D5 | Closeout and tags: the final tag on the green fresh (L3) run (E24) [OPEN: final tag name] | After D4's PASS |

## 9a. Apply credentials (A)

The access the apply path needs, to the pinned repositories, the hypervisor
and the hub (3.2 `SSH_AUTH_SOCK`; 4.4 `PREFLIGHT.REPO_ACCESS` and
`PREFLIGHT.TARGET_ACCESS`), is by scoped keys with forced commands. That is
decided (A). There are two runner accounts (Q0b (iii), 5.3b): the loop key's
files live only under the loop runner account's home directory, and the L3
key's files only under the L3 runner account's home directory, each at mode
600. The loop runner account cannot read the L3 runner account's home or
key. These are also decided:

- The L3 forced program refuses every verb outside the armed window of the
  hypervisor's L3 arm gate (5.3b).
- The test VMs and their snapshots are created by the L3 key inside an armed
  window, in D2a (section 9).
- `destroy` is limited to the pinned set, the installer's own marker, the
  armed window and a hard deny list. Two lists apply, and `destroy` needs
  both: the L3 forced program's own hard deny list on the hypervisor, which
  protects VMs whatever `alpha2.hosts` says and is specified in
  [OPEN: apply credentials design, NET]; and the runner-side list
  `destroy_deny` in `alpha2.hosts` (6.2), which decides `destroy`'s scope and
  lock set and without which it refuses.
- VMs on the hypervisor that predate the installer's marker are adopted
  (given the marker) by a reviewed operator step before `--destroy` retires
  them (section 9). The real VMs are then rebuilt from bare by the final run
  (E1, E2).
- S0's git reads ssh's configuration only from `<HOME>/.ssh/config_overlay` (`GIT_SSH_COMMAND` = `ssh -F` that
  file, the one variable git gets beyond its fixed set; HOME must be a plain absolute path or `RUNNER.ENV`). Each
  runner account holds its own read-only overlay deploy key and the overlay host's pinned key there (NET's creds
  r7 part 2), because S0 fetches `overlay.tag` in every run, loop runs included. `overlay.repo` is the
  `ssh://git@<host>[:<port>]/<path>` form; the components are https. Before the fetch, S0 reads ssh's EFFECTIVE
  configuration for that exact host and port (`ssh -G` under `config_overlay`) and requires: the same hostname and
  port, `user git`, the account's own `id_a2_*_overlay` key alone, `<HOME>/.ssh/known_hosts_overlay` alone,
  `stricthostkeychecking` on, `hostkeyalias a2-overlay`, `batchmode`, `identitiesonly`, no agent and no agent
  forwarding. Anything else is `PREFLIGHT.REPO_ACCESS`, with nothing fetched.
- A loop run's S2 does not use the L3 key. It creates a missing test VM only
  if the loop key's forced commands allow it; otherwise S2 fails closed.

The key inventory, each key's forced command, the custody paths and their
checks are [OPEN: apply credentials design, NET]. When they are supplied,
this section lists each key and its forced command. It never names a key
path or a key value.

## 10. Open slots

| Slot | Where | Waits on |
|---|---|---|
| [OPEN: final tag name] | section 1 E24, 9 D5 | The name of the final tag on the green fresh (L3) run, as plan section 11 gives it |
| [OPEN: sandy's list] | 3.7 rule 10 | sandy's owner (a.12) |
| [OPEN: endpoint] | 3.7 rule 3 | DS with sandy's owner (Appendix C) |
| [OPEN: the shapes] | 8 L4 | The S1 review |
| [OPEN: S1 review] | 3.3 output guard | Whether the guard stays armed through S8 to S10 |
| [OPEN: usage read-back measured] | 5.3c | Whether the runner can read the loop account's 7-day usage without a person present: path (a) or (b). For path (b): who reads the loop runner's subscription account, and how each reading reaches the monitor, carrying the account it read, the percent and `observed_at`, fresh within 60 minutes, on a request and answer timed to launches (one reading for each launch of any command that can write to a target, so at least 12 a day when L2 runs its daily count). Until then path (b) permits nothing |
| [OPEN: S2 review] | 5.3b | The hypervisor's read-only probe for the loop identity's tasks, for VM placement, for the hypervisor's identity, and its verb for reading the L3 arm gate |
| [OPEN: sleep probe measured] | 5.3a | A read-only probe that shows the runner host's sleep disabled; without one, `PREFLIGHT.KEEP_AWAKE` is removed and the fact recorded in section 1 |
| [OPEN: apply credentials design, NET] | 9a, 5.3b | The key inventory, forced commands, custody paths and checks of the decided scoped keys (A), and that no loop key or account can create, extend or change the L3 arm file, and that no loop-readable key is authorized on an `l3` VM |
| [OPEN: budget broker, DS] | 5.3c, 9 D2b | The broker's code, socket path, answer bound, per-account daily ceiling and review; it is root-owned and installed in D2b, with tests for an unreachable broker, a hung broker, a symlinked or FIFO `permit.json`, a duplicate `run_id` across subdirectories, a schema-breaking request, and a caller of neither account |
| [OPEN: D3 launch paths] | 5.3b, 9 D3, D4 | The launcher, installer checkout and interpreter paths, the L3 `sudo` line and the matching line for `--destroy`, frozen at D3; NET's host verifier then proves them, as the loop runner account, before D4 |
| [OPEN: RL reply-depth check] | 5.5, section 1 E13 | RL's per-run reply-depth check, in review; a per-run evidence item for L2 and L3 runs |
| [OPEN: S0 review: the identity source] | 6.2 `runner.host_id` | How S0 reads the runner host's identity |
| [OPEN: NET (W4)] | 6.1 `vm_template` | The template's pin form; S2's review is blocked on it |
| [OPEN: RL/HOP] | 6.2 `vms[].router` | Whether slug and logical id are authored or minted; absent until then, and S6/S9 review needing it is blocked |
