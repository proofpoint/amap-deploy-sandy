# D2 text 3: the dry attach on a test VM

This is one of the reviewed texts of the setup sitting D2 (stage contract
section 9; proposal b.9: "a dry attach on a test VM with the test key").

**What it answers:** does an agent that S7 prepared start and attach with no
dialog and no startup prompt? That is K11 and A2-01. The proposal's exceptions 2
to 4 were the trust dialog and two more prompts. The dry attach lets the operator
see this once at first hand. The evidence for it remains S9's processing proof
(E21).

**Where it runs:** on ONE loop test VM (scope `loop` in `alpha2.hosts`), never on
a real VM. The operator types it after an L1 run has carried that VM through S7
with the test credential.

**What it changes:** it starts one agent on the test VM and stops it again. The
operator types NOTHING into the agent's pane, at any point and in any result:
the session is ended from a second ssh session, never by keys typed into the
pane. Nothing on the runner host changes.

## Preconditions

- An L1 run that ended at S7 (`--only` or `--from`, ending at S7) on
  `<test-vm>` has exit 0. Its receipt sha is written down as `<s7-receipt-sha>`.
  S7 leaves the agent stopped (contract section 2).
- That run did not reach S8, so the relay end on the VM was never started by
  it, and no delegation is delivered to the agent while it runs here. This is
  INFERRED from the stage order (S8 starts the router side); confirm it with
  `sandy --print-state` on the VM, read-only, if in doubt.
- The VM's host key is already in the runner host's known hosts, from S0's
  route rehearsal (`PREFLIGHT.OPERATOR_ROUTE`, E20). The test credential is the
  OAuth setup token: an API-key-only start is NOT proven free of the API-key
  modal (sandy a.12 answers at 41021ff, 1b).

## Steps

`<alias>` is ONE word: the ssh alias that follows `ssh` on the access line S10
printed for `<test-vm>` (`vm <name> access: ssh <alias> INFERRED`, E20). It is
`vms[].ssh_alias` of a `loop` VM in `alpha2.hosts`, never a real VM's, and has
the shape `[a-z][a-z0-9-]{0,62}`. Copy only that word, never the whole line.
`<id>` is the agent's id from `alpha2.hosts`. `<ws>` is the absolute path of
`~/dev/agent-<id>` on the VM.

Every ssh below adds `-o BatchMode=yes -o StrictHostKeyChecking=yes`. A host-key
question or a password prompt then fails at once instead of asking. That failure
is a FAIL of the route, not of the agent. Steps 1 and 3 also add `-n`, so a
question from `sandy` fails instead of waiting for input.

1. **Session 1: start.**

   ```sh
   ssh -n -o BatchMode=yes -o StrictHostKeyChecking=yes <alias> sandy --start --workspace <ws>
   ```

   Expect exit 0, and no question printed.

2. **Session 1: attach and look, without touching anything.**

   ```sh
   ssh -t -o BatchMode=yes -o StrictHostKeyChecking=yes <alias> sandy --attach --workspace <ws>
   ```

   PASS means the agent's pane shows its idle prompt, with none of these:
   - a workspace trust dialog;
   - an API-key approval ("use this API key");
   - any other question waiting for an answer.

   FAIL means any one of them is shown. Do NOT answer it. The fix is S7's
   (A2-01), never the operator's.

   While attached, every key reaches the agent's active pane, dialogs included
   (sandy's answers at 41021ff, (a)). So, in either case:
   - Type nothing. In particular, never press Ctrl-b (byte 0x02): it is tmux's
     prefix inside the container, and the next key runs a tmux command, some of
     them destructive. Never press Ctrl-p Ctrl-q either.
   - Do not click or scroll in the window. Mouse mode is on: a click changes the
     target pane, and the scroll wheel enters copy mode.

   Go to step 3.

3. **Session 2, a second terminal: stop.** This ends session 1's attach
   without a keystroke in the pane: the container is removed, and session 1's
   `sandy --attach` exits 0 (sandy's answers, (b)).

   ```sh
   ssh -n -o BatchMode=yes -o StrictHostKeyChecking=yes <alias> sandy --stop --workspace <ws>
   ```

   Expect exit 0, and session 1 to return to the runner host's prompt. If
   session 1's screen looks stuck after that, run `tput rmcup` there; sandy
   does not leave the alternate screen (sandy's answers, (b)). If session 1
   does not return at all, close its terminal window. Never type into the
   agent's pane.

## What is recorded

Record one line in the sitting's private notes:

`DRY-ATTACH <test-vm> agent-<id> PASS|FAIL <what was shown, in your own words> s7=<s7-receipt-sha>`

Take no screen capture: the pane can hold approval text.

## Sources and open points

- sandy's answers from source at 41021ff (controller 4bcc8622, sha 361771e3):
  - `--attach` makes the terminal a tmux client of the agent's session;
  - `--stop` from another session ends the attach with exit 0;
  - the detach keys are the tmux and docker defaults, never used here;
  - `--print-state` is effectively read-only (it creates its first-run files
    only if absent).
- NEEDS MEASUREMENT (D2.4): whether session 1's screen is clean after the stop
  (the alternate screen).
- The test credential is entered once at D2 (b.9, "test credentials entered
  once"), in D2 text 2, which is not part of this unit.
