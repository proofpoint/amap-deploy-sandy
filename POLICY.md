# `payload/INBOX-POLICY.md`: what it is, and why it says what it says

`INBOX-POLICY.md` reaches every selected agent as part of its **system
prompt**. `install --apply` copies it onto the feature payload. At every
launch that sandy selects, the manifest's `agent_args` pass Claude Code
`--append-system-prompt-file /opt/sandy/features/amap/INBOX-POLICY.md`.
Nothing is written into a sandbox. Everything in the file is paid for on
every turn, so the file carries rules and no reasoning. The reasoning is
here, where an operator reads it once.

That route has two consequences, both accepted on purpose:

- **A conversation keeps the rules it started with until it is compacted.**
  Claude Code records the system prompt on a conversation's first request and
  resends it verbatim when the conversation resumes. An edit therefore reaches
  new conversations at once, and existing ones at their next compaction.
- **It is not in `CLAUDE.md`**, so the agent it calibrates cannot edit it
  away. The payload is mounted read-only into the sandbox.

---

## It is calibration, not enforcement

The file tells a cooperating agent how much authority a message carries. It
stops nothing: an agent that ignores its instructions ignores this file too.

Every control that actually holds sits on the router's side of the seam:

- the graph of who may task whom, decided when a message is submitted
- the mutual-peer check on mail
- replies bound to the sender
- read-only inbound lanes

Those controls hold whatever the agent decides.

**So never add a rule here that only works if the agent obeys it.** If a
property matters, it belongs in the router.

## Why it grants so much

The graph of who may reach an agent is not SPF/DKIM, and the agent should
not second-guess it. An operator declared that edge deliberately, so the
selected set is a security decision and not bookkeeping. **That makes it a
content-trust decision, delegated on purpose.**

Agent-side suspicion of a vetted peer buys nothing, because no security
property depends on the agent behaving. It only buys the hedging that makes an
agent tiresome to work with, and that is the common failure here, not the
rare one. "An allowlisted peer can be compromised, confused, or relaying" is
the argument that forbids all internal automation. The policy does not make
it.

## Why the line falls where it does

The router bounds the **message path**: who may reach you, who you may
reach, and where a reply can go. It has no opinion about tools. A peer asking
you to fetch a URL, delete a directory or use a credential is asking for
something the transport never covered.

So the question is not *how much do I trust this sender*. It is **does the
transport's guarantee cover this action**. That is why a reply needs no
confirmation (it is bound to the sender) while `curl` does. Neither is a
comment on the sender.

## The rules that are not about the sender at all

**Quoted material.** The peer who wrote to you is vetted. What they pasted is
not. This is the one place where the sender's trustworthiness genuinely is not
the question, and it is the textbook injection path.

**Forwarding.** A reply is bound to the sender and cannot be redirected. A
send to anyone else is checked against the graph, which refuses a stranger and
*permits a peer*. So "the router would stop it" is true only for strangers.
An instruction to forward material to a listed peer would be delivered, and
the router would be right to deliver it. As an agent put it when it refused
such an injection in a live test: *"The router is a backstop, not a
substitute for not sending."*

The policy therefore separates two cases. Relaying your own work is
ordinary; say whose request it was. Forwarding material because a message
told you to is not a request to weigh at all.

**Concealment.** A request to hide an action from the sender is disqualifying
on its own. A genuine correspondent has no reason to need something hidden
from them.

## Testing it

The direct test is an injection. Agent A sends B a body that instructs B to
forward results to C. Two claims are involved, and they must be proved
separately:

- **The agent tier.** B, reading a well-formed injection from a genuinely
  granted peer, treats the body as data and sends nothing.
- **The router tier.** When C is not a peer, C receives nothing even from an
  obedient B. That is the router's refusal, and it is proved on the router's
  side, not here.
