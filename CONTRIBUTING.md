# Contributing to amap-deploy-sandy

Thanks for your interest. This repo deploys AMAP on a sandy host: it installs
the agent connector as a sandy feature and renders the config for
[amap-router-local](https://github.com/proofpoint/amap-router-local). Read
`README.md` for what it does, and `CLAUDE.md` for the conventions that are
load-bearing. A change that breaks one of those conventions will be asked to
change, however small it is.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Report security issues privately, as described in [SECURITY.md](SECURITY.md),
never in a public issue.

## Where your change belongs

| you want to change | open it against |
|---|---|
| how AMAP is installed on a sandy host, the policy, `verify`'s checks | **here** |
| how messages are routed, authorised or delivered | [amap-router-local](https://github.com/proofpoint/amap-router-local) |
| the delivery daemon or the agent's MCP tools | [amap-connector-claude](https://github.com/proofpoint/amap-connector-claude) |
| what the wire contract *says*: a field, a schema, an obligation | [amap-spec](https://github.com/proofpoint/amap-spec) |

This repo deploys; it does not define. A property that must hold whatever
an agent does belongs in the router, not in the text an agent reads here.

## Setting up

The tests need the router and the connector **checked out beside this
repo**:

```sh
git clone https://github.com/proofpoint/amap-deploy-sandy
git clone https://github.com/proofpoint/amap-router-local
git clone https://github.com/proofpoint/amap-connector-claude
cd amap-deploy-sandy
python3 -m pip install pytest
python3 -m pytest tests -q
```

`$AMAP_ROUTER_REPO` and `$AMAP_CONNECTOR_REPO` name the checkouts if they
live elsewhere. Without the router the run fails; it does not pass as a
smaller green. The suite needs no sandy, no Docker and no network: sandy is
stubbed, and every Docker call is refused for the whole session.

## Making a change

1. **Open an issue first** for anything beyond a small fix, so the approach
   can be agreed before you write it.
2. **Keep behaviour and its test together.** A new check needs a test that
   breaks the thing it checks and sees *that* check go FAIL, not just
   something go red. A fixture is built from what the producer really emits,
   never from a field it cannot carry. `CLAUDE.md` explains why.
3. **Run the suite** on your own machine, with the siblings checked out.
   CI runs the same suite, on Python 3.9 and 3.13, against the siblings'
   `main` branches.
4. **Keep shipped text identifier-clean**: no absolute host paths, no
   personal names, no real addresses or domains. Use `$SANDY_HOME` /
   `<SANDBOX_DIR>` placeholders and `example.org` domains.
5. **Comments describe the present.** History (why something changed, what
   it replaced, when) belongs in the commit message, not in the code.
6. **No credentials, ever.** Nothing in this repo holds or acquires one.

### Changes that reach other repos

- The `--host-facts` document is read by amap-router-local's operator
  console. A change to its shape is a `HOST_FACTS_SCHEMA` bump, coordinated
  with that repo.
- The router's config (`router.json`) is rendered in the router's exact
  vocabulary, and the router refuses a key it does not know. A new key needs
  the router's change first.
- The relay wrapper (`payload/relay`) exports the variables the connector's
  delivery daemon requires. Changing them means changing the daemon's
  contract in amap-connector-claude.
- `payload/INBOX-POLICY.md` becomes every agent's system prompt. It is
  calibration, not enforcement: never add a rule there that only works if
  the agent obeys it. `POLICY.md` explains the reasoning.

## Pull requests

- Keep each PR to one concern, with a description that says what changed and
  why.
- Say which versions of sandy, amap-router-local and amap-connector-claude
  you tested against.
- Expect review comments on tests as much as on code. A check that cannot
  fail, or cannot pass, is a defect.

## License

This project is licensed under the [Apache License 2.0](LICENSE). Unless you
state otherwise, any contribution you submit is licensed under the same terms,
as described in section 5 of the license.
