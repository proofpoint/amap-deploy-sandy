"""Authored fleet-wide Codex conversation choice; portable and host compatible."""

POLICY_KEY = "codex_conversation_mode"
EXPORT = "AMAP_CODEX_CONVERSATION_MODE"
MODES = ("separate", "unified")
FRESH_FILES = ("fresh-birth.json", "fresh-plan.json", "fresh-initialization.json", "fresh-startup.json", "fresh-selection.json")


def fresh_markers(state):
    return tuple(state / name for name in FRESH_FILES) + (state.parent / (".fresh-intent-" + state.name + ".json"),)


def mode(policy):
    value = policy.get(POLICY_KEY, "separate")
    if not isinstance(value, str) or value not in MODES:
        raise ValueError("codex_conversation_mode must be separate or unified")
    return value


def environment(env):
    return mode({POLICY_KEY: env.get(EXPORT, "separate")})


def select(policy, requested):
    selected = dict(policy)
    if requested is not None:
        selected[POLICY_KEY] = requested
    if requested == "unified":
        agents = selected.get("agents")
        if not isinstance(agents, dict) or not isinstance(agents.get("include"), list):
            raise ValueError("explicit unified choice requires the loaded fleet agent selection")
        agents = dict(agents)
        agents["include"] = list(agents["include"])
        if "codex" not in agents["include"]:
            agents["include"].append("codex")
        selected["agents"] = agents
    mode(selected)
    return selected
