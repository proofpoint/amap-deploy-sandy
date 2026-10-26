"""Authored fleet-wide Codex conversation choice; portable and host compatible."""

POLICY_KEY = "codex_conversation_mode"
EXPORT = "AMAP_CODEX_CONVERSATION_MODE"
MODES = ("separate", "unified")


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
    mode(selected)
    return selected
