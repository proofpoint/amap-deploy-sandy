"""The sandy capabilities S6 renders the amap feature for, at the lock's sandy pin (ruling W7-R1-R2-DESIGN, R2 (a)).

S6 runs before S7 installs sandy, so the feature manifest is rendered for these reviewed constants, and S7 imports
them (never copies) and checks the installed sandy's `--print-schema` against them after install. A sandy that
answers otherwise refuses at S7.
- SCHEMA_VERSION: `--print-schema`'s `schema_version`, compared by membership as this repo's SANDY_SCHEMA_VERSIONS
  compares it (tests/test_a2_s6_agreement.py holds it to that set).
- MANIFEST_KEYS: top-level manifest keys the rendered feature relies on, each in `manifest.top_level_keys`.
- RECEIVES_VALUES: the `receives` values the feature names, each in `manifest.receives_values`.
"""

SCHEMA_VERSION = 4
MANIFEST_KEYS = ("receives", "agent_wrapper")
RECEIVES_VALUES = ("cross_session",)
