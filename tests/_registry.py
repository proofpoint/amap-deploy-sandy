"""The test overlay: neutral stand-ins for the host registry's identifiers.

The real identifiers live in the deployment overlay, which is private, and
the replayed fixture `tests/fixtures/registry_cli.json` carries these
stand-ins in their place.
"""

import json
from pathlib import Path

import host_adapter as ha

IDS = ha.Identifiers(interface="example-registry.adapter/1", module="example_registry",
                     operator_module="example_registry.opverbs",
                     name_schema="example-registry.name/1")


def write_overlay(path: Path, **override) -> Path:
    """An overlay file holding IDS, with `override` replacing its keys."""
    section = {k: getattr(IDS, k) for k in ha.IDENTIFIER_KEYS}
    section.update(override)
    path.write_text(json.dumps({ha.OVERLAY_SECTION: section}))
    return path
