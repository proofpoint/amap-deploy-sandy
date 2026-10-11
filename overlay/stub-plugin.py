"""A STUB transport plugin, for exercising the overlay plumbing only.

It implements nothing, and importing it fails, so it can never be loaded as
a working transport by mistake. Its sha256 is a known value that `verify`
reports as the stub, never as a production pin: the production overlay pins
a reviewed plugin artifact by its own digest.
"""

raise ImportError("this is the overlay plumbing's stub plugin; it carries no transport")
