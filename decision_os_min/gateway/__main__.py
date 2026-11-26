"""`python -m decision_os_min.gateway ...` is the same CLI as `decision-os`.

Wrapped MCP configs call the gateway this way (with an absolute interpreter
path) so they keep working when the client app runs with a minimal PATH.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
