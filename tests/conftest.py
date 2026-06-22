import sys
from pathlib import Path

import pytest

# Ensure repository root is on sys.path so `import enroll` resolves to the local package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _disable_cli_root_path_prompt_by_default(monkeypatch):
    """Keep CLI tests deterministic when the test runner itself runs as root.

    Individual tests that cover the root PATH guard can override this monkeypatch.
    """

    import enroll.cli as cli

    monkeypatch.setattr(cli, "_is_effective_root", lambda: False)
