from __future__ import annotations

# The version module is hard to test fully because it uses importlib.metadata
# which is difficult to mock. We'll test what we can.


def test_get_enroll_version_returns_string():
    from enroll.version import get_enroll_version

    result = get_enroll_version()
    assert isinstance(result, str)
    assert len(result) > 0
