from __future__ import annotations

RESERVED_SINGLETON_ROLE_NAMES = {
    "users",
    "flatpak",
    "snap",
    "apt_config",
    "dnf_config",
    "firewall_runtime",
    "etc_custom",
    "usr_local_custom",
    "extra_paths",
    "common_packages",
}


def avoid_reserved_role_name(role_name: str, *, prefix: str) -> str:
    """Return a role name that cannot collide with singleton roles.

    Singleton roles are generated once per manifest from dedicated top-level
    state sections. Package and service roles can naturally have the same names
    as those singletons, e.g. the OS package named ``flatpak``. Prefix those
    generated package/service roles so they cannot overwrite singleton role
    directories during manifestation.
    """
    if role_name in RESERVED_SINGLETON_ROLE_NAMES:
        return f"{prefix}_{role_name}"
    return role_name
