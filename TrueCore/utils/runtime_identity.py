from __future__ import annotations

from TrueCore.utils.install_mode import (
    get_primary_update_channel,
    get_reference_update_channel,
    is_dev_install,
)
from TrueCore.utils.private_dev_channel import load_private_dev_channel_config
from TrueCore.utils.runtime_info import get_version


def resolve_runtime_identity(*, version=None, install_profile=None, private_dev_channel=None):
    resolved_version = str(version or get_version() or "").strip()
    profile = dict(install_profile or {})
    private_channel = dict(private_dev_channel or load_private_dev_channel_config() or {})

    embedded_dev_build = resolved_version.lower().startswith("dv")

    if embedded_dev_build:
        private_dev_enabled = bool(private_channel.get("enabled"))
        profile_primary_channel = get_primary_update_channel(profile)
        inferred_dev_install = (
            is_dev_install(profile)
            or private_dev_enabled
            or profile_primary_channel == "dev"
        )

        promoted_install_profile = {
            "machine_role": "dev",
            "update_channel": "dev",
            "show_production_reference": True,
            "developer_tools_enabled": True,
        }

        return {
            "version": resolved_version,
            "embedded_dev_build": True,
            "inferred_dev_install": inferred_dev_install,
            "should_promote_install_profile": (
                inferred_dev_install and (
                    not is_dev_install(profile)
                    or not bool(profile.get("developer_tools_enabled"))
                    or profile_primary_channel != "dev"
                )
            ),
            "promoted_install_profile": promoted_install_profile,
            "machine_role": "dev",
            "primary_update_channel": "dev",
            "reference_update_channel": get_reference_update_channel(profile),
            "developer_tools_enabled": True,
        }

    return {
        "version": resolved_version,
        "embedded_dev_build": False,
        "inferred_dev_install": False,
        "should_promote_install_profile": False,
        "promoted_install_profile": None,
        "machine_role": "office",
        "primary_update_channel": "production",
        "reference_update_channel": None,
        "developer_tools_enabled": False,
    }
