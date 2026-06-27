from __future__ import annotations

import json
import os

from TrueCore.utils.runtime_info import resource_path, runtime_data_path


def deep_merge(base, updates):
    merged = dict(base or {})
    for key, value in dict(updates or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged.get(key) or {}, value)
        else:
            merged[key] = value
    return merged


def default_export_dir():
    home = os.path.expanduser("~")
    for candidate in ("Desktop", "Documents", "Downloads"):
        path = os.path.join(home, candidate)
        if os.path.isdir(path):
            return path
    return home


def default_va_form_10172_template_path():
    candidates = [
        resource_path("ui/pyside_gui/assets/VA_Form_10-10172.pdf"),
        r"C:\Users\aaron\OneDrive\Desktop\TrueDisc_VA_Complete_Submission_Program_v1.0\03_Patient_Submission_Templates\VA_Form_10-10172.pdf",
    ]
    for path in candidates:
        normalized = str(path or "").strip()
        if normalized and os.path.exists(normalized):
            return normalized
    return ""


DEFAULT_DEV_TOOLS_CONFIG_PATH = runtime_data_path("dev_system", "dev_tools_config.json")


def default_dev_tools_config():
    return {
        "legacy_gallery_paths": [],
        "packet_builder_export_dir": default_export_dir(),
        "va_form_10172_template_path": default_va_form_10172_template_path(),
    }


def normalize_dev_tools_config(
    data=None,
    *,
    default_config=None,
    default_export_dir_fn=default_export_dir,
    default_va_form_10172_template_path_fn=default_va_form_10172_template_path,
):
    payload = deep_merge(default_config or default_dev_tools_config(), data or {})
    legacy_paths = []
    seen_paths = set()
    for raw_path in list(payload.get("legacy_gallery_paths") or []):
        normalized = str(raw_path or "").strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen_paths:
            continue
        seen_paths.add(key)
        legacy_paths.append(normalized)
    payload["legacy_gallery_paths"] = legacy_paths
    export_dir = str(payload.get("packet_builder_export_dir") or "").strip() or default_export_dir_fn()
    payload["packet_builder_export_dir"] = export_dir
    template_path = str(payload.get("va_form_10172_template_path") or "").strip()
    if not template_path:
        template_path = default_va_form_10172_template_path_fn()
    payload["va_form_10172_template_path"] = template_path
    return payload


def load_dev_tools_config(
    *,
    config_path=DEFAULT_DEV_TOOLS_CONFIG_PATH,
    default_config=None,
    normalize_dev_tools_config_fn=normalize_dev_tools_config,
):
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    if not os.path.exists(config_path):
        save_dev_tools_config(
            {},
            config_path=config_path,
            default_config=default_config,
            normalize_dev_tools_config_fn=normalize_dev_tools_config_fn,
        )
    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            return normalize_dev_tools_config_fn(json.load(handle), default_config=default_config)
    except Exception:
        return normalize_dev_tools_config_fn({}, default_config=default_config)


def save_dev_tools_config(
    data,
    *,
    config_path=DEFAULT_DEV_TOOLS_CONFIG_PATH,
    default_config=None,
    normalize_dev_tools_config_fn=normalize_dev_tools_config,
):
    payload = normalize_dev_tools_config_fn(data, default_config=default_config)
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4)
    return payload


def update_dev_tools_config(
    changes,
    *,
    config_path=DEFAULT_DEV_TOOLS_CONFIG_PATH,
    default_config=None,
    load_dev_tools_config_fn=load_dev_tools_config,
    save_dev_tools_config_fn=save_dev_tools_config,
):
    return save_dev_tools_config_fn(
        deep_merge(
            load_dev_tools_config_fn(
                config_path=config_path,
                default_config=default_config,
            ),
            changes or {},
        ),
        config_path=config_path,
        default_config=default_config,
    )
