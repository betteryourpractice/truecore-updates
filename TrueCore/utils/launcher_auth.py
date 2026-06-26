import hashlib
import hmac
import json
import os
import secrets

from TrueCore.utils.runtime_info import office_runtime_data_path


LAUNCHER_AUTH_PATH = office_runtime_data_path("launcher_auth.json")
DEFAULT_LAUNCHER_AUTH = {
    "version": 1,
    "username": "truevalour",
    "algorithm": "pbkdf2_sha256",
    "iterations": 200000,
    "salt": "4f8d72c0d4af6a2c7d53d7f0fd5a109e",
    "password_hash": "d763262d22a8f0c3f1ca1f19ca33d5308549b5c5d6f957cf8e9c16bcf27807a4",
}


def normalize_launcher_username(username):
    return " ".join(str(username or "").strip().lower().split())


def _normalize_auth_config(data):
    payload = dict(DEFAULT_LAUNCHER_AUTH)
    payload.update(dict(data or {}))
    payload["version"] = int(payload.get("version") or DEFAULT_LAUNCHER_AUTH["version"])
    payload["username"] = normalize_launcher_username(payload.get("username"))
    payload["algorithm"] = str(payload.get("algorithm") or DEFAULT_LAUNCHER_AUTH["algorithm"]).strip().lower()
    payload["iterations"] = int(payload.get("iterations") or DEFAULT_LAUNCHER_AUTH["iterations"])
    payload["salt"] = str(payload.get("salt") or DEFAULT_LAUNCHER_AUTH["salt"]).strip().lower()
    payload["password_hash"] = str(payload.get("password_hash") or DEFAULT_LAUNCHER_AUTH["password_hash"]).strip().lower()
    return payload


def ensure_launcher_auth_config():
    os.makedirs(os.path.dirname(LAUNCHER_AUTH_PATH), exist_ok=True)
    if os.path.exists(LAUNCHER_AUTH_PATH):
        return LAUNCHER_AUTH_PATH

    with open(LAUNCHER_AUTH_PATH, "w", encoding="utf-8") as handle:
        json.dump(DEFAULT_LAUNCHER_AUTH, handle, indent=4)

    return LAUNCHER_AUTH_PATH


def load_launcher_auth_config():
    ensure_launcher_auth_config()

    try:
        with open(LAUNCHER_AUTH_PATH, "r", encoding="utf-8") as handle:
            return _normalize_auth_config(json.load(handle))
    except Exception:
        return dict(DEFAULT_LAUNCHER_AUTH)


def save_launcher_auth_config(data):
    payload = _normalize_auth_config(data)
    os.makedirs(os.path.dirname(LAUNCHER_AUTH_PATH), exist_ok=True)
    with open(LAUNCHER_AUTH_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4)
    return payload


def hash_launcher_password(password, *, salt, iterations):
    secret = str(password or "").encode("utf-8")
    salt_bytes = bytes.fromhex(str(salt or ""))
    digest = hashlib.pbkdf2_hmac("sha256", secret, salt_bytes, int(iterations or DEFAULT_LAUNCHER_AUTH["iterations"]))
    return digest.hex()


def verify_launcher_credentials(username, password):
    config = load_launcher_auth_config()
    expected_username = config.get("username") or DEFAULT_LAUNCHER_AUTH["username"]
    expected_hash = config.get("password_hash") or DEFAULT_LAUNCHER_AUTH["password_hash"]

    provided_username = normalize_launcher_username(username)
    if not hmac.compare_digest(provided_username, normalize_launcher_username(expected_username)):
        return False

    candidate = hash_launcher_password(
        password,
        salt=config.get("salt"),
        iterations=config.get("iterations"),
    )

    return hmac.compare_digest(candidate, expected_hash)


def launcher_auth_uses_default_credentials(config=None):
    payload = _normalize_auth_config(config or load_launcher_auth_config())
    defaults = _normalize_auth_config(DEFAULT_LAUNCHER_AUTH)
    return (
        payload.get("username") == defaults.get("username")
        and payload.get("password_hash") == defaults.get("password_hash")
        and payload.get("salt") == defaults.get("salt")
    )


def update_launcher_credentials(username, password, *, iterations=None):
    normalized_username = normalize_launcher_username(username)
    if not normalized_username:
        raise ValueError("Launcher username is required.")

    secret = str(password or "")
    if not secret.strip():
        raise ValueError("Launcher password is required.")

    iteration_count = int(iterations or DEFAULT_LAUNCHER_AUTH["iterations"])
    salt = secrets.token_hex(16)
    payload = {
        "version": DEFAULT_LAUNCHER_AUTH["version"],
        "username": normalized_username,
        "algorithm": DEFAULT_LAUNCHER_AUTH["algorithm"],
        "iterations": iteration_count,
        "salt": salt,
        "password_hash": hash_launcher_password(secret, salt=salt, iterations=iteration_count),
    }
    return save_launcher_auth_config(payload)
