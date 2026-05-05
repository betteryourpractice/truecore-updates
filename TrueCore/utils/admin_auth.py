import hashlib
import hmac
import json
import os

from TrueCore.utils.runtime_info import resource_path


ADMIN_AUTH_PATH = resource_path("dev_system/admin_auth.json")
DEFAULT_ADMIN_AUTH = {
    "version": 1,
    "algorithm": "pbkdf2_sha256",
    "iterations": 200000,
    "salt": "18d3d1c1fdb4af3f0e56a52f5b398988",
    "password_hash": "0b0afba9a1ccbe5a5663e25376cc03a67e36f2541077add10929f4512005d1bb",
}


def _normalize_auth_config(data):
    payload = dict(DEFAULT_ADMIN_AUTH)
    payload.update(dict(data or {}))
    payload["iterations"] = int(payload.get("iterations") or DEFAULT_ADMIN_AUTH["iterations"])
    payload["version"] = int(payload.get("version") or DEFAULT_ADMIN_AUTH["version"])
    payload["algorithm"] = str(payload.get("algorithm") or DEFAULT_ADMIN_AUTH["algorithm"]).strip().lower()
    payload["salt"] = str(payload.get("salt") or DEFAULT_ADMIN_AUTH["salt"]).strip().lower()
    payload["password_hash"] = str(payload.get("password_hash") or DEFAULT_ADMIN_AUTH["password_hash"]).strip().lower()
    return payload


def ensure_admin_auth_config():
    os.makedirs(os.path.dirname(ADMIN_AUTH_PATH), exist_ok=True)
    if os.path.exists(ADMIN_AUTH_PATH):
        return ADMIN_AUTH_PATH

    with open(ADMIN_AUTH_PATH, "w", encoding="utf-8") as handle:
        json.dump(DEFAULT_ADMIN_AUTH, handle, indent=4)
    return ADMIN_AUTH_PATH


def load_admin_auth_config():
    ensure_admin_auth_config()

    try:
        with open(ADMIN_AUTH_PATH, "r", encoding="utf-8") as handle:
            return _normalize_auth_config(json.load(handle))
    except Exception:
        return dict(DEFAULT_ADMIN_AUTH)


def hash_admin_password(password, *, salt, iterations):
    secret = str(password or "").encode("utf-8")
    salt_bytes = bytes.fromhex(str(salt or ""))
    digest = hashlib.pbkdf2_hmac("sha256", secret, salt_bytes, int(iterations or DEFAULT_ADMIN_AUTH["iterations"]))
    return digest.hex()


def verify_admin_password(password):
    config = load_admin_auth_config()
    expected = config.get("password_hash") or DEFAULT_ADMIN_AUTH["password_hash"]
    candidate = hash_admin_password(
        password,
        salt=config.get("salt"),
        iterations=config.get("iterations"),
    )
    return hmac.compare_digest(candidate, expected)
