import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SIGNATURE_ALGORITHM = "ed25519"


def canonical_manifest_payload(payload):
    manifest = dict(payload or {})
    manifest.pop("signature", None)
    return manifest


def canonical_manifest_bytes(payload):
    manifest = canonical_manifest_payload(payload)
    return json.dumps(
        manifest,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_private_key(path):
    with open(path, "rb") as handle:
        return serialization.load_pem_private_key(handle.read(), password=None)


def load_public_key(path):
    with open(path, "rb") as handle:
        return serialization.load_pem_public_key(handle.read())


def save_private_key(path, private_key):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def save_public_key(path, public_key):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def generate_signing_keypair(private_key_path, public_key_path):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    save_private_key(private_key_path, private_key)
    save_public_key(public_key_path, public_key)
    return private_key, public_key


def ensure_signing_keypair(private_key_path, public_key_path):
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        return load_private_key(private_key_path), load_public_key(public_key_path), False

    private_key, public_key = generate_signing_keypair(private_key_path, public_key_path)
    return private_key, public_key, True


def sign_manifest(payload, private_key):
    signature = private_key.sign(canonical_manifest_bytes(payload))
    return base64.b64encode(signature).decode("ascii")


def verify_manifest_signature(payload, signature, public_key):
    if not signature:
        return False

    try:
        signature_bytes = base64.b64decode(str(signature).encode("ascii"), validate=True)
        public_key.verify(signature_bytes, canonical_manifest_bytes(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_key_id(public_key):
    if isinstance(public_key, Ed25519PrivateKey):
        public_key = public_key.public_key()

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]
