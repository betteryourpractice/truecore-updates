from __future__ import annotations

from TrueCore.ui.pyside_gui.dev_tools_controls import (
    build_signature_image_html,
    build_typed_signature_image_bytes,
    resolve_signature_image_bytes,
)
from TrueCore.ui.pyside_gui.dev_tools_payload_logic import sanitize_packet_builder_text


SIGNATURE_IMAGE_FIELDS = {
    "patient_signature_name": "patient_signature_image",
    "office_staff_signature": "office_staff_signature_image",
    "va10172_signature_text": "va10172_signature_image",
}


SIGNATURE_ROLE_LABELS = {
    "patient_signature_name": "Veteran / patient signature",
    "office_staff_signature": "program user / office staff signature",
    "va10172_signature_text": "CCN ordering provider signature",
}


def signature_image_bytes(payload, field_name):
    return resolve_signature_image_bytes(
        payload,
        field_name,
        image_fields=SIGNATURE_IMAGE_FIELDS,
        sanitize_text_fn=sanitize_packet_builder_text,
    )


def signature_image_html(payload, field_name, width_px=220, height_px=54):
    return build_signature_image_html(
        payload,
        field_name,
        image_fields=SIGNATURE_IMAGE_FIELDS,
        sanitize_text_fn=sanitize_packet_builder_text,
        width_px=width_px,
        height_px=height_px,
    )


def typed_signature_image_bytes(text):
    return build_typed_signature_image_bytes(text, sanitize_packet_builder_text)
