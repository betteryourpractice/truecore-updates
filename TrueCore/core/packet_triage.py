import os
import shutil

from TrueCore.core.case_memory import record_packet_event
from TrueCore.utils.logging_system import log_event

def triage_packet(packet_path, score, result=None):

    base_dir = os.path.join(os.path.expanduser("~"), "Desktop")

    approved = os.path.join(base_dir, "Approved_Packets")
    review = os.path.join(base_dir, "Needs_Review")
    rejected = os.path.join(base_dir, "Rejected")

    os.makedirs(approved, exist_ok=True)
    os.makedirs(review, exist_ok=True)
    os.makedirs(rejected, exist_ok=True)

    if score >= 90:
        dest = approved
        status = "approved"
    elif score >= 70:
        dest = review
        status = "needs_review"
    else:
        dest = rejected
        status = "rejected"
    try:
        shutil.copy(packet_path, os.path.join(dest, os.path.basename(packet_path)))
        log_event("packet_triaged", f"{packet_path} | status={status}")

        if result:
            record_packet_event(
                packet_path,
                result,
                event_type="triage",
                event_status=status,
                note=f"Packet routed to {os.path.basename(dest)}",
                details={
                    "destination": dest,
                    "score": score,
                },
            )
    except Exception:
        pass
