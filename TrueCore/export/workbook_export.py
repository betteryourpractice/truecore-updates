import time
import os
from openpyxl import load_workbook, Workbook


# -------------------------------------------------
# WORKBOOK LOCATION
# -------------------------------------------------

WORKBOOK_PATH = os.path.join(os.getcwd(), "TrueCore", "Outputs", "TrueValour Operations.xlsx")


# -------------------------------------------------
# CREATE WORKBOOK IF MISSING
# -------------------------------------------------

def create_workbook_if_missing(path):

    if os.path.exists(path):
        return

    try:

        os.makedirs(os.path.dirname(path), exist_ok=True)

        wb = Workbook()
        ws = wb.active
        ws.title = "Patients"

        headers = [
            "ICN",
            "Patient Name",
            "DOB",
            "Authorization",
            "Ordering Doctor",
            "",
            "Treatment",
            "ICD Codes",
            "",
            "",
            "",
            "Packet Link"
        ]

        ws.append(headers)

        wb.save(path)

        print("Workbook created:", path)

    except Exception as e:
        print("Failed to create workbook:", e)


# -------------------------------------------------
# EXPORT PATIENT
# -------------------------------------------------

def export_patient(fields, packet_path):

    # Ensure workbook exists
    create_workbook_if_missing(WORKBOOK_PATH)

    if not os.path.exists(WORKBOOK_PATH):
        return

    try:

        wb = load_workbook(WORKBOOK_PATH)
        ws = wb["Patients"]

        icn = fields.get("icn")
        auth = fields.get("authorization_number")

        # Duplicate protection
        for r in range(2, ws.max_row + 1):

            if ws[f"A{r}"].value == icn or ws[f"D{r}"].value == auth:
                print("Duplicate patient detected. Skipping export.")
                return

        row = ws.max_row + 1

        codes = fields.get("icd_codes", [])

        ws[f"A{row}"] = icn
        ws[f"B{row}"] = fields.get("patient_name")
        ws[f"C{row}"] = fields.get("dob")
        ws[f"D{row}"] = auth
        ws[f"E{row}"] = fields.get("ordering_doctor")

        if any(code.upper().startswith("M54") for code in codes):
            ws[f"G{row}"] = "Fibrin"

        ws[f"H{row}"] = ", ".join(codes)

        cell = ws[f"L{row}"]
        cell.value = "Open Packet"
        cell.hyperlink = os.path.abspath(packet_path)
        cell.style = "Hyperlink"

        for attempt in range(3):

            try:
                wb.save(WORKBOOK_PATH)
                break

            except PermissionError:

                if attempt < 2:
                    time.sleep(2)
                else:
                    print("Excel workbook is open. Close it and retry export.")

    except Exception as e:

        print("Workbook export error:", e)