from __future__ import annotations

import os
import subprocess


def find_word_executable():
    candidates = [
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        r"C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE",
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WindowsApps", "WINWORD.EXE"),
    ]
    for candidate in candidates:
        normalized = str(candidate or "").strip()
        if normalized and os.path.exists(normalized):
            return normalized
    return ""


def convert_docx_to_pdf_via_word(docx_path, pdf_path):
    docx_path = os.path.abspath(str(docx_path or "").strip())
    pdf_path = os.path.abspath(str(pdf_path or "").strip())
    if not docx_path or not os.path.exists(docx_path):
        raise RuntimeError("The DOCX preview source could not be found.")
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
    docx_literal = docx_path.replace("'", "''")
    pdf_literal = pdf_path.replace("'", "''")
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        "$word = $null\n"
        "$doc = $null\n"
        f"$docxPath = '{docx_literal}'\n"
        f"$pdfPath = '{pdf_literal}'\n"
        "try {\n"
        "  $word = New-Object -ComObject Word.Application\n"
        "  $word.Visible = $false\n"
        "  $word.DisplayAlerts = 0\n"
        "  $doc = $word.Documents.Open($docxPath, $false, $true)\n"
        "  $doc.ExportAsFixedFormat($pdfPath, 17)\n"
        "} finally {\n"
        "  if ($doc) { $doc.Close($false) | Out-Null }\n"
        "  if ($word) { $word.Quit() | Out-Null }\n"
        "}\n"
    )
    startupinfo = None
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        startupinfo=startupinfo,
        check=False,
    )
    if completed.returncode != 0 or not os.path.exists(pdf_path):
        message = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(message or "Microsoft Word could not convert the DOCX preview to PDF.")
    return pdf_path
