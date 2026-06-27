from __future__ import annotations

import os

from PySide6.QtCore import QObject, Signal


class ExactPreviewRenderWorker(QObject):
    finished = Signal(str, str)
    failed = Signal(str, str)

    def __init__(
        self,
        *,
        render_key,
        payload,
        output_dir,
        is_va_10172_fn,
        write_pdf_fn,
        write_word_fn,
        convert_docx_to_pdf_fn,
    ):
        super().__init__()
        self.render_key = str(render_key or "").strip()
        self.payload = dict(payload or {})
        self.output_dir = str(output_dir or "").strip()
        self.is_va_10172_fn = is_va_10172_fn
        self.write_pdf_fn = write_pdf_fn
        self.write_word_fn = write_word_fn
        self.convert_docx_to_pdf_fn = convert_docx_to_pdf_fn

    def run(self):
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            pdf_path = os.path.join(self.output_dir, f"{self.render_key}.pdf")
            if self.is_va_10172_fn(self.payload.get("packet_profile")):
                self.write_pdf_fn(pdf_path, self.payload)
            else:
                docx_path = os.path.join(self.output_dir, f"{self.render_key}.docx")
                self.write_word_fn(docx_path, self.payload)
                self.convert_docx_to_pdf_fn(docx_path, pdf_path)
            self.finished.emit(self.render_key, pdf_path)
        except Exception as exc:
            self.failed.emit(self.render_key, str(exc))


class PacketExportWorker(QObject):
    finished = Signal(dict)
    failed = Signal(str)

    def __init__(self, *, request, run_export_fn):
        super().__init__()
        self.request = dict(request or {})
        self.run_export_fn = run_export_fn

    def run(self):
        try:
            result = self.run_export_fn(self.request)
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))
