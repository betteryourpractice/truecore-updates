from __future__ import annotations

import base64
import re

from PySide6.QtCore import QByteArray, QBuffer, QRectF, QSignalBlocker, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QImage, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


def build_typed_signature_image_bytes(text, sanitize_text_fn):
    cleaned = sanitize_text_fn(text)
    if not cleaned:
        return b""
    image = QImage(420, 110, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setRenderHint(QPainter.TextAntialiasing, True)
    font_candidates = ["Segoe Script", "Lucida Handwriting", "Brush Script MT", "Segoe Print", "Comic Sans MS"]
    font = QFont(font_candidates[0], 28)
    for family in font_candidates:
        candidate = QFont(family, 28)
        metrics = QFontMetrics(candidate)
        if metrics.horizontalAdvance(cleaned) <= 380:
            font = candidate
            break
    painter.setFont(font)
    painter.setPen(QColor("#111827"))
    painter.drawText(QRectF(12, 10, 396, 86), Qt.AlignLeft | Qt.AlignVCenter, cleaned)
    painter.end()
    array = QByteArray()
    buffer = QBuffer(array)
    buffer.open(QBuffer.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(array)


def resolve_signature_image_bytes(payload, field_name, *, image_fields, sanitize_text_fn):
    image_field = dict(image_fields or {}).get(field_name, field_name)
    raw = str((payload or {}).get(image_field) or "").strip()
    if not raw:
        typed_text = sanitize_text_fn((payload or {}).get(field_name) or "")
        if typed_text:
            return build_typed_signature_image_bytes(typed_text, sanitize_text_fn)
        return b""
    try:
        return base64.b64decode(raw)
    except Exception:
        return b""


def build_signature_image_html(payload, field_name, *, image_fields, sanitize_text_fn, width_px=220, height_px=54):
    image_bytes = resolve_signature_image_bytes(
        payload,
        field_name,
        image_fields=image_fields,
        sanitize_text_fn=sanitize_text_fn,
    )
    if not image_bytes:
        return ""
    raw = base64.b64encode(image_bytes).decode("ascii")
    return (
        f"<img src='data:image/png;base64,{raw}' "
        f"style='max-width:{int(width_px)}px; max-height:{int(height_px)}px; display:block;'/>"
    )


class SignaturePadWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(420, 150)
        self.setStyleSheet("background:#FFFFFF; border:1px solid #C9D4E2; border-radius:8px;")
        self._pixmap = QPixmap(self.size())
        self._pixmap.fill(Qt.white)
        self._last_point = None
        self._drawing = False

    def resizeEvent(self, event):
        if self.width() <= 0 or self.height() <= 0:
            return
        new_pixmap = QPixmap(self.size())
        new_pixmap.fill(Qt.white)
        if not self._pixmap.isNull():
            painter = QPainter(new_pixmap)
            painter.drawPixmap(0, 0, self._pixmap)
            painter.end()
        self._pixmap = new_pixmap
        super().resizeEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.drawPixmap(0, 0, self._pixmap)
        painter.end()
        super().paintEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drawing = True
            self._last_point = event.position().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._drawing and self._last_point is not None:
            painter = QPainter(self._pixmap)
            painter.setRenderHint(QPainter.Antialiasing, True)
            painter.setPen(QPen(QColor("#111827"), 2.2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            current_point = event.position().toPoint()
            painter.drawLine(self._last_point, current_point)
            painter.end()
            self._last_point = current_point
            self.update()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drawing = False
            self._last_point = None
        super().mouseReleaseEvent(event)

    def clear_signature(self):
        self._pixmap.fill(Qt.white)
        self.update()

    def load_signature_bytes(self, data):
        self.clear_signature()
        if not data:
            return
        image = QImage()
        if image.loadFromData(data, "PNG"):
            scaled = QPixmap.fromImage(image).scaled(
                self.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
            self._pixmap.fill(Qt.white)
            painter = QPainter(self._pixmap)
            x = max(0, (self.width() - scaled.width()) // 2)
            y = max(0, (self.height() - scaled.height()) // 2)
            painter.drawPixmap(x, y, scaled)
            painter.end()
            self.update()

    def export_signature_base64(self):
        image = self._pixmap.toImage()
        if image.isNull():
            return ""
        nonwhite = False
        step_x = max(1, image.width() // 40)
        step_y = max(1, image.height() // 20)
        for x in range(0, image.width(), step_x):
            for y in range(0, image.height(), step_y):
                if image.pixelColor(x, y) != QColor(Qt.white):
                    nonwhite = True
                    break
            if nonwhite:
                break
        if not nonwhite:
            return ""
        array = QByteArray()
        buffer = QBuffer(array)
        buffer.open(QBuffer.WriteOnly)
        self._pixmap.save(buffer, "PNG")
        return bytes(array.toBase64()).decode("ascii")


class SignatureCaptureDialog(QDialog):
    def __init__(self, label_text="", existing_base64="", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Draw Signature")
        self.setModal(True)
        self.resize(520, 260)
        self.setStyleSheet("QDialog { background:#0F1823; color:#E5E7EB; }")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        help_label = QLabel(label_text or "Draw the signature below, then accept or reset it.")
        help_label.setWordWrap(True)
        help_label.setStyleSheet("color:#E5E7EB;")
        layout.addWidget(help_label)

        self.pad = SignaturePadWidget()
        layout.addWidget(self.pad, stretch=1)
        if existing_base64:
            try:
                self.pad.load_signature_bytes(base64.b64decode(existing_base64))
            except Exception:
                self.pad.load_signature_bytes(b"")

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        self.cancel_button = QPushButton("Cancel")
        self.reset_button = QPushButton("Reset")
        self.accept_button = QPushButton("Accept")
        for button in [self.cancel_button, self.reset_button, self.accept_button]:
            button.setMinimumWidth(100)
        self.cancel_button.clicked.connect(self.reject)
        self.reset_button.clicked.connect(self.pad.clear_signature)
        self.accept_button.clicked.connect(self.accept)
        button_row.addWidget(self.cancel_button)
        button_row.addWidget(self.reset_button)
        button_row.addWidget(self.accept_button)
        layout.addLayout(button_row)

    def signature_base64(self):
        return self.pad.export_signature_base64()


class MultiSelectPromptDialog(QDialog):
    def __init__(self, title, options, selected_values=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title or "Choose Options")
        self.setModal(True)
        self.resize(430, 330)
        self.setStyleSheet("QDialog { background:#0F1823; color:#E5E7EB; }")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        help_label = QLabel("Choose one or more prompts that fit this packet. Leave everything clear to keep the field on Auto.")
        help_label.setWordWrap(True)
        help_label.setStyleSheet("color:#BFD0E3;")
        layout.addWidget(help_label)

        self._checks = []
        selected = {str(value or "").strip() for value in (selected_values or [])}
        options_scroll = QScrollArea()
        options_scroll.setWidgetResizable(True)
        options_scroll.setFrameShape(QFrame.NoFrame)
        options_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        options_container = QWidget()
        options_layout = QVBoxLayout(options_container)
        options_layout.setContentsMargins(0, 0, 0, 0)
        options_layout.setSpacing(8)
        for option in options or []:
            checkbox = QCheckBox(str(option))
            checkbox.setChecked(str(option) in selected)
            checkbox.setStyleSheet("QCheckBox { color:#EAF2FF; font-size:14px; padding:2px 0; }")
            options_layout.addWidget(checkbox)
            self._checks.append(checkbox)
        options_layout.addStretch(1)
        options_scroll.setWidget(options_container)
        layout.addWidget(options_scroll, stretch=1)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        clear_button = QPushButton("Reset to Auto")
        clear_button.clicked.connect(self._clear_all)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        accept_button = QPushButton("Accept")
        accept_button.clicked.connect(self.accept)
        for button in (clear_button, cancel_button, accept_button):
            button_metrics = QFontMetrics(button.font())
            button_width = max(84, min(132, button_metrics.horizontalAdvance(button.text()) + 34))
            button.setFixedHeight(32)
            button.setFixedWidth(button_width)
            button.setStyleSheet(
                "QPushButton {"
                "background-color:#1D2A3A; color:#FFFFFF; border:1px solid #34506B; border-radius:8px; "
                "padding:4px 10px; font-size:12px; font-weight:600; }"
                "QPushButton:hover { background-color:#223246; }"
            )
            button_row.addWidget(button)
        layout.addLayout(button_row)

    def _clear_all(self):
        for checkbox in self._checks:
            checkbox.setChecked(False)

    def selected_items(self):
        return [checkbox.text() for checkbox in self._checks if checkbox.isChecked()]


class MultiSelectPromptField(QWidget):
    textChanged = Signal(str)

    def __init__(self, title, options, parent=None):
        super().__init__(parent)
        self._title = str(title or "Choose Prompts")
        self._options = [str(option) for option in (options or [])]
        self._selected = []
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.summary_input = QLineEdit()
        self.summary_input.setReadOnly(True)
        self.summary_input.setPlaceholderText("Auto")
        self.summary_input.setMinimumWidth(0)
        layout.addWidget(self.summary_input, stretch=1)

        self.choose_button = QPushButton("Choose")
        self.choose_button.setFixedHeight(32)
        self.choose_button.setMaximumWidth(88)
        self.choose_button.setStyleSheet(
            "QPushButton {"
            "background-color:#1D2A3A; color:#FFFFFF; border:1px solid #34506B; border-radius:8px; "
            "padding:4px 10px; font-size:12px; font-weight:600; }"
            "QPushButton:hover { background-color:#223246; }"
        )
        self.choose_button.clicked.connect(self._open_picker)
        layout.addWidget(self.choose_button, 0)
        self._refresh_summary(emit_signal=False)

    def _open_picker(self):
        dialog = MultiSelectPromptDialog(self._title, self._options, self._selected, parent=self)
        if dialog.exec() != QDialog.Accepted:
            return
        self._selected = dialog.selected_items()
        self._refresh_summary()

    def _refresh_summary(self, emit_signal=True):
        summary = "Auto" if not self._selected else "; ".join(self._selected)
        with QSignalBlocker(self.summary_input):
            self.summary_input.setText(summary)
        self.summary_input.setToolTip(summary)
        if emit_signal:
            self.textChanged.emit(self.text())

    def text(self):
        return "Auto" if not self._selected else " | ".join(self._selected)

    def setText(self, value):
        raw = str(value or "").strip()
        if not raw or raw.lower() == "auto":
            self._selected = []
        else:
            pieces = [part.strip() for part in raw.replace("\n", "|").split("|") if part.strip()]
            option_map = {re.sub(r"\s+", " ", option).strip().lower(): option for option in self._options}
            selected = []
            for piece in pieces:
                key = re.sub(r"\s+", " ", piece).strip().lower()
                selected.append(option_map.get(key, piece))
            deduped = []
            for item in selected:
                if item not in deduped:
                    deduped.append(item)
            self._selected = deduped
        self._refresh_summary()


class AutoSizingPlainTextEdit(QPlainTextEdit):
    def __init__(self, minimum_height=140, parent=None):
        super().__init__(parent)
        self._minimum_editor_height = int(minimum_height or 140)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.textChanged.connect(self.update_content_height)
        QTimer.singleShot(0, self.update_content_height)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        QTimer.singleShot(0, self.update_content_height)

    def update_content_height(self):
        document = self.document()
        layout = document.documentLayout()
        if layout is None:
            return
        content_height = layout.documentSize().height()
        margin = document.documentMargin()
        frame = self.frameWidth() * 2
        target_height = int(max(self._minimum_editor_height, content_height + (margin * 2) + frame + 8))
        self.setFixedHeight(target_height)
