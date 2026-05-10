import json
import os

from PySide6.QtCharts import (
    QBarCategoryAxis,
    QBarSeries,
    QBarSet,
    QChart,
    QChartView,
    QLineSeries,
    QPieSeries,
    QValueAxis,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
)

from TrueCore.core.case_memory import get_recent_packet_runs
from TrueCore.core.cross_office_benchmarking import (
    list_imported_snapshot_files,
    load_network_rollup,
)
from TrueCore.core.cross_office_learning import build_cross_office_snapshot
from TrueCore.core.office_rollout import (
    load_office_profile,
    record_office_profile_confirmed,
    update_office_profile,
)


class MainWindowAdminMixin:

    def build_admin_action_grid(self, actions, columns=3):

        host = QWidget()
        layout = QGridLayout(host)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(10)
        layout.setVerticalSpacing(10)

        normalized_columns = max(1, int(columns or 1))

        for index, action in enumerate(actions or []):
            label = action[0]
            handler = action[1]
            tooltip = action[2] if len(action) > 2 else ""

            button = QPushButton(str(label or "Action"))
            button.setMinimumHeight(36)
            button.setMinimumWidth(0)
            button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            if tooltip:
                button.setToolTip(str(tooltip))
            button.clicked.connect(handler)

            row = index // normalized_columns
            column = index % normalized_columns
            layout.addWidget(button, row, column)

        for column in range(normalized_columns):
            layout.setColumnStretch(column, 1)

        return host

    def admin_modal_stylesheet(self):

        return """
            QDialog, QMessageBox, QFileDialog {
                background-color: #11161E;
                color: #E5E7EB;
            }
            QLabel {
                color: #E5E7EB;
            }
            QPushButton {
                background-color: #1A2430;
                color: #E5E7EB;
                border: 1px solid #2B3A4D;
                border-radius: 6px;
                padding: 8px 14px;
                min-width: 96px;
            }
            QPushButton:hover {
                background-color: #223247;
            }
            QLineEdit, QTextEdit, QListView, QTreeView {
                background-color: #0F1722;
                color: #E5E7EB;
                border: 1px solid #2B3A4D;
                border-radius: 6px;
                selection-background-color: #2F80ED;
            }
            QHeaderView::section {
                background-color: #17212D;
                color: #FFFFFF;
                border: 0;
                padding: 6px;
            }
            QComboBox {
                background-color: #0F1722;
                color: #E5E7EB;
                border: 1px solid #2B3A4D;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QTabWidget::pane {
                border: 1px solid #253243;
                border-radius: 8px;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #17212D;
                color: #DCE6F2;
                border: 1px solid #253243;
                padding: 9px 16px;
                min-width: 110px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #223247;
                color: #FFFFFF;
                font-weight: 700;
            }
            QTabBar::tab:hover {
                background-color: #1D2A39;
            }
        """

    def show_admin_message(self, title, message, icon=QMessageBox.Information):

        dialog = QMessageBox(self.admin_dialog or self)
        dialog.setIcon(icon)
        dialog.setWindowTitle(title)
        dialog.setText(str(message))
        dialog.setStyleSheet(self.admin_modal_stylesheet())
        dialog.exec()

    def confirm_admin_action(self, title, message, informative_text="", confirm_label="Proceed"):

        dialog = QMessageBox(self.admin_dialog or self)
        dialog.setIcon(QMessageBox.Warning)
        dialog.setWindowTitle(title)
        dialog.setText(str(message))
        if informative_text:
            dialog.setInformativeText(str(informative_text))
        dialog.setStandardButtons(QMessageBox.Cancel | QMessageBox.Yes)
        confirm_button = dialog.button(QMessageBox.Yes)
        if confirm_button is not None:
            confirm_button.setText(confirm_label)
        dialog.setDefaultButton(QMessageBox.Cancel)
        dialog.setStyleSheet(self.admin_modal_stylesheet())
        return dialog.exec() == QMessageBox.Yes

    def get_admin_open_file_names(self, title, start_dir, file_filter):

        dialog = QFileDialog(self.admin_dialog or self, title, start_dir, file_filter)
        dialog.setFileMode(QFileDialog.ExistingFiles)
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        dialog.setStyleSheet(self.admin_modal_stylesheet())

        if dialog.exec() != QDialog.Accepted:
            return []

        return dialog.selectedFiles()

    def open_office_profile_editor(self):

        profile = dict(load_office_profile() or {})
        onboarding = dict(profile.get("onboarding") or {})
        credential_policy = dict(profile.get("credential_policy") or {})

        dialog = QDialog(self.admin_dialog or self)
        dialog.setWindowTitle("Edit Office Profile")
        dialog.setMinimumWidth(620)
        dialog.setStyleSheet(self.admin_modal_stylesheet())

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Office identity and rollout setup")
        title.setStyleSheet("font-size:18px; font-weight:700; color:#FFFFFF;")
        title.setWordWrap(True)
        layout.addWidget(title)

        intro = QLabel(
            "Use this to name the office, define rollout posture, and capture who this install belongs to. "
            "Saving here updates the rollout checklist and deployment views."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#B8C4D6;")
        layout.addWidget(intro)

        form_grid = QGridLayout()
        form_grid.setHorizontalSpacing(12)
        form_grid.setVerticalSpacing(10)

        def make_label(text):
            label = QLabel(text)
            label.setStyleSheet("font-weight:600; color:#FFFFFF;")
            return label

        organization_edit = QLineEdit(profile.get("organization_id") or "")
        office_id_edit = QLineEdit(profile.get("office_id") or "")
        office_name_edit = QLineEdit(profile.get("office_name") or "")
        support_name_edit = QLineEdit(profile.get("support_contact_name") or "")
        support_email_edit = QLineEdit(profile.get("support_contact_email") or "")
        username_hint_edit = QLineEdit(credential_policy.get("username_hint") or "")

        rollout_tier_combo = QComboBox(dialog)
        rollout_tiers = [
            ("Single Office", "single_office"),
            ("Multi-Office Local", "multi_office_local"),
            ("Network Ready", "multi_office_network_ready"),
        ]
        for label, value in rollout_tiers:
            rollout_tier_combo.addItem(label, value)
        current_rollout_tier = str(profile.get("rollout_tier") or "single_office").strip().lower()
        rollout_index = rollout_tier_combo.findData(current_rollout_tier)
        if rollout_index >= 0:
            rollout_tier_combo.setCurrentIndex(rollout_index)

        credential_mode_combo = QComboBox(dialog)
        credential_modes = [
            ("Local Install Shared", "local_install_shared"),
            ("Per Office Shared", "per_office_shared"),
            ("Future Remote Identity", "future_remote_identity"),
        ]
        for label, value in credential_modes:
            credential_mode_combo.addItem(label, value)
        current_credential_mode = str(credential_policy.get("mode") or "local_install_shared").strip().lower()
        credential_index = credential_mode_combo.findData(current_credential_mode)
        if credential_index >= 0:
            credential_mode_combo.setCurrentIndex(credential_index)

        notes_edit = QTextEdit(dialog)
        notes_edit.setFixedHeight(90)
        notes_edit.setPlaceholderText("Optional rollout notes, office-specific setup details, or support context.")
        notes_edit.setText(onboarding.get("notes") or "")

        identity_summary = QLabel(
            f"Install ID: {profile.get('install_id') or 'Unknown'}\n"
            f"Created: {profile.get('created_at') or 'Unknown'}"
        )
        identity_summary.setWordWrap(True)
        identity_summary.setStyleSheet(
            "background-color:#0F1722; border:1px solid #253243; border-radius:8px; "
            "padding:10px; color:#C9D5E6;"
        )

        rows = [
            ("Organization ID", organization_edit),
            ("Office ID", office_id_edit),
            ("Office Name", office_name_edit),
            ("Rollout Tier", rollout_tier_combo),
            ("Support Contact Name", support_name_edit),
            ("Support Contact Email", support_email_edit),
            ("Launcher Username", username_hint_edit),
            ("Credential Mode", credential_mode_combo),
        ]

        for row_index, (label_text, widget) in enumerate(rows):
            form_grid.addWidget(make_label(label_text), row_index, 0)
            form_grid.addWidget(widget, row_index, 1)

        layout.addLayout(form_grid)
        layout.addWidget(make_label("Rollout Notes"))
        layout.addWidget(notes_edit)
        layout.addWidget(identity_summary)

        footer_hint = QLabel(
            "Tip: use real office names and support contacts here before wider rollout. "
            "This makes support exports and benchmarking much easier to trust."
        )
        footer_hint.setWordWrap(True)
        footer_hint.setStyleSheet("color:#9CA3AF;")
        layout.addWidget(footer_hint)

        button_row = QHBoxLayout()
        button_row.addStretch()
        cancel_button = QPushButton("Cancel")
        save_button = QPushButton("Save Office Profile")
        save_button.setStyleSheet(
            "background-color:#1E6FDB; color:#FFFFFF; border:1px solid #2F80ED; "
            "border-radius:6px; padding:8px 14px;"
        )
        button_row.addWidget(cancel_button)
        button_row.addWidget(save_button)
        layout.addLayout(button_row)

        cancel_button.clicked.connect(dialog.reject)

        def save_profile():
            office_name = office_name_edit.text().strip()
            organization_id = organization_edit.text().strip()
            office_id = office_id_edit.text().strip()

            if not office_name or not organization_id or not office_id:
                self.show_admin_message(
                    "Profile Incomplete",
                    "Organization ID, Office ID, and Office Name are required.",
                    icon=QMessageBox.Warning,
                )
                return

            updated_profile = update_office_profile({
                "organization_id": organization_id,
                "office_id": office_id,
                "office_name": office_name,
                "rollout_tier": rollout_tier_combo.currentData(),
                "support_contact_name": support_name_edit.text().strip(),
                "support_contact_email": support_email_edit.text().strip(),
                "onboarding": {
                    "notes": notes_edit.toPlainText().strip(),
                },
                "credential_policy": {
                    "mode": credential_mode_combo.currentData(),
                    "username_hint": username_hint_edit.text().strip(),
                },
            })
            record_office_profile_confirmed()
            dialog.accept()
            self.refresh_admin_panel()
            self.log(f"Updated office profile: {updated_profile.get('office_name')}")
            self.show_admin_message(
                "Office Profile Saved",
                "The office profile was updated successfully.\n\n"
                "Rollout readiness, support exports, and benchmarking now reflect the new office identity.",
            )

        save_button.clicked.connect(save_profile)

        dialog.exec()

    def clear_layout_widgets(self, layout):

        if layout is None:
            return

        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            child_layout = item.layout()

            if widget is not None:
                widget.deleteLater()
            elif child_layout is not None:
                self.clear_layout_widgets(child_layout)

    def admin_section_frame(self, title, accent="#57B6FF", focus_key=None, expanded=False):

        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ background-color:#10161E; border:1px solid #253243; "
            f"border-left:3px solid {accent}; border-radius:8px; }}"
        )

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(8)

        if focus_key:
            title_button = QPushButton(title)
            title_button.setCursor(Qt.PointingHandCursor)
            title_button.setFlat(True)
            title_button.setStyleSheet(
                "QPushButton { background: transparent; border: 0; color: #FFFFFF; "
                "font-size:14px; font-weight:700; padding:0; text-align:left; }"
                "QPushButton:hover { color: #DCE6F2; text-decoration: underline; }"
            )
            title_button.clicked.connect(lambda _checked=False, key=focus_key: self.toggle_admin_dashboard_focus(key))
            header_layout.addWidget(title_button, 1)

            action_label = QLabel("Click to collapse" if expanded else "Click to expand")
            action_label.setStyleSheet("color:#9CA3AF; font-size:11px; font-weight:600;")
            header_layout.addWidget(action_label, 0, Qt.AlignRight)
        else:
            title_label = QLabel(title)
            title_label.setStyleSheet("color:#FFFFFF; font-size:14px; font-weight:700;")
            header_layout.addWidget(title_label, 1)

        layout.addLayout(header_layout)

        return frame, layout

    def toggle_admin_dashboard_focus(self, focus_key):

        normalized_key = str(focus_key or "").strip().lower() or None
        if self.admin_dashboard_focus == normalized_key:
            self.admin_dashboard_focus = None
        else:
            self.admin_dashboard_focus = normalized_key

        self.refresh_admin_panel()

    def build_admin_metric_card_widget(self, title, value, subtitle, accent="#57B6FF"):

        frame = QFrame()
        frame.setMinimumHeight(108)
        frame.setStyleSheet(
            f"QFrame {{ background-color:#10161E; border:1px solid #253243; "
            f"border-top:3px solid {accent}; border-radius:8px; }}"
        )

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        if value in (None, "", [], {}):
            value_text = "-"
        else:
            value_text = str(value)

        title_label = QLabel(str(title or ""))
        title_label.setStyleSheet("color:#FFFFFF; font-size:12px; font-weight:600;")

        value_label = QLabel(value_text)
        value_label.setStyleSheet(f"color:{accent}; font-size:24px; font-weight:700;")

        subtitle_label = QLabel(str(subtitle or ""))
        subtitle_label.setWordWrap(True)
        subtitle_label.setStyleSheet("color:#9CA3AF; font-size:11px;")

        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addWidget(subtitle_label)
        layout.addStretch()

        return frame

    def build_admin_chart_view(self, chart):

        chart.setTheme(QChart.ChartThemeDark)
        chart.setBackgroundVisible(False)
        chart.setPlotAreaBackgroundVisible(False)
        chart.legend().setLabelColor(QColor("#E5E7EB"))

        view = QChartView(chart)
        view.setRenderHint(QPainter.Antialiasing)
        view.setMinimumHeight(220)
        view.setStyleSheet("QChartView { background: transparent; border: 0; }")
        return view

    def build_admin_bar_chart_card(self, title, distribution, accent="#57B6FF", max_items=6, focus_key=None, expanded=False):

        frame, layout = self.admin_section_frame(title, accent=accent, focus_key=focus_key, expanded=expanded)
        frame.setMinimumHeight(520 if expanded else 290)
        distribution = dict(distribution or {})
        items = []

        for label, value in distribution.items():
            try:
                numeric_value = int(value)
            except (TypeError, ValueError):
                continue

            if numeric_value > 0:
                items.append((self.format_field(str(label or "Unknown")), numeric_value))

        items = sorted(items, key=lambda item: (-item[1], item[0]))[:max_items]
        if not items:
            empty = QLabel("No data available yet.")
            empty.setStyleSheet("color:#9CA3AF;")
            layout.addWidget(empty)
            return frame

        bar_set = QBarSet("Count")
        bar_set.setColor(QColor(accent))

        categories = []
        peak = max(value for _, value in items) or 1
        label_limit = 32 if expanded else 18
        for label, numeric_value in items:
            categories.append(label if len(label) <= label_limit else label[: label_limit - 1] + "...")
            bar_set.append(numeric_value)

        series = QBarSeries()
        series.append(bar_set)

        chart = QChart()
        chart.addSeries(series)
        chart.legend().hide()
        chart.setAnimationOptions(QChart.SeriesAnimations)

        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        axis_x.setLabelsColor(QColor("#DCE6F2"))
        axis_x.setLabelsAngle(-30 if expanded else 0)

        axis_y = QValueAxis()
        axis_y.setRange(0, max(peak + 1, int(peak * 1.15)))
        axis_y.setLabelFormat("%d")
        axis_y.setLabelsColor(QColor("#DCE6F2"))
        axis_y.setGridLineColor(QColor("#253243"))

        chart.addAxis(axis_x, Qt.AlignBottom)
        chart.addAxis(axis_y, Qt.AlignLeft)
        series.attachAxis(axis_x)
        series.attachAxis(axis_y)

        layout.addWidget(self.build_admin_chart_view(chart))
        return frame

    def build_admin_donut_chart_card(self, title, distribution, accent="#57B6FF", max_items=6, focus_key=None, expanded=False):

        frame, layout = self.admin_section_frame(title, accent=accent, focus_key=focus_key, expanded=expanded)
        frame.setMinimumHeight(520 if expanded else 290)
        distribution = dict(distribution or {})
        items = []

        for label, value in distribution.items():
            try:
                numeric_value = int(value)
            except (TypeError, ValueError):
                continue

            if numeric_value > 0:
                items.append((self.format_field(str(label or "Unknown")), numeric_value))

        items = sorted(items, key=lambda item: (-item[1], item[0]))[:max_items]
        if not items:
            empty = QLabel("No data available yet.")
            empty.setStyleSheet("color:#9CA3AF;")
            layout.addWidget(empty)
            return frame

        palette = ["#57B6FF", "#2DCE89", "#F2C94C", "#F2994A", "#9B8CFF", "#EB5757"]
        series = QPieSeries()
        series.setHoleSize(0.56)

        for index, (label, numeric_value) in enumerate(items):
            slice_ = series.append(label, numeric_value)
            slice_.setBrush(QColor(palette[index % len(palette)]))

        chart = QChart()
        chart.addSeries(series)
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.legend().setAlignment(Qt.AlignRight)

        layout.addWidget(self.build_admin_chart_view(chart))
        return frame

    def build_admin_line_chart_card(self, title, points, accent="#57B6FF", focus_key=None, expanded=False):

        frame, layout = self.admin_section_frame(title, accent=accent, focus_key=focus_key, expanded=expanded)
        frame.setMinimumHeight(520 if expanded else 290)
        normalized_points = []

        for point in list(points or []):
            try:
                normalized_points.append(float(point))
            except (TypeError, ValueError):
                continue

        if not normalized_points:
            empty = QLabel("No trend data available yet.")
            empty.setStyleSheet("color:#9CA3AF;")
            layout.addWidget(empty)
            return frame

        series = QLineSeries()
        series.setColor(QColor(accent))
        for index, value in enumerate(normalized_points, start=1):
            series.append(index, value)

        chart = QChart()
        chart.addSeries(series)
        chart.legend().hide()
        chart.setAnimationOptions(QChart.SeriesAnimations)

        axis_x = QValueAxis()
        axis_x.setRange(1, len(normalized_points))
        axis_x.setTickCount(min(max(len(normalized_points), 2), 8))
        axis_x.setLabelFormat("%d")
        axis_x.setLabelsColor(QColor("#DCE6F2"))
        axis_x.setGridLineColor(QColor("#253243"))

        min_value = min(normalized_points)
        max_value = max(normalized_points)
        if min_value == max_value:
            min_value -= 1
            max_value += 1

        axis_y = QValueAxis()
        rounded_min = min_value
        rounded_max = max_value

        if title.lower().find("score") >= 0:
            rounded_min = max(0, int(min_value // 10) * 10)
            rounded_max = min(100, int((max_value + 9) // 10) * 10)
            if rounded_min == rounded_max:
                rounded_min = max(0, rounded_min - 10)
                rounded_max = min(100, rounded_max + 10)
            axis_y.setLabelFormat("%d")
            axis_y.setTickCount(min(max(int((rounded_max - rounded_min) / 10) + 1, 3), 6))
        else:
            if rounded_min == rounded_max:
                rounded_min -= 1
                rounded_max += 1
            else:
                padding = (rounded_max - rounded_min) * 0.08
                rounded_min -= padding
                rounded_max += padding

        axis_y.setRange(rounded_min, rounded_max)
        axis_y.setLabelsColor(QColor("#DCE6F2"))
        axis_y.setGridLineColor(QColor("#253243"))

        chart.addAxis(axis_x, Qt.AlignBottom)
        chart.addAxis(axis_y, Qt.AlignLeft)
        series.attachAxis(axis_x)
        series.attachAxis(axis_y)

        layout.addWidget(self.build_admin_chart_view(chart))
        return frame

    def build_admin_table_card_widget(self, title, headers, rows, accent="#57B6FF"):

        frame, layout = self.admin_section_frame(title, accent=accent)
        frame.setMinimumHeight(300)

        if not rows:
            empty = QLabel("No table data available yet.")
            empty.setStyleSheet("color:#9CA3AF;")
            layout.addWidget(empty)
            return frame

        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setRowCount(len(rows))
        table.setHorizontalHeaderLabels([str(header) for header in headers])
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionMode(QTableWidget.NoSelection)
        table.setFocusPolicy(Qt.NoFocus)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setMinimumHeight(230)
        table.setStyleSheet(
            "QTableWidget { background-color:#0F1722; color:#E5E7EB; border:1px solid #253243; "
            "border-radius:6px; alternate-background-color:#13202D; }"
            "QTableWidget::item { padding:6px; }"
        )

        for row_index, row in enumerate(rows):
            for col_index, value in enumerate(list(row)):
                item = QTableWidgetItem(self.format_detail_value(value))
                item.setForeground(QColor("#E5E7EB"))
                table.setItem(row_index, col_index, item)

        layout.addWidget(table)
        return frame

    def collect_admin_dashboard_data(self):

        recent_runs = get_recent_packet_runs(20)
        scores = [run.get("score") for run in recent_runs if run.get("score") not in (None, "", [], {})]
        runtimes = [run.get("runtime_seconds") for run in recent_runs if run.get("runtime_seconds") not in (None, "", [], {})]

        high_risk_count = 0
        correction_required_count = 0
        recurring_issue_counter = {}
        recent_score_trend = []

        for run in recent_runs:
            risk = str(run.get("denial_risk") or "").strip().lower()
            if risk in {"high", "critical"}:
                high_risk_count += 1

            pipeline_state = str(run.get("pipeline_state") or "").strip().lower()
            if pipeline_state in {"correction_required", "review_required"}:
                correction_required_count += 1

            try:
                recent_score_trend.append(float(run.get("score")))
            except (TypeError, ValueError):
                pass

            try:
                issue_values = list(json.loads(run.get("issues_json") or "[]") or [])
            except Exception:
                issue_values = []

            for issue in issue_values:
                recurring_issue_counter[issue] = recurring_issue_counter.get(issue, 0) + 1

        office_profile = load_office_profile()
        current_snapshot = build_cross_office_snapshot()
        current_summary = dict(current_snapshot.get("summary") or {})
        network_rollup = load_network_rollup()
        imported_snapshot_count = len(list_imported_snapshot_files())

        active_summary = network_rollup or current_summary
        office_rankings = list((network_rollup or {}).get("office_rankings") or [])

        if office_rankings:
            ranking_rows = [
                [
                    index,
                    rollup.get("office_name") or rollup.get("office_id") or "Unknown Office",
                    self.format_field(rollup.get("standing") or "unknown"),
                    rollup.get("packet_count") or 0,
                    int(round(float(rollup.get("average_packet_score") or 0))) if rollup.get("average_packet_score") not in (None, "") else "-",
                    self.format_runtime_value(rollup.get("average_runtime_seconds")),
                ]
                for index, rollup in enumerate(office_rankings[:6], start=1)
            ]
        else:
            ranked_runs = sorted(
                recent_runs,
                key=lambda run: float(run.get("score") or 0.0),
                reverse=True,
            )[:6]
            ranking_rows = [
                [
                    index,
                    os.path.basename(str(run.get("file_name") or "Unknown")),
                    self.format_field(run.get("denial_risk") or "unknown"),
                    run.get("score") or "-",
                    self.format_runtime_value(run.get("runtime_seconds")),
                    self.format_field(run.get("analysis_mode") or "unknown"),
                ]
                for index, run in enumerate(ranked_runs, start=1)
            ]

        return {
            "office_profile": office_profile,
            "current_summary": current_summary,
            "network_rollup": network_rollup,
            "imported_snapshot_count": imported_snapshot_count,
            "recent_runs": recent_runs,
            "recent_avg_score": round(sum(float(value) for value in scores) / len(scores), 2) if scores else None,
            "recent_avg_runtime": round(sum(float(value) for value in runtimes) / len(runtimes), 2) if runtimes else None,
            "high_risk_count": high_risk_count,
            "correction_required_count": correction_required_count,
            "active_summary": active_summary,
            "top_issue_distribution": dict(sorted(recurring_issue_counter.items(), key=lambda item: item[1], reverse=True)[:6]),
            "recent_score_trend": list(reversed(recent_score_trend[-8:])),
            "ranking_rows": ranking_rows,
        }

    def populate_admin_dashboard(self):

        if not self.admin_dashboard_host:
            return

        host_layout = self.admin_dashboard_host.layout()
        self.clear_layout_widgets(host_layout)

        data = self.collect_admin_dashboard_data()
        office_profile = dict(data.get("office_profile") or {})
        current_summary = dict(data.get("current_summary") or {})
        network_rollup = data.get("network_rollup") or {}
        active_summary = dict(data.get("active_summary") or {})
        imported_snapshot_count = int(data.get("imported_snapshot_count") or 0)
        network_live = bool(network_rollup)

        summary_label = QLabel(
            "Business Intelligence Dashboard"
            + ("  |  Network view active" if network_live else "  |  Local office view active")
        )
        summary_label.setStyleSheet("color:#FFFFFF; font-size:16px; font-weight:700; padding:2px 2px 6px 2px;")
        host_layout.addWidget(summary_label)

        card_grid = QGridLayout()
        card_grid.setHorizontalSpacing(10)
        card_grid.setVerticalSpacing(10)

        metric_cards = [
            ("Office", office_profile.get("office_name") or "Default Office", office_profile.get("organization_id") or "Local organization", "#57B6FF"),
            ("Packets Analyzed", current_summary.get("packet_count") or 0, "Local retained packet history", "#2DCE89"),
            ("Average Score", int(round(float(data["recent_avg_score"]))) if data.get("recent_avg_score") not in (None, "") else "-", "Recent packet quality average", "#F2C94C"),
            ("Average Runtime", self.format_runtime_value(data.get("recent_avg_runtime")), "Recent local processing speed", "#9B8CFF"),
            ("High Risk Packets", data.get("high_risk_count") or 0, "Recent high / critical denial risk", "#EB5757"),
            ("Imported Offices", imported_snapshot_count, "Cross-office feeds staged locally", "#57B6FF"),
        ]

        for index, (title, value, subtitle, accent) in enumerate(metric_cards):
            card_grid.addWidget(self.build_admin_metric_card_widget(title, value, subtitle, accent=accent), index // 3, index % 3)

        host_layout.addLayout(card_grid)

        chart_grid = QGridLayout()
        chart_grid.setHorizontalSpacing(10)
        chart_grid.setVerticalSpacing(10)

        dashboard_focus = str(self.admin_dashboard_focus or "").strip().lower() or None
        chart_builders = {
            "workflow_distribution": lambda expanded=False: self.build_admin_bar_chart_card(
                "Workflow Distribution",
                active_summary.get("workflow_distribution"),
                accent="#57B6FF",
                max_items=8 if expanded else 6,
                focus_key="workflow_distribution",
                expanded=expanded,
            ),
            "denial_risk_mix": lambda expanded=False: self.build_admin_donut_chart_card(
                "Denial Risk Mix",
                active_summary.get("denial_risk_distribution"),
                accent="#EB5757",
                max_items=8 if expanded else 6,
                focus_key="denial_risk_mix",
                expanded=expanded,
            ),
            "top_recurring_issues": lambda expanded=False: self.build_admin_bar_chart_card(
                "Top Recurring Issues",
                data.get("top_issue_distribution"),
                accent="#F2C94C",
                max_items=8 if expanded else 6,
                focus_key="top_recurring_issues",
                expanded=expanded,
            ),
            "recent_packet_score_trend": lambda expanded=False: self.build_admin_line_chart_card(
                "Recent Packet Score Trend",
                data.get("recent_score_trend"),
                accent="#2DCE89",
                focus_key="recent_packet_score_trend",
                expanded=expanded,
            ),
        }

        if dashboard_focus and dashboard_focus in chart_builders:
            focus_hint = QLabel("Focused chart view. Click the banner again to return to the four-chart dashboard.")
            focus_hint.setStyleSheet("color:#9CA3AF; font-size:11px; padding:0 2px 2px 2px;")
            host_layout.addWidget(focus_hint)
            chart_grid.addWidget(chart_builders[dashboard_focus](True), 0, 0, 1, 2)
        else:
            chart_grid.addWidget(chart_builders["workflow_distribution"](), 0, 0)
            chart_grid.addWidget(chart_builders["denial_risk_mix"](), 0, 1)
            chart_grid.addWidget(chart_builders["top_recurring_issues"](), 1, 0)
            chart_grid.addWidget(chart_builders["recent_packet_score_trend"](), 1, 1)

        host_layout.addLayout(chart_grid)

        if network_live:
            table_title = "Office Rankings"
            headers = ["Rank", "Office", "Standing", "Packets", "Avg Score", "Avg Runtime"]
        else:
            table_title = "Top Local Packet Runs"
            headers = ["Rank", "Packet", "Risk", "Score", "Runtime", "Mode"]

        host_layout.addWidget(
            self.build_admin_table_card_widget(
                table_title,
                headers,
                data.get("ranking_rows"),
                accent="#2DCE89" if network_live else "#57B6FF",
            )
        )
