import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from TrueCore.ui.pyside_gui.main_window_admin_mixin import MainWindowAdminMixin


class _DummyAdminWindow(MainWindowAdminMixin):
    pass


class MainWindowAdminMixinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_build_admin_action_grid_returns_widget_with_buttons(self):
        window = _DummyAdminWindow()
        triggered = []

        grid = window.build_admin_action_grid(
            [
                ("One", lambda: triggered.append("one")),
                ("Two", lambda: triggered.append("two"), "Tooltip"),
            ],
            columns=2,
        )

        buttons = grid.findChildren(QPushButton)
        self.assertEqual(len(buttons), 2)
        self.assertEqual(buttons[1].toolTip(), "Tooltip")
        buttons[0].click()
        self.assertEqual(triggered, ["one"])


if __name__ == "__main__":
    unittest.main()
