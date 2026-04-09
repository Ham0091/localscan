"""
LocalScan GUI — PySide6 desktop interface.

Entry point:
    python -m localscan.gui          (from project root)
    python localscan/gui.py

Layout:
    ┌───────────────────────────────────────────────────────────┐
    │  HEADER — hostname · OS · Python · last scan · RUN SCAN  │
    ├──────────┬────────────────────────────────────────────────┤
    │          │                                                │
    │ SIDEBAR  │            MAIN CONTENT STACK                 │
    │          │                                               │
    │ nav list │  Dashboard / Network / System / …             │
    │          │                                               │
    ├──────────┴────────────────────────────────────────────────┤
    │  LIVE LOG CONSOLE                                         │
    └───────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import platform
import socket
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional

from PySide6.QtCore import (
    Qt,
    QSize,
    QPropertyAnimation,
    QEasingCurve,
    QThread,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontDatabase,
    QPalette,
    QIcon,
    QPixmap,
    QPainter,
    QPen,
    QBrush,
    QConicalGradient,
    QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

class Palette:
    BG_DEEP     = "#090910"
    BG_BASE     = "#0d0d17"
    BG_PANEL    = "#12121f"
    BG_CARD     = "#17172a"
    BG_HOVER    = "#1e1e33"
    BORDER      = "#1e1e36"
    BORDER_LT   = "#28284a"

    TEXT_PRIMARY   = "#e2e2f0"
    TEXT_SECONDARY = "#8888aa"
    TEXT_MUTED     = "#444466"
    TEXT_MONO      = "#b0ffa0"

    ACCENT      = "#6c63ff"
    ACCENT_LITE = "#8b85ff"
    ACCENT_DIM  = "#3a3660"

    CRITICAL = "#ef4444"
    HIGH     = "#f97316"
    MEDIUM   = "#eab308"
    LOW      = "#22c55e"
    INFO     = "#71717a"

    BTN_RUN_START = "#6c63ff"
    BTN_RUN_END   = "#a855f7"


# ---------------------------------------------------------------------------
# Global stylesheet
# ---------------------------------------------------------------------------

STYLESHEET = f"""
/* ── Application base ──────────────────────────────────────── */
QMainWindow, QWidget {{
    background: {Palette.BG_BASE};
    color: {Palette.TEXT_PRIMARY};
    font-family: "Segoe UI", "SF Pro Text", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}}

QScrollBar:vertical {{
    background: {Palette.BG_PANEL};
    width: 6px;
    border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: {Palette.BORDER_LT};
    border-radius: 3px;
    min-height: 24px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: {Palette.BG_PANEL};
    height: 6px;
    border-radius: 3px;
}}
QScrollBar::handle:horizontal {{
    background: {Palette.BORDER_LT};
    border-radius: 3px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

QSplitter::handle {{
    background: {Palette.BORDER};
}}

QToolTip {{
    background: {Palette.BG_CARD};
    color: {Palette.TEXT_PRIMARY};
    border: 1px solid {Palette.BORDER_LT};
    padding: 4px 8px;
    border-radius: 4px;
}}
"""


# ---------------------------------------------------------------------------
# Reusable primitives
# ---------------------------------------------------------------------------

def _separator(vertical: bool = False) -> QFrame:
    """Thin hairline separator."""
    line = QFrame()
    line.setFrameShape(
        QFrame.Shape.VLine if vertical else QFrame.Shape.HLine
    )
    line.setStyleSheet(f"color: {Palette.BORDER}; background: {Palette.BORDER};")
    line.setFixedHeight(1) if not vertical else line.setFixedWidth(1)
    return line


def _label(
    text: str,
    size: int = 13,
    color: str = Palette.TEXT_PRIMARY,
    bold: bool = False,
    mono: bool = False,
) -> QLabel:
    lbl = QLabel(text)
    family = '"JetBrains Mono", "Cascadia Code", Consolas, monospace' if mono else \
             '"Segoe UI", "Helvetica Neue", Arial, sans-serif'
    weight = "bold" if bold else "normal"
    lbl.setStyleSheet(
        f"color: {color}; font-size: {size}px; font-weight: {weight}; "
        f"font-family: {family}; background: transparent;"
    )
    return lbl


def _card(parent: Optional[QWidget] = None) -> QFrame:
    """Rounded dark card container — layered look, no harsh border."""
    frame = QFrame(parent)
    frame.setStyleSheet(f"""
        QFrame {{
            background: {Palette.BG_CARD};
            border: 1px solid {Palette.BORDER};
            border-radius: 8px;
        }}
        QFrame:focus {{
            border: 1px solid {Palette.BORDER_LT};
        }}
    """)
    return frame


# ---------------------------------------------------------------------------
# Risk score gauge (QPainter arc)
# ---------------------------------------------------------------------------

class RiskGauge(QWidget):
    """Semi-circular arc gauge showing a 0-100 risk score."""

    def __init__(self, score: int = 0, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._score = max(0, min(100, score))
        self.setMinimumSize(180, 120)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

    def set_score(self, score: int) -> None:
        self._score = max(0, min(100, score))
        self.update()

    def _score_color(self) -> QColor:
        if self._score >= 70:
            return QColor(Palette.CRITICAL)
        if self._score >= 40:
            return QColor(Palette.HIGH)
        if self._score >= 20:
            return QColor(Palette.MEDIUM)
        return QColor(Palette.LOW)

    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        cx, cy = w / 2, h * 0.55
        radius = min(w, h * 1.8) * 0.40
        arc_w = radius * 0.22

        rect_x = cx - radius
        rect_y = cy - radius
        rect_side = radius * 2

        # Background arc (track)
        pen = QPen(QColor(Palette.BORDER_LT))
        pen.setWidth(int(arc_w))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(
            int(rect_x), int(rect_y), int(rect_side), int(rect_side),
            180 * 16, -180 * 16,
        )

        # Filled arc (score)
        if self._score > 0:
            pen2 = QPen(self._score_color())
            pen2.setWidth(int(arc_w))
            pen2.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen2)
            span = int(-180 * 16 * self._score / 100)
            painter.drawArc(
                int(rect_x), int(rect_y),
                int(rect_side), int(rect_side),
                180 * 16, span,
            )

        # Score number — optically centred in the arc bowl
        # The arc spans 180° from 9 o'clock to 3 o'clock; its visual
        # centre is at cy-0.10*radius.  We nudge the text block upward
        # slightly so the number sits in the optical middle of the bowl.
        painter.setPen(QPen(self._score_color()))
        font = QFont()
        font.setBold(True)
        font.setPointSize(int(radius * 0.40))
        painter.setFont(font)
        score_block_top = int(cy - radius * 0.28)
        score_block_h   = int(radius * 0.52)
        painter.drawText(
            int(cx - radius), score_block_top,
            int(radius * 2), score_block_h,
            Qt.AlignmentFlag.AlignCenter,
            str(self._score),
        )

        # Label — sits just below the number, inside the arc opening
        painter.setPen(QPen(QColor(Palette.TEXT_SECONDARY)))
        font2 = QFont()
        font2.setPointSize(int(radius * 0.14))
        painter.setFont(font2)
        label_top = score_block_top + score_block_h - int(radius * 0.04)
        painter.drawText(
            int(cx - radius), label_top,
            int(radius * 2), int(radius * 0.30),
            Qt.AlignmentFlag.AlignCenter,
            "RISK SCORE",
        )

        painter.end()


# ---------------------------------------------------------------------------
# Severity summary card
# ---------------------------------------------------------------------------

class SeverityCard(QFrame):
    """Single-severity count card."""

    def __init__(
        self,
        label: str,
        count: int,
        color: str,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._label = label
        self._count = count
        self._color = color
        self._build()

    def _build(self) -> None:
        self.setStyleSheet(f"""
            QFrame {{
                background: {Palette.BG_CARD};
                border: none;
                border-left: 3px solid {self._color};
                border-radius: 8px;
            }}
        """)
        self.setMinimumWidth(120)
        self.setMinimumHeight(88)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 14)
        layout.setSpacing(0)

        layout.addStretch(1)

        count_lbl = _label(str(self._count), size=30, color=self._color, bold=True)
        count_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
        count_lbl.setMinimumHeight(36)
        layout.addWidget(count_lbl)

        layout.addSpacing(5)

        sev_lbl = _label(self._label.upper(), size=10, color=Palette.TEXT_SECONDARY)
        sev_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
        sev_lbl.setStyleSheet(
            f"color: {Palette.TEXT_SECONDARY}; font-size: 10px; "
            f"letter-spacing: 1px; background: transparent;"
        )
        layout.addWidget(sev_lbl)

        layout.addStretch(1)

    def set_count(self, count: int) -> None:
        self._count = count
        # layout: stretch(0), count_lbl(1), spacing(2), sev_lbl(3), stretch(4)
        layout = self.layout()
        if layout and layout.count() > 1:
            item = layout.itemAt(1)
            if item and item.widget():
                item.widget().setText(str(count))


# ---------------------------------------------------------------------------
# Sidebar navigation button
# ---------------------------------------------------------------------------

class NavButton(QPushButton):
    """Left-sidebar navigation item."""

    _ACTIVE_STYLE = f"""
        QPushButton {{
            background: {Palette.ACCENT_DIM};
            color: {Palette.ACCENT_LITE};
            border: none;
            border-left: 3px solid {Palette.ACCENT};
            border-radius: 0px;
            padding: 10px 18px 10px 22px;
            font-size: 13px;
            font-weight: 600;
            text-align: left;
        }}
    """
    _NORMAL_STYLE = f"""
        QPushButton {{
            background: transparent;
            color: {Palette.TEXT_SECONDARY};
            border: none;
            border-left: 3px solid transparent;
            border-radius: 0px;
            padding: 10px 18px 10px 22px;
            font-size: 13px;
            text-align: left;
        }}
        QPushButton:hover {{
            background: {Palette.BG_HOVER};
            color: {Palette.TEXT_PRIMARY};
        }}
    """

    def __init__(self, icon_char: str, label: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(f"  {icon_char}  {label}", parent)
        self._active = False
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(self._NORMAL_STYLE)
        self.setFixedHeight(42)
        self.toggled.connect(self._on_toggled)

    def _on_toggled(self, checked: bool) -> None:
        self._active = checked
        self.setStyleSheet(self._ACTIVE_STYLE if checked else self._NORMAL_STYLE)


# ---------------------------------------------------------------------------
# Live log console
# ---------------------------------------------------------------------------

class LogConsole(QPlainTextEdit):
    """Scrolling monospace log panel with colored severity lines."""

    _LEVEL_COLORS = {
        "INFO":     "#71c3f5",
        "WARN":     "#eab308",
        "ERROR":    "#f97316",
        "ERR":      "#f97316",
        "CRITICAL": "#ef4444",
        "HIGH":     "#ef4444",
        "OK":       "#4ade80",
        "SCAN":     "#8b85ff",
    }

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setMaximumBlockCount(2000)
        self.setStyleSheet(f"""
            QPlainTextEdit {{
                background: {Palette.BG_DEEP};
                color: {Palette.TEXT_MONO};
                border: none;
                border-top: 1px solid {Palette.BORDER};
                font-family: "JetBrains Mono", "Cascadia Code", Consolas,
                             "Courier New", monospace;
                font-size: 12px;
                padding: 8px 12px;
                selection-background-color: {Palette.ACCENT_DIM};
            }}
        """)

    def append_line(self, level: str, message: str) -> None:
        """Append a colored log line."""
        ts = datetime.now().strftime("%H:%M:%S")
        color = self._LEVEL_COLORS.get(level.upper(), Palette.TEXT_MONO)

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(Palette.TEXT_MUTED))
        cursor = QTextCursor(self.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(f"[{ts}] ", fmt)

        fmt2 = QTextCharFormat()
        fmt2.setForeground(QColor(color))
        cursor.insertText(f"[{level.upper():>8}] ", fmt2)

        fmt3 = QTextCharFormat()
        fmt3.setForeground(QColor(Palette.TEXT_PRIMARY))
        cursor.insertText(f"{message}\n", fmt3)

        self.setTextCursor(cursor)
        self.ensureCursorVisible()


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------

class DashboardPage(QScrollArea):
    """Main dashboard with gauge + severity summary cards."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setStyleSheet("background: transparent;")

        container = QWidget()
        container.setStyleSheet("background: transparent;")
        self.setWidget(container)
        root = QVBoxLayout(container)
        root.setContentsMargins(28, 28, 28, 28)
        root.setSpacing(20)

        # Page title
        title = _label("Dashboard", size=20, bold=True)
        root.addWidget(title)

        # ── Top row: gauge + severity cards ──────────────────────
        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        # Gauge card
        gauge_card = _card()
        gauge_card.setMinimumHeight(210)
        gauge_card.setMinimumWidth(230)
        gauge_lay = QVBoxLayout(gauge_card)
        gauge_lay.setContentsMargins(20, 20, 20, 20)
        self.gauge = RiskGauge(score=0)
        gauge_lay.addWidget(self.gauge)
        top_row.addWidget(gauge_card, 2)

        # Severity cards column
        sev_grid = QGridLayout()
        sev_grid.setSpacing(10)
        sev_grid.setColumnMinimumWidth(0, 120)
        sev_grid.setColumnMinimumWidth(1, 120)
        self._sev_cards: dict[str, SeverityCard] = {}
        severities = [
            ("Critical", 0, Palette.CRITICAL),
            ("High",     0, Palette.HIGH),
            ("Medium",   0, Palette.MEDIUM),
            ("Low",      0, Palette.LOW),
            ("Info",     0, Palette.INFO),
        ]
        for i, (label, count, color) in enumerate(severities):
            card = SeverityCard(label, count, color)
            self._sev_cards[label] = card
            sev_grid.addWidget(card, i // 2, i % 2)  # 2-column grid

        sev_container = QWidget()
        sev_container.setStyleSheet("background: transparent;")
        sev_container.setLayout(sev_grid)
        top_row.addWidget(sev_container, 3)
        root.addLayout(top_row)

        root.addWidget(_separator())

        # ── Summary placeholder ───────────────────────────────────
        ph_title = _label("Recent Findings", size=15, bold=True)
        root.addWidget(ph_title)

        ph_card = _card()
        ph_lay = QVBoxLayout(ph_card)
        ph_lay.setContentsMargins(32, 40, 32, 40)
        ph_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        ph_icon = _label("◎", size=36, color=Palette.TEXT_MUTED)
        ph_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ph_lay.addWidget(ph_icon)

        ph_msg = _label(
            "No scan results yet.\nPress  Run Scan  to begin.",
            size=13,
            color=Palette.TEXT_SECONDARY,
        )
        ph_msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ph_msg.setWordWrap(True)
        ph_lay.addWidget(ph_msg)

        root.addWidget(ph_card, 1)
        root.addStretch()

    def update_results(self, score: int, counts: dict) -> None:
        self.gauge.set_score(score)
        for label, card in self._sev_cards.items():
            card.set_count(counts.get(label, 0))


# ---------------------------------------------------------------------------
# Generic placeholder page
# ---------------------------------------------------------------------------

class PlaceholderPage(QWidget):
    """Placeholder for not-yet-implemented section pages."""

    def __init__(
        self,
        title: str,
        icon: str,
        description: str,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 60, 40, 40)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
        layout.setSpacing(16)

        icon_lbl = _label(icon, size=48, color=Palette.TEXT_MUTED)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_lbl)

        title_lbl = _label(title, size=22, bold=True)
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_lbl)

        desc_lbl = _label(description, size=13, color=Palette.TEXT_SECONDARY)
        desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_lbl.setWordWrap(True)
        layout.addWidget(desc_lbl)

        layout.addStretch()


# ---------------------------------------------------------------------------
# Header bar
# ---------------------------------------------------------------------------

class HeaderBar(QWidget):
    """Top header: system meta info + Run Scan button."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(62)
        self.setStyleSheet(f"""
            QWidget {{
                background: {Palette.BG_PANEL};
                border-bottom: 1px solid {Palette.BORDER};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(0)

        # Left: system info chips
        info_layout = QHBoxLayout()
        info_layout.setSpacing(20)

        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"

        os_name = f"{platform.system()} {platform.release()}"
        py_ver  = f"Python {sys.version.split()[0]}"

        for icon, text in [("🖥", hostname), ("⚙", os_name), ("🐍", py_ver)]:
            chip = QWidget()
            chip.setStyleSheet("background: transparent; border: none;")
            chip_lay = QHBoxLayout(chip)
            chip_lay.setContentsMargins(0, 0, 0, 0)
            chip_lay.setSpacing(6)

            i_lbl = _label(icon, size=13, color=Palette.TEXT_SECONDARY)
            t_lbl = _label(text, size=12, color=Palette.TEXT_SECONDARY)
            chip_lay.addWidget(i_lbl)
            chip_lay.addWidget(t_lbl)
            info_layout.addWidget(chip)

            if icon != "🐍":
                div = QFrame()
                div.setFrameShape(QFrame.Shape.VLine)
                div.setFixedWidth(1)
                div.setFixedHeight(16)
                div.setStyleSheet(f"color: {Palette.BORDER}; background: {Palette.BORDER}; border: none;")
                info_layout.addWidget(div)

        layout.addLayout(info_layout)
        layout.addStretch()

        # Last scan label
        self.last_scan_lbl = _label(
            "Last scan: —", size=11, color=Palette.TEXT_MUTED
        )
        self.last_scan_lbl.setStyleSheet(
            f"color: {Palette.TEXT_MUTED}; font-size: 11px; background: transparent; border: none;"
        )
        layout.addWidget(self.last_scan_lbl)
        layout.addSpacing(24)

        # Report toggle checkbox
        self.report_toggle = QCheckBox("Save Report")
        self.report_toggle.setToolTip("Generate and save an HTML report to localscan/reports/")
        self.report_toggle.setChecked(False)
        self.report_toggle.setStyleSheet(f"""
            QCheckBox {{
                color: {Palette.TEXT_SECONDARY};
                font-size: 12px;
                background: transparent;
                border: none;
                spacing: 6px;
            }}
            QCheckBox:hover {{
                color: {Palette.TEXT_PRIMARY};
            }}
            QCheckBox::indicator {{
                width: 14px;
                height: 14px;
                border: 1px solid {Palette.BORDER_LT};
                border-radius: 3px;
                background: {Palette.BG_CARD};
            }}
            QCheckBox::indicator:checked {{
                background: {Palette.ACCENT};
                border-color: {Palette.ACCENT};
            }}
        """)
        layout.addWidget(self.report_toggle)
        layout.addSpacing(16)

        # Run Scan button
        self.run_btn = QPushButton("▶  Run Scan")
        self.run_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.run_btn.setFixedHeight(36)
        self.run_btn.setMinimumWidth(140)
        self.run_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 {Palette.BTN_RUN_START},
                    stop:1 {Palette.BTN_RUN_END}
                );
                color: #ffffff;
                border: none;
                border-radius: 6px;
                font-size: 13px;
                font-weight: 700;
                padding: 0 18px;
            }}
            QPushButton:hover {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #7c74ff,
                    stop:1 #b866f8
                );
            }}
            QPushButton:pressed {{
                background: {Palette.ACCENT_DIM};
                color: {Palette.ACCENT_LITE};
            }}
            QPushButton:disabled {{
                background: {Palette.BORDER};
                color: {Palette.TEXT_MUTED};
            }}
        """)
        layout.addWidget(self.run_btn)

    def set_last_scan(self, ts: str) -> None:
        self.last_scan_lbl.setText(f"Last scan: {ts}")


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

class Sidebar(QWidget):
    """Left navigation sidebar."""

    NAV_ITEMS = [
        ("⬡", "Dashboard"),
        ("⬡", "Network"),
        ("⬡", "System"),
        ("⬡", "Filesystem"),
        ("⬡", "Services"),
        ("⬡", "Reports"),
        ("⬡", "Settings"),
    ]

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedWidth(210)
        self.setStyleSheet(f"""
            QWidget {{
                background: {Palette.BG_PANEL};
                border-right: 1px solid {Palette.BORDER};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo / brand
        brand = QWidget()
        brand.setFixedHeight(62)
        brand.setStyleSheet(f"""
            background: {Palette.BG_PANEL};
            border-bottom: 1px solid {Palette.BORDER};
            border-right: 1px solid {Palette.BORDER};
        """)
        brand_lay = QHBoxLayout(brand)
        brand_lay.setContentsMargins(20, 0, 16, 0)

        brand_icon = _label("⬡", size=22, color=Palette.ACCENT, bold=True)
        brand_text = _label("LocalScan", size=15, color=Palette.TEXT_PRIMARY, bold=True)
        brand_lay.addWidget(brand_icon)
        brand_lay.addSpacing(8)
        brand_lay.addWidget(brand_text)
        brand_lay.addStretch()
        layout.addWidget(brand)

        # Nav section label
        layout.addSpacing(16)
        nav_lbl = _label("  NAVIGATION", size=10, color=Palette.TEXT_MUTED, bold=True)
        nav_lbl.setStyleSheet(
            f"color: {Palette.TEXT_MUTED}; font-size: 10px; font-weight: bold; "
            f"letter-spacing: 1.5px; background: transparent; border: none; "
            f"padding: 0 0 6px 20px;"
        )
        layout.addWidget(nav_lbl)

        # Navigation buttons (mutually exclusive)
        self.buttons: list[NavButton] = []
        for icon, label in self.NAV_ITEMS:
            btn = NavButton(icon, label)
            layout.addWidget(btn)
            self.buttons.append(btn)

        layout.addStretch()

        # Version footer
        ver_lbl = _label("v0.1.0-alpha", size=10, color=Palette.TEXT_MUTED)
        ver_lbl.setStyleSheet(
            f"color: {Palette.TEXT_MUTED}; font-size: 10px; "
            f"background: transparent; border: none; padding: 12px 16px;"
        )
        layout.addWidget(ver_lbl)

    def set_active(self, index: int) -> None:
        for i, btn in enumerate(self.buttons):
            btn.setChecked(i == index)


# ---------------------------------------------------------------------------
# Scan worker — runs scanner core on a background QThread
# ---------------------------------------------------------------------------

class ScanWorker(QThread):
    """Executes :func:`localscan.scanner.run_scan` off the main thread.

    Signals
    -------
    module_started(str, int, int)
        (module_name, step, total)
    progress(str, str)
        (module_name, message)
    finding(str, dict)
        (module_name, finding_dict)
    module_done(str, int, int)
        (module_name, step, total)  — percentage = step/total * 100
    scan_complete(dict)
        Full results mapping ``{module_key: [findings]}``.
    scan_error(str)
        If the scan crashes unexpectedly.
    """

    module_started = Signal(str, int, int)
    progress       = Signal(str, str)
    finding        = Signal(str, dict)
    module_done    = Signal(str, int, int)
    scan_complete  = Signal(dict)
    scan_error     = Signal(str)

    def __init__(
        self,
        quick: bool = False,
        generate_report: bool = False,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.quick = quick
        self.generate_report = generate_report

    def run(self) -> None:  # noqa: D401  — Qt override
        """Thread entry-point — called by QThread.start()."""
        try:
            from localscan.scanner import run_scan, ScanCallbacks  # noqa: PLC0415

            class _GuiCallbacks(ScanCallbacks):
                def __init__(self, worker: "ScanWorker") -> None:
                    self._w = worker

                def on_module_start(self, name: str, step: int, total: int) -> None:
                    self._w.module_started.emit(name, step, total)

                def on_progress(self, name: str, message: str) -> None:
                    self._w.progress.emit(name, message)

                def on_finding(self, name: str, finding: dict) -> None:
                    self._w.finding.emit(name, finding)

                def on_module_done(self, name: str, findings: list,
                                   step: int, total: int) -> None:
                    self._w.module_done.emit(name, step, total)

                def on_scan_complete(self, results: dict) -> None:
                    # Optionally generate report
                    if self._w.generate_report:
                        try:
                            from localscan.report import (  # noqa: PLC0415
                                generate_report,
                                get_report_path,
                            )
                            report_path = get_report_path()
                            generate_report(results, str(report_path))
                        except Exception:
                            pass
                    self._w.scan_complete.emit(results)

            all_results = run_scan(
                quick=self.quick,
                callbacks=_GuiCallbacks(self),
            )
        except Exception as exc:
            self.scan_error.emit(str(exc))


# ---------------------------------------------------------------------------
# Reports page
# ---------------------------------------------------------------------------

class ReportsPage(QWidget):
    """Lists saved HTML reports with a 'View Latest' button."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(16)

        title = _label("Reports", size=20, bold=True)
        layout.addWidget(title)

        btn_row = QHBoxLayout()
        self.view_latest_btn = QPushButton("⬡  View Latest Report")
        self.view_latest_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.view_latest_btn.setFixedHeight(34)
        self.view_latest_btn.setStyleSheet(f"""
            QPushButton {{
                background: {Palette.ACCENT_DIM};
                color: {Palette.ACCENT_LITE};
                border: 1px solid {Palette.ACCENT};
                border-radius: 6px;
                font-size: 13px;
                font-weight: 600;
                padding: 0 18px;
            }}
            QPushButton:hover {{
                background: {Palette.ACCENT};
                color: #ffffff;
            }}
            QPushButton:disabled {{
                background: {Palette.BORDER};
                color: {Palette.TEXT_MUTED};
                border-color: {Palette.BORDER};
            }}
        """)
        btn_row.addWidget(self.view_latest_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.list_widget = QListWidget()
        self.list_widget.setStyleSheet(f"""
            QListWidget {{
                background: {Palette.BG_CARD};
                border: 1px solid {Palette.BORDER};
                border-radius: 8px;
                color: {Palette.TEXT_PRIMARY};
                font-size: 13px;
                padding: 8px;
            }}
            QListWidget::item {{
                padding: 8px 12px;
                border-radius: 4px;
            }}
            QListWidget::item:selected {{
                background: {Palette.ACCENT_DIM};
                color: {Palette.ACCENT_LITE};
            }}
            QListWidget::item:hover {{
                background: {Palette.BG_HOVER};
            }}
        """)
        layout.addWidget(self.list_widget, 1)

        self.view_latest_btn.clicked.connect(self._open_latest)
        self.list_widget.itemDoubleClicked.connect(self._open_item)
        self.refresh()

    def refresh(self) -> None:
        """Reload the list from the reports directory."""
        self.list_widget.clear()
        try:
            from localscan.report import get_reports_dir
            reports_dir = get_reports_dir()
            files = sorted(reports_dir.glob("report_*.html"), reverse=True)
            for f in files:
                item = QListWidgetItem(f.name)
                item.setData(Qt.ItemDataRole.UserRole, str(f))
                self.list_widget.addItem(item)
        except Exception:
            pass
        has_reports = self.list_widget.count() > 0
        self.view_latest_btn.setEnabled(has_reports)

    def _open_latest(self) -> None:
        item = self.list_widget.item(0)
        if item:
            self._open_path(item.data(Qt.ItemDataRole.UserRole))

    def _open_item(self, item: QListWidgetItem) -> None:
        self._open_path(item.data(Qt.ItemDataRole.UserRole))

    def _open_path(self, path_str: str) -> None:
        try:
            webbrowser.open(Path(path_str).as_uri())
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    """Top-level application window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("LocalScan")
        self.setMinimumSize(1100, 680)
        self.resize(1280, 800)
        self._build_ui()
        self._connect_signals()
        self._populate_demo_log()

    # ── UI construction ──────────────────────────────────────────

    def _build_ui(self) -> None:
        central = QWidget()
        central.setStyleSheet(f"background: {Palette.BG_BASE};")
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        self.header = HeaderBar()
        root.addWidget(self.header)

        # Middle: sidebar + content
        mid_splitter = QSplitter(Qt.Orientation.Horizontal)
        mid_splitter.setHandleWidth(1)
        mid_splitter.setChildrenCollapsible(False)

        self.sidebar = Sidebar()
        mid_splitter.addWidget(self.sidebar)

        # Content stack
        self.stack = QStackedWidget()
        self.stack.setStyleSheet(f"background: {Palette.BG_BASE};")
        mid_splitter.addWidget(self.stack)

        mid_splitter.setSizes([210, 1070])
        mid_splitter.setStretchFactor(0, 0)
        mid_splitter.setStretchFactor(1, 1)

        # Pages
        self.dashboard_page = DashboardPage()
        self.stack.addWidget(self.dashboard_page)

        page_defs = [
            ("Network",    "⬡", "Network check results will appear here after a scan."),
            ("System",     "⬡", "System check results will appear here after a scan."),
            ("Filesystem", "⬡", "Filesystem check results will appear here after a scan."),
            ("Services",   "⬡", "Services & persistence check results will appear here after a scan."),
        ]
        for title, icon, desc in page_defs:
            self.stack.addWidget(PlaceholderPage(title, icon, desc))

        self.reports_page = ReportsPage()
        self.stack.addWidget(self.reports_page)  # index 5

        self.stack.addWidget(PlaceholderPage(
            "Settings", "⬡", "Scan configuration and preferences will live here."
        ))

        # Bottom splitter (content / log)
        v_splitter = QSplitter(Qt.Orientation.Vertical)
        v_splitter.setHandleWidth(1)
        v_splitter.setChildrenCollapsible(False)
        v_splitter.addWidget(mid_splitter)

        # Log panel
        log_container = QWidget()
        log_container.setStyleSheet(f"background: {Palette.BG_DEEP};")
        log_lay = QVBoxLayout(log_container)
        log_lay.setContentsMargins(0, 0, 0, 0)
        log_lay.setSpacing(0)

        log_header = QWidget()
        log_header.setFixedHeight(32)
        log_header.setStyleSheet(
            f"background: {Palette.BG_PANEL}; "
            f"border-top: 1px solid {Palette.BORDER}; "
            f"border-bottom: 1px solid {Palette.BORDER};"
        )
        lh_lay = QHBoxLayout(log_header)
        lh_lay.setContentsMargins(16, 0, 14, 0)
        lh_lbl = _label("LIVE LOG", size=10, color=Palette.TEXT_SECONDARY, bold=True)
        lh_lbl.setStyleSheet(
            f"color: {Palette.TEXT_SECONDARY}; font-size: 10px; font-weight: bold; "
            f"letter-spacing: 1.8px; background: transparent; border: none;"
        )
        lh_lay.addWidget(lh_lbl)
        lh_lay.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.setFixedHeight(20)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {Palette.TEXT_MUTED};
                border: 1px solid {Palette.BORDER};
                border-radius: 3px;
                font-size: 10px;
                padding: 0 8px;
            }}
            QPushButton:hover {{
                color: {Palette.TEXT_PRIMARY};
                border-color: {Palette.BORDER_LT};
            }}
        """)
        lh_lay.addWidget(clear_btn)
        log_lay.addWidget(log_header)

        self.log_console = LogConsole()
        self.log_console.setFixedHeight(148)
        log_lay.addWidget(self.log_console)
        log_container.setFixedHeight(180)
        v_splitter.addWidget(log_container)

        v_splitter.setSizes([620, 178])
        v_splitter.setStretchFactor(0, 1)
        v_splitter.setStretchFactor(1, 0)

        root.addWidget(v_splitter)

        clear_btn.clicked.connect(self.log_console.clear)

    # ── Signal wiring ─────────────────────────────────────────────

    def _connect_signals(self) -> None:
        for i, btn in enumerate(self.sidebar.buttons):
            btn.clicked.connect(lambda _checked, idx=i: self._navigate(idx))

        self.header.run_btn.clicked.connect(self._on_run_scan_clicked)

        # Activate Dashboard by default
        self.sidebar.set_active(0)

    def _navigate(self, index: int) -> None:
        self.sidebar.set_active(index)
        self.stack.setCurrentIndex(index)
        if index == 5:  # Reports page
            self.reports_page.refresh()
        section_names = [
            "Dashboard", "Network", "System",
            "Filesystem", "Services", "Reports", "Settings",
        ]
        if index < len(section_names):
            self.log_console.append_line(
                "INFO", f"Navigated to section: {section_names[index]}"
            )

    def _on_run_scan_clicked(self) -> None:
        """Launch the scanner on a background thread."""
        self.header.run_btn.setEnabled(False)
        self.header.run_btn.setText("◌  Scanning…")
        self.log_console.append_line("SCAN", "Scan started.")

        generate_report = self.header.report_toggle.isChecked()
        if generate_report:
            self.log_console.append_line("INFO", "Report saving enabled — report will be written to localscan/reports/")
        else:
            self.log_console.append_line("INFO", "Report saving disabled. Check 'Save Report' to generate HTML report.")

        self._scan_worker = ScanWorker(
            quick=False,
            generate_report=generate_report,
            parent=self,
        )
        self._scan_worker.module_started.connect(self._on_scan_module_started)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.finding.connect(self._on_scan_finding)
        self._scan_worker.module_done.connect(self._on_scan_module_done)
        self._scan_worker.scan_complete.connect(self._on_scan_complete)
        self._scan_worker.scan_error.connect(self._on_scan_error)
        self._scan_worker.start()

    # ── Scan signal handlers ──────────────────────────────────────

    def _on_scan_module_started(self, name: str, step: int, total: int) -> None:
        pct = int((step - 1) / total * 100)
        self.log_console.append_line("SCAN", f"[{pct}%] Running {name} checks… ({step}/{total})")

    def _on_scan_progress(self, name: str, message: str) -> None:
        self.log_console.append_line("INFO", f"[{name}] {message}")

    def _on_scan_finding(self, name: str, finding: dict) -> None:
        sev = finding.get("severity", "Info")
        fname = finding.get("name", "")
        conf = finding.get("confidence", "")
        conf_str = f" [{conf}]" if conf else ""
        if sev in ("Critical", "High"):
            tag = "HIGH"
        elif sev == "Medium":
            tag = "WARN"
        else:
            tag = "OK"
        self.log_console.append_line(tag, f"[{sev}{conf_str}] {fname}")

    def _on_scan_module_done(self, name: str, step: int, total: int) -> None:
        pct = int(step / total * 100)
        self.log_console.append_line("OK", f"[{pct}%] {name} checks complete.")

    def _on_scan_complete(self, results: dict) -> None:
        self.header.run_btn.setEnabled(True)
        self.header.run_btn.setText("▶  Run Scan")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.header.set_last_scan(ts)

        total_findings = sum(len(v) for v in results.values())
        self.log_console.append_line("SCAN", f"Scan complete — {total_findings} findings across {len(results)} modules.")

        if self.header.report_toggle.isChecked():
            self.log_console.append_line("OK", "HTML report saved to localscan/reports/.")
            self.reports_page.refresh()

    def _on_scan_error(self, error_msg: str) -> None:
        self.header.run_btn.setEnabled(True)
        self.header.run_btn.setText("▶  Run Scan")
        self.log_console.append_line("ERR", f"Scan failed: {error_msg}")

    # ── Demo log lines ────────────────────────────────────────────

    def _populate_demo_log(self) -> None:
        self.log_console.append_line("INFO",  "LocalScan GUI started.")
        self.log_console.append_line("INFO",  f"Platform: {platform.system()} {platform.release()}")
        self.log_console.append_line("INFO",  f"Python {sys.version.split()[0]}")
        self.log_console.append_line("OK",    "All modules imported successfully.")
        self.log_console.append_line("INFO",  "Press  ▶ Run Scan  to begin a local security scan.")


# ---------------------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------------------

def _apply_dark_palette(app: QApplication) -> None:
    """Apply a base QPalette so native widgets inherit the dark theme."""
    pal = QPalette()
    bg      = QColor(Palette.BG_BASE)
    bg_alt  = QColor(Palette.BG_PANEL)
    fg      = QColor(Palette.TEXT_PRIMARY)
    fg_dim  = QColor(Palette.TEXT_SECONDARY)
    accent  = QColor(Palette.ACCENT)
    border  = QColor(Palette.BORDER)

    pal.setColor(QPalette.ColorRole.Window,          bg)
    pal.setColor(QPalette.ColorRole.WindowText,      fg)
    pal.setColor(QPalette.ColorRole.Base,            QColor(Palette.BG_DEEP))
    pal.setColor(QPalette.ColorRole.AlternateBase,   bg_alt)
    pal.setColor(QPalette.ColorRole.Text,            fg)
    pal.setColor(QPalette.ColorRole.BrightText,      fg)
    pal.setColor(QPalette.ColorRole.ButtonText,      fg)
    pal.setColor(QPalette.ColorRole.Button,          bg_alt)
    pal.setColor(QPalette.ColorRole.Highlight,       accent)
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.ColorRole.PlaceholderText, fg_dim)
    pal.setColor(QPalette.ColorRole.Mid,             border)
    pal.setColor(QPalette.ColorRole.Dark,            QColor(Palette.BG_DEEP))

    app.setPalette(pal)


def main() -> None:
    # High-DPI policy must be set before QApplication is constructed
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("LocalScan")
    app.setApplicationVersion("0.1.0")
    app.setOrganizationName("LocalScan")

    _apply_dark_palette(app)
    app.setStyleSheet(STYLESHEET)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
