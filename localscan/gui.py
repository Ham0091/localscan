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
    QTimer,
    Property,
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
    """Semi-circular arc gauge showing a 0-100 risk score with zone bands."""

    # Zone definitions: (start_pct, end_pct, color)
    _ZONES = [
        (0,  20,  "#3b82f6"),   # blue  — low risk
        (20, 50,  "#eab308"),   # yellow — medium risk
        (50, 100, "#ef4444"),   # red   — high risk
    ]
    _ZONE_DIM_ALPHA = 45        # opacity for background zone bands
    _TRACK_COLOR    = "#1e1e36"

    def __init__(self, score: int = 0, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._score = 0.0       # animated property value
        self._target = max(0, min(100, score))
        self.setMinimumSize(180, 120)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        # Animation
        self._anim = QPropertyAnimation(self, b"animatedScore")
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.setDuration(800)
        if self._target:
            self.set_score(self._target)

    # ── Qt property for animation ─────────────────────────────────
    def _get_animated_score(self) -> float:
        return self._score

    def _set_animated_score(self, val: float) -> None:
        self._score = val
        self.update()

    animatedScore = Property(float, _get_animated_score, _set_animated_score)

    # ── Public API ────────────────────────────────────────────────
    def set_score(self, score: int) -> None:
        target = max(0.0, min(100.0, float(score)))
        self._anim.stop()
        self._anim.setStartValue(self._score)
        self._anim.setEndValue(target)
        self._anim.start()

    def _needle_color(self) -> QColor:
        s = self._score
        if s > 50:
            return QColor("#ef4444")
        if s > 20:
            return QColor("#eab308")
        return QColor("#3b82f6")

    # ── Painting ──────────────────────────────────────────────────
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

        # 1) Full track (dark background)
        pen = QPen(QColor(self._TRACK_COLOR))
        pen.setWidth(int(arc_w))
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        painter.setPen(pen)
        painter.drawArc(
            int(rect_x), int(rect_y), int(rect_side), int(rect_side),
            180 * 16, -180 * 16,
        )

        # 2) Zone bands (semi-transparent colored segments)
        for z_start, z_end, z_color in self._ZONES:
            c = QColor(z_color)
            c.setAlpha(self._ZONE_DIM_ALPHA)
            pen_z = QPen(c)
            pen_z.setWidth(int(arc_w))
            pen_z.setCapStyle(Qt.PenCapStyle.FlatCap)
            painter.setPen(pen_z)
            start_angle = int(180 * 16 - (z_start / 100) * 180 * 16)
            span_angle  = int(-((z_end - z_start) / 100) * 180 * 16)
            painter.drawArc(
                int(rect_x), int(rect_y), int(rect_side), int(rect_side),
                start_angle, span_angle,
            )

        # 3) Filled arc up to current score
        if self._score > 0.5:
            pen2 = QPen(self._needle_color())
            pen2.setWidth(int(arc_w))
            pen2.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen2)
            span = int(-180 * 16 * self._score / 100)
            painter.drawArc(
                int(rect_x), int(rect_y),
                int(rect_side), int(rect_side),
                180 * 16, span,
            )

        # 4) Score number
        painter.setPen(QPen(self._needle_color()))
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
            str(int(round(self._score))),
        )

        # 5) Label
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
# Finding card — collapsible card for a single scan finding
# ---------------------------------------------------------------------------

_SEV_BADGE = {
    "Critical": (Palette.CRITICAL, "#1a0505"),
    "High":     (Palette.HIGH,     "#1a0e05"),
    "Medium":   (Palette.MEDIUM,   "#1a1505"),
    "Low":      (Palette.LOW,      "#051a0a"),
    "Info":     (Palette.ACCENT_LITE, Palette.BG_CARD),
}


class FindingCard(QFrame):
    """Collapsible card displaying a single finding."""

    def __init__(
        self,
        finding: dict,
        module_name: str = "",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._expanded = False
        self._finding = finding

        sev = finding.get("severity", "Info")
        name = finding.get("name", "Unknown Finding")
        desc = finding.get("description", "")
        rec = finding.get("recommendation", "")
        conf = finding.get("confidence", "")
        evidence = finding.get("evidence", "")

        fg, bg = _SEV_BADGE.get(sev, _SEV_BADGE["Info"])

        self.setStyleSheet(f"""
            FindingCard {{
                background: {Palette.BG_CARD};
                border: 1px solid {Palette.BORDER};
                border-radius: 8px;
            }}
            FindingCard:hover {{
                border-color: {Palette.BORDER_LT};
            }}
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header row ────────────────────────────────────────────
        header = QWidget()
        header.setStyleSheet("background: transparent; border: none;")
        h_lay = QHBoxLayout(header)
        h_lay.setContentsMargins(16, 12, 16, 12)
        h_lay.setSpacing(10)

        # Expand indicator
        self._arrow = _label("▸", size=11, color=Palette.TEXT_MUTED)
        self._arrow.setFixedWidth(14)
        h_lay.addWidget(self._arrow)

        # Severity badge
        badge = QLabel(sev.upper())
        badge.setFixedHeight(22)
        badge.setStyleSheet(f"""
            QLabel {{
                background: {bg};
                color: {fg};
                border: 1px solid {fg};
                border-radius: 4px;
                font-size: 10px;
                font-weight: 700;
                letter-spacing: 0.8px;
                padding: 0 8px;
            }}
        """)
        h_lay.addWidget(badge)

        # Title
        title_lbl = _label(name, size=13, bold=True)
        title_lbl.setStyleSheet(f"color: {Palette.TEXT_PRIMARY}; background: transparent; border: none;")
        h_lay.addWidget(title_lbl, 1)

        # Module chip
        if module_name:
            mod_lbl = _label(module_name, size=10, color=Palette.TEXT_SECONDARY)
            mod_lbl.setStyleSheet(
                f"color: {Palette.TEXT_SECONDARY}; background: {Palette.BG_PANEL}; "
                f"border: 1px solid {Palette.BORDER}; border-radius: 4px; "
                "padding: 2px 8px; font-size: 10px;"
            )
            h_lay.addWidget(mod_lbl)

        # Confidence chip
        if conf:
            conf_lbl = _label(conf, size=10, color=Palette.TEXT_MUTED)
            conf_lbl.setStyleSheet(
                f"color: {Palette.TEXT_MUTED}; background: transparent; "
                "border: none; font-size: 10px;"
            )
            h_lay.addWidget(conf_lbl)

        root.addWidget(header)

        # ── Body (hidden by default) ──────────────────────────────
        self._body = QWidget()
        self._body.setVisible(False)
        self._body.setStyleSheet(f"""
            QWidget {{
                background: transparent;
                border: none;
                border-top: 1px solid {Palette.BORDER};
            }}
        """)
        b_lay = QVBoxLayout(self._body)
        b_lay.setContentsMargins(42, 12, 16, 16)
        b_lay.setSpacing(8)

        if desc:
            b_lay.addWidget(self._detail_block("DESCRIPTION", desc))
        if rec:
            b_lay.addWidget(self._detail_block("REMEDIATION", rec))
        if evidence:
            b_lay.addWidget(self._detail_block("EVIDENCE", str(evidence), mono=True))

        root.addWidget(self._body)

    @staticmethod
    def _detail_block(heading: str, text: str, mono: bool = False) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background: transparent; border: none;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        h = _label(heading, size=10, color=Palette.TEXT_MUTED, bold=True)
        h.setStyleSheet(
            f"color: {Palette.TEXT_MUTED}; font-size: 10px; font-weight: 700; "
            "letter-spacing: 1.2px; background: transparent; border: none;"
        )
        lay.addWidget(h)

        body = QLabel(text)
        body.setWordWrap(True)
        font_family = (
            '"JetBrains Mono", "Cascadia Code", Consolas, monospace'
            if mono
            else ""
        )
        body.setStyleSheet(
            f"color: {Palette.TEXT_PRIMARY}; font-size: 12px; "
            f"line-height: 1.4; background: transparent; border: none;"
            + (f" font-family: {font_family};" if font_family else "")
        )
        lay.addWidget(body)
        return w

    def mousePressEvent(self, _event) -> None:  # noqa: N802
        self._expanded = not self._expanded
        self._body.setVisible(self._expanded)
        self._arrow.setText("▾" if self._expanded else "▸")


# ---------------------------------------------------------------------------
# Findings page — scrollable list of FindingCards for one module
# ---------------------------------------------------------------------------

class FindingsPage(QScrollArea):
    """Scrollable page that displays FindingCards for a scan module."""

    def __init__(
        self,
        title: str,
        placeholder_text: str = "Run a scan to see findings.",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._title_text = title
        self._placeholder_text = placeholder_text
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setStyleSheet("background: transparent;")

        self._container = QWidget()
        self._container.setStyleSheet("background: transparent;")
        self.setWidget(self._container)

        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(28, 28, 28, 28)
        self._layout.setSpacing(12)

        self._title_lbl = _label(title, size=20, bold=True)
        self._layout.addWidget(self._title_lbl)

        self._count_lbl = _label("", size=12, color=Palette.TEXT_SECONDARY)
        self._layout.addWidget(self._count_lbl)

        self._placeholder = _label(
            placeholder_text, size=13, color=Palette.TEXT_MUTED,
        )
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._layout.addWidget(self._placeholder)

        self._layout.addStretch()

    def set_findings(self, findings: list, module_name: str = "") -> None:
        """Replace current cards with new findings."""
        # Remove old cards (keep title, count, placeholder, stretch)
        while self._layout.count() > 4:
            item = self._layout.takeAt(3)  # position after count_lbl
            if item.widget():
                item.widget().deleteLater()

        if findings:
            self._placeholder.setVisible(False)
            self._count_lbl.setText(f"{len(findings)} finding{'s' if len(findings) != 1 else ''}")
            # Insert cards before the stretch
            insert_pos = 3
            for f in findings:
                card = FindingCard(f, module_name=module_name)
                self._layout.insertWidget(insert_pos, card)
                insert_pos += 1
        else:
            self._placeholder.setVisible(True)
            self._placeholder.setText("No findings for this module.")
            self._count_lbl.setText("")

    def clear_findings(self) -> None:
        """Reset to placeholder state."""
        while self._layout.count() > 4:
            item = self._layout.takeAt(3)
            if item.widget():
                item.widget().deleteLater()
        self._placeholder.setVisible(True)
        self._placeholder.setText(self._placeholder_text)
        self._count_lbl.setText("")


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

        # Module findings pages (indices 1-4)
        self.network_page    = FindingsPage("Network",    "Network check results will appear here after a scan.")
        self.system_page     = FindingsPage("System",     "System check results will appear here after a scan.")
        self.filesystem_page = FindingsPage("Filesystem", "Filesystem check results will appear here after a scan.")
        self.services_page   = FindingsPage("Services",   "Services & persistence check results will appear here after a scan.")
        self.stack.addWidget(self.network_page)     # index 1
        self.stack.addWidget(self.system_page)      # index 2
        self.stack.addWidget(self.filesystem_page)  # index 3
        self.stack.addWidget(self.services_page)    # index 4

        # Module key -> page mapping for scan result routing
        self._module_pages = {
            "network":    self.network_page,
            "system":     self.system_page,
            "filesystem": self.filesystem_page,
            "services":   self.services_page,
        }

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

        # Populate module findings pages
        for module_key, findings in results.items():
            page = self._module_pages.get(module_key)
            if page is not None:
                page.set_findings(findings, module_name=module_key.title())

        # Update dashboard gauge with risk score
        try:
            from localscan.report import calculate_risk_score
            all_findings = [f for fl in results.values() for f in fl]
            score = calculate_risk_score(all_findings)
            self.dashboard_page.gauge.set_score(score)
        except Exception:
            pass

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
# Splash screen
# ---------------------------------------------------------------------------

class SplashScreen(QWidget):
    """Dark splash with radar-pulse animation, progress bar, and status text."""

    _MESSAGES = [
        "Initializing LocalScan Engine...",
        "Detecting OS...",
        "Checking Privileges...",
        "Loading Modules...",
    ]

    finished = Signal()  # emitted when the splash sequence is done

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedSize(420, 320)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.SplashScreen
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setStyleSheet(f"background: {Palette.BG_DEEP};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 36, 40, 32)
        layout.setSpacing(0)

        # Shield / radar icon area
        self._pulse_angle = 0.0
        self._pulse_widget = QWidget()
        self._pulse_widget.setFixedSize(120, 120)
        self._pulse_widget.setStyleSheet("background: transparent;")
        layout.addWidget(self._pulse_widget, 0, Qt.AlignmentFlag.AlignCenter)

        layout.addSpacing(16)

        # Title
        title = _label("LocalScan", size=18, bold=True)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"color: {Palette.TEXT_PRIMARY}; background: transparent;")
        layout.addWidget(title)

        layout.addSpacing(20)

        # Status text
        self._status = _label(self._MESSAGES[0], size=11, color=Palette.TEXT_SECONDARY)
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status.setStyleSheet(
            f"color: {Palette.TEXT_SECONDARY}; background: transparent; "
            "letter-spacing: 0.6px;"
        )
        layout.addWidget(self._status)

        layout.addSpacing(14)

        # Progress bar
        self._bar_bg = QWidget()
        self._bar_bg.setFixedHeight(4)
        self._bar_bg.setStyleSheet(
            f"background: {Palette.BORDER}; border-radius: 2px;"
        )
        layout.addWidget(self._bar_bg)

        self._bar_fill = QWidget(self._bar_bg)
        self._bar_fill.setFixedHeight(4)
        self._bar_fill.setStyleSheet(
            f"background: {Palette.ACCENT}; border-radius: 2px;"
        )
        self._bar_fill.setFixedWidth(0)

        layout.addStretch()

        # State
        self._step = 0
        self._progress = 0.0

        # Pulse animation timer (radar sweep)
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(30)
        self._pulse_timer.timeout.connect(self._tick_pulse)

        # Step timer — advance message every 400ms
        self._step_timer = QTimer(self)
        self._step_timer.setInterval(400)
        self._step_timer.timeout.connect(self._advance)

    # ── Start / stop ──────────────────────────────────────────────
    def begin(self) -> None:
        self.show()
        self._center_on_screen()
        self._pulse_timer.start()
        self._step_timer.start()

    def _center_on_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            self.move(
                geo.x() + (geo.width() - self.width()) // 2,
                geo.y() + (geo.height() - self.height()) // 2,
            )

    # ── Timers ────────────────────────────────────────────────────
    def _tick_pulse(self) -> None:
        self._pulse_angle = (self._pulse_angle + 3) % 360
        self._pulse_widget.update()
        self.update()  # trigger paintEvent for the radar

    def _advance(self) -> None:
        self._step += 1
        total = len(self._MESSAGES)
        if self._step < total:
            self._status.setText(self._MESSAGES[self._step])
            frac = self._step / total
            self._bar_fill.setFixedWidth(int(self._bar_bg.width() * frac))
        else:
            self._bar_fill.setFixedWidth(self._bar_bg.width())
            self._status.setText("Ready.")
            self._step_timer.stop()
            self._pulse_timer.stop()
            QTimer.singleShot(300, self._finish)

    def _finish(self) -> None:
        self.finished.emit()
        self.close()

    # ── Paint: radar pulse rings ──────────────────────────────────
    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Map pulse widget position to self coords
        pw = self._pulse_widget
        cx = pw.x() + pw.width() / 2
        cy = pw.y() + pw.height() / 2
        max_r = pw.width() / 2

        # Concentric rings (static, dim)
        for i in range(1, 4):
            r = max_r * i / 3
            c = QColor(Palette.BORDER_LT)
            c.setAlpha(40 + i * 10)
            pen = QPen(c)
            pen.setWidthF(1.0)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(int(cx - r), int(cy - r), int(r * 2), int(r * 2))

        # Sweep wedge
        sweep_color = QColor(Palette.ACCENT)
        sweep_color.setAlpha(50)
        grad = QConicalGradient(cx, cy, -self._pulse_angle)
        grad.setColorAt(0.0, sweep_color)
        t = QColor(Palette.ACCENT)
        t.setAlpha(0)
        grad.setColorAt(0.15, t)
        grad.setColorAt(1.0, t)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(grad))
        painter.drawEllipse(int(cx - max_r), int(cy - max_r), int(max_r * 2), int(max_r * 2))

        # Centre dot
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(Palette.ACCENT))
        painter.drawEllipse(int(cx - 3), int(cy - 3), 6, 6)

        painter.end()


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

    splash = SplashScreen()
    window = MainWindow()

    def _on_splash_done() -> None:
        window.show()

    splash.finished.connect(_on_splash_done)
    splash.begin()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
