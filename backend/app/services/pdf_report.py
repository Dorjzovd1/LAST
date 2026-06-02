"""Forensic тайланг PDF болгон үүсгэх (fpdf2).

Кирилл (Монгол) үсэг дэмжихийн тулд системд байгаа Unicode TTF фонтыг (DejaVuSans
эсвэл Arial) олж бүртгэнэ. Олдохгүй бол latin-1 fallback ашиглана.
"""
from __future__ import annotations

import os
from datetime import datetime

from fpdf import FPDF

from app.services.reporting import _esc  # noqa: F401  (тогтвортой импорт)

# Unicode TTF фонтын нэр дэвшигчид (regular, bold).
_FONT_CANDIDATES = [
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/truetype/freefont/FreeSans.ttf", "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf"),
    ("C:\\Windows\\Fonts\\arial.ttf", "C:\\Windows\\Fonts\\arialbd.ttf"),
    ("C:\\Windows\\Fonts\\segoeui.ttf", "C:\\Windows\\Fonts\\segoeuib.ttf"),
    ("/Library/Fonts/Arial Unicode.ttf", "/Library/Fonts/Arial Unicode.ttf"),
]

FONT = "rea"


def _find_fonts() -> tuple[str, str] | None:
    for regular, bold in _FONT_CANDIDATES:
        if os.path.exists(regular):
            return regular, bold if os.path.exists(bold) else regular
    return None


class _PDF(FPDF):
    unicode = True

    def __init__(self) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=18)
        fonts = _find_fonts()
        if fonts:
            self.add_font(FONT, "", fonts[0])
            self.add_font(FONT, "B", fonts[1])
            self.unicode = True
        else:
            self.unicode = False

    def _font(self, style: str = "", size: int = 10) -> None:
        if self.unicode:
            self.set_font(FONT, style, size)
        else:
            self.set_font("Helvetica", style, size)

    def _t(self, text: object) -> str:
        s = "" if text is None else str(text)
        if self.unicode:
            return s
        # Unicode фонт байхгүй бол latin-1-д хөрвүүлж, боломжгүй тэмдэгтийг '?' болгоно.
        return s.encode("latin-1", "replace").decode("latin-1")

    def footer(self) -> None:
        self.set_y(-14)
        self._font("", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8, self._t(f"Removable Evidence Analyzer · хуудас {self.page_no()}/{{nb}}"), align="C")


def _heading(pdf: _PDF, text: str) -> None:
    pdf.ln(3)
    pdf._font("B", 12)
    pdf.set_text_color(15, 52, 96)
    pdf.cell(0, 8, pdf._t(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(15, 52, 96)
    pdf.set_line_width(0.4)
    y = pdf.get_y()
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(2)
    pdf.set_text_color(30, 30, 30)


def _kv(pdf: _PDF, rows: list[tuple[str, str]]) -> None:
    label_w = 50
    full = pdf.w - pdf.l_margin - pdf.r_margin
    for key, value in rows:
        pdf._font("B", 9)
        pdf.set_fill_color(243, 244, 248)
        pdf.cell(label_w, 7, pdf._t(key), border=1, fill=True)
        pdf._font("", 9)
        x = pdf.get_x()
        y = pdf.get_y()
        pdf.multi_cell(full - label_w, 7, pdf._t(value or "—"), border=1, new_x="LMARGIN", new_y="NEXT")
        # multi_cell олон мөр болбол дараагийн мөр зөв эхэлнэ.
        if pdf.get_y() <= y:
            pdf.set_xy(x, y)
            pdf.ln(7)


def _table(pdf: _PDF, headers: list[str], rows: list[list[str]], widths: list[float]) -> None:
    pdf._font("B", 8)
    pdf.set_fill_color(15, 52, 96)
    pdf.set_text_color(255, 255, 255)
    for h, w in zip(headers, widths):
        pdf.cell(w, 7, pdf._t(h), border=1, fill=True, align="L")
    pdf.ln(7)
    pdf.set_text_color(30, 30, 30)
    pdf._font("", 8)
    fill = False
    for row in rows:
        # Хуудас халих эсэхийг шалгаж толгойг давтахгүйгээр шинэ хуудас.
        if pdf.get_y() > pdf.h - 25:
            pdf.add_page()
        pdf.set_fill_color(248, 249, 251)
        for val, w in zip(row, widths):
            pdf.cell(w, 6, pdf._t(val), border="LR", fill=fill, align="L")
        pdf.ln(6)
        fill = not fill
    pdf.set_draw_color(200, 200, 200)
    pdf.cell(sum(widths), 0, "", border="T")
    pdf.ln(2)


def _subheading(pdf: _PDF, text: str) -> None:
    pdf.ln(1)
    pdf._font("B", 10)
    pdf.set_text_color(15, 52, 96)
    pdf.cell(0, 6, pdf._t(text), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 30, 30)


def _narrative(pdf: _PDF, text: str) -> None:
    if not text:
        return
    pdf._font("", 9)
    for block in text.split("\n\n"):
        block = block.strip()
        if block:
            pdf.multi_cell(0, 5.5, pdf._t(block), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)


def generate_pdf(data: dict) -> bytes:
    case = data["case"]
    device = data["device"]
    scan = data["scan"]
    summary = data["summary"]
    forensic = data.get("forensic") or {}
    risk = forensic.get("risk_assessment") or {}
    correlated = forensic.get("correlated_timeline") or []
    clusters = (forensic.get("correlations") or {}).get("time_clusters") or []

    pdf = _PDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    title = forensic.get("report_title", "Forensic тайлан")
    pdf._font("B", 15)
    pdf.set_text_color(15, 52, 96)
    pdf.multi_cell(0, 8, pdf._t(title), new_x="LMARGIN", new_y="NEXT")
    pdf._font("", 9)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, pdf._t(f"Scan #{scan.id} · {datetime.now().strftime('%Y-%m-%d %H:%M')}"), new_x="LMARGIN", new_y="NEXT")

    _heading(pdf, "1. Төхөөрөмж")
    _kv(pdf, [
        ("Зам (dev)", device.dev_path if device else "—"),
        ("Нэр", device.name if device else "—"),
        ("Хэмжээ", str(device.size_bytes) if device else "—"),
        ("FS", device.fs_type if device else "—"),
        ("Read-only", "Тийм" if device and device.read_only else "Үгүй"),
    ])

    _heading(pdf, "2. Сэжигтэй байдлын үнэлгээ")
    pdf._font("", 9)
    pdf.multi_cell(0, 5.5, pdf._t(risk.get("executive_narrative", "")), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    sev = summary["by_severity"]
    high = sev.get("high", 0)
    medium = sev.get("medium", 0)
    normal = sev.get("normal", 0)
    sus = summary.get("suspicious_count", high + medium)
    sus_pct = summary.get("suspicious_percent", 0)
    pdf.multi_cell(
        0, 5.5,
        pdf._t(
            f"Нийт: {summary['total_findings']} · Сэжигтэй: {sus} ({sus_pct}%) · "
            f"Өндөр: {high}, Дунд: {medium}, Хэвийн: {normal}."
        ),
        new_x="LMARGIN", new_y="NEXT",
    )

    _heading(pdf, "3. Шинжээчийн тайлан")
    _subheading(pdf, "Timeline")
    _narrative(pdf, forensic.get("timeline_narrative", ""))
    _subheading(pdf, "Correlation шинжилгээ")
    _narrative(pdf, forensic.get("correlation_narrative", ""))
    _subheading(pdf, "Зөвлөмж")
    _narrative(pdf, forensic.get("recommendations_narrative", ""))
    _subheading(pdf, "Нэгдсэн дүгнэлт")
    _narrative(pdf, forensic.get("examiner_report", ""))

    _heading(pdf, "4. Өндөр эрсдэлтэй файлууд")
    hrows = [
        [
            (f.get("file_name") or "—")[:28],
            (f.get("original_path") or "—")[:36],
            str(f.get("risk_score", 0)),
        ]
        for f in risk.get("high_risk_findings", [])[:20]
    ]
    if hrows:
        _table(pdf, ["Файл", "Зам", "FIPS"], hrows, [45, 95, 20])
    else:
        pdf._font("", 9)
        pdf.cell(0, 6, pdf._t("Өндөр эрсдэл олдсонгүй."), new_x="LMARGIN", new_y="NEXT")

    _heading(pdf, "5. Уялдуулсан timeline (timestamp + metadata + эрсдэл)")
    trows = [
        [
            str(e.get("timestamp", ""))[:16],
            str(e.get("event_type", "")),
            str(e.get("severity", ""))[:6],
            (e.get("file_name") or "—")[:22],
            str(e.get("risk_score", 0)),
        ]
        for e in correlated[:100]
    ]
    if trows:
        _table(pdf, ["Цаг", "MACB", "Эрсдэл", "Файл", "FIPS"], trows, [38, 14, 18, 50, 16])
    else:
        pdf._font("", 9)
        pdf.cell(0, 6, pdf._t("Timeline хоосон."), new_x="LMARGIN", new_y="NEXT")

    _heading(pdf, "6. Цаг хугацааны cluster")
    crows = [
        [
            str(c.get("window", ""))[:16],
            str(c.get("event_count", 0)),
            str(c.get("high_risk_events", 0)),
            (c.get("note") or "")[:55],
        ]
        for c in clusters[:15]
    ]
    if crows:
        _table(pdf, ["Цонх", "Үйлдэл", "Өндөр", "Тайлбар"], crows, [36, 18, 18, 110])
    else:
        pdf._font("", 9)
        pdf.cell(0, 6, pdf._t("Cluster олдсонгүй."), new_x="LMARGIN", new_y="NEXT")

    _heading(pdf, "7. Файлын metadata (MACB)")
    frows = [
        [
            f.severity.value,
            (f.file_name or "—")[:30],
            str(f.size_bytes),
            str(f.mtime)[:16] if f.mtime else "—",
        ]
        for f in data["findings"][:40]
    ]
    if frows:
        _table(pdf, ["Зэрэг", "Файл", "Хэмжээ", "Modified"], frows, [18, 70, 24, 40])

    _heading(pdf, "8. Chain-of-custody")
    arows = [[str(a.timestamp)[:19], a.action, (a.target or "")[:40]] for a in data["audit"]]
    if arows:
        _table(pdf, ["Цаг", "Үйлдэл", "Объект"], arows, [42, 50, 90])
    else:
        pdf._font("", 9)
        pdf.cell(0, 6, pdf._t("Бүртгэл алга."), new_x="LMARGIN", new_y="NEXT")

    out = pdf.output()
    return bytes(out)
