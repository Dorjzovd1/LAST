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


def generate_pdf(data: dict) -> bytes:
    case = data["case"]
    device = data["device"]
    scan = data["scan"]
    summary = data["summary"]

    pdf = _PDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    # Гарчиг
    pdf._font("B", 17)
    pdf.set_text_color(15, 52, 96)
    pdf.cell(0, 10, pdf._t("Forensic тайлан"), new_x="LMARGIN", new_y="NEXT")
    pdf._font("", 9)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 6, pdf._t(f"Removable Evidence Analyzer · Scan #{scan.id} · {datetime.now().strftime('%Y-%m-%d %H:%M')}"), new_x="LMARGIN", new_y="NEXT")

    # 1. Хэрэг
    _heading(pdf, "1. Хэргийн мэдээлэл")
    _kv(pdf, [
        ("Хэргийн дугаар", case.case_number if case else "—"),
        ("Гарчиг", case.title if case else "—"),
        ("Шинжээч", case.investigator if case else "—"),
        ("Тайлбар", case.description if case else "—"),
    ])

    # 2. Төхөөрөмж
    _heading(pdf, "2. Төхөөрөмжийн мэдээлэл")
    _kv(pdf, [
        ("Зам (dev)", device.dev_path if device else "—"),
        ("Нэр / Модель", device.name if device else "—"),
        ("Сериал", device.serial if device else "—"),
        ("Холболт", device.bus if device else "—"),
        ("Хэмжээ (bytes)", str(device.size_bytes) if device else "—"),
        ("Файлын систем", device.fs_type if device else "—"),
        ("Read-only", "Тийм" if device and device.read_only else "Үгүй"),
    ])

    # 3. Дүгнэлт
    _heading(pdf, "3. Дүгнэлт")
    pdf._font("", 10)
    sev = summary["by_severity"]
    high = sev.get("high", 0)
    medium = sev.get("medium", 0)
    normal = sev.get("normal", 0)
    total = high + medium + normal
    sus_pct = round((high + medium) / total * 100, 1) if total else 0.0
    pdf.multi_cell(
        0, 6,
        pdf._t(
            f"Нийт файл: {summary['total_findings']} "
            f"(устгагдсан: {summary.get('deleted', 0)}, сэргээсэн: {summary['recovered']}).\n"
            f"Эрсдэлийн түвшин — Өндөр: {high}, Дунд: {medium}, Хэвийн: {normal}.\n"
            f"Сэжигтэй (Өндөр+Дунд): {high + medium} буюу нийт файлын {sus_pct}%."
        ),
        new_x="LMARGIN", new_y="NEXT",
    )

    # NIST SP 800-60 + FIPS 199 стандартын тайлбар.
    pdf.ln(2)
    pdf._font("B", 9)
    pdf.cell(0, 6, pdf._t("Эрсдэлийн үнэлгээний стандарт:"), new_x="LMARGIN", new_y="NEXT")
    pdf._font("", 9)
    from app.services.risk_assessment import RISK_FRAMEWORK

    pdf.multi_cell(
        0,
        5.5,
        pdf._t(RISK_FRAMEWORK["standard"]),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    for ref in RISK_FRAMEWORK["references"]:
        pdf.cell(0, 5.5, pdf._t(f"  • {ref}"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(
        0,
        5.5,
        pdf._t(
            "FIPS 199: Нийт түвшин = max(Нууцлал C, Бүрэн бүтэн байдал I, Байдал A). "
            "HIGH → Өндөр, MODERATE → Дунд, LOW → Хэвийн."
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.set_text_color(30, 30, 30)

    # 4. Файлын жагсаалт (MACB цаг)
    _heading(pdf, "4. Файлын жагсаалт (хэзээ ямар үйлдэл — MACB)")
    frows = [
        [
            f.severity.value,
            "устгасан" if (f.meta or {}).get("deleted") else "идэвхтэй",
            (f.file_name or "—")[:34],
            str(f.size_bytes),
            str(f.mtime)[:16] if f.mtime else "—",
            str(f.crtime)[:16] if f.crtime else "—",
        ]
        for f in data["findings"]
    ]
    if frows:
        _table(pdf, ["Зэрэг", "Төлөв", "Файл", "Хэмжээ", "Modified", "Born"], frows, [18, 20, 50, 22, 40, 40])
    else:
        pdf._font("", 9)
        pdf.cell(0, 6, pdf._t("Файл олдсонгүй."), new_x="LMARGIN", new_y="NEXT")

    # 5. Timeline (хамгийн ихдээ 120 мөр)
    _heading(pdf, "5. Timeline")
    trows = [[str(e.timestamp)[:19], e.event_type, e.description[:70]] for e in data["timeline"][:120]]
    if trows:
        _table(pdf, ["Цаг", "MACB", "Тайлбар"], trows, [42, 16, 124])
    else:
        pdf._font("", 9)
        pdf.cell(0, 6, pdf._t("Timeline хоосон."), new_x="LMARGIN", new_y="NEXT")

    # 6. Audit
    _heading(pdf, "6. Chain-of-custody (audit)")
    arows = [[str(a.timestamp)[:19], a.action, a.actor, (a.target or "")[:40]] for a in data["audit"]]
    if arows:
        _table(pdf, ["Цаг", "Үйлдэл", "Хэрэглэгч", "Объект"], arows, [42, 50, 30, 60])
    else:
        pdf._font("", 9)
        pdf.cell(0, 6, pdf._t("Бүртгэл алга."), new_x="LMARGIN", new_y="NEXT")

    out = pdf.output()
    return bytes(out)
