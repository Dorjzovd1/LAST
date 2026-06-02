"""Forensic тайлангийн narrative — шинжээчийн хэлбэрээр бичсэн мэт текст үүсгэнэ."""
from __future__ import annotations

from typing import Any

from app.models import FindingType, Severity

_IMPACT_MN = {"low": "бага", "moderate": "дунд", "high": "өндөр"}


def _types_phrase(types: list[str]) -> str:
    if not types:
        return "ангилаагүй ерөнхий мэдээлэл"
    if len(types) == 1:
        return f"«{types[0]}» төрлийн мэдээлэл"
    return "«" + "», «".join(types[:3]) + "» зэрэг мэдээллийн төрлүүд"


def narrate_file_executive(
    *,
    file_name: str,
    original_path: str,
    type_label: str,
    sev_label: str,
    overall: str,
    score: int,
    information_types: list[str],
    recovered: bool,
) -> str:
    path = original_path or "—"
    rec = "Агуулгыг амжилттай сэргээж, hash-ээр баталгаажуулах боломжтой байдалтай тул нотлох баримтын чанартай." if recovered else "Одоогоор зөвхөн metadata түвшинд үнэлэгдсэн."
    return (
        f"Энэхүү тайланд «{file_name}» ({path}) файлыг зөөврийн носитол дээр илрүүлсэн "
        f"ул мөрийн хувьд NIST SP 800-60 болон FIPS 199 стандартын дагуу хийсэн эрсдэлийн "
        f"үнэлгээний дүгнэлийг танилцуулж байна. Файл нь {type_label} гэсэн forensic "
        f"контексттэй, мэдээллийн төрлийн хувьд {_types_phrase(information_types)} "
        f"хамаарах ангилалд орсон. Нийт нөлөөллийн түвшин {_IMPACT_MN.get(overall, overall)} "
        f"({sev_label}), FIPS composite оноо {score} байна. {rec}"
    )


def narrate_file_conclusion(
    *,
    file_name: str,
    sev_label: str,
    c: str,
    i: str,
    a: str,
    type_label: str,
) -> str:
    return (
        f"Дээрх шинжилгээний үр дүнд «{file_name}» файлыг {sev_label} эрсдэлтэй гэж үнэлсэн. "
        f"Нууцлалын ({_IMPACT_MN.get(c, c)}), бүрэн бүтэн байдлын ({_IMPACT_MN.get(i, i)}), "
        f"байдлын ({_IMPACT_MN.get(a, a)}) нөлөөллийг тусад нь авч үзэхэд хамгийн "
        f"мэдрэмтгий зорилго нь FIPS 199-ийн high-water mark зарчмаар тодорсон. "
        f"{type_label} гэсэн илрүүлэлтийн шинж нь энэ файлыг хэргийн timeline болон "
        f"бусад ул мөртэй хамтад нь судлах шаардлагатай эсэхийг шийдэхэд чухал ач холбогдолтой."
    )


def narrate_file_recommendations(
    *,
    severity: Severity,
    finding_type: FindingType,
    file_name: str,
    original_path: str,
    recovered: bool,
    sev_label: str,
) -> dict[str, Any]:
    """Зөвлөмж — bullet + шинжээчийн narrative."""
    bullets: list[str] = []
    paragraphs: list[str] = []

    path = original_path or "—"

    if severity == Severity.HIGH:
        bullets.extend([
            "Chain-of-custody журмыг баримтлан хадгалах",
            "SHA-256 hash баталгаажуулах",
            "Гүнзгий агуулгын шинжилгээ хийх",
        ])
        paragraphs.append(
            f"«{file_name}» файлыг {sev_label} ангилалд оруулсан тул эх сурвалжийг "
            f"write-blocker-ийн дараа тусгаарлан хадгалах, hash-ийг тогтмол шалгах "
            f"зайлшгүй шаардлагатай. Зам ({path}) болон файлын нэрийн шинж төлөв "
            f"нөөц мэдээлэл, нууц материал эсвэл архивжуулсан агуулга байж болзошгүй "
            f"тул агуулгын дүн шинжилгээг эргэн хийхийг зөвлөж байна."
        )
    elif severity == Severity.MEDIUM:
        bullets.extend([
            "Timeline-тай харьцуулах",
            "Бусад эмзэг файлтай холбоос шалгах",
        ])
        paragraphs.append(
            f"«{file_name}» нь {sev_label} эрсдэлтэй тул шууд гүн шинжилгээ шаардлагагүй "
            f"ч гэсэн хэргийн бусад үйл явдалтай (MAC цаг, ижил цагийн cluster) "
            f"харьцуулж судлах нь зүйтэй. Хэрэв ижил хавтас эсвэл ижил хугацаанд "
            f"өөр эмзэг файл илэрсэн бол хамтад нь дүгнэлт гаргана."
        )
    else:
        bullets.append("Ердийн каталогчилал")
        paragraphs.append(
            f"«{file_name}» одоогоор хэвийн эрсдэлтэй ангилагдсан. Гэхдээ хэрэгийн "
            f"ерөнхий timeline-д нэмж бүртгэж, дараа нь шинэ ул мөр илэрвэл "
            f"дахин үнэлгээ хийхэд бэлэн байлгахыг зөвлөж байна."
        )

    if finding_type in (FindingType.DELETED_FILE, FindingType.CARVED_FILE, FindingType.RECYCLE_ARTIFACT):
        bullets.append("Устгах/нуух үйлдлийн ул мөрийг timeline-д нягтлах")
        paragraphs.append(
            "Файл устгагдсан эсвэл recycle/carving-аар илэрсэн нь хэрэглэгчийн "
            "санаатай үйлдэл байсан гэсэн таамаглал дэвшүүлдэг. Иймд activity timeline-д "
            "байршуулж, устгахын өмнөх болон дараах үйл ажиллагаатай холбож үзэх нь "
            "шинжилгээний гол чиглэл болно."
        )

    if recovered:
        bullets.append("Сэргээсэн хуулбарыг тусад нь хадгалах")
        paragraphs.append(
            "Агуулгыг сэргээсэн тул сэргээсэн хуулбарыг эх носитлоос тусгаарлан "
            "хадгалж, тайланд MD5/SHA-256 hash заавал оруулах шаардлагатай. "
            "Шүүхэд гаргах боломжтой chain-of-custody баримтыг бүрэн болгохыг анхаарна."
        )

    narrative = "\n\n".join(paragraphs)
    return {"bullets": bullets, "narrative": narrative}


def narrate_file_examiner_opinion(
    *,
    file_name: str,
    sev_label: str,
    type_label: str,
    information_types: list[str],
    overall: str,
) -> str:
    return (
        f"Шинжээчийн санал: «{file_name}» файлыг metadata болон стандартчилсан "
        f"эрсдэлийн шалгуураар үнэлэхэд {sev_label} түвшинд хамаарах нь зүйтэй. "
        f"{type_label} гэсэн контекст нь хэрэгт онцгой анхаарал хандуулах шалтгаан "
        f"болж байна. Мэдээллийн төрөл ({_types_phrase(information_types)})-ийг "
        f"харгалзахад нийт нөлөөлөл {_IMPACT_MN.get(overall, overall)} түвшинд "
        f"байгаа нь энэ файлыг priority жагсаалтад оруулахыг цалин болгож байна. "
        f"Дээрх зөвлөмжийг хэрэгжүүлснээр хэргийн бусад ул мөртэй уялдуулан "
        f"итгэл төрүүлэх дүгнэлт гаргах боломжтой."
    )


def narrate_scan_executive(
    *,
    total: int,
    high: int,
    medium: int,
    normal: int,
    suspicious: int,
    sus_pct: float,
    timeline_count: int,
) -> str:
    return (
        f"Зөөврийн носитол дээр хийсэн шинжилгээгээр нийт {total} ул мөр илэрсэн. "
        f"NIST SP 800-60 болон FIPS 199 стандартын дагуу өндөр эрсдэлтэй {high}, "
        f"дунд зэргийн {medium}, хэвийн {normal} файл тус тус тодорсон. "
        f"Сэжигтэй (өндөр+дунд) гэж ангилагдсан ул мөр {suspicious} ({sus_pct}%) "
        f"байна. Бүх илэрсэн MAC timestamp ({timeline_count} үйл явдал) болон "
        f"metadata-г цагийн дарааллаар нэгтгэн доор уялдуулсан timeline болон "
        f"correlation шинжилгээг танилцуулж байна."
    )


def narrate_scan_recommendations(
    *,
    high: int,
    medium: int,
    deletion_high: int,
    cluster_count: int,
) -> str:
    parts = [
        "Ерөнхий зөвлөмж: Эх носитлыг read-only горимд хадгалж, scan-ийн hash "
        "болон audit бүртгэлийг хадгалах. Өндөр эрсдэлтэй файлуудаас эхлэн "
        "агуулгын шинжилгээ, timeline харьцуулалт хийх."
    ]
    if high > 0:
        parts.append(
            f"Ялангуяа {high} өндөр эрсдэлтэй файлд priority өгч, "
            f"тэдгээрийн hash, зам, MAC цагийг тайланд заавал тусгана."
        )
    if medium > 0:
        parts.append(
            f"{medium} дунд эрсдэлтэй файлыг timeline cluster-тай хамт "
            f"харьцуулж, шаардлагатай бол гүнзгий шинжилгээнд оруулна."
        )
    if deletion_high > 0:
        parts.append(
            f"Устгагдсан/ recycle artifact-аас {deletion_high} нь өндөр эсвэл "
            f"дунд эрсдэлтэй — устгах үйлдлийн санаа зорилготой байсан эсэхийг "
            f"timeline-аар нягтлан судална."
        )
    if cluster_count > 0:
        parts.append(
            f"{cluster_count} цагийн cluster илэрсэн нь тухайн цагийн завсарт "
            f"олон үйлдэл хийгдсэн гэсэн таамаглал дэвшүүлдэг. Эдгээр цонхыг "
            f"эхлээд шалгах нь зүйтэй."
        )
    return " ".join(parts)


def narrate_correlation(
    *,
    clusters: list[dict],
    path_hotspots: list[dict],
    deletion: dict,
) -> str:
    parts: list[str] = []
    if clusters:
        top = clusters[0]
        parts.append(
            f"Цагийн хувьд {top.get('window', '—')} цагийн завсарт {top.get('event_count', 0)} "
            f"үйлдэл төвлөрсөн (өндөр эрсдэл: {top.get('high_risk_events', 0)}). "
            f"Энэ нь тухайн цагт олон файлын metadata өөрчлөгдсөн эсвэл "
            f"хандалт, үүсэл явагдсан гэсэн таамаглал дэвшүүлдэг."
        )
    if path_hotspots:
        h = path_hotspots[0]
        parts.append(
            f"Замын хувьд «{h.get('folder', '—')}» хавтасанд {h.get('count', 0)} "
            f"эмзэг файл төвлөрсөн нь тухайн логик бүсэд чухал агуулга "
            f"байршсан байж магадгүй."
        )
    dh = deletion.get("high_medium_risk_deleted", 0)
    if dh:
        parts.append(
            f"Устгагдсан/recycle artifact-аас {dh} нь өндөр эсвэл дунд эрсдэлтэй "
            f"тул зориуд устгах, нуух оролдлогын ул мөр байж болзошгүй."
        )
    if not parts:
        return (
            "Одоогоор онцгой цагийн cluster эсвэл замын hotspot илрээгүй. "
            "Гэхдээ бүх timeline үйл явдлыг цагийн дарааллаар хянаж, "
            "шинэ ул мөр илэрвэл дахин correlation хийх шаардлагатай."
        )
    return " ".join(parts)


def narrate_timeline_overview(*, event_count: int, high_events: int, first_ts: str, last_ts: str) -> str:
    if event_count == 0:
        return "Timeline үйл явдал бүртгэгдээгүй — scan дахин ажиллуулж MAC цаг цуглуулна."
    span = f"{first_ts} – {last_ts}" if first_ts and last_ts else "—"
    return (
        f"Нийт {event_count} MAC үйл явдлыг цагийн дарааллаар нэгтгэсэн. "
        f"Хугацааны хүрээ: {span}. Эдгээрийн {high_events} нь өндөр эрсдэлтэй "
        f"файлтай холбогдсон. Дараах хүснэгтэд timestamp, metadata, эрсдэлийг "
        f"хамтад нь харуулсан."
    )
