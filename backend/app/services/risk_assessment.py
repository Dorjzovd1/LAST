"""NIST SP 800-60 Rev. 1 + FIPS 199 дагуу эрсдэлийн үнэлгээ.

Forensic finding бүрт мэдээллийн төрөл (NIST SP 800-60) болон
Нууцлал / Бүрэн бүтэн байдал / Байдал (C/I/A) нөлөөллийг (FIPS 199)
тооцож, нийт түвшинг FIPS 199 «high-water mark» аргаар тогтооно.

Лавлагаа:
  - NIST SP 800-60 Rev. 1 — Guide for Mapping Types of Information and Information
    Systems to Security Categories
  - FIPS 199 — Standards for Security Categorization of Federal Information
    and Information Systems (Section 3: impact levels, overall categorization)
  - NIST SP 800-86 — Guide to Integrating Forensic Techniques (chain of custody,
    evidence handling context for deleted/recovered artifacts)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

from app.models import FindingType, Severity
from app.services.report_narrative import (
    narrate_file_conclusion,
    narrate_file_examiner_opinion,
    narrate_file_executive,
    narrate_file_recommendations,
)

ImpactLevel = Literal["low", "moderate", "high"]

RISK_STANDARD = "NIST SP 800-60 Rev. 1 + FIPS 199"
RISK_STANDARD_REF = "NIST SP 800-60 Rev. 1; FIPS 199; NIST SP 800-86 (forensic context)"

_IMPACT_ORDER: tuple[ImpactLevel, ...] = ("low", "moderate", "high")
_IMPACT_NUM: dict[ImpactLevel, int] = {"low": 1, "moderate": 2, "high": 3}
_IMPACT_MN: dict[ImpactLevel, str] = {
    "low": "Бага",
    "moderate": "Дунд",
    "high": "Өндөр",
}

# NIST SP 800-60 — мэдээллийн төрөл тодорхойлох түлхүүр үг.
_AUTH_KEYWORDS = (
    "password", "passwd", "credential", "token", "secret", "private key",
    "api_key", "apikey", "auth", "login", "нууц", "нууц үг",
)
_PII_KEYWORDS = (
    "ssn", "passport", "id_card", "personal", "pii", "хувийн", "иргэн",
    "regno", "register", "birth", "phone", "email",
)
_FINANCIAL_KEYWORDS = (
    "invoice", "payment", "bank", "salary", "tax", "financial", "төлбөр",
    "данс", "цалин", "sanhuu", "санхүү",
)

# NIST SP 800-60 — өргөтгөлөөр мэдээллийн ангилал.
_CRYPTO_EXT = {"pem", "key", "p12", "pfx", "kdbx", "gpg", "asc", "ppk"}
_DB_EXT = {"db", "sqlite", "sqlite3", "mdb", "accdb", "sql", "dbf"}
_EMAIL_EXT = {"pst", "ost", "eml", "mbox"}
_BUSINESS_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "odt", "ods"}
_TEXT_EXT = {"txt", "csv", "log", "rtf"}
_ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "bz2", "enc"}
_EXECUTABLE_EXT = {"exe", "dll", "bat", "cmd", "ps1", "sh", "scr", "vbs", "js", "msi", "com"}


@dataclass(frozen=True)
class InformationTypeProfile:
    """NIST SP 800-60 мэдээллийн төрөл → FIPS 199 C/I/A."""

    nist_type: str
    confidentiality: ImpactLevel
    integrity: ImpactLevel
    availability: ImpactLevel


@dataclass
class RiskAssessment:
    severity: Severity
    score: int
    reasons: list[str] = field(default_factory=list)
    confidentiality: ImpactLevel = "low"
    integrity: ImpactLevel = "low"
    availability: ImpactLevel = "low"
    overall_impact: ImpactLevel = "low"
    information_types: list[str] = field(default_factory=list)
    standard: str = RISK_STANDARD
    report: dict = field(default_factory=dict)


_FINDING_TYPE_MN: dict[FindingType, str] = {
    FindingType.ACTIVE_FILE: "Идэвхтэй файл (файлын системд бүртгэлтэй)",
    FindingType.DELETED_FILE: "Устгагдсан файл (файлын системээс устгасан)",
    FindingType.CARVED_FILE: "Carving — unallocated space-аас сэргээгдсэн",
    FindingType.RECYCLE_ARTIFACT: "Recycle Bin / Trash артефакт",
    FindingType.SLACK_SPACE: "Slack / unallocated space үлдэгдэл",
}

_SEVERITY_MN: dict[Severity, str] = {
    Severity.HIGH: "Өндөр түвшин",
    Severity.MEDIUM: "Дунд түвшин",
    Severity.NORMAL: "Хэвийн түвшин",
}

_IMPACT_RATIONALE: dict[str, dict[ImpactLevel, str]] = {
    "confidentiality": {
        "low": "Мэдээллийн нууцлалд ноцтой нөлөөлөхгүй эсвэл хязгаарлагдмал.",
        "moderate": "Хязгаарлагдмал нууц эсвэл дотоод хэрэглээний мэдээлэл агуулж болзошгүй.",
        "high": "Нууц мэдээлэл, PII, түлхүүр материал эсвэл эмзэг агуулга байх магадлал өндөр.",
    },
    "integrity": {
        "low": "Бүрэн бүтэн байдалд ноцтой аюул байхгүй.",
        "moderate": "Мэдээлэл өөрчлөгдсөн эсвэл устгах ул мөр илэрсэн болзошгүй.",
        "high": "Гүйцэтгэх код, түлхүүр материал эсвэл tampering-ийн өндөр эрсдэл.",
    },
    "availability": {
        "low": "Үйлчилгээний байдалд нөлөөлөхгүй.",
        "moderate": "Тодорхой системд хязгаарлагдмал нөлөө.",
        "high": "Malware/executable-ийн улмаас системийн ажиллагаанд ноцтой нөлөө.",
    },
}


def _max_impact(a: ImpactLevel, b: ImpactLevel) -> ImpactLevel:
    return _IMPACT_ORDER[max(_IMPACT_ORDER.index(a), _IMPACT_ORDER.index(b))]


def _bump_impact(level: ImpactLevel, steps: int = 1) -> ImpactLevel:
    idx = min(_IMPACT_ORDER.index(level) + steps, len(_IMPACT_ORDER) - 1)
    return _IMPACT_ORDER[idx]


def _high_water_mark(c: ImpactLevel, i: ImpactLevel, a: ImpactLevel) -> ImpactLevel:
    """FIPS 199 Section 3 — overall impact = max(C, I, A)."""
    return _max_impact(_max_impact(c, i), a)


def _fips_composite_score(c: ImpactLevel, i: ImpactLevel, a: ImpactLevel) -> int:
    """C/I/A-ийн тоон илэрхийлэл — эрэмбэлэх, UI-д харуулах."""
    return _IMPACT_NUM[c] * 100 + _IMPACT_NUM[i] * 10 + _IMPACT_NUM[a]


def _impact_to_severity(overall: ImpactLevel) -> Severity:
    if overall == "high":
        return Severity.HIGH
    if overall == "moderate":
        return Severity.MEDIUM
    return Severity.NORMAL


def _detect_information_types(text: str, ext: str) -> list[InformationTypeProfile]:
    """NIST SP 800-60 дагуу файлын мэдээллийн төрлүүд."""
    profiles: list[InformationTypeProfile] = []

    if ext in _CRYPTO_EXT or any(k in text for k in _AUTH_KEYWORDS):
        profiles.append(
            InformationTypeProfile(
                nist_type="Authentication / Cryptographic Key Material",
                confidentiality="high",
                integrity="high",
                availability="low",
            )
        )

    if any(k in text for k in _PII_KEYWORDS):
        profiles.append(
            InformationTypeProfile(
                nist_type="Privacy / PII",
                confidentiality="high",
                integrity="moderate",
                availability="low",
            )
        )

    if ext in _DB_EXT:
        profiles.append(
            InformationTypeProfile(
                nist_type="Information System / Database Content",
                confidentiality="high",
                integrity="moderate",
                availability="moderate",
            )
        )

    if ext in _EMAIL_EXT:
        profiles.append(
            InformationTypeProfile(
                nist_type="Email / Messaging Records",
                confidentiality="moderate",
                integrity="moderate",
                availability="low",
            )
        )

    if any(k in text for k in _FINANCIAL_KEYWORDS) or ext in {"xlsx", "xls"}:
        profiles.append(
            InformationTypeProfile(
                nist_type="Financial / Proprietary Business Information",
                confidentiality="moderate",
                integrity="moderate",
                availability="low",
            )
        )

    if ext in _BUSINESS_EXT or ext in _TEXT_EXT:
        profiles.append(
            InformationTypeProfile(
                nist_type="General Business / Operational Records",
                confidentiality="moderate",
                integrity="low",
                availability="low",
            )
        )

    if ext in _ARCHIVE_EXT:
        profiles.append(
            InformationTypeProfile(
                nist_type="Archive / Encrypted Container (concealment risk)",
                confidentiality="moderate",
                integrity="low",
                availability="low",
            )
        )

    if ext in _EXECUTABLE_EXT:
        profiles.append(
            InformationTypeProfile(
                nist_type="Software / Executable Code (malware risk)",
                confidentiality="low",
                integrity="high",
                availability="high",
            )
        )

    if not profiles:
        profiles.append(
            InformationTypeProfile(
                nist_type="Unclassified / General Data",
                confidentiality="low",
                integrity="low",
                availability="low",
            )
        )

    return profiles


def _apply_forensic_context(
    *,
    finding_type: FindingType,
    recovered: bool,
    c: ImpactLevel,
    i: ImpactLevel,
    a: ImpactLevel,
) -> tuple[ImpactLevel, ImpactLevel, ImpactLevel, list[str]]:
    """NIST SP 800-86 — forensic контекст (тайлбар + carving/slack-д C/I нэмэгдүүлэлт)."""
    reasons: list[str] = []
    new_c, new_i, new_a = c, i, a

    if finding_type == FindingType.DELETED_FILE:
        reasons.append(
            "NIST SP 800-86: Файлын системээс устгагдсан — chain-of-custody-д анхаарах"
        )
    elif finding_type == FindingType.CARVED_FILE:
        new_i = _max_impact(_bump_impact(new_i), "moderate")
        reasons.append(
            "NIST SP 800-86: Unallocated/carving — нуух/устгах ул мөр; "
            f"бүрэн бүтэн байдал (I) → {_IMPACT_MN[new_i]}"
        )
    elif finding_type == FindingType.RECYCLE_ARTIFACT:
        reasons.append("NIST SP 800-86: Recycle/Trash артефакт — устгах үйлдлийн ул мөр")
    elif finding_type == FindingType.SLACK_SPACE:
        if new_c == "low":
            new_c = "moderate"
        reasons.append(
            f"NIST SP 800-86: Slack/unallocated үлдэгдэл — нууцлал (C) → {_IMPACT_MN[new_c]}"
        )

    if recovered:
        reasons.append(
            "NIST SP 800-86: Агуулга сэргээгдсэн — chain of custody-д нотлох баримт боломжтой"
        )

    return new_c, new_i, new_a, reasons


def _impact_block(key: str, level: ImpactLevel) -> dict:
    return {
        "level": level,
        "label_mn": _IMPACT_MN[level],
        "label_en": level.upper(),
        "rationale": _IMPACT_RATIONALE[key][level],
    }


def _recommendations(severity: Severity, finding_type: FindingType, recovered: bool) -> list[str]:
    recs: list[str] = []
    if severity == Severity.HIGH:
        recs.extend([
            "Тухайн файлыг шинжилгээний эх сурвалжид chain-of-custody журмыг баримтлан хадгалах.",
            "SHA-256 hash-ийг баталгаажуулж, өөрчлөлтгүй байдлыг тогтмол шалгах.",
            "Агуулгыг гүнзгий forensic шинжилгээнд (агуулга, metadata, холбоотой artifact) өргөмжлөнө.",
        ])
    elif severity == Severity.MEDIUM:
        recs.extend([
            "Файлыг хэргийн бусад ул мөртэй (timeline, хэрэглэгчийн үйлдэл) харьцуулж үзнэ.",
            "Шаардлагатай бол агуулгын урьдчилсан шинжилгээ (preview/hash) хийнэ.",
        ])
    else:
        recs.append("Ердийн каталогчилалын горимд бүртгэж, онцгой шалтгаан гарвал дахин үнэлнэ.")

    if finding_type in (FindingType.DELETED_FILE, FindingType.CARVED_FILE, FindingType.RECYCLE_ARTIFACT):
        recs.append("Устгах/нуух үйлдлийн ул мөр тул timeline-тай хамт нягтлан судална.")
    if recovered:
        recs.append("Сэргээгдсэн агуулгыг тусгаарласан хадгалалтад хадгалж, тайланд hash заавал оруулна.")
    return recs


def build_official_risk_report(
    *,
    assessment: RiskAssessment,
    finding_type: FindingType,
    file_name: str,
    original_path: str,
    recovered: bool,
    reasons: list[str],
) -> dict:
    """Албан ёсны эрсдэлийн үнэлгээний тайлбар (UI/PDF-д)."""
    ext = os.path.splitext(file_name)[1].lstrip(".").lower() or "—"
    type_label = _FINDING_TYPE_MN.get(finding_type, finding_type.value)
    sev_label = _SEVERITY_MN[assessment.severity]
    c, i, a = assessment.confidentiality, assessment.integrity, assessment.availability
    overall = assessment.overall_impact

    rec_pack = narrate_file_recommendations(
        severity=assessment.severity,
        finding_type=finding_type,
        file_name=file_name,
        original_path=original_path,
        recovered=recovered,
        sev_label=sev_label,
    )

    executive = narrate_file_executive(
        file_name=file_name,
        original_path=original_path,
        type_label=type_label,
        sev_label=sev_label,
        overall=overall,
        score=assessment.score,
        information_types=assessment.information_types,
        recovered=recovered,
    )

    conclusion = narrate_file_conclusion(
        file_name=file_name,
        sev_label=sev_label,
        c=c,
        i=i,
        a=a,
        type_label=type_label,
    )

    examiner_opinion = narrate_file_examiner_opinion(
        file_name=file_name,
        sev_label=sev_label,
        type_label=type_label,
        information_types=assessment.information_types,
        overall=overall,
    )

    analysis_steps = [
        {
            "step": 1,
            "title": "Мэдээллийн төрөл тодорхойлох",
            "standard": "NIST SP 800-60 Rev. 1",
            "detail": (
                "Файлын нэр, зам, өргөтгөлөөр NIST SP 800-60-д заасан мэдээллийн "
                f"ангилал тогтоосон. Илэрсэн төрлүүд: {', '.join(assessment.information_types) or '—'}."
            ),
        },
        {
            "step": 2,
            "title": "C/I/A нөлөөллийн үнэлгээ",
            "standard": "FIPS 199",
            "detail": (
                "Нууцлал, бүрэн бүтэн байдал, байдал гэсэн гурван зорилгоор "
                "LOW / MODERATE / HIGH түвшин тус бүрд оноож, нийт түвшинг "
                "max(C, I, A) — high-water mark аргаар тогтоосон."
            ),
        },
        {
            "step": 3,
            "title": "Forensic контекст",
            "standard": "NIST SP 800-86",
            "detail": (
                f"Илрүүлэлтийн төрөл: {type_label}. "
                f"Сэргээгдсэн эсэх: {'Тийм' if recovered else 'Үгүй'}. "
                "Устгасан, carving, recycle, slack зэрэг контекстэд chain-of-custody "
                "болон шинжилгээний ач холбогдолд нөлөөлнө."
            ),
        },
        {
            "step": 4,
            "title": "Эрсдэлийн түвшин холбох",
            "standard": "FIPS 199 → REA severity",
            "detail": (
                f"HIGH → Өндөр; MODERATE → Дунд; LOW → Хэвийн. "
                f"Энэ файл: {_IMPACT_MN[overall]} → {sev_label}."
            ),
        },
    ]

    return {
        "document_type": "FORENSIC_RISK_ASSESSMENT_MEMO",
        "title": "Эрсдэлийн үнэлгээний албан ёсны тайлбар",
        "standard_framework": RISK_STANDARD,
        "standard_references": [
            {
                "id": "NIST-800-60",
                "citation": "NIST SP 800-60 Rev. 1",
                "scope": "Мэдээллийн төрөл → аюулгүй байдлын ангилал",
            },
            {
                "id": "FIPS-199",
                "citation": "FIPS 199",
                "scope": "Нууцлал, бүрэн бүтэн байдал, байдал (C/I/A)",
            },
            {
                "id": "NIST-800-86",
                "citation": "NIST SP 800-86",
                "scope": "Forensic арга, chain of custody, ул мөрийн контекст",
            },
        ],
        "methodology": (
            "Энэ систем нь зөөврийн носитол дээрх файлуудыг read-only горимд шинжилж, "
            "metadata (нэр, зам, MAC цаг, илрүүлэлтийн төрөл) дээр суурилан "
            "NIST SP 800-60 Rev. 1-ийн мэдээллийн төрөл, FIPS 199-ийн C/I/A нөлөөлөл, "
            "NIST SP 800-86-ийн forensic контекстийг нэгтгэн automat эрсдэлийн triage гүйцэтгэнэ. "
            "Үнэлгээ нь субъектив биш, давтагдах, стандартын лавлагаатай байх зорилготой."
        ),
        "subject": {
            "file_name": file_name,
            "original_path": original_path or "—",
            "extension": ext,
            "finding_type": finding_type.value,
            "finding_type_label": type_label,
            "recovered": recovered,
        },
        "impact_assessment": {
            "confidentiality": _impact_block("confidentiality", c),
            "integrity": _impact_block("integrity", i),
            "availability": _impact_block("availability", a),
            "overall": {
                "level": overall,
                "label_mn": _IMPACT_MN[overall],
                "method": "FIPS 199 high-water mark (max of C, I, A)",
            },
            "fips_composite_score": assessment.score,
            "severity": assessment.severity.value,
            "severity_label_mn": sev_label,
        },
        "information_types": assessment.information_types,
        "analysis_steps": analysis_steps,
        "detailed_findings": reasons,
        "executive_summary": executive,
        "conclusion": conclusion,
        "recommendations": rec_pack["bullets"],
        "recommendations_narrative": rec_pack["narrative"],
        "examiner_opinion": examiner_opinion,
        "disclaimer": (
            "Анхааруулга: Энэ баримт нь автomat metadata-based triage үр дүн болно. "
            "Агуулгын дүн шинжилгээ, хууль зүйн дүгнэлт, шинжээчийн эцсийн санал "
            "биш. Шаардлагатай тохиолдолд агуулгын forensic шинжилгээ, hash баталгаажуулалт, "
            "chain-of-custody журмыг мөрдөнө."
        ),
    }


def assess_risk(
    *,
    finding_type: FindingType,
    file_name: str,
    original_path: str = "",
    recovered: bool = False,
) -> RiskAssessment:
    """NIST SP 800-60 + FIPS 199 дагуу эрсдэлийн үнэлгээ."""
    text = f"{file_name} {original_path}".lower()
    ext = os.path.splitext(file_name)[1].lstrip(".").lower()

    profiles = _detect_information_types(text, ext)
    c: ImpactLevel = "low"
    i: ImpactLevel = "low"
    a: ImpactLevel = "low"
    type_names: list[str] = []
    reasons: list[str] = []

    for profile in profiles:
        type_names.append(profile.nist_type)
        c = _max_impact(c, profile.confidentiality)
        i = _max_impact(i, profile.integrity)
        a = _max_impact(a, profile.availability)
        reasons.append(
            f"NIST SP 800-60 [{profile.nist_type}]: "
            f"C={_IMPACT_MN[profile.confidentiality]}, "
            f"I={_IMPACT_MN[profile.integrity]}, "
            f"A={_IMPACT_MN[profile.availability]}"
        )

    # Идэвхтэй файл — устгах контекст нэмэхгүй (800-86).
    if finding_type != FindingType.ACTIVE_FILE:
        c, i, a, forensic_reasons = _apply_forensic_context(
            finding_type=finding_type,
            recovered=recovered,
            c=c,
            i=i,
            a=a,
        )
        reasons.extend(forensic_reasons)
    elif recovered:
        reasons.append(
            "NIST SP 800-86: Идэвхтэй файл — chain of custody-д шууд нотлох боломжтой"
        )

    overall = _high_water_mark(c, i, a)
    severity = _impact_to_severity(overall)
    score = _fips_composite_score(c, i, a)

    reasons.append(
        f"FIPS 199 (high-water mark): Нийт түвшин = {_IMPACT_MN[overall]} "
        f"(C={_IMPACT_MN[c]}, I={_IMPACT_MN[i]}, A={_IMPACT_MN[a]})"
    )

    assessment = RiskAssessment(
        severity=severity,
        score=score,
        reasons=reasons,
        confidentiality=c,
        integrity=i,
        availability=a,
        overall_impact=overall,
        information_types=type_names,
        standard=RISK_STANDARD,
    )
    assessment.report = build_official_risk_report(
        assessment=assessment,
        finding_type=finding_type,
        file_name=file_name,
        original_path=original_path,
        recovered=recovered,
        reasons=reasons,
    )
    return assessment


# PDF/UI-д харуулах стандартын товч тайлбар.
RISK_FRAMEWORK = {
    "standard": RISK_STANDARD,
    "references": [
        "NIST SP 800-60 Rev. 1 — мэдээллийн төрөл → C/I/A нөлөөлөл",
        "FIPS 199 — нийт аюулгүй байдлын ангилал (max of C, I, A)",
        "NIST SP 800-86 — forensic контекст (устгасан, carving, сэргээлт)",
    ],
    "severity_mapping": {
        "high": "FIPS 199 overall impact = HIGH → Өндөр",
        "moderate": "FIPS 199 overall impact = MODERATE → Дунд",
        "low": "FIPS 199 overall impact = LOW → Хэвийн",
    },
}

# Хуучин PDF import-тай нийцэх alias.
RISK_RULES = [
    {"rule": ref, "points": "—"}
    for ref in RISK_FRAMEWORK["references"]
]
