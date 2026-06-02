import type { Finding } from "../api/types";

export interface RiskImpactBlock {
  level: string;
  label_mn: string;
  label_en?: string;
  rationale: string;
}

export interface RiskAnalysisStep {
  step: number;
  title: string;
  standard: string;
  detail: string;
}

export interface RiskOfficialReport {
  document_type?: string;
  title: string;
  standard_framework: string;
  standard_references?: { id: string; citation: string; scope: string }[];
  methodology: string;
  subject: {
    file_name: string;
    original_path: string;
    extension: string;
    finding_type: string;
    finding_type_label: string;
    recovered: boolean;
  };
  impact_assessment: {
    confidentiality: RiskImpactBlock;
    integrity: RiskImpactBlock;
    availability: RiskImpactBlock;
    overall: { level: string; label_mn: string; method: string };
    fips_composite_score: number;
    severity: string;
    severity_label_mn: string;
  };
  information_types: string[];
  analysis_steps: RiskAnalysisStep[];
  detailed_findings: string[];
  executive_summary: string;
  conclusion: string;
  recommendations: string[];
  recommendations_narrative?: string;
  examiner_opinion?: string;
  disclaimer: string;
}

const SEV_MN: Record<string, string> = {
  high: "Өндөр түвшин",
  medium: "Дунд түвшин",
  normal: "Хэвийн түвшин",
};

const IMPACT_MN: Record<string, string> = {
  low: "Бага",
  moderate: "Дунд",
  high: "Өндөр",
};

/** Meta-аас албан ёсны тайлан унших эсвэл хуучин scan-д fallback үүсгэх. */
export function getRiskReport(finding: Finding): RiskOfficialReport {
  const stored = finding.meta?.["risk_report"] as RiskOfficialReport | undefined;
  if (stored?.title && stored.executive_summary) return stored;

  const c = (finding.meta?.["risk_confidentiality"] as string) ?? "low";
  const i = (finding.meta?.["risk_integrity"] as string) ?? "low";
  const a = (finding.meta?.["risk_availability"] as string) ?? "low";
  const overall = (finding.meta?.["risk_overall_impact"] as string) ?? "low";
  const reasons = (finding.meta?.["risk_reasons"] as string[]) ?? [];
  const types = (finding.meta?.["risk_information_types"] as string[]) ?? [];

  return {
    title: "Эрсдэлийн үнэлгээний албан ёсны тайлбар",
    standard_framework: (finding.meta?.["risk_standard"] as string) ?? "NIST SP 800-60 Rev. 1 + FIPS 199",
    methodology:
      "Metadata (нэр, зам, илрүүлэлтийн төрөл) дээр суурилан NIST SP 800-60, FIPS 199, NIST SP 800-86 стандартаар automat үнэлгээ.",
    subject: {
      file_name: finding.file_name,
      original_path: finding.original_path || "—",
      extension: finding.file_name.split(".").pop() ?? "—",
      finding_type: finding.finding_type,
      finding_type_label: finding.finding_type,
      recovered: finding.recovered,
    },
    impact_assessment: {
      confidentiality: { level: c, label_mn: IMPACT_MN[c] ?? c, rationale: "—" },
      integrity: { level: i, label_mn: IMPACT_MN[i] ?? i, rationale: "—" },
      availability: { level: a, label_mn: IMPACT_MN[a] ?? a, rationale: "—" },
      overall: { level: overall, label_mn: IMPACT_MN[overall] ?? overall, method: "FIPS 199 high-water mark" },
      fips_composite_score: (finding.meta?.["risk_score"] as number) ?? 0,
      severity: finding.severity,
      severity_label_mn: SEV_MN[finding.severity] ?? finding.severity,
    },
    information_types: types,
    analysis_steps: reasons.map((r, idx) => ({
      step: idx + 1,
      title: "Шалгуур",
      standard: "NIST / FIPS",
      detail: r,
    })),
    detailed_findings: reasons,
    executive_summary: `Файл «${finding.file_name}» — ${SEV_MN[finding.severity] ?? finding.severity} эрсдэл.`,
    conclusion: reasons.join(" "),
    recommendations: ["Шинэ scan хийж бүрэн албан ёсны тайлан авна уу."],
    disclaimer: "Хуучин scan өгөгдөл — шинэ scan хийвэл бүрэн тайлан гарна.",
  };
}
