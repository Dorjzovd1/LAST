import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Finding } from "../api/types";
import { formatDate, findingDisplayName, findingFileStatusLabel, findingIsActive, findingIsDownloadable, findingTypeLabel } from "../lib/format";

const SEV_LABEL: Record<string, string> = {
  high: "Өндөр түвшин",
  medium: "Дунд түвшин",
  normal: "Хэвийн",
};

const IMPACT_MN: Record<string, string> = {
  low: "Бага",
  moderate: "Дунд",
  high: "Өндөр",
};

export function RiskExplanation({ finding }: { finding: Finding }) {
  const reasons = (finding.meta?.["risk_reasons"] as string[] | undefined) ?? [];
  const score = (finding.meta?.["risk_score"] as number) ?? 0;
  const standard = (finding.meta?.["risk_standard"] as string) ?? "NIST SP 800-60 Rev. 1 + FIPS 199";
  const c = (finding.meta?.["risk_confidentiality"] as string) ?? "—";
  const i = (finding.meta?.["risk_integrity"] as string) ?? "—";
  const a = (finding.meta?.["risk_availability"] as string) ?? "—";
  const overall = (finding.meta?.["risk_overall_impact"] as string) ?? "—";

  return (
    <div className="risk-box">
      <div className="risk-head">
        <span>Эрсдэлийн үнэлгээ — {SEV_LABEL[finding.severity] ?? finding.severity}</span>
        <span className={`badge sev-${finding.severity}`}>FIPS: {score}</span>
      </div>
      <div style={{ color: "var(--text-dim)", fontSize: 11, marginBottom: 8 }}>
        Стандарт: {standard}
      </div>
      <div style={{ fontSize: 12, marginBottom: 8 }}>
        C (Нууцлал): {IMPACT_MN[c] ?? c} · I (Бүрэн бүтэн байдал): {IMPACT_MN[i] ?? i} · A (Байдал):{" "}
        {IMPACT_MN[a] ?? a} · Нийт: {IMPACT_MN[overall] ?? overall}
      </div>
      {reasons.length > 0 ? (
        <ul className="risk-reasons">
          {reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      ) : (
        <div style={{ color: "var(--text-dim)", fontSize: 12 }}>Эмзэг шинж олдсонгүй.</div>
      )}
    </div>
  );
}

export function FindingDetailPanel({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const [preview, setPreview] = useState("");

  useEffect(() => {
    if (!finding.recovered) return;
    api.previewFinding(finding.id)
      .then((p) => setPreview(p.available ? p.preview : "(урьдчилан харах боломжгүй)"))
      .catch(() => setPreview("(алдаа)"));
  }, [finding.id, finding.recovered]);

  return (
    <div className="panel" style={{ marginTop: 18, background: "var(--bg-panel-2)" }}>
      <div className="row-flex">
        <h2 style={{ margin: 0 }}>{findingDisplayName(finding.original_path, finding.file_name)}</h2>
        <span className={`badge sev-${finding.severity}`}>{finding.severity}</span>
        <span className={`badge ${findingIsActive(finding.finding_type) ? "status-active" : "status-deleted"}`}>
          {findingFileStatusLabel(finding.finding_type)}
        </span>
        <div className="spacer" />
        <button className="btn secondary sm" onClick={onClose}>
          Хаах
        </button>
      </div>

      <RiskExplanation finding={finding} />
      <table style={{ marginTop: 12 }}>
        <tbody>
          <tr><td>Төрөл</td><td>{findingTypeLabel(finding.finding_type)}</td></tr>
          <tr><td>Эх зам</td><td className="mono">{finding.original_path || "—"}</td></tr>
          <tr><td>Inode</td><td className="mono">{finding.inode || "—"}</td></tr>
          <tr><td>MIME</td><td>{finding.mime_type || "—"}</td></tr>
          <tr><td>Хэрэгсэл</td><td>{finding.source_tool}</td></tr>
          <tr><td>MD5</td><td className="mono">{finding.md5 || "—"}</td></tr>
          <tr><td>SHA-256</td><td className="mono">{finding.sha256 || "—"}</td></tr>
          <tr><td>Born (B)</td><td>{formatDate(finding.crtime)}</td></tr>
          <tr><td>Modified (M)</td><td>{formatDate(finding.mtime)}</td></tr>
          <tr><td>Accessed (A)</td><td>{formatDate(finding.atime)}</td></tr>
          <tr><td>Changed (C)</td><td>{formatDate(finding.ctime)}</td></tr>
        </tbody>
      </table>
      {findingIsDownloadable(finding) && (
        <div style={{ marginTop: 12 }}>
          <a className="btn sm" href={api.downloadUrl(finding.id)}>
            Сэргээсэн файл татах
          </a>
        </div>
      )}
      {finding.recovered && preview && (
        <>
          <h3>Урьдчилан харах</h3>
          <div className="preview-box">{preview}</div>
        </>
      )}
    </div>
  );
}
