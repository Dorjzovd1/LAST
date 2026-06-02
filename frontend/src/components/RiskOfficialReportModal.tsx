import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Finding } from "../api/types";
import { findingDisplayName, findingFileStatusLabel } from "../lib/format";
import { getRiskReport, type RiskOfficialReport } from "../lib/riskReport";

interface Props {
  finding: Finding;
  onClose: () => void;
}

function sevBadgeClass(level: string): string {
  if (level === "high") return "high";
  if (level === "moderate") return "medium";
  return "normal";
}

export default function RiskOfficialReportModal({ finding, onClose }: Props) {
  const [report, setReport] = useState<RiskOfficialReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .findingRiskReport(finding.id)
      .then((data) => {
        if (!cancelled) setReport(data);
      })
      .catch(() => {
        if (!cancelled) setReport(getRiskReport(finding));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [finding]);

  const ia = report?.impact_assessment;
  const severityClass = ia?.severity ?? finding.severity;

  return (
    <div className="risk-modal-overlay" onClick={onClose} role="presentation">
      <div
        className="risk-modal"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-labelledby="risk-report-title"
      >
        <div className="risk-doc-header">
          <div className="risk-doc-badge">АЛБАН ЁСНЫ ТАЙЛБАР</div>
          <h2 id="risk-report-title">
            {report?.title ?? "Эрсдэлийн үнэлгээний албан ёсны тайлбар"}
          </h2>
          <div className="risk-doc-meta">
            <span>Finding ID: #{finding.id}</span>
            <span>Scan ID: #{finding.scan_id}</span>
            {ia && (
              <span className={`badge sev-${severityClass}`}>{ia.severity_label_mn}</span>
            )}
          </div>
        </div>

        <div className="risk-doc-body">
          {loading || !report ? (
            <p className="risk-doc-summary">Тайлан бэлтгэж байна…</p>
          ) : (
            <>
              <section className="risk-doc-section">
                <h3>1. Стандарт, арга зүй</h3>
                <p className="risk-doc-framework">
                  <strong>Хэрэглэсэн стандарт:</strong> {report.standard_framework}
                </p>
                <p>{report.methodology}</p>
                {report.standard_references && (
                  <table className="risk-ref-table">
                    <thead>
                      <tr>
                        <th>Лавлагаа</th>
                        <th>Хамрах хүрээ</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.standard_references.map((ref) => (
                        <tr key={ref.id}>
                          <td className="mono">{ref.citation}</td>
                          <td>{ref.scope}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </section>

              <section className="risk-doc-section">
                <h3>2. Шинжилгээний объект</h3>
                <table className="risk-kv-table">
                  <tbody>
                    <tr><td>Файлын нэр</td><td><strong>{report.subject.file_name}</strong></td></tr>
                    <tr><td>Эх зам</td><td className="mono">{report.subject.original_path}</td></tr>
                    <tr><td>Өргөтгөл</td><td>{report.subject.extension}</td></tr>
                    <tr><td>Илрүүлэлт</td><td>{report.subject.finding_type_label}</td></tr>
                    <tr><td>Төлөв</td><td>{findingFileStatusLabel(finding.finding_type)}</td></tr>
                    <tr><td>Сэргээсэн</td><td>{report.subject.recovered ? "Тийм" : "Үгүй"}</td></tr>
                    <tr><td>Хэмжээ</td><td>{finding.size_bytes.toLocaleString()} byte</td></tr>
                  </tbody>
                </table>
              </section>

              <section className="risk-doc-section">
                <h3>3. Удирдлагын хураангуй</h3>
                <p className="risk-doc-summary">{report.executive_summary}</p>
              </section>

              <section className="risk-doc-section">
                <h3>4. FIPS 199 C/I/A нөлөөллийн үнэлгээ</h3>
                <table className="risk-cia-table">
                  <thead>
                    <tr>
                      <th>Зорилго</th>
                      <th>Түвшин</th>
                      <th>Тайлбар</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td><strong>C</strong> — Нууцлал (Confidentiality)</td>
                      <td><span className={`badge sev-${sevBadgeClass(ia!.confidentiality.level)}`}>{ia!.confidentiality.label_mn}</span></td>
                      <td>{ia!.confidentiality.rationale}</td>
                    </tr>
                    <tr>
                      <td><strong>I</strong> — Бүрэн бүтэн байдал (Integrity)</td>
                      <td><span className={`badge sev-${sevBadgeClass(ia!.integrity.level)}`}>{ia!.integrity.label_mn}</span></td>
                      <td>{ia!.integrity.rationale}</td>
                    </tr>
                    <tr>
                      <td><strong>A</strong> — Байдал (Availability)</td>
                      <td><span className={`badge sev-${sevBadgeClass(ia!.availability.level)}`}>{ia!.availability.label_mn}</span></td>
                      <td>{ia!.availability.rationale}</td>
                    </tr>
                  </tbody>
                </table>
                <div className="risk-doc-result">
                  <div>
                    <span className="lbl">Нийт нөлөөлөл (FIPS high-water mark)</span>
                    <strong>{ia!.overall.label_mn}</strong>
                  </div>
                  <div>
                    <span className="lbl">FIPS composite</span>
                    <strong>{ia!.fips_composite_score}</strong>
                  </div>
                  <div>
                    <span className="lbl">Эрсдэлийн ангилал</span>
                    <strong className={`sev-text-${severityClass}`}>{ia!.severity_label_mn}</strong>
                  </div>
                </div>
              </section>

              {report.information_types.length > 0 && (
                <section className="risk-doc-section">
                  <h3>5. NIST SP 800-60 — Мэдээллийн төрөл</h3>
                  <ul className="risk-doc-list">
                    {report.information_types.map((t) => (
                      <li key={t}>{t}</li>
                    ))}
                  </ul>
                </section>
              )}

              <section className="risk-doc-section">
                <h3>6. Шинжилгээний алхамууд</h3>
                <ol className="risk-steps">
                  {report.analysis_steps.map((s) => (
                    <li key={s.step}>
                      <div className="risk-step-head">
                        <strong>{s.step}. {s.title}</strong>
                        <span className="tag">{s.standard}</span>
                      </div>
                      <p>{s.detail}</p>
                    </li>
                  ))}
                </ol>
              </section>

              {report.detailed_findings.length > 0 && (
                <section className="risk-doc-section">
                  <h3>7. Дэлгэрэнгүй олдворууд</h3>
                  <ul className="risk-doc-list">
                    {report.detailed_findings.map((line, i) => (
                      <li key={i}>{line}</li>
                    ))}
                  </ul>
                </section>
              )}

              <section className="risk-doc-section">
                <h3>8. Дүгнэлт</h3>
                <p className="risk-doc-conclusion">{report.conclusion}</p>
              </section>

              {report.examiner_opinion && (
                <section className="risk-doc-section">
                  <h3>9. Шинжээчийн санал</h3>
                  <p className="risk-doc-narrative">{report.examiner_opinion}</p>
                </section>
              )}

              <section className="risk-doc-section">
                <h3>{report.examiner_opinion ? "10" : "9"}. Зөвлөмж (шинжээчид)</h3>
                {report.recommendations_narrative && (
                  <p className="risk-doc-narrative">{report.recommendations_narrative}</p>
                )}
                {report.recommendations.length > 0 && (
                  <ol className="risk-doc-list numbered">
                    {report.recommendations.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ol>
                )}
              </section>

              <section className="risk-doc-disclaimer">
                <strong>Анхааруулга:</strong> {report.disclaimer}
              </section>
            </>
          )}
        </div>

        <div className="risk-modal-footer">
          <span className="risk-doc-file">{findingDisplayName(finding.original_path, finding.file_name)}</span>
          <button type="button" className="btn" onClick={onClose}>Хаах</button>
        </div>
      </div>
    </div>
  );
}
