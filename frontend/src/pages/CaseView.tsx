import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import type { AuditLog, Case, Scan } from "../api/types";
import { formatDate } from "../lib/format";

export default function CaseView() {
  const { caseId } = useParams();
  const id = Number(caseId);
  const [c, setC] = useState<Case | null>(null);
  const [audit, setAudit] = useState<AuditLog[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);

  useEffect(() => {
    api.getCase(id).then(setC).catch(() => setC(null));
    api.caseAudit(id).then(setAudit).catch(() => setAudit([]));
    api.listScans().then(setScans).catch(() => setScans([]));
  }, [id]);

  if (!c) return <div className="empty">Ачаалж байна…</div>;

  return (
    <div>
      <h1 className="page-title">
        {c.case_number} · {c.title}
      </h1>
      <p className="page-sub">Шинжээч: {c.investigator || "—"}</p>

      <div className="panel">
        <h2>Шинжилгээнүүд</h2>
        {scans.length === 0 ? (
          <div className="empty">Шинжилгээ алга.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Төлөв</th>
                <th>Явц</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td>#{s.id}</td>
                  <td>{s.status}</td>
                  <td>{s.progress.toFixed(0)}%</td>
                  <td>
                    <Link to={`/scans/${s.id}`}>Нээх</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h2>Chain-of-custody (audit) бүртгэл</h2>
        {audit.length === 0 ? (
          <div className="empty">Бүртгэл алга.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Цаг</th>
                <th>Үйлдэл</th>
                <th>Хэрэглэгч</th>
                <th>Объект</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{formatDate(a.timestamp)}</td>
                  <td>{a.action}</td>
                  <td>{a.actor}</td>
                  <td className="mono">{a.target || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
