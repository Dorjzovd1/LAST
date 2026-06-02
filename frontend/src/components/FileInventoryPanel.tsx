import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { Finding } from "../api/types";
import {
  formatBytes,
  formatDate,
  findingDisplayName,
  findingFileStatusLabel,
  findingIsActive,
  findingIsDownloadable,
  findingMacDate,
  findingTypeLabel,
} from "../lib/format";
import { FindingDetailPanel } from "./FindingDetailPanel";

type StatusFilter = "" | "active" | "deleted";

const PAGE_SIZE = 100;

export default function FileInventoryPanel({
  scanId,
  title,
  subtitle,
  defaultStatusFilter = "",
}: {
  scanId: number;
  title: string;
  subtitle?: string;
  defaultStatusFilter?: StatusFilter;
}) {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>(defaultStatusFilter);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [page, setPage] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");

  const queryKey = useMemo(
    () => `${scanId}|${statusFilter}|${severity}|${q.trim().toLowerCase()}`,
    [scanId, statusFilter, severity, q]
  );

  useEffect(() => {
    setPage(0);
  }, [queryKey]);

  const loadPage = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const params: Record<string, string | number | boolean | undefined> = {
        scan_id: scanId,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      };
      if (statusFilter === "active") params.finding_type = "active_file";
      else if (statusFilter === "deleted") params.deleted_only = true;
      if (severity) params.severity = severity;
      if (q.trim()) params.q = q.trim();

      const res = await api.listFindings(params);
      setFindings(res.items);
      setTotal(res.total);
    } catch (e) {
      setFindings([]);
      setTotal(0);
      setLoadError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [scanId, statusFilter, severity, q, page]);

  useEffect(() => {
    loadPage();
  }, [loadPage]);

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const from = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const to = Math.min(total, (page + 1) * PAGE_SIZE);

  return (
    <div>
      <div style={{ marginBottom: 14 }}>
        <h2 style={{ margin: "0 0 4px", fontSize: 16 }}>{title}</h2>
        {subtitle && <p style={{ margin: 0, color: "var(--text-dim)", fontSize: 12 }}>{subtitle}</p>}
      </div>

      <div className="filters">
        <input
          type="text"
          placeholder="Файл/замаар хайх…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}>
          <option value="">Бүх төлөв</option>
          <option value="active">Идэвхтэй (ашиглагдаж байгаа)</option>
          <option value="deleted">Устгагдсан / Recycle</option>
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">Бүх эрсдэл</option>
          <option value="high">Өндөр</option>
          <option value="medium">Дунд</option>
          <option value="normal">Хэвийн</option>
        </select>
        <span style={{ color: "var(--text-dim)", fontSize: 12, alignSelf: "center" }}>
          {total === 0 ? "0 файл" : `${from}–${to} / ${total} файл`}
        </span>
      </div>

      {loadError && (
        <div className="warn-banner" style={{ marginBottom: 12 }}>
          Файлын жагсаалт ачаалж чадсангүй: {loadError}
        </div>
      )}

      {loading ? (
        <div className="empty">Файлын жагсаалт ачаалж байна…</div>
      ) : total === 0 ? (
        <div className="empty">Файл олдсонгүй. Шинэ scan эхлүүлнэ үү (sudo backend).</div>
      ) : (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Төлөв</th>
                  <th>Эрсдэл</th>
                  <th>Файлын нэр</th>
                  <th>Эх зам</th>
                  <th>Хэмжээ</th>
                  <th>MIME</th>
                  <th>Born</th>
                  <th>Modified</th>
                  <th>Accessed</th>
                  <th>Changed</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => {
                  const active = findingIsActive(f.finding_type);
                  const score = (f.meta?.["risk_score"] as number) ?? 0;
                  return (
                    <tr key={f.id}>
                      <td>
                        <span className={`badge ${active ? "status-active" : "status-deleted"}`}>
                          {findingFileStatusLabel(f.finding_type)}
                        </span>
                      </td>
                      <td>
                        <span className={`badge sev-${f.severity}`}>{f.severity}</span>
                        {score > 0 && (
                          <span style={{ fontSize: 10, marginLeft: 4, color: "var(--text-dim)" }}>{score}</span>
                        )}
                      </td>
                      <td>
                        <div className="file-name-cell">{findingDisplayName(f.original_path, f.file_name)}</div>
                        <div style={{ fontSize: 10, color: "var(--text-dim)" }}>{findingTypeLabel(f.finding_type)}</div>
                      </td>
                      <td>
                        <div className="mono path-cell">{f.original_path || "—"}</div>
                      </td>
                      <td>{formatBytes(f.size_bytes)}</td>
                      <td style={{ fontSize: 11 }}>{f.mime_type?.split("/").pop() || "—"}</td>
                      <td style={{ fontSize: 11 }}>{formatDate(findingMacDate(f, "crtime"))}</td>
                      <td style={{ fontSize: 11 }}>{formatDate(findingMacDate(f, "mtime"))}</td>
                      <td style={{ fontSize: 11 }}>{formatDate(findingMacDate(f, "atime"))}</td>
                      <td style={{ fontSize: 11 }}>{formatDate(findingMacDate(f, "ctime"))}</td>
                      <td>
                        <div className="row-flex">
                          <button className="btn secondary sm" onClick={() => setSelected(f)}>
                            Metadata
                          </button>
                          {findingIsDownloadable(f) && (
                            <a className="btn sm" href={api.downloadUrl(f.id)}>
                              Татах
                            </a>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {pageCount > 1 && (
            <div className="row-flex" style={{ marginTop: 12 }}>
              <button className="btn secondary sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                ← Өмнөх
              </button>
              <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
                Хуудас {page + 1} / {pageCount}
              </span>
              <button
                className="btn secondary sm"
                disabled={page >= pageCount - 1}
                onClick={() => setPage((p) => p + 1)}
              >
                Дараах →
              </button>
            </div>
          )}
        </>
      )}

      {selected && <FindingDetailPanel finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
