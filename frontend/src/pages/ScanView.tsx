import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import type { Finding, Scan, TimelineEvent } from "../api/types";
import { useEvents } from "../lib/events";
import { formatBytes, formatDate, findingDisplayName, findingHasOriginalName, findingIsPermanentDelete, findingTypeLabel } from "../lib/format";

type Tab = "findings" | "timeline";

export default function ScanView() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [tab, setTab] = useState<Tab>("findings");
  const { subscribe } = useEvents();

  const [filters, setFilters] = useState({ finding_type: "", severity: "", recovered: "", q: "" });

  const loadScan = async () => setScan(await api.getScan(id));
  const loadFindings = async () => {
    const params: Record<string, string | number | boolean> = { scan_id: id };
    if (filters.finding_type) params.finding_type = filters.finding_type;
    if (filters.severity) params.severity = filters.severity;
    if (filters.recovered) params.recovered = filters.recovered === "yes";
    if (filters.q) params.q = filters.q;
    setFindings(await api.listFindings(params));
  };
  const loadTimeline = async () => setTimeline(await api.scanTimeline(id));

  useEffect(() => {
    loadScan();
  }, [id]);

  useEffect(() => {
    loadFindings();
  }, [id, filters]);

  useEffect(() => {
    if (tab === "timeline") loadTimeline();
  }, [tab, id]);

  useEffect(() => {
    return subscribe((ev) => {
      const sid = (ev.data as any)?.scan_id;
      if (sid !== id) return;
      if (ev.type === "scan_progress") {
        setScan((prev) =>
          prev
            ? { ...prev, progress: (ev.data as any).progress, current_step: (ev.data as any).step, status: (ev.data as any).status }
            : prev
        );
      }
      if (ev.type === "scan_completed" || ev.type === "scan_failed") {
        loadScan();
        loadFindings();
      }
    });
  }, [subscribe, id]);

  if (!scan) return <div className="empty">Ачаалж байна…</div>;

  const running = scan.status === "running" || scan.status === "pending";
  const counts = {
    total: findings.length,
    recovered: findings.filter((f) => f.recovered).length,
    high: findings.filter((f) => f.severity === "high").length,
  };

  return (
    <div>
      <h1 className="page-title">Шинжилгээ #{scan.id}</h1>
      <p className="page-sub">Бүх файлын жагсаалт — хэзээ ямар үйлдэл хийсэн (MAC цаг), идэвхтэй + устгагдсан.</p>

      <div className="panel">
        <div className="row-flex">
          <strong>Төлөв: {scan.status}</strong>
          <div className="spacer" />
          {running ? (
            <button className="btn danger sm" onClick={() => api.cancelScan(id).then(loadScan)}>
              Цуцлах
            </button>
          ) : (
            <div className="row-flex">
              <a className="btn sm" href={api.reportPdfUrl(id)}>
                PDF тайлан татах
              </a>
              <a className="btn secondary sm" href={api.reportHtmlUrl(id)} target="_blank" rel="noreferrer">
                HTML тайлан
              </a>
            </div>
          )}
        </div>
        <div style={{ margin: "14px 0 6px" }} className="progress">
          <div className="progress-bar" style={{ width: `${scan.progress}%` }} />
        </div>
        <div style={{ color: "var(--text-dim)", fontSize: 12 }}>
          {scan.progress.toFixed(0)}% · {scan.current_step || "—"}
        </div>
        {scan.error && <div style={{ color: "var(--red)", marginTop: 8 }}>{scan.error}</div>}

        <div className="stat-row" style={{ marginTop: 16 }}>
          <div className="stat">
            <div className="num">{counts.total}</div>
            <div className="lbl">Нийт ул мөр</div>
          </div>
          <div className="stat">
            <div className="num">{counts.recovered}</div>
            <div className="lbl">Сэргээсэн</div>
          </div>
          <div className="stat">
            <div className="num" style={{ color: "var(--red)" }}>
              {counts.high}
            </div>
            <div className="lbl">Өндөр эрсдэл</div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="row-flex" style={{ marginBottom: 14 }}>
          <button className={`btn sm ${tab === "findings" ? "" : "secondary"}`} onClick={() => setTab("findings")}>
            Олдсон ул мөр
          </button>
          <button className={`btn sm ${tab === "timeline" ? "" : "secondary"}`} onClick={() => setTab("timeline")}>
            Timeline
          </button>
        </div>

        {tab === "findings" ? (
          <FindingsTab findings={findings} filters={filters} setFilters={setFilters} />
        ) : (
          <TimelineTab events={timeline} />
        )}
      </div>
    </div>
  );
}

function FindingsTab({
  findings,
  filters,
  setFilters,
}: {
  findings: Finding[];
  filters: { finding_type: string; severity: string; recovered: string; q: string };
  setFilters: (f: any) => void;
}) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const [preview, setPreview] = useState<string>("");

  const openPreview = async (f: Finding) => {
    setSelected(f);
    setPreview("");
    if (f.recovered) {
      try {
        const p = await api.previewFinding(f.id);
        setPreview(p.available ? p.preview : "(урьдчилан харах боломжгүй)");
      } catch {
        setPreview("(алдаа)");
      }
    }
  };

  return (
    <div>
      <div className="filters">
        <input
          type="text"
          placeholder="Файл/замаар хайх…"
          value={filters.q}
          onChange={(e) => setFilters({ ...filters, q: e.target.value })}
        />
        <select value={filters.finding_type} onChange={(e) => setFilters({ ...filters, finding_type: e.target.value })}>
          <option value="">Бүх төрөл</option>
          <option value="active_file">Идэвхтэй файл</option>
          <option value="deleted_file">Устгагдсан файл</option>
          <option value="carved_file">Carved файл</option>
          <option value="recycle_artifact">Recycle artifact</option>
          <option value="slack_space">Slack space</option>
        </select>
        <select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
          <option value="">Бүх түвшин</option>
          <option value="high">Өндөр түвшин</option>
          <option value="medium">Дунд түвшин</option>
          <option value="normal">Хэвийн</option>
        </select>
        <select value={filters.recovered} onChange={(e) => setFilters({ ...filters, recovered: e.target.value })}>
          <option value="">Сэргээсэн (бүгд)</option>
          <option value="yes">Зөвхөн сэргээсэн</option>
          <option value="no">Сэргээгээгүй</option>
        </select>
      </div>

      {findings.length === 0 ? (
        <div className="empty">Ул мөр олдсонгүй.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Зэрэг</th>
              <th>Төрөл</th>
              <th>Файлын нэр</th>
              <th>Эх зам</th>
              <th>Хэмжээ</th>
              <th>Өөрчилсөн (M)</th>
              <th>Үүссэн (B)</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => {
              const displayName = findingDisplayName(f.original_path, f.file_name);
              const named = findingHasOriginalName(f.meta);
              const permanent = findingIsPermanentDelete(f.meta);
              return (
              <tr key={f.id}>
                <td>
                  <span className={`badge sev-${f.severity}`}>{f.severity}</span>
                </td>
                <td>
                  <span className="type-label">{findingTypeLabel(f.finding_type)}</span>
                  {named && <span className="badge named">нэртэй</span>}
                  {permanent && <span className="badge" style={{ background: "var(--orange)" }}>Shift+Del</span>}
                </td>
                <td>
                  <div className="file-name-cell">{displayName}</div>
                </td>
                <td>
                  <div className="mono path-cell">{f.original_path || "—"}</div>
                </td>
                <td>{formatBytes(f.size_bytes)}</td>
                <td style={{ fontSize: 11 }}>{formatDate(f.mtime)}</td>
                <td style={{ fontSize: 11 }}>{formatDate(f.crtime)}</td>
                <td>
                  <div className="row-flex">
                    <button className="btn secondary sm" onClick={() => openPreview(f)}>
                      Дэлгэрэнгүй
                    </button>
                    {f.recovered && (
                      <a className="btn sm" href={api.downloadUrl(f.id)}>
                        Татах
                      </a>
                    )}
                  </div>
                </td>
              </tr>
            );})}
          </tbody>
        </table>
      )}

      {selected && (
        <div className="panel" style={{ marginTop: 18, background: "var(--bg-panel-2)" }}>
          <div className="row-flex">
            <h2 style={{ margin: 0 }}>{findingDisplayName(selected.original_path, selected.file_name)}</h2>
            <span className={`badge sev-${selected.severity}`}>{selected.severity}</span>
            <div className="spacer" />
            <button className="btn secondary sm" onClick={() => setSelected(null)}>
              Хаах
            </button>
          </div>

          <RiskExplanation finding={selected} />
          <table style={{ marginTop: 12 }}>
            <tbody>
              <tr><td>Төрөл</td><td>{selected.finding_type}</td></tr>
              <tr><td>Эх зам</td><td className="mono">{selected.original_path || "—"}</td></tr>
              <tr><td>Inode</td><td className="mono">{selected.inode || "—"}</td></tr>
              <tr><td>Хэрэгсэл</td><td>{selected.source_tool}</td></tr>
              <tr><td>MD5</td><td className="mono">{selected.md5 || "—"}</td></tr>
              <tr><td>SHA-256</td><td className="mono">{selected.sha256 || "—"}</td></tr>
              <tr><td>Modified</td><td>{formatDate(selected.mtime)}</td></tr>
              <tr><td>Accessed</td><td>{formatDate(selected.atime)}</td></tr>
              <tr><td>Changed</td><td>{formatDate(selected.ctime)}</td></tr>
              <tr><td>Created</td><td>{formatDate(selected.crtime)}</td></tr>
            </tbody>
          </table>
          {selected.recovered && (
            <>
              <h3>Урьдчилан харах</h3>
              <div className="preview-box">{preview || "Ачаалж байна…"}</div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

const SEV_LABEL: Record<string, string> = {
  high: "Өндөр түвшин",
  medium: "Дунд түвшин",
  normal: "Хэвийн",
};

function RiskExplanation({ finding }: { finding: Finding }) {
  const reasons = (finding.meta?.["risk_reasons"] as string[] | undefined) ?? [];
  const score = (finding.meta?.["risk_score"] as number | undefined) ?? 0;

  return (
    <div className="risk-box">
      <div className="risk-head">
        <span>Яагаад "{SEV_LABEL[finding.severity] ?? finding.severity}" гэж үнэлсэн бэ?</span>
        <span className={`badge sev-${finding.severity}`}>Нийт оноо: {score}</span>
      </div>
      {reasons.length > 0 ? (
        <ul className="risk-reasons">
          {reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      ) : (
        <div style={{ color: "var(--text-dim)", fontSize: 12 }}>Шалтгаан бүртгэгдээгүй.</div>
      )}
      <div className="risk-scale">
        Шалгуур: оноо <b style={{ color: "var(--red)" }}>≥5 Өндөр</b> ·{" "}
        <b style={{ color: "var(--orange)" }}>2–4 Дунд</b> · <b style={{ color: "var(--green)" }}>&lt;2 Хэвийн</b>
      </div>
    </div>
  );
}

function TimelineTab({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) return <div className="empty">Timeline хоосон байна.</div>;
  return (
    <div>
      {events.map((e) => (
        <div className="timeline-item" key={e.id}>
          <div className="timeline-time">{formatDate(e.timestamp)}</div>
          <div className={`timeline-kind kind-${e.event_type}`}>{e.event_type}</div>
          <div>{e.description}</div>
        </div>
      ))}
    </div>
  );
}
