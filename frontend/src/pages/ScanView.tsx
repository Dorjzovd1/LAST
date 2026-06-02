import { useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { Finding, Scan, TimelineEvent } from "../api/types";
import { useEvents } from "../lib/events";
import { formatBytes, formatDate, findingDisplayName, findingHasOriginalName, findingIsPermanentDelete, findingTypeLabel } from "../lib/format";

type Tab = "all" | "active" | "deleted" | "timeline" | "risk";

const TAB_LABELS: Record<Tab, string> = {
  all: "Бүх файлууд",
  active: "Идэвхтэй файлууд",
  deleted: "Устгагдсан",
  timeline: "Timeline (MAC)",
  risk: "Эрсдэлтэй үнэлгээ",
};

const EVENT_LABELS: Record<string, string> = {
  M: "Modified — өөрчилсөн",
  A: "Accessed — хандсан",
  C: "Changed — метадата",
  B: "Born — үүссэн",
};

export default function ScanView() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get("tab") as Tab | null;
  const [scan, setScan] = useState<Scan | null>(null);
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [tab, setTab] = useState<Tab>(tabParam && TAB_LABELS[tabParam] ? tabParam : "all");
  const { subscribe } = useEvents();

  const [filters, setFilters] = useState({ severity: "", recovered: "", q: "" });

  const loadScan = async () => setScan(await api.getScan(id));
  const loadFindings = async () => {
    setAllFindings(await api.listFindings({ scan_id: id }));
  };
  const loadTimeline = async () => setTimeline(await api.scanTimeline(id));

  useEffect(() => {
    loadScan();
    loadFindings();
    loadTimeline();
  }, [id]);

  useEffect(() => {
    if (tabParam && TAB_LABELS[tabParam]) setTab(tabParam);
  }, [tabParam]);

  useEffect(() => {
    return subscribe((ev) => {
      const sid = (ev.data as { scan_id?: number })?.scan_id;
      if (sid !== id) return;
      if (ev.type === "scan_progress") {
        setScan((prev) =>
          prev
            ? {
                ...prev,
                progress: (ev.data as { progress: number }).progress,
                current_step: (ev.data as { step: string }).step,
                status: (ev.data as { status: string }).status as Scan["status"],
              }
            : prev
        );
      }
      if (ev.type === "scan_completed" || ev.type === "scan_failed") {
        loadScan();
        loadFindings();
        loadTimeline();
      }
    });
  }, [subscribe, id]);

  const counts = useMemo(() => {
    const active = allFindings.filter((f) => f.finding_type === "active_file").length;
    const deleted = allFindings.filter((f) =>
      ["deleted_file", "recycle_artifact", "carved_file"].includes(f.finding_type)
    ).length;
    const high = allFindings.filter((f) => f.severity === "high").length;
    const medium = allFindings.filter((f) => f.severity === "medium").length;
    return { total: allFindings.length, active, deleted, high, medium, recovered: allFindings.filter((f) => f.recovered).length };
  }, [allFindings]);

  const tabFindings = useMemo(() => {
    let list = allFindings;
    if (tab === "active") list = list.filter((f) => f.finding_type === "active_file");
    else if (tab === "deleted")
      list = list.filter((f) => ["deleted_file", "recycle_artifact", "carved_file"].includes(f.finding_type));
    else if (tab === "risk") list = list.filter((f) => f.severity === "high" || f.severity === "medium");

    if (filters.severity) list = list.filter((f) => f.severity === filters.severity);
    if (filters.recovered === "yes") list = list.filter((f) => f.recovered);
    if (filters.recovered === "no") list = list.filter((f) => !f.recovered);
    if (filters.q) {
      const q = filters.q.toLowerCase();
      list = list.filter(
        (f) =>
          f.file_name.toLowerCase().includes(q) ||
          (f.original_path || "").toLowerCase().includes(q)
      );
    }

    if (tab === "risk") {
      list = [...list].sort(
        (a, b) =>
          ((b.meta?.["risk_score"] as number) ?? 0) - ((a.meta?.["risk_score"] as number) ?? 0)
      );
    }
    return list;
  }, [allFindings, tab, filters]);

  const switchTab = (next: Tab) => {
    setTab(next);
    setSearchParams(next === "all" ? {} : { tab: next });
  };

  if (!scan) return <div className="empty">Ачаалж байна…</div>;

  const running = scan.status === "running" || scan.status === "pending";

  return (
    <div>
      <h1 className="page-title">Шинжилгээ #{scan.id}</h1>
      <p className="page-sub">
        Бүх файлын каталог — идэвхтэй + устгагдсан, MAC timeline, эрсдэлийн үнэлгээ.
      </p>

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
                PDF тайлан
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
            <div className="lbl">Нийт</div>
          </div>
          <div className="stat">
            <div className="num" style={{ color: "var(--green)" }}>
              {counts.active}
            </div>
            <div className="lbl">Идэвхтэй</div>
          </div>
          <div className="stat">
            <div className="num" style={{ color: "var(--orange)" }}>
              {counts.deleted}
            </div>
            <div className="lbl">Устгагдсан</div>
          </div>
          <div className="stat">
            <div className="num" style={{ color: "var(--red)" }}>
              {counts.high}
            </div>
            <div className="lbl">Өндөр эрсдэл</div>
          </div>
          <div className="stat">
            <div className="num">{timeline.length}</div>
            <div className="lbl">Timeline үйл</div>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="module-tabs" style={{ marginBottom: 14 }}>
          {(Object.keys(TAB_LABELS) as Tab[]).map((key) => (
            <button
              key={key}
              className={`btn sm ${tab === key ? "" : "secondary"}`}
              onClick={() => switchTab(key)}
            >
              {TAB_LABELS[key]}
              {key === "active" && counts.active > 0 && <span className="tab-count">{counts.active}</span>}
              {key === "deleted" && counts.deleted > 0 && <span className="tab-count">{counts.deleted}</span>}
              {key === "risk" && counts.high + counts.medium > 0 && (
                <span className="tab-count">{counts.high + counts.medium}</span>
              )}
            </button>
          ))}
        </div>

        {tab === "timeline" ? (
          <TimelineTab events={timeline} findings={allFindings} />
        ) : tab === "risk" ? (
          <RiskTab findings={tabFindings} counts={counts} />
        ) : (
          <FindingsTab
            findings={tabFindings}
            filters={filters}
            setFilters={setFilters}
            showTypeFilter={tab === "all"}
          />
        )}
      </div>
    </div>
  );
}

function FindingsTab({
  findings,
  filters,
  setFilters,
  showTypeFilter,
}: {
  findings: Finding[];
  filters: { severity: string; recovered: string; q: string };
  setFilters: (f: { severity: string; recovered: string; q: string }) => void;
  showTypeFilter?: boolean;
}) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const [preview, setPreview] = useState<string>("");
  const [typeFilter, setTypeFilter] = useState("");

  const displayed = showTypeFilter && typeFilter
    ? findings.filter((f) => f.finding_type === typeFilter)
    : findings;

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
        {showTypeFilter && (
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
            <option value="">Бүх төрөл</option>
            <option value="active_file">Идэвхтэй</option>
            <option value="deleted_file">Shift+Delete</option>
            <option value="recycle_artifact">Recycle Bin</option>
            <option value="carved_file">Carved</option>
          </select>
        )}
        <select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
          <option value="">Бүх түвшин</option>
          <option value="high">Өндөр</option>
          <option value="medium">Дунд</option>
          <option value="normal">Хэвийн</option>
        </select>
        <select value={filters.recovered} onChange={(e) => setFilters({ ...filters, recovered: e.target.value })}>
          <option value="">Сэргээсэн (бүгд)</option>
          <option value="yes">Зөвхөн сэргээсэн</option>
          <option value="no">Сэргээгээгүй</option>
        </select>
      </div>

      {displayed.length === 0 ? (
        <div className="empty">Ул мөр олдсонгүй.</div>
      ) : (
        <FindingsTable findings={displayed} onSelect={openPreview} />
      )}

      {selected && (
        <FindingDetail finding={selected} preview={preview} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function FindingsTable({ findings, onSelect }: { findings: Finding[]; onSelect: (f: Finding) => void }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Эрсдэл</th>
          <th>Төрөл</th>
          <th>Файлын нэр</th>
          <th>Эх зам</th>
          <th>Хэмжээ</th>
          <th>Modified</th>
          <th>Created</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => {
          const displayName = findingDisplayName(f.original_path, f.file_name);
          const named = findingHasOriginalName(f.meta);
          const permanent = findingIsPermanentDelete(f.meta);
          const score = (f.meta?.["risk_score"] as number) ?? 0;
          return (
            <tr key={f.id}>
              <td>
                <span className={`badge sev-${f.severity}`}>{f.severity}</span>
                {score > 0 && <span style={{ fontSize: 10, marginLeft: 4, color: "var(--text-dim)" }}>{score}o</span>}
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
                  <button className="btn secondary sm" onClick={() => onSelect(f)}>
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
          );
        })}
      </tbody>
    </table>
  );
}

function RiskTab({
  findings,
  counts,
}: {
  findings: Finding[];
  counts: { high: number; medium: number };
}) {
  const [selected, setSelected] = useState<Finding | null>(null);

  return (
    <div>
      <div className="risk-summary">
        <div className="risk-summary-item">
          <span className="badge sev-high">Өндөр</span>
          <strong>{counts.high}</strong> файл
        </div>
        <div className="risk-summary-item">
          <span className="badge sev-medium">Дунд</span>
          <strong>{counts.medium}</strong> файл
        </div>
        <p style={{ color: "var(--text-dim)", fontSize: 12, margin: "12px 0 0" }}>
          Дүрэмд суурилсан оноо: эмзэг түлхүүр үг (+5), баримт/архив (+2–3), устгагдсан (+1), carving (+2).
          Оноо ≥5 → Өндөр, 2–4 → Дунд, &lt;2 → Хэвийн.
        </p>
      </div>

      {findings.length === 0 ? (
        <div className="empty">Эрсдэлтэй файл илрээгүй.</div>
      ) : (
        <FindingsTable findings={findings} onSelect={setSelected} />
      )}

      {selected && <FindingDetail finding={selected} preview="" onClose={() => setSelected(null)} />}
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
  const score = (finding.meta?.["risk_score"] as number) ?? 0;

  return (
    <div className="risk-box">
      <div className="risk-head">
        <span>Яагаад &quot;{SEV_LABEL[finding.severity] ?? finding.severity}&quot; гэж үнэлсэн бэ?</span>
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

function FindingDetail({
  finding,
  preview: previewProp,
  onClose,
}: {
  finding: Finding;
  preview: string;
  onClose: () => void;
}) {
  const [preview, setPreview] = useState(previewProp);

  useEffect(() => {
    setPreview(previewProp);
    if (!finding.recovered) return;
    if (previewProp) return;
    api.previewFinding(finding.id)
      .then((p) => setPreview(p.available ? p.preview : "(урьдчилан харах боломжгүй)"))
      .catch(() => setPreview("(алдаа)"));
  }, [finding.id, finding.recovered, previewProp]);

  return (
    <div className="panel" style={{ marginTop: 18, background: "var(--bg-panel-2)" }}>
      <div className="row-flex">
        <h2 style={{ margin: 0 }}>{findingDisplayName(finding.original_path, finding.file_name)}</h2>
        <span className={`badge sev-${finding.severity}`}>{finding.severity}</span>
        <div className="spacer" />
        <button className="btn secondary sm" onClick={onClose}>
          Хаах
        </button>
      </div>

      <RiskExplanation finding={finding} />
      <table style={{ marginTop: 12 }}>
        <tbody>
          <tr>
            <td>Төрөл</td>
            <td>{findingTypeLabel(finding.finding_type)}</td>
          </tr>
          <tr>
            <td>Эх зам</td>
            <td className="mono">{finding.original_path || "—"}</td>
          </tr>
          <tr>
            <td>Inode</td>
            <td className="mono">{finding.inode || "—"}</td>
          </tr>
          <tr>
            <td>Хэрэгсэл</td>
            <td>{finding.source_tool}</td>
          </tr>
          <tr>
            <td>MD5</td>
            <td className="mono">{finding.md5 || "—"}</td>
          </tr>
          <tr>
            <td>SHA-256</td>
            <td className="mono">{finding.sha256 || "—"}</td>
          </tr>
          <tr>
            <td>Modified</td>
            <td>{formatDate(finding.mtime)}</td>
          </tr>
          <tr>
            <td>Accessed</td>
            <td>{formatDate(finding.atime)}</td>
          </tr>
          <tr>
            <td>Changed</td>
            <td>{formatDate(finding.ctime)}</td>
          </tr>
          <tr>
            <td>Created</td>
            <td>{formatDate(finding.crtime)}</td>
          </tr>
        </tbody>
      </table>
      {finding.recovered && (
        <>
          <h3>Урьдчилан харах</h3>
          <div className="preview-box">{preview || "Ачаалж байна…"}</div>
        </>
      )}
    </div>
  );
}

function TimelineTab({ events, findings }: { events: TimelineEvent[]; findings: Finding[] }) {
  const [kindFilter, setKindFilter] = useState("");
  const findingMap = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings]);

  const filtered = kindFilter ? events.filter((e) => e.event_type === kindFilter) : events;

  if (events.length === 0) return <div className="empty">Timeline хоосон — scan дууссаны дараа MAC үйлдлүүд энд харагдана.</div>;

  return (
    <div>
      <div className="filters" style={{ marginBottom: 14 }}>
        <select value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}>
          <option value="">Бүх үйлдэл (M/A/C/B)</option>
          <option value="M">Modified (M)</option>
          <option value="A">Accessed (A)</option>
          <option value="C">Changed (C)</option>
          <option value="B">Born (B)</option>
        </select>
        <span style={{ color: "var(--text-dim)", fontSize: 12 }}>{filtered.length} үйлдэл</span>
      </div>
      {filtered.map((e) => {
        const linked = e.finding_id ? findingMap.get(e.finding_id) : undefined;
        return (
          <div className="timeline-item" key={e.id}>
            <div className="timeline-time">{formatDate(e.timestamp)}</div>
            <div className={`timeline-kind kind-${e.event_type}`} title={EVENT_LABELS[e.event_type]}>
              {e.event_type}
            </div>
            <div>
              <div>{e.description}</div>
              {linked && (
                <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 4 }}>
                  {findingTypeLabel(linked.finding_type)} ·{" "}
                  <span className={`badge sev-${linked.severity}`}>{linked.severity}</span>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
