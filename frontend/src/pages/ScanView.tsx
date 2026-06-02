import { useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { Finding, Scan, ScanSummary, FileTimelineSummary, FileTimelineDetail } from "../api/types";
import FileInventoryPanel from "../components/FileInventoryPanel";
import RiskOfficialReportModal from "../components/RiskOfficialReportModal";
import { useEvents } from "../lib/events";
import {
  formatDate,
  findingDisplayName,
  findingFileStatusLabel,
  findingIsActive,
} from "../lib/format";
import { activeScanTab } from "../lib/scanTabs";

const PAGE_SIZE = 100;

const EVENT_LABELS: Record<string, string> = {
  B: "Born — үүссэн",
  M: "Modified — өөрчилсөн",
  A: "Accessed — хандсан",
  C: "Changed — metadata",
  DELETE: "Устгагдсан",
  RECYCLE: "Recycle Bin",
  DELETED: "Устгагдсан",
  CARVED: "Carving",
  ACTIVE: "Идэвхтэй",
  RECOVERED: "Сэргээсэн",
  SLACK: "Slack",
};

const CATEGORY_LABELS: Record<string, string> = {
  mac: "Үйлдлийн систем (MAC)",
  forensic: "Forensic",
  os: "Үйлдлийн систем",
};

export default function ScanView() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const [searchParams] = useSearchParams();
  const tabParam = searchParams.get("tab");
  const [scan, setScan] = useState<Scan | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [loadError, setLoadError] = useState("");
  const [purged, setPurged] = useState<{ findings: number } | null>(null);
  const [finishing, setFinishing] = useState(false);
  const tab = activeScanTab(tabParam);
  const { subscribe } = useEvents();

  const reload = async () => {
    setLoadError("");
    try {
      setScan(await api.getScan(id));
      setSummary(await api.scanSummary(id));
      setPurged(null);
    } catch (e) {
      const msg = (e as Error).message;
      if (msg.startsWith("404:")) {
        setScan(null);
        setSummary(null);
      } else {
        setLoadError(msg);
      }
    }
  };

  useEffect(() => {
    reload();
  }, [id]);

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
      if (ev.type === "scan_completed") reload();
      if (ev.type === "scan_purged") {
        setPurged({
          findings: Number((ev.data as { findings_removed?: number }).findings_removed ?? 0),
        });
        setScan(null);
        setSummary(null);
      }
      if (ev.type === "scan_failed") reload();
    });
  }, [subscribe, id]);

  const counts = useMemo(() => {
    if (!summary) {
      return { total: 0, active: 0, deleted: 0, high: 0, medium: 0, timeline: 0, recovered: 0 };
    }
    return {
      total: summary.total_files,
      active: summary.active_files,
      deleted: summary.deleted_files + summary.recycle_artifacts + summary.carved_files,
      high: summary.risk_high,
      medium: summary.risk_medium,
      timeline: summary.timeline_events,
      recovered: summary.recovered_files,
    };
  }, [summary]);

  const registeredCount = useMemo(() => {
    const m = scan?.current_step?.match(/(\d+)\s+файл бүртгэгдсэн/);
    return m ? Number(m[1]) : null;
  }, [scan?.current_step]);

  const dataMismatch =
    scan?.status === "completed" &&
    registeredCount != null &&
    registeredCount > 0 &&
    summary != null &&
    summary.total_files === 0;

  const finishScan = async () => {
    const total = summary?.total_files ?? counts.total;
    const msg =
      `Scan #${id}-ийн бүх өгөгдөл (файлын жагсаалт, timeline, сэргээсэн ${summary?.recovered_files ?? 0} файл) ` +
      `сервер болон үйлдлийн системээс бүрмөсөн устгагдана.\n\n` +
      `PDF/HTML тайлангаа татсан эсэхээ шалгаад үргэлжлүүлнэ үү.\n\nДууслаа гэж тэмдэглэх үү?`;
    if (!confirm(msg)) return;
    setFinishing(true);
    try {
      const res = await api.purgeScan(id);
      setPurged({ findings: res.findings_removed });
      setScan(null);
      setSummary(null);
    } catch (e) {
      alert("Устгахад алдаа: " + (e as Error).message);
    } finally {
      setFinishing(false);
    }
  };

  if (!scan && purged) {
    return (
      <div>
        <h1 className="page-title">Шинжилгээ #{id} дууссан</h1>
        <div className="panel">
          <p style={{ marginTop: 0 }}>
            Scan-ийн өгөгдөл амжилттай цэвэрлэгдлээ
            {purged.findings > 0 && (
              <>
                {" "}
                (<b>{purged.findings.toLocaleString()}</b> файлын бүртгэл, сэргээсэн агуулга)
              </>
            )}
            .
          </p>
          <p style={{ color: "var(--text-dim)", fontSize: 13 }}>
            Сервер дээр scan хадгалагдаагүй. Дахин шинжлэх бол Dashboard-оос шинэ scan эхлүүлнэ.
          </p>
          <Link className="btn sm" to="/">
            Dashboard руу буцах
          </Link>
        </div>
      </div>
    );
  }

  if (!scan) return <div className="empty">{loadError || "Ачаалж байна…"}</div>;

  const running = scan.status === "running" || scan.status === "pending";

  return (
    <div>
      <h1 className="page-title">Шинжилгээ #{scan.id}</h1>
        <p className="page-sub">
        Нийт файлын metadata — timestamp (MACB) уялдуулал, эрсдэлийн үнэлгээ. PDF/HTML тайланд
        бүх ул мөр цагийн дарааллаар нэгтгэгдэнэ.
      </p>

      <div className="panel">
        <div className="row-flex">
          <strong>Төлөв: {scan.status}</strong>
          <div className="spacer" />
          {running ? (
            <button className="btn danger sm" onClick={() => api.cancelScan(id).then(reload)}>
              Цуцлах
            </button>
          ) : (
            <div className="row-flex">
              <a className="btn sm" href={api.reportPdfUrl(id)}>PDF тайлан</a>
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
        {scan.status === "completed" && counts.active === 0 && counts.deleted > 0 && (
          <div className="warn-banner" style={{ marginTop: 12 }}>
            Flash дээрх <b>идэвхтэй файл олдсонгүй</b> — зөвхөн устгагдсан харагдаж байна.
            Backend-ийг <code>sudo uvicorn</code>-оор ажиллуулж, <code>ntfs-3g</code> суулгаад шинэ scan хийнэ үү.
          </div>
        )}
        {scan.error && <div style={{ color: "var(--red)", marginTop: 8 }}>{scan.error}</div>}
        {loadError && (
          <div className="warn-banner" style={{ marginTop: 12 }}>
            Scan мэдээлэл ачаалж чадсангүй: {loadError}
          </div>
        )}
        {dataMismatch && (
          <div className="warn-banner" style={{ marginTop: 12 }}>
            Scan <b>{registeredCount}</b> файл бүртгэсэн гэж тэмдэглэсэн боловч өгөгдлийн сан хоосон байна.
            Hard disk сэргээлтийн дараа DB эвдэрсэн эсвэл хуучин scan байж болно — Dashboard-оос <b>шинэ scan</b> хийнэ үү.
          </div>
        )}

        <div className="stat-row" style={{ marginTop: 16 }}>
          <div className="stat highlight-stat">
            <div className="num">{counts.total}</div>
            <div className="lbl">Нийт файл</div>
          </div>
          <div className="stat">
            <div className="num" style={{ color: "var(--green)" }}>{counts.active}</div>
            <div className="lbl">Идэвхтэй</div>
          </div>
          <div className="stat">
            <div className="num" style={{ color: "var(--orange)" }}>{counts.deleted}</div>
            <div className="lbl">Устгагдсан</div>
          </div>
          <div className="stat">
            <div className="num" style={{ color: "var(--red)" }}>{counts.high}</div>
            <div className="lbl">Өндөр эрсдэл</div>
          </div>
          <div className="stat">
            <div className="num">{counts.timeline}</div>
            <div className="lbl">Activity</div>
          </div>
        </div>
      </div>

      <div className="panel">
        {tab === "inventory" && (
          <FileInventoryPanel
            scanId={id}
            title="Нийт файлын metadata"
            subtitle="Flash/USB дээр байгаа бүх файл — идэвхтэй (pptx, docx…) + устгагдсан. Explorer-т харагдах файлууд энд."
          />
        )}
        {tab === "active" && (
          <FileInventoryPanel
            scanId={id}
            title="Идэвхтэй файлууд"
            subtitle="Төхөөрөмж дээр одоо байгаа, ашиглагдаж байгаа файлууд."
            defaultStatusFilter="active"
          />
        )}
        {tab === "deleted" && (
          <FileInventoryPanel
            scanId={id}
            title="Устгагдсан файлууд"
            subtitle="Shift+Delete, Recycle Bin, carving — metadata + сэргээлт."
            defaultStatusFilter="deleted"
          />
        )}
        {tab === "risk" && (
          <RiskTab scanId={id} high={counts.high} medium={counts.medium ?? 0} />
        )}
        {tab === "timeline" && <TimelineTab scanId={id} scanStatus={scan.status} />}
      </div>

      {!running && scan.status !== "pending" && (
        <div className="panel scan-finish-panel">
          <p style={{ margin: "0 0 12px", color: "var(--text-dim)", fontSize: 13 }}>
            Тайлан татаж, шаардлагатай файлуудаа хадгалсны дараа доорх товчийг дарна уу.
            Сэргээсэн файлууд болон scan-ийн бүх өгөгдөл серверээс устгагдана.
          </p>
          <button className="btn danger" disabled={finishing} onClick={finishScan}>
            {finishing ? "Устгаж байна…" : "Дууслаа"}
          </button>
        </div>
      )}
    </div>
  );
}

function RiskTab({ scanId, high, medium }: { scanId: number; high: number; medium: number }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Finding | null>(null);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api.listFindings({ scan_id: scanId, severity: "high", limit: PAGE_SIZE, offset: 0 }),
      api.listFindings({ scan_id: scanId, severity: "medium", limit: PAGE_SIZE, offset: 0 }),
    ])
      .then(([highPage, mediumPage]) => {
        const merged = [...highPage.items, ...mediumPage.items];
        merged.sort(
          (a, b) => ((b.meta?.["risk_score"] as number) ?? 0) - ((a.meta?.["risk_score"] as number) ?? 0)
        );
        setFindings(merged);
      })
      .catch(() => setFindings([]))
      .finally(() => setLoading(false));
  }, [scanId]);

  return (
    <div>
      <div className="risk-summary">
        <div className="risk-summary-item">
          <span className="badge sev-high">Өндөр</span>
          <strong>{high}</strong> файл
        </div>
        <div className="risk-summary-item">
          <span className="badge sev-medium">Дунд</span>
          <strong>{medium}</strong> файл
        </div>
        <p style={{ color: "var(--text-dim)", fontSize: 12, margin: "12px 0 0", width: "100%" }}>
          NIST SP 800-60 Rev. 1 + FIPS 199: мэдээллийн төрөл (C/I/A) болон NIST SP 800-86 forensic
          контекстээр үнэлнэ. Нийт түвшин = max(C, I, A).
        </p>
      </div>
      {loading ? (
        <div className="empty">Эрсдэлийн жагсаалт ачаалж байна…</div>
      ) : findings.length === 0 ? (
        <div className="empty">Эрсдэлтэй файл илрээгүй.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>FIPS</th>
              <th>Төлөв</th>
              <th>Файл</th>
              <th>Зам</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td>
                  <span className={`badge sev-${f.severity}`}>{(f.meta?.["risk_score"] as number) ?? 0}</span>
                </td>
                <td>
                  <span className={`badge ${findingIsActive(f.finding_type) ? "status-active" : "status-deleted"}`}>
                    {findingFileStatusLabel(f.finding_type)}
                  </span>
                </td>
                <td>{findingDisplayName(f.original_path, f.file_name)}</td>
                <td className="mono path-cell">{f.original_path || "—"}</td>
                <td>
                  <button className="btn secondary sm" onClick={() => setSelected(f)}>Шалтгаан</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {selected && (
        <RiskOfficialReportModal finding={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function TimelineTab({ scanId, scanStatus }: { scanId: number; scanStatus: Scan["status"] }) {
  const [files, setFiles] = useState<FileTimelineSummary[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<FileTimelineDetail | null>(null);
  const [loadingFiles, setLoadingFiles] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [query, setQuery] = useState("");
  const [reverse, setReverse] = useState(false);
  const [page, setPage] = useState(0);
  const PAGE = 200;

  useEffect(() => {
    setLoadingFiles(true);
    api
      .scanTimelineFiles(scanId)
      .then((rows) => {
        setFiles(rows);
        if (rows.length > 0) setSelectedId((prev) => prev ?? rows[0].finding_id);
      })
      .catch(() => setFiles([]))
      .finally(() => setLoadingFiles(false));
  }, [scanId]);

  useEffect(() => {
    if (selectedId == null) {
      setDetail(null);
      return;
    }
    setLoadingDetail(true);
    api
      .findingFileTimeline(selectedId)
      .then(setDetail)
      .catch(() => setDetail(null))
      .finally(() => setLoadingDetail(false));
  }, [selectedId]);

  const filteredFiles = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = !q
      ? files
      : files.filter(
          (f) =>
            f.file_name.toLowerCase().includes(q) ||
            f.original_path.toLowerCase().includes(q)
        );
    return list;
  }, [files, query]);

  useEffect(() => {
    setPage(0);
  }, [query, files.length]);

  const pageCount = Math.max(1, Math.ceil(filteredFiles.length / PAGE));
  const pagedFiles = filteredFiles.slice(page * PAGE, (page + 1) * PAGE);

  const events = useMemo(() => {
    if (!detail) return [];
    const list = [...detail.events];
    list.sort((a, b) => {
      const ta = new Date(a.timestamp).getTime();
      const tb = new Date(b.timestamp).getTime();
      return reverse ? tb - ta : ta - tb;
    });
    return list;
  }, [detail, reverse]);

  if (loadingFiles && files.length === 0) {
    return <div className="empty">Activity timeline ачаалж байна…</div>;
  }

  if (files.length === 0) {
    if (scanStatus === "running" || scanStatus === "pending") {
      return (
        <div className="empty">
          Scan ажиллаж байна… Дууссаны дараа файл бүрийн activity timeline энд гарна.
        </div>
      );
    }
    return (
      <div className="empty">
        Энэ scan-д файл илрээгүй. Шинэ scan хийж, Activity Timeline-ийг дахин шалгана уу.
      </div>
    );
  }

  return (
    <div className="file-timeline-layout">
      <aside className="file-timeline-sidebar">
        <p className="file-timeline-sidebar-title">
          Файлууд ({filteredFiles.length})
        </p>
        <input
          className="file-timeline-search"
          placeholder="Файл хайх…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <div className="file-timeline-list">
          {pagedFiles.map((f) => (
            <button
              key={f.finding_id}
              type="button"
              className={`file-timeline-item${selectedId === f.finding_id ? " active" : ""}`}
              onClick={() => setSelectedId(f.finding_id)}
            >
              <div className="file-timeline-item-name">
                {findingDisplayName(f.original_path, f.file_name)}
              </div>
              <div className="file-timeline-item-meta">
                <span className={`badge ${f.finding_type === "active_file" ? "status-active" : "status-deleted"}`}>
                  {findingFileStatusLabel(f.finding_type)}
                </span>
                <span className={`badge sev-${f.severity}`}>{f.event_count} үйлдэл</span>
              </div>
              {f.last_timestamp && (
                <div className="file-timeline-item-time">{formatDate(f.last_timestamp)}</div>
              )}
            </button>
          ))}
        </div>
        {pageCount > 1 && (
          <div className="row-flex" style={{ marginTop: 8 }}>
            <button className="btn secondary sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              ←
            </button>
            <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
              {page + 1}/{pageCount}
            </span>
            <button
              className="btn secondary sm"
              disabled={page >= pageCount - 1}
              onClick={() => setPage((p) => p + 1)}
            >
              →
            </button>
          </div>
        )}
      </aside>

      <section className="file-timeline-detail">
        {loadingDetail || !detail ? (
          <div className="empty">Файлын timeline ачаалж байна…</div>
        ) : (
          <>
            <div className="file-timeline-detail-head">
              <div>
                <h3>{findingDisplayName(detail.original_path, detail.file_name)}</h3>
                <p className="mono path-cell">{detail.original_path || "—"}</p>
              </div>
              <div className="row-flex">
                <button className="btn secondary sm" onClick={() => setReverse((r) => !r)}>
                  {reverse ? "↓ Шинэ эхэнд" : "↑ Хуучин эхэнд"}
                </button>
              </div>
            </div>
            <p className="file-timeline-narrative">{detail.narrative}</p>
            <div className="file-timeline-stats">
              <span className="badge">MAC: {detail.mac_events}</span>
              <span className="badge">Forensic: {detail.forensic_events}</span>
              <span className="badge">Нийт: {detail.event_count}</span>
              {detail.first_timestamp && detail.last_timestamp && (
                <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
                  {formatDate(detail.first_timestamp)} → {formatDate(detail.last_timestamp)}
                </span>
              )}
            </div>
            <div className="file-timeline-events">
              {events.map((e) => (
                <div className="timeline-item file-timeline-event" key={`${e.sequence}-${e.event_type}-${e.timestamp}`}>
                  <div className="timeline-seq">{e.sequence}</div>
                  <div className="timeline-time">{formatDate(e.timestamp)}</div>
                  <div
                    className={`timeline-kind kind-${e.event_type.charAt(0)} kind-${e.event_type}`}
                    title={EVENT_LABELS[e.event_type] ?? e.event_type}
                  >
                    {e.event_type.length <= 2 ? e.event_type : e.event_type.charAt(0)}
                  </div>
                  <div className="timeline-event-body">
                    <div className="timeline-event-title">
                      {e.title}
                      <span className="timeline-cat">{CATEGORY_LABELS[e.category] ?? e.category}</span>
                    </div>
                    <div className="timeline-event-desc">{e.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </section>
    </div>
  );
}
