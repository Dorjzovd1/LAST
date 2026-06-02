import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Overview as OverviewData } from "../api/types";
import { useEvents } from "../lib/events";

const SEVERITY_META: Record<string, { label: string; color: string }> = {
  high: { label: "Өндөр түвшин", color: "var(--red)" },
  medium: { label: "Дунд түвшин", color: "var(--orange)" },
  normal: { label: "Хэвийн", color: "var(--green)" },
};

const TYPE_LABEL: Record<string, string> = {
  active_file: "Идэвхтэй файл",
  deleted_file: "Устгагдсан файл",
  carved_file: "Carved файл",
  recycle_artifact: "Recycle artifact",
  slack_space: "Slack space",
};

export default function Overview() {
  const [data, setData] = useState<OverviewData | null>(null);
  const { subscribe } = useEvents();

  const load = () => api.overview().then(setData).catch(() => setData(null));

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    return subscribe((ev) => {
      if (["scan_completed", "scan_progress", "device_hotplug"].includes(ev.type)) {
        load();
      }
    });
  }, [subscribe]);

  if (!data) return null;

  const totalFindings = data.findings_total;
  const susPct = data.suspicious_pct;
  const normPct = data.normal_pct;

  // Donut: conic-gradient-ийн зэрэг.
  const donut =
    totalFindings > 0
      ? `conic-gradient(var(--red) 0% ${susPct}%, var(--green) ${susPct}% 100%)`
      : `conic-gradient(var(--border) 0% 100%)`;

  const sevMax = Math.max(1, ...Object.values(data.by_severity));

  return (
    <div className="overview">
      <div className="ov-cards">
        <StatCard num={data.cases} label="Хэрэг" icon="folder" />
        <StatCard num={data.devices} label="Төхөөрөмж" icon="usb" />
        <StatCard num={data.scans} label="Шинжилгээ" sub={data.scans_running ? `${data.scans_running} идэвхтэй` : undefined} icon="scan" />
        <StatCard num={totalFindings} label="Нийт ул мөр" sub={`${data.findings_recovered} сэргээсэн`} icon="file" />
      </div>

      <div className="ov-main">
        <div className="panel ov-donut-panel">
          <h2>Сэжигтэй байдлын үнэлгээ</h2>
          {totalFindings === 0 ? (
            <div className="empty">Хараахан шинжилгээ хийгээгүй. Шинжилгээ хийсний дараа энд харагдана.</div>
          ) : (
            <div className="donut-wrap">
              <div className="donut" style={{ background: donut }}>
                <div className="donut-hole">
                  <div className="donut-pct" style={{ color: susPct >= 50 ? "var(--red)" : "var(--green)" }}>
                    {susPct}%
                  </div>
                  <div className="donut-cap">сэжигтэй</div>
                </div>
              </div>
              <div className="donut-legend">
                <LegendRow color="var(--red)" label="Сэжигтэй (Өндөр+Дунд)" value={data.suspicious} pct={susPct} />
                <LegendRow color="var(--green)" label="Хэвийн" value={data.normal} pct={normPct} />
              </div>
            </div>
          )}
          <details className="criteria">
            <summary>Эрсдэл үнэлэх стандарт шалгуур</summary>
            <ul>
              <li>Эмзэг түлхүүр үг (password, secret, нууц…) — <b>+5</b></li>
              <li>Эмзэг өргөтгөл (docx, xlsx, pdf, db, pem, key…) — <b>+3</b></li>
              <li>Архив/шифрлэгдсэн (zip, rar, 7z, kdbx, gpg) — <b>+2</b></li>
              <li>Гүйцэтгэх/скрипт (exe, dll, ps1, sh…) — <b>+2</b></li>
              <li>Carving (unallocated)-аас сэргээгдсэн — <b>+2</b></li>
              <li>Устгагдсан / Recycle / Slack — <b>+1</b></li>
              <li>Агуулга амжилттай сэргээгдсэн — <b>+1</b></li>
            </ul>
            <div className="criteria-note">
              Нийт оноо: <b style={{ color: "var(--red)" }}>≥5 Өндөр</b> ·{" "}
              <b style={{ color: "var(--orange)" }}>2–4 Дунд</b> ·{" "}
              <b style={{ color: "var(--green)" }}>&lt;2 Хэвийн</b>
            </div>
          </details>
        </div>

        <div className="panel ov-bars-panel">
          <h2>Эрсдэлийн зэрэглэл</h2>
          {Object.entries(data.by_severity).map(([sev, cnt]) => {
            const meta = SEVERITY_META[sev] ?? { label: sev, color: "var(--text-dim)" };
            return (
              <div className="bar-row" key={sev}>
                <div className="bar-label">{meta.label}</div>
                <div className="bar-track">
                  <div
                    className="bar-fill"
                    style={{ width: `${(cnt / sevMax) * 100}%`, background: meta.color }}
                  />
                </div>
                <div className="bar-num">{cnt}</div>
              </div>
            );
          })}

          <h3>Төрлөөр</h3>
          <div className="type-chips">
            {Object.entries(data.by_type).map(([t, cnt]) => (
              <span className="type-chip" key={t}>
                {TYPE_LABEL[t] ?? t} <b>{cnt}</b>
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ num, label, sub, icon }: { num: number; label: string; sub?: string; icon: string }) {
  return (
    <div className="ov-card">
      <div className={`ov-icon ic-${icon}`} />
      <div>
        <div className="ov-num">{num}</div>
        <div className="ov-label">{label}</div>
        {sub && <div className="ov-sub">{sub}</div>}
      </div>
    </div>
  );
}

function LegendRow({ color, label, value, pct }: { color: string; label: string; value: number; pct: number }) {
  return (
    <div className="legend-row">
      <span className="legend-dot" style={{ background: color }} />
      <span className="legend-label">{label}</span>
      <span className="legend-val">
        {value} · {pct}%
      </span>
    </div>
  );
}
