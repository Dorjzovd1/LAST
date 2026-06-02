import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import type { Case, DetectedDevice, Device } from "../api/types";
import { useEvents } from "../lib/events";
import { formatBytes } from "../lib/format";
import Overview from "../components/Overview";

export default function Dashboard() {
  const [cases, setCases] = useState<Case[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [detected, setDetected] = useState<DetectedDevice[]>([]);
  const [activeCase, setActiveCase] = useState<number | null>(null);
  const [busy, setBusy] = useState<string>("");
  const { subscribe } = useEvents();
  const navigate = useNavigate();

  const reload = async () => {
    const [c, d] = await Promise.all([api.listCases(), api.listDevices()]);
    setCases(c);
    setDevices(d);
    if (!activeCase && c.length) setActiveCase(c[0].id);
  };

  const detect = async () => {
    setBusy("detect");
    try {
      setDetected(await api.detectDevices());
    } finally {
      setBusy("");
    }
  };

  useEffect(() => {
    reload();
    detect();
  }, []);

  useEffect(() => {
    return subscribe((ev) => {
      if (ev.type === "device_hotplug") detect();
      if (ev.type === "scan_completed") reload();
    });
  }, [subscribe]);

  return (
    <div>
      <h1 className="page-title">Хяналтын самбар</h1>
      <p className="page-sub">Зөөврийн төхөөрөмжийг таниж, хэрэгт бүртгэн, read-only шинжилгээ эхлүүлнэ.</p>

      <Overview />

      <div className="grid grid-2">
        <CasePanel cases={cases} activeCase={activeCase} setActiveCase={setActiveCase} onCreated={reload} />
        <DetectPanel detected={detected} busy={busy} onDetect={detect} activeCase={activeCase} onRegistered={reload} />
      </div>

      <RegisteredDevices
        devices={devices}
        cases={cases}
        onChanged={reload}
        setBusy={setBusy}
        busy={busy}
        navigate={navigate}
      />
    </div>
  );
}

function CasePanel({
  cases,
  activeCase,
  setActiveCase,
  onCreated,
}: {
  cases: Case[];
  activeCase: number | null;
  setActiveCase: (id: number) => void;
  onCreated: () => void;
}) {
  const [form, setForm] = useState({ case_number: "", title: "", investigator: "", description: "" });
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    try {
      const c = await api.createCase(form);
      setForm({ case_number: "", title: "", investigator: "", description: "" });
      setActiveCase(c.id);
      onCreated();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <div className="panel">
      <h2>Хэрэг</h2>
      <div className="field">
        <label>Идэвхтэй хэрэг (шинжилгээнд хэрэглэнэ)</label>
        <select value={activeCase ?? ""} onChange={(e) => setActiveCase(Number(e.target.value))}>
          <option value="">— сонгох —</option>
          {cases.map((c) => (
            <option key={c.id} value={c.id}>
              {c.case_number} · {c.title}
            </option>
          ))}
        </select>
      </div>

      <h3>Шинэ хэрэг үүсгэх</h3>
      <div className="field">
        <label>Хэргийн дугаар</label>
        <input type="text" value={form.case_number} onChange={(e) => setForm({ ...form, case_number: e.target.value })} />
      </div>
      <div className="field">
        <label>Гарчиг</label>
        <input type="text" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
      </div>
      <div className="field">
        <label>Шинжээч</label>
        <input type="text" value={form.investigator} onChange={(e) => setForm({ ...form, investigator: e.target.value })} />
      </div>
      {err && <div style={{ color: "var(--red)", fontSize: 12, marginBottom: 8 }}>{err}</div>}
      <button className="btn" disabled={!form.case_number || !form.title} onClick={submit}>
        Хэрэг үүсгэх
      </button>
    </div>
  );
}

function DetectPanel({
  detected,
  busy,
  onDetect,
  activeCase,
  onRegistered,
}: {
  detected: DetectedDevice[];
  busy: string;
  onDetect: () => void;
  activeCase: number | null;
  onRegistered: () => void;
}) {
  const register = async (dev: DetectedDevice) => {
    await api.registerDevice(dev.dev_path, activeCase);
    onRegistered();
  };

  return (
    <div className="panel">
      <div className="row-flex">
        <h2 style={{ margin: 0 }}>Илрүүлсэн төхөөрөмж</h2>
        <div className="spacer" />
        <button className="btn secondary sm" disabled={busy === "detect"} onClick={onDetect}>
          {busy === "detect" ? "Хайж байна…" : "Дахин илрүүлэх"}
        </button>
      </div>
      {detected.length === 0 ? (
        <div className="empty">Зөөврийн төхөөрөмж олдсонгүй. USB/SD холбоод "Дахин илрүүлэх" дарна уу.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Зам</th>
              <th>Нэр</th>
              <th>Хэмжээ</th>
              <th>FS</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {detected.map((d) => (
              <tr key={d.dev_path}>
                <td className="mono">{d.dev_path}</td>
                <td>{d.name || "—"}</td>
                <td>{formatBytes(d.size_bytes)}</td>
                <td>{d.fs_type || "—"}</td>
                <td>
                  <button className="btn sm" onClick={() => register(d)}>
                    Бүртгэх
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function RegisteredDevices({
  devices,
  cases,
  onChanged,
  setBusy,
  busy,
  navigate,
}: {
  devices: Device[];
  cases: Case[];
  onChanged: () => void;
  setBusy: (s: string) => void;
  busy: string;
  navigate: ReturnType<typeof useNavigate>;
}) {
  const caseLabel = (id: number | null) => cases.find((c) => c.id === id)?.case_number ?? "—";

  const readOnly = async (id: number) => {
    setBusy(`ro-${id}`);
    try {
      await api.setReadOnly(id);
      onChanged();
    } finally {
      setBusy("");
    }
  };

  const startScan = async (dev: Device) => {
    setBusy(`scan-${dev.id}`);
    try {
      if (!dev.read_only) await api.setReadOnly(dev.id);
      const scan = await api.createScan(dev.id, {
        recover_files: true,
        run_carving: false,
        run_recycle: true,
        run_named_tools: true,
        max_recover_size_mb: 512,
      });
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      alert("Шинжилгээ эхлүүлэхэд алдаа: " + (e as Error).message);
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="panel">
      <h2>Бүртгэгдсэн төхөөрөмжүүд</h2>
      {devices.length === 0 ? (
        <div className="empty">Хараахан төхөөрөмж бүртгээгүй байна.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Зам</th>
              <th>Нэр</th>
              <th>Хэрэг</th>
              <th>Хэмжээ</th>
              <th>Төлөв</th>
              <th>Read-only</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id}>
                <td className="mono">{d.dev_path}</td>
                <td>{d.name || "—"}</td>
                <td>{caseLabel(d.case_id)}</td>
                <td>{formatBytes(d.size_bytes)}</td>
                <td>
                  <span className={`state state-${d.state}`}>{d.state}</span>
                </td>
                <td>{d.read_only ? <span className="dot on" /> : <span className="dot off" />}</td>
                <td>
                  <div className="row-flex">
                    {!d.read_only && (
                      <button className="btn secondary sm" disabled={busy === `ro-${d.id}`} onClick={() => readOnly(d.id)}>
                        Write-block
                      </button>
                    )}
                    <button
                      className="btn sm"
                      disabled={busy === `scan-${d.id}`}
                      onClick={() => startScan(d)}
                      title="Read-only TSK — бүх файлын жагсаалт ба MAC цаг"
                    >
                      {busy === `scan-${d.id}` ? "Шинжилж байна…" : "Шинжилгээ хийх"}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
