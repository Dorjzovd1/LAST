import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { api } from "./api/client";
import type { HealthInfo } from "./api/types";
import { useEvents } from "./lib/events";
import Dashboard from "./pages/Dashboard";
import ScanView from "./pages/ScanView";
import CaseView from "./pages/CaseView";

interface Toast {
  id: number;
  text: string;
}

export default function App() {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const { connected, subscribe } = useEvents();
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  useEffect(() => {
    return subscribe((ev) => {
      const labels: Record<string, string> = {
        scan_completed: "Scan дууслаа",
        scan_failed: "Scan амжилтгүй",
        device_hotplug: "Төхөөрөмжийн өөрчлөлт",
      };
      if (labels[ev.type]) {
        const id = Date.now();
        setToasts((t) => [...t, { id, text: labels[ev.type] }]);
        setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000);
      }
    });
  }, [subscribe]);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="logo">
          REA<span>.</span>
        </div>
        <div className="tagline">Removable Evidence Analyzer</div>
        <nav className="nav">
          <NavLink to="/" end>
            Хяналтын самбар
          </NavLink>
          <NavLink to="/cases">Хэргүүд</NavLink>
        </nav>

        <div className="status-pill">
          <div>
            <span className={`dot ${connected ? "on" : "off"}`} />
            Real-time {connected ? "холбогдсон" : "тасарсан"}
          </div>
          {health && (
            <div style={{ marginTop: 8 }}>
              <span className={`dot ${health.tools_ready ? "on" : "warn"}`} />
              {health.tools_ready ? "Forensic хэрэгсэл бэлэн" : health.mock_mode ? "Mock горим" : "Хэрэгсэл дутуу"}
            </div>
          )}
          {health && (
            <div style={{ marginTop: 8, color: "var(--text-dim)" }}>
              v{health.version} · {health.platform}
            </div>
          )}
        </div>
      </aside>

      <main className="main">
        {health && !health.tools_ready && (
          <div className="warn-banner">
            {health.mock_mode
              ? "Анхаар: forensic CLI хэрэгслүүд олдсонгүй тул систем DEMO/MOCK горимд ажиллаж байна. Бодит шинжилгээ хийхийн тулд Ubuntu дээр sleuthkit, photorec зэргийг суулгана уу."
              : "Forensic хэрэгслүүд дутуу байна."}
          </div>
        )}
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/cases" element={<Dashboard />} />
          <Route path="/cases/:caseId" element={<CaseView />} />
          <Route path="/scans/:scanId" element={<ScanView />} />
        </Routes>
      </main>

      <div className="toast-area">
        {toasts.map((t) => (
          <div className="toast" key={t.id}>
            {t.text}
          </div>
        ))}
      </div>
    </div>
  );
}
