import { useEffect, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { api } from "./api/client";
import type { HealthInfo } from "./api/types";
import { useEvents } from "./lib/events";
import SidebarNav from "./components/SidebarNav";
import Dashboard from "./pages/Dashboard";
import ScanView from "./pages/ScanView";
import CaseView from "./pages/CaseView";

interface Toast {
  id: number;
  text: string;
}

export default function App() {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const { subscribe } = useEvents();
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
        <div className="app-brand">
          <div className="app-brand-mark" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2">
              <rect x="7" y="2" width="10" height="14" rx="2" />
              <path d="M12 16v6M9 22h6" />
              <path d="M9 7h6M9 11h4" />
            </svg>
          </div>
          <p className="app-brand-title">
            Зөөврийн мэдээлэл тээгч төхөөрөмжийн{" "}
            <span>тоон ул мөр илрүүлэх систем</span>
          </p>
        </div>
        <SidebarNav />
      </aside>

      <main className="main">
        {health && !health.mock_mode && health.device_access_ok === false && (
          <div className="warn-banner">
            Анхаар: backend root эрхгүй ажиллаж байна — USB шинжилгээ (write-block) ажиллахгүй.
            Backend-ийг sudo-оор ажиллуулна уу:{" "}
            <code>sudo uvicorn app.main:app --host 0.0.0.0 --port 8000</code>
          </div>
        )}
        {health && health.mock_mode && (
          <div className="warn-banner">
            Анхаар: forensic CLI хэрэгслүүд олдсонгүй тул систем DEMO/MOCK горимд ажиллаж байна.
            Бодит шинжилгээ хийхийн тулд Ubuntu дээр sleuthkit зэргийг суулгана уу.
          </div>
        )}
        {health && !health.tools_ready && !health.mock_mode && (
          <div className="warn-banner">Forensic хэрэгслүүд дутуу байна.</div>
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
