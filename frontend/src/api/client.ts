import type {
  AuditLog,
  Case,
  DetectedDevice,
  Device,
  Finding,
  HealthInfo,
  Overview,
  Scan,
  ScanOptions,
  ScanSummary,
  TimelineEvent,
  FileTimelineSummary,
  FileTimelineDetail,
} from "./types";
import type { RiskOfficialReport } from "../lib/riskReport";

const BASE = "/api";

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  health: () => http<HealthInfo>("/health"),
  overview: () => http<Overview>("/stats/overview"),

  // Cases
  listCases: () => http<Case[]>("/cases"),
  createCase: (data: Partial<Case>) =>
    http<Case>("/cases", { method: "POST", body: JSON.stringify(data) }),
  getCase: (id: number) => http<Case>(`/cases/${id}`),
  caseAudit: (id: number) => http<AuditLog[]>(`/cases/${id}/audit`),

  // Devices
  detectDevices: () => http<DetectedDevice[]>("/devices/detect"),
  listDevices: () => http<Device[]>("/devices"),
  getDevice: (id: number) => http<Device>(`/devices/${id}`),
  registerDevice: (dev_path: string, case_id: number | null) =>
    http<Device>("/devices", { method: "POST", body: JSON.stringify({ dev_path, case_id }) }),
  setReadOnly: (id: number) => http<Device>(`/devices/${id}/read-only`, { method: "POST" }),

  // Scans
  listScans: () => http<Scan[]>("/scans"),
  createScan: (device_id: number, options: ScanOptions) =>
    http<Scan>("/scans", { method: "POST", body: JSON.stringify({ device_id, options }) }),
  getScan: (id: number) => http<Scan>(`/scans/${id}`),
  cancelScan: (id: number) => http<Scan>(`/scans/${id}/cancel`, { method: "POST" }),
  scanTimeline: (id: number) => http<TimelineEvent[]>(`/scans/${id}/timeline`),
  scanTimelineFiles: (id: number) => http<FileTimelineSummary[]>(`/scans/${id}/timeline/files`),
  scanSummary: (id: number) => http<ScanSummary>(`/scans/${id}/summary`),

  // Findings
  listFindings: (params: Record<string, string | number | boolean | undefined>) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== "") qs.append(k, String(v));
    });
    return http<Finding[]>(`/findings?${qs.toString()}`);
  },
  previewFinding: (id: number) =>
    http<{ preview: string; available: boolean; truncated?: boolean }>(`/findings/${id}/preview`),
  findingRiskReport: (id: number) => http<RiskOfficialReport>(`/findings/${id}/risk-report`),
  findingFileTimeline: (id: number) => http<FileTimelineDetail>(`/findings/${id}/file-timeline`),
  downloadUrl: (id: number) => `${BASE}/findings/${id}/download`,

  // Reports
  reportHtmlUrl: (scanId: number) => `${BASE}/reports/scan/${scanId}/html`,
  reportPdfUrl: (scanId: number) => `${BASE}/reports/scan/${scanId}/pdf`,
  reportJson: (scanId: number) => http<Record<string, unknown>>(`/reports/scan/${scanId}/json`),
};

export function connectEvents(onMessage: (ev: { type: string; data: any }) => void): WebSocket {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/events`);
  ws.onmessage = (e) => {
    try {
      onMessage(JSON.parse(e.data));
    } catch {
      /* ignore */
    }
  };
  // Холболтыг нээлттэй байлгах keep-alive.
  const ping = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send("ping");
  }, 25000);
  ws.onclose = () => clearInterval(ping);
  return ws;
}
