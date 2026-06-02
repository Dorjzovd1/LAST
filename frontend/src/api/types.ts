export interface Case {
  id: number;
  case_number: string;
  title: string;
  investigator: string;
  description: string;
  created_at: string;
}

export interface DetectedDevice {
  dev_path: string;
  name: string;
  serial: string;
  bus: string;
  size_bytes: number;
  fs_type: string;
  is_removable: boolean;
  details: Record<string, unknown>;
}

export interface Device {
  id: number;
  case_id: number | null;
  dev_path: string;
  name: string;
  serial: string;
  bus: string;
  size_bytes: number;
  fs_type: string;
  is_removable: boolean;
  read_only: boolean;
  state: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface ScanOptions {
  recover_files: boolean;
  run_carving: boolean;
  run_recycle: boolean;
  run_named_tools: boolean;
  max_recover_size_mb: number;
}

export interface Scan {
  id: number;
  device_id: number;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  current_step: string;
  options: Record<string, unknown>;
  error: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface Finding {
  id: number;
  scan_id: number;
  finding_type: "active_file" | "deleted_file" | "carved_file" | "recycle_artifact" | "slack_space";
  severity: "high" | "medium" | "normal";
  file_name: string;
  original_path: string;
  inode: string;
  size_bytes: number;
  mime_type: string;
  recovered: boolean;
  recovered_path: string;
  md5: string;
  sha256: string;
  mtime: string | null;
  atime: string | null;
  ctime: string | null;
  crtime: string | null;
  source_tool: string;
  meta: Record<string, unknown>;
  created_at: string;
}

export interface TimelineEvent {
  id: number;
  scan_id: number;
  finding_id: number | null;
  timestamp: string;
  event_type: string;
  description: string;
}

export interface AuditLog {
  id: number;
  case_id: number | null;
  action: string;
  actor: string;
  target: string;
  detail: Record<string, unknown>;
  timestamp: string;
}

export interface HealthInfo {
  status: string;
  version: string;
  platform: string;
  mock_mode: boolean;
  tools: Record<string, boolean>;
  tools_ready: boolean;
  running_as_root?: boolean | null;
  device_access_ok?: boolean;
}

export interface RealtimeEvent {
  type: string;
  data: Record<string, unknown>;
}

export interface Overview {
  cases: number;
  devices: number;
  scans: number;
  scans_running: number;
  findings_total: number;
  findings_recovered: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  suspicious: number;
  normal: number;
  suspicious_pct: number;
  normal_pct: number;
}
