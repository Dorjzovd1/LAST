import type { FileTimelineDetail, FileTimelineEvent, FileTimelineSummary, Finding } from "../api/types";

const MAC_FIELDS: Array<{ field: keyof Finding; type: string; title: string; detail: string }> = [
  {
    field: "crtime",
    type: "B",
    title: "Файл анх үүссэн (Born)",
    detail: "NTFS Created timestamp — файл эхний удаа үүссэн цаг.",
  },
  {
    field: "mtime",
    type: "M",
    title: "Агуулга өөрчлөгдсөн (Modified)",
    detail: "Файлын агуулга эсвэл хэмжээ өөрчлөгдсөн.",
  },
  {
    field: "atime",
    type: "A",
    title: "Файлд хандсан (Accessed)",
    detail: "Хэрэглэгч эсвэл програм файлд хандсан.",
  },
  {
    field: "ctime",
    type: "C",
    title: "Metadata өөрчлөгдсөн (Changed)",
    detail: "Нэр, атрибут, зөвшөөрөл эсвэл устгах үйлдлийн metadata.",
  },
];

const STATUS_LABELS: Record<string, { code: string; title: string; desc: string }> = {
  active_file: {
    code: "ACTIVE",
    title: "Идэвхтэй файл",
    desc: "Scan үед файлын системд бүртгэлтэй байсан.",
  },
  deleted_file: {
    code: "DELETED",
    title: "Устгагдсан файл",
    desc: "Файлын системээс устгагдсан гэж илэрсэн.",
  },
  recycle_artifact: {
    code: "RECYCLE",
    title: "Recycle Bin",
    desc: "Recycle Bin artifact — устгах үйлдлийн ул мөр.",
  },
  carved_file: {
    code: "CARVED",
    title: "Carving",
    desc: "Unallocated space-аас carving-аар илэрсэн.",
  },
  slack_space: {
    code: "SLACK",
    title: "Slack space",
    desc: "Cluster slack space-д үлдсэн агуулга.",
  },
};

function tsList(f: Finding): string[] {
  return [f.crtime, f.mtime, f.atime, f.ctime, f.created_at].filter(Boolean) as string[];
}

export function summarizeFinding(f: Finding): FileTimelineSummary {
  const times = tsList(f);
  const macEvents = [f.crtime, f.mtime, f.atime, f.ctime].filter(Boolean).length;
  let forensicEvents = 1;
  if (f.finding_type !== "active_file") forensicEvents += 1;
  if (f.recovered) forensicEvents += 1;

  return {
    finding_id: f.id,
    file_name: f.file_name,
    original_path: f.original_path,
    finding_type: f.finding_type,
    severity: f.severity,
    mime_type: f.mime_type,
    size_bytes: f.size_bytes,
    recovered: f.recovered,
    event_count: macEvents + forensicEvents,
    mac_events: macEvents,
    forensic_events: forensicEvents,
    first_timestamp: times.length ? times.reduce((a, b) => (a < b ? a : b)) : f.created_at,
    last_timestamp: times.length ? times.reduce((a, b) => (a > b ? a : b)) : f.created_at,
  };
}

export function buildFileTimelineDetail(f: Finding): FileTimelineDetail {
  const label = f.file_name || f.original_path || `finding-${f.id}`;
  const events: FileTimelineEvent[] = [];

  for (const mac of MAC_FIELDS) {
    const ts = f[mac.field] as string | null;
    if (!ts) continue;
    events.push({
      id: null,
      sequence: 0,
      timestamp: ts,
      event_type: mac.type,
      category: "mac",
      title: mac.title,
      description: `${mac.title}: ${label}. ${mac.detail}`,
      source: "ntfs_mac",
    });
  }

  const status = STATUS_LABELS[f.finding_type];
  if (status) {
    events.push({
      id: null,
      sequence: 0,
      timestamp: f.created_at,
      event_type: status.code,
      category: "forensic",
      title: status.title,
      description: `Forensic scan-ээр «${label}» ${status.desc}`,
      source: "scan_detection",
    });
  }

  if (f.finding_type !== "active_file") {
    const delTs = f.ctime || f.mtime || f.atime || f.created_at;
    if (delTs) {
      events.push({
        id: null,
        sequence: 0,
        timestamp: delTs,
        event_type: "DELETE",
        category: "os",
        title: f.finding_type === "recycle_artifact" ? "Recycle Bin-д шилжсэн" : "Файл устгагдсан",
        description: `«${label}» устгах үйлдлийн ул мөр илэрсэн.`,
        source: "inferred",
      });
    }
  }

  if (f.recovered) {
    events.push({
      id: null,
      sequence: 0,
      timestamp: f.created_at,
      event_type: "RECOVERED",
      category: "forensic",
      title: "Forensic сэргээлт",
      description: `«${label}» агуулгыг scan-ийн үед сэргэсэн.`,
      source: "scan_recovery",
    });
  }

  events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  events.forEach((e, i) => {
    e.sequence = i + 1;
  });

  const summary = summarizeFinding(f);
  const first = events[0]?.timestamp ?? null;
  const last = events[events.length - 1]?.timestamp ?? null;

  return {
    ...summary,
    event_count: events.length,
    mac_events: events.filter((e) => e.category === "mac").length,
    forensic_events: events.filter((e) => e.category === "forensic").length,
    first_timestamp: first,
    last_timestamp: last,
    narrative: `«${label}» — ${events.length} үйл явдал (MAC + lifecycle).`,
    events,
  };
}

export function sortFileSummaries(rows: FileTimelineSummary[]): FileTimelineSummary[] {
  return [...rows].sort((a, b) => {
    const ta = a.last_timestamp ? new Date(a.last_timestamp).getTime() : 0;
    const tb = b.last_timestamp ? new Date(b.last_timestamp).getTime() : 0;
    return tb - ta;
  });
}
