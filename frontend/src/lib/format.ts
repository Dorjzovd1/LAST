export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${units[i]}`;
}

/** API-аас ирсэн цаг — timezone байхгүй бол UTC гэж үзнэ. */
export const DISPLAY_TZ = "Asia/Ulaanbaatar";

export function parseApiDate(iso: string): Date {
  if (iso.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(iso)) {
    return new Date(iso);
  }
  return new Date(`${iso}Z`);
}

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = parseApiDate(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString("mn-MN", {
    timeZone: DISPLAY_TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function shortHash(hash: string, n = 12): string {
  return hash ? hash.slice(0, n) + "…" : "—";
}

/** Ул мөрийн харагдах нэр — эх замын сүүлийн хэсэг эсвэл file_name. */
export function findingDisplayName(originalPath: string, fileName: string): string {
  const path = (originalPath || fileName || "").replace(/\\/g, "/");
  if (!path) return "—";
  const base = path.split("/").filter(Boolean).pop();
  return base || fileName || path;
}

export function findingHasOriginalName(meta: Record<string, unknown> | null | undefined): boolean {
  if (!meta) return false;
  if (meta["has_original_name"] === true) return true;
  return meta["recovery_method"] === "filesystem_metadata";
}

/** MAC timestamp — DB талбар эсвэл meta backup-аас. */
export function findingMacDate(
  f: { meta?: Record<string, unknown> | null },
  field: "crtime" | "mtime" | "atime" | "ctime"
): string | null {
  const direct = (f as Record<string, string | null | undefined>)[field];
  if (direct) return direct;
  const backup = f.meta?.["mac_timestamps"] as Record<string, string> | undefined;
  return backup?.[field] ?? null;
}

const TYPE_LABELS: Record<string, string> = {
  active_file: "Идэвхтэй файл",
  deleted_file: "Устгагдсан (Shift+Delete)",
  carved_file: "Carving (нэргүй)",
  recycle_artifact: "Recycle Bin (энгийн Delete)",
  slack_space: "Slack space",
};

/** Shift+Delete (permanent) эсэхийг meta-аас шалгана. */
export function findingIsPermanentDelete(meta: Record<string, unknown> | null | undefined): boolean {
  if (!meta) return false;
  return meta["delete_method"] === "permanent" || meta["recycle_bypass"] === true;
}

export function findingIsDownloadable(f: { recovered: boolean; size_bytes: number; meta?: Record<string, unknown> | null }): boolean {
  if (!f.recovered || f.size_bytes <= 0) return false;
  // partial recovery — татах боломжтой, гэхдээ нээж чадахгүй байж болно
  if (f.meta?.["recovery_partial"] === true) return true;
  if (f.meta?.["recovery_valid"] === false) return false;
  return true;
}

export function findingTypeLabel(t: string): string {
  return TYPE_LABELS[t] ?? t;
}

const ACTIVE_TYPES = new Set(["active_file"]);

export function findingIsActive(findingType: string): boolean {
  return ACTIVE_TYPES.has(findingType);
}

export function findingFileStatusLabel(findingType: string): string {
  if (findingIsActive(findingType)) return "Идэвхтэй";
  if (findingType === "recycle_artifact") return "Recycle Bin";
  if (findingType === "carved_file") return "Carved";
  return "Устгагдсан";
}
