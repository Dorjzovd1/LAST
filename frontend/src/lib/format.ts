export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${units[i]}`;
}

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
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

const TYPE_LABELS: Record<string, string> = {
  active_file: "Идэвхтэй файл",
  deleted_file: "Устгагдсан (нэртэй)",
  carved_file: "Carving (нэргүй)",
  recycle_artifact: "Recycle Bin (нэртэй)",
  slack_space: "Slack space",
};

export function findingTypeLabel(t: string): string {
  return TYPE_LABELS[t] ?? t;
}
