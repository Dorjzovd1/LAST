export type ScanTab = "inventory" | "active" | "deleted" | "risk" | "timeline";

export const SCAN_TAB_LABELS: Record<ScanTab, string> = {
  inventory: "Нийт файл",
  active: "Идэвхтэй",
  deleted: "Устгагдсан",
  risk: "Эрсдэлийн үнэлгээ",
  timeline: "Activity Timeline",
};

export const SCAN_TABS: ScanTab[] = ["inventory", "active", "deleted", "risk", "timeline"];

export function isScanTab(value: string | null): value is ScanTab {
  return value !== null && value in SCAN_TAB_LABELS;
}

export function scanTabPath(scanId: number, tab: ScanTab): string {
  if (tab === "inventory") return `/scans/${scanId}`;
  return `/scans/${scanId}?tab=${tab}`;
}

export function activeScanTab(tabParam: string | null): ScanTab {
  return isScanTab(tabParam) ? tabParam : "inventory";
}
