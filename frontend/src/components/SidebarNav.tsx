import { Link, NavLink, useLocation, useSearchParams } from "react-router-dom";
import {
  SCAN_TABS,
  SCAN_TAB_LABELS,
  activeScanTab,
  scanTabPath,
} from "../lib/scanTabs";

export default function SidebarNav() {
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const scanMatch = location.pathname.match(/^\/scans\/(\d+)/);
  const scanId = scanMatch ? Number(scanMatch[1]) : null;
  const currentTab = scanId ? activeScanTab(searchParams.get("tab")) : null;

  return (
    <nav className="nav">
      <div className="nav-group">
        <NavLink to="/" end className={({ isActive }) => `nav-parent${isActive ? " active" : ""}`}>
          Хяналтын самбар
        </NavLink>
        {scanId && currentTab ? (
          <div className="nav-sub">
            {SCAN_TABS.map((tab) => (
              <Link
                key={tab}
                to={scanTabPath(scanId, tab)}
                className={`nav-sub-link${currentTab === tab ? " active" : ""}`}
              >
                {SCAN_TAB_LABELS[tab]}
              </Link>
            ))}
          </div>
        ) : null}
      </div>
    </nav>
  );
}
