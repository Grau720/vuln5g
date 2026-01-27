import React, { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import Vulnerabilidades5GDashboard, { type CVE } from "./components/Vulnerabilidades5GDashboard";
import HomeDashboard from "./components/HomeDashboard";
import IADashboard from "./components/IADashboard";
import AlertasDashboard from "./components/AlertasDashboard";
import AttackGroupsDashboard from "./components/AttackGroupsDashboard";
import AttackGroupDetail from "./components/AttackGroupDetail";
import AssetsDashboard from "./components/AssetsDashboard";
import AssetDetail from "./components/AssetDetail";
import AssetDiscoveryDashboard from "./components/AssetDiscoveryDashboard"; // 👈 NUEVO

// ============================================================================
// THEME HOOK
// ============================================================================
const THEME_KEY = "theme";

function useGlobalTheme() {
  const [theme, setTheme] = useState<"light" | "dark">(
    () => (localStorage.getItem(THEME_KEY) as "light" | "dark") || "dark"
  );

  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove("theme-cosmos", "theme-light");
    root.classList.add(theme === "dark" ? "theme-cosmos" : "theme-light");
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  const toggle = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  return { theme, toggle };
}

// ============================================================================
// SIDEBAR COMPONENT
// ============================================================================
type NavItem = {
  path: string;
  icon: string;
  label: string;
  badge?: number;
};

type NavSection = {
  title: string;
  items: NavItem[];
};

function Sidebar({ 
  theme, 
  onToggleTheme,
  collapsed,
  onToggleCollapse,
  stats
}: { 
  theme: "light" | "dark"; 
  onToggleTheme: () => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  stats: { activeGroups: number; criticalCVEs: number; pendingAssets: number }; // 👈 AÑADIDO pendingAssets
}) {
  const location = useLocation();
  const navigate = useNavigate();

  const sections: NavSection[] = [
    {
      title: "MONITORIZACIÓN",
      items: [
        { path: "/", icon: "📊", label: "Dashboard" },
        { path: "/alerts/groups", icon: "🚨", label: "Ataques", badge: stats.activeGroups || undefined },
        { path: "/alerts/events", icon: "📡", label: "Eventos" },
      ]
    },
    {
      title: "INTELIGENCIA",
      items: [
        { path: "/dashboard", icon: "🛡️", label: "CVEs", badge: stats.criticalCVEs || undefined },
        { path: "/assets", icon: "🧩", label: "Assets" }, 
        { path: "/ia", icon: "🤖", label: "IA Analysis" },
      ]
    }
  ];

  const isActive = (path: string) => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  return (
    <aside 
      className={`
        fixed left-0 top-0 h-screen z-50
        bg-[#0a0e17] border-r border-slate-800/60
        flex flex-col
        transition-all duration-300 ease-in-out
        ${collapsed ? "w-[68px]" : "w-[240px]"}
      `}
    >
      {/* Logo */}
      <div 
        className={`
          h-16 flex items-center border-b border-slate-800/60
          cursor-pointer group
          ${collapsed ? "justify-center px-2" : "px-4 gap-3"}
        `}
        onClick={() => navigate("/")}
      >
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center text-lg shadow-lg shadow-orange-500/20 group-hover:shadow-orange-500/40 transition-shadow">
          🛡️
        </div>
        {!collapsed && (
          <div className="flex flex-col">
            <span className="font-bold text-white text-sm tracking-wide">VulnDB</span>
            <span className="text-[10px] text-amber-500 font-medium -mt-0.5">5G SECURITY</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-2">
        {sections.map((section, idx) => (
          <div key={section.title} className={idx > 0 ? "mt-6" : ""}>
            {!collapsed && (
              <div className="px-3 mb-2 text-[10px] font-semibold text-slate-500 tracking-wider">
                {section.title}
              </div>
            )}
            <div className="space-y-1">
              {section.items.map((item) => {
                const active = isActive(item.path);
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={`
                      flex items-center gap-3 px-3 py-2.5 rounded-lg
                      transition-all duration-200
                      ${active 
                        ? "bg-gradient-to-r from-amber-500/20 to-orange-500/10 text-amber-400 border-l-2 border-amber-500" 
                        : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border-l-2 border-transparent"
                      }
                      ${collapsed ? "justify-center" : ""}
                    `}
                    title={collapsed ? item.label : undefined}
                  >
                    <span className="text-lg flex-shrink-0">{item.icon}</span>
                    {!collapsed && (
                      <>
                        <span className="text-sm font-medium flex-1">{item.label}</span>
                        {item.badge !== undefined && item.badge > 0 && (
                          <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-red-500/20 text-red-400 border border-red-500/30">
                            {item.badge}
                          </span>
                        )}
                      </>
                    )}
                    {collapsed && item.badge !== undefined && item.badge > 0 && (
                      <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                    )}
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-slate-800/60 p-2">
        {/* Theme toggle */}
        <button
          onClick={onToggleTheme}
          className={`
            w-full flex items-center gap-3 px-3 py-2.5 rounded-lg
            text-slate-400 hover:bg-slate-800/50 hover:text-slate-200
            transition-all duration-200
            ${collapsed ? "justify-center" : ""}
          `}
          title={theme === "dark" ? "Modo claro" : "Modo oscuro"}
        >
          <span className="text-lg">{theme === "dark" ? "☀️" : "🌙"}</span>
          {!collapsed && <span className="text-sm">Cambiar tema</span>}
        </button>

        {/* Collapse toggle */}
        <button
          onClick={onToggleCollapse}
          className={`
            w-full flex items-center gap-3 px-3 py-2.5 rounded-lg
            text-slate-400 hover:bg-slate-800/50 hover:text-slate-200
            transition-all duration-200
            ${collapsed ? "justify-center" : ""}
          `}
          title={collapsed ? "Expandir" : "Colapsar"}
        >
          <span className="text-lg">{collapsed ? "»" : "«"}</span>
          {!collapsed && <span className="text-sm">Colapsar menú</span>}
        </button>
      </div>
    </aside>
  );
}

// ============================================================================
// LAYOUT COMPONENT
// ============================================================================
function AppLayout({ children }: { children: React.ReactNode }) {
  const { theme, toggle } = useGlobalTheme();
  const [collapsed, setCollapsed] = useState(() => {
    const saved = localStorage.getItem("sidebar_collapsed");
    return saved === "true";
  });
  const [stats, setStats] = useState({ 
    activeGroups: 0, 
    criticalCVEs: 0,
    pendingAssets: 0 // 👈 NUEVO
  });

  // Persistir estado del sidebar
  useEffect(() => {
    localStorage.setItem("sidebar_collapsed", String(collapsed));
  }, [collapsed]);

  // 👇 ACTUALIZADO: Cargar stats incluyendo pending assets
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const [groupsRes, cvesRes, assetsRes] = await Promise.all([
          fetch("/api/v1/alerts/groups?status=active&per_page=1"),
          fetch("/api/v1/cves?min_score=9&per_page=1"),
        ]);
        
        const groupsData = await groupsRes.json();
        const cvesData = await cvesRes.json();
        const assetsData = await assetsRes.json();
        
        setStats({
          activeGroups: groupsData.pagination?.total || 0,
          criticalCVEs: cvesData.total || 0,
          pendingAssets: assetsData.total || 0 // 👈 NUEVO
        });
      } catch (e) {
        console.error("Error loading sidebar stats:", e);
      }
    };

    fetchStats();
    // Refresh cada 30 segundos
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-[#060910]">
      <Sidebar 
        theme={theme} 
        onToggleTheme={toggle}
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed(!collapsed)}
        stats={stats}
      />
      <main 
        className={`
          transition-all duration-300 ease-in-out
          ${collapsed ? "ml-[68px]" : "ml-[240px]"}
        `}
      >
        {children}
      </main>
    </div>
  );
}

// ============================================================================
// MAIN APP
// ============================================================================
export default function App() {
  const [initialData, setInitialData] = useState<CVE[] | null>(null);

  useEffect(() => {
    fetch(`/api/v1/cves${window.location.search}`)
      .then((r) => r.json())
      .then((j) => setInitialData(j.cves || []))
      .catch(() => setInitialData([]));
  }, []);

  return (
    <BrowserRouter>
      <AppLayout>
        <Routes>
          {/* Dashboard principal */}
          <Route path="/" element={<HomeDashboard />} />
          
          {/* CVEs */}
          <Route
            path="/dashboard"
            element={<Vulnerabilidades5GDashboard initialData={initialData || []} endpoint="/api/v1/cves" />}
          />
          <Route
            path="/dashboard/:cveId"
            element={<Vulnerabilidades5GDashboard initialData={initialData || []} endpoint="/api/v1/cves" />}
          />
          
          {/* Alertas y Ataques */}
          <Route path="/alerts/events" element={<AlertasDashboard />} />
          <Route path="/alerts/groups" element={<AttackGroupsDashboard />} />
          <Route path="/alerts/groups/:groupId" element={<AttackGroupDetail />} />

          {/* Assets */}
          <Route path="/assets" element={<AssetsDashboard />} />
          <Route path="/assets/:ip" element={<AssetDetail />} />
          
          {/* IA */}
          <Route path="/ia" element={<IADashboard />} />
          
          {/* Fallback */}
          <Route path="*" element={<HomeDashboard />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  );
}