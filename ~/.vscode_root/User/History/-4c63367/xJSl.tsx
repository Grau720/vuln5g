import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { BrowserRouter, Routes, Route, NavLink, useLocation } from "react-router-dom";
import Vulnerabilidades5GDashboard, { type CVE } from "./components/Vulnerabilidades5GDashboard";
import EscaneosDashboard from "./components/EscaneosDashboard";
import HomeDashboard from "./components/HomeDashboard";
import IADashboard from "./components/IADashboard";

// claves de storage para mantener compatibilidad con tu dashboard actual
const THEME_KEY = "theme";

function useGlobalTheme() {
  const [theme, setTheme] = useState<"light" | "dark">(
    () => (localStorage.getItem(THEME_KEY) as "light" | "dark") || "dark"
  );

  // aplica clase al <html> y persiste
  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove("theme-cosmos", "theme-light");
    root.classList.add(theme === "dark" ? "theme-cosmos" : "theme-light");
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  const toggle = () => setTheme((t) => (t === "dark" ? "light" : "dark"));
  return { theme, toggle };
}

function TopNav({ theme, onToggle }: { theme: "light" | "dark"; onToggle: () => void }) {
  const location = useLocation();
  const isActive = (path: string) => location.pathname.startsWith(path);
  const navigate = useNavigate();

  return (
    <header className="sticky top-0 z-40 bg-[var(--panel-bg)] border-b border-[var(--panel-border)] backdrop-blur">
      <div className="max-w-[1600px] mx-auto flex items-center justify-between px-4 py-2">
        {/* Logo / Nombre */}
        <div className="flex items-center gap-2 cursor-pointer" onClick={() => navigate("/")}>
          <span className="text-xl">🛡️</span>
          <span className="font-bold text-lg">VulnDB 5G</span>
        </div>

        {/* Links */}
        <nav className="flex gap-6 text-sm font-medium">
          {/* <NavLink
            to="/"
            className={({ isActive }) =>
              isActive ? "text-blue-400 font-semibold" : "hover:text-blue-300 text-[var(--muted)]"
            }
          >
            🏠 Inicio
          </NavLink> */}
          <NavLink
            to="/scan"
            className={({ isActive }) =>
              isActive ? "text-blue-400 font-semibold" : "hover:text-blue-300 text-[var(--muted)]"
            }
          >
            🛰️ Escaneos
          </NavLink>
          <NavLink
            to="/dashboard"
            className={({ isActive }) =>
              isActive ? "text-blue-400 font-semibold" : "hover:text-blue-300 text-[var(--muted)]"
            }
          >
            📊 Vulnerabilidades
          </NavLink>
        </nav>

        {/* Acciones */}
        <div className="flex items-center gap-2">
          <button
            className="w-9 h-9 flex items-center justify-center rounded-full hover:bg-slate-700/40"
            onClick={onToggle}
            title="Cambiar tema"
          >
            {theme === "dark" ? "☀️" : "🌙"}
          </button>
        </div>
      </div>
    </header>
  );
}


export default function App() {
  const { theme, toggle } = useGlobalTheme();
  const [initialData, setInitialData] = useState<CVE[] | null>(null);

  useEffect(() => {
    fetch(`/api/v1/cves${window.location.search}`)
      .then((r) => r.json())
      .then((j) => setInitialData(j.cves || []))
      .catch(() => setInitialData([]));
  }, []);

  return (
    <BrowserRouter>
      <TopNav theme={theme} onToggle={toggle} />
        <Routes>
          <Route path="/" element={<HomeDashboard />} />
          <Route
            path="/dashboard"
            element={<Vulnerabilidades5GDashboard initialData={initialData || []} endpoint="/api/v1/cves" />}
          />
          <Route
            path="/dashboard/:cveId"
            element={<Vulnerabilidades5GDashboard initialData={initialData || []} endpoint="/api/v1/cves" />}
          />
          <Route path="/scan" element={<EscaneosDashboard />} />
          <Route path="*" element={<Vulnerabilidades5GDashboard initialData={initialData || []} endpoint="/api/v1/cves" />} />
        </Routes>
    </BrowserRouter>
  );
}
