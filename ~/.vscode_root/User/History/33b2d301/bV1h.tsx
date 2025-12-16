import React, { useEffect, useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ReTooltip,
  Legend
} from "recharts";

// ======================================================
// TYPES
// ======================================================
type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type AttackVector = "NETWORK" | "LOCAL" | "ADJACENT" | "PHYSICAL" | "UNKNOWN";

type CVEPrediction = {
  cve_id: string;
  exploit_probability: number;
  risk_level: RiskLevel;
  attack_vector: AttackVector;
  cvss_score: number;
  tipo: string;
  infraestructura_5g?: string[];
};

type IAStats = {
  total_cves: number;
  by_risk_level: Record<RiskLevel, number>;
  by_attack_vector: Record<AttackVector, number>;
  critical_by_component: Record<string, number>;
};

type SinglePrediction = {
  cve_id: string;
  exploit_probability: number;
  predicted_class: number;
  risk_level: RiskLevel;
  attack_vector: AttackVector;
  threshold_info?: {
    base_threshold: number;
    adjustment: number;
    final_threshold: number;
  };
  metadata: {
    cvss_score: number;
    tipo: string;
    componente?: string;
    infraestructura_5g?: string[];
  };
  explanation?: string;
};

// ======================================================
// COLORS
// ======================================================
const RISK_COLORS: Record<RiskLevel, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#f97316",
  MEDIUM: "#facc15",
  LOW: "#22c55e"
};

const RISK_ICONS: Record<RiskLevel, string> = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MEDIUM: "🟡",
  LOW: "🟢"
};

const AV_ICONS: Record<AttackVector, string> = {
  NETWORK: "🌐",
  LOCAL: "💻",
  ADJACENT: "📡",
  PHYSICAL: "🔌",
  UNKNOWN: "❓"
};

// ======================================================
// CACHE UTILITIES
// ======================================================
const CACHE_KEY = 'ia_dashboard_cache_v1';
const CACHE_DURATION = 3 * 60 * 1000; // 3 minutos

function getCachedData() {
  try {
    const cached = localStorage.getItem(CACHE_KEY);
    if (!cached) return null;
    
    const { data, timestamp } = JSON.parse(cached);
    const age = Date.now() - timestamp;
    
    if (age > CACHE_DURATION) {
      localStorage.removeItem(CACHE_KEY);
      return null;
    }
    
    return data;
  } catch (e) {
    console.error("Error reading cache:", e);
    return null;
  }
}

function setCachedData(data: any) {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify({
      data,
      timestamp: Date.now()
    }));
  } catch (e) {
    console.error("Error setting cache:", e);
  }
}

function clearCache() {
  localStorage.removeItem(CACHE_KEY);
}

// ======================================================
// MAIN COMPONENT
// ======================================================
export default function IADashboard() {
  const [stats, setStats] = useState<IAStats | null>(null);
  const [topRisks, setTopRisks] = useState<CVEPrediction[]>([]);
  const [searchCVE, setSearchCVE] = useState("");
  const [searchResult, setSearchResult] = useState<SinglePrediction | null>(null);
  const [loading, setLoading] = useState(true);
  const [searching, setSearching] = useState(false);
  const [showExplanation, setShowExplanation] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);

  // Load initial data
  useEffect(() => {
    let mounted = true;

    const fetchData = async () => {
      // Try cache first
      const cached = getCachedData();
      if (cached && mounted) {
        console.log("📦 Loading from cache");
        setStats(cached.stats);
        setTopRisks(cached.topRisks);
        setLastUpdate(new Date(cached.timestamp));
        setLoading(false);
        return;
      }

      console.log("🌐 Fetching fresh data...");
      const startTime = Date.now();

      try {
        // Fetch both endpoints
        const [statsRes, topRes] = await Promise.all([
          fetch("/api/v1/ia/stats"),
          fetch("/api/v1/ia/top-risk?limit=20")
        ]);

        if (!mounted) return;

        if (!statsRes.ok || !topRes.ok) {
          throw new Error("Failed to fetch data");
        }

        const statsData = await statsRes.json();
        const topData = await topRes.json();

        const loadTime = Date.now() - startTime;
        console.log(`✅ Data loaded in ${loadTime}ms`);

        const cacheData = {
          stats: statsData,
          topRisks: topData.top_risks || [],
          timestamp: Date.now()
        };

        setStats(statsData);
        setTopRisks(topData.top_risks || []);
        setLastUpdate(new Date());
        setCachedData(cacheData);

      } catch (e) {
        console.error("❌ Error loading data:", e);
        if (mounted) {
          setError("Error al cargar los datos. Por favor, recarga la página.");
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    fetchData();

    return () => {
      mounted = false;
    };
  }, []);

  // Search CVE
  const handleSearch = async () => {
    if (!searchCVE.trim()) return;
    
    setSearching(true);
    setError("");
    
    try {
      const res = await fetch(`/api/v1/ia/predict/${searchCVE.trim()}?explain=${showExplanation}`);
      if (res.ok) {
        const data = await res.json();
        setSearchResult(data);
      } else {
        setSearchResult(null);
        setError("CVE no encontrado");
        setTimeout(() => setError(""), 3000);
      }
    } catch (e) {
      console.error("Error searching CVE:", e);
      setError("Error al buscar CVE");
      setTimeout(() => setError(""), 3000);
    } finally {
      setSearching(false);
    }
  };

  const handleRefresh = () => {
    clearCache();
    setStats(null);
    setTopRisks([]);
    setLoading(true);
    window.location.reload();
  };

  // Charts data - memoized
  const riskChartData = useMemo(() => {
    if (!stats) return [];
    return Object.entries(stats.by_risk_level).map(([level, count]) => ({
      name: level,
      value: count,
      color: RISK_COLORS[level as RiskLevel]
    }));
  }, [stats]);

  const avChartData = useMemo(() => {
    if (!stats) return [];
    return Object.entries(stats.by_attack_vector)
      .sort((a, b) => b[1] - a[1])
      .map(([av, count]) => ({
        name: av,
        count
      }));
  }, [stats]);

  const componentChartData = useMemo(() => {
    if (!stats) return [];
    return Object.entries(stats.critical_by_component)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([comp, count]) => ({
        name: comp,
        count
      }));
  }, [stats]);

  // Loading state
  if (loading) {
    return (
      <div className="global-bg min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-6xl mb-4 animate-bounce">🤖</div>
          <p className="text-xl mb-2">Analizando datos de IA...</p>
          <p className="text-sm text-[var(--muted)]">Esto puede tardar unos segundos</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error && !stats) {
    return (
      <div className="global-bg min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-6xl mb-4">⚠️</div>
          <p className="text-xl mb-4 text-red-400">{error}</p>
          <Button onClick={handleRefresh}>Reintentar</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="global-bg min-h-screen">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8">
        {/* Header */}
        <header className="mb-6">
          <div className="flex justify-between items-start mb-2">
            <div>
              <h1 className="text-2xl font-semibold">🤖 Intelligence Analysis</h1>
              <p className="text-sm text-[var(--muted)]">
                Predicción de explotabilidad con ML - Modelo V2.1
              </p>
            </div>
            <div className="flex gap-2 items-center">
              {lastUpdate && (
                <span className="text-xs text-[var(--muted)]">
                  Última actualización: {lastUpdate.toLocaleTimeString()}
                </span>
              )}
              <Button onClick={handleRefresh} className="text-xs">
                🔄 Actualizar
              </Button>
            </div>
          </div>
        </header>

        {/* KPIs */}
        {stats && (
          <div className="mb-6 grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="transition-all hover:scale-105">
              <CardHeader className="py-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  {RISK_ICONS.CRITICAL} CRITICAL
                </CardTitle>
              </CardHeader>
              <CardContent className="text-3xl font-bold text-red-600">
                {stats.by_risk_level.CRITICAL}
              </CardContent>
            </Card>
            <Card className="transition-all hover:scale-105">
              <CardHeader className="py-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  {RISK_ICONS.HIGH} HIGH
                </CardTitle>
              </CardHeader>
              <CardContent className="text-3xl font-bold text-orange-600">
                {stats.by_risk_level.HIGH}
              </CardContent>
            </Card>
            <Card className="transition-all hover:scale-105">
              <CardHeader className="py-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  {RISK_ICONS.MEDIUM} MEDIUM
                </CardTitle>
              </CardHeader>
              <CardContent className="text-3xl font-bold text-yellow-600">
                {stats.by_risk_level.MEDIUM}
              </CardContent>
            </Card>
            <Card className="transition-all hover:scale-105">
              <CardHeader className="py-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  {RISK_ICONS.LOW} LOW
                </CardTitle>
              </CardHeader>
              <CardContent className="text-3xl font-bold text-green-600">
                {stats.by_risk_level.LOW}
              </CardContent>
            </Card>
          </div>
        )}

        {/* Search CVE */}
        <Card className="mb-6">
          <CardHeader className="py-3">
            <CardTitle>🔍 Analizar CVE específico</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-3 flex-wrap items-center">
              <input
                type="text"
                placeholder="CVE-2024-1234"
                value={searchCVE}
                onChange={(e) => setSearchCVE(e.target.value.toUpperCase())}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                className="flex-1 min-w-[200px] px-3 py-2 border border-[var(--panel-border)] rounded bg-[var(--panel-bg)] text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={showExplanation}
                  onChange={(e) => setShowExplanation(e.target.checked)}
                  className="w-4 h-4"
                />
                <span className="text-sm">Explicación detallada</span>
              </label>
              <Button onClick={handleSearch} disabled={searching} className="btn-solid">
                {searching ? "⏳ Analizando..." : "🔍 Analizar"}
              </Button>
            </div>
            
            {error && (
              <div className="mt-3 p-2 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-sm">
                {error}
              </div>
            )}

            {/* Search Result */}
            {searchResult && (
              <div className="mt-4 p-4 border border-[var(--panel-border)] rounded bg-[var(--panel-bg)] animate-fadeIn">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h3 className="text-lg font-semibold">{searchResult.cve_id}</h3>
                    <p className="text-sm text-[var(--muted)]">{searchResult.metadata.tipo}</p>
                  </div>
                  <div className="text-right">
                    <div className={`text-3xl font-bold mb-1`} style={{ color: RISK_COLORS[searchResult.risk_level] }}>
                      {(searchResult.exploit_probability * 100).toFixed(1)}%
                    </div>
                    <div className="text-sm">
                      {RISK_ICONS[searchResult.risk_level]} {searchResult.risk_level}
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                  <div className="p-2 bg-slate-700/30 rounded">
                    <div className="text-xs text-[var(--muted)] mb-1">CVSS Score</div>
                    <div className="text-xl font-semibold">{searchResult.metadata.cvss_score}</div>
                  </div>
                  <div className="p-2 bg-slate-700/30 rounded">
                    <div className="text-xs text-[var(--muted)] mb-1">Attack Vector</div>
                    <div className="text-lg font-semibold">
                      {AV_ICONS[searchResult.attack_vector]} {searchResult.attack_vector}
                    </div>
                  </div>
                  {searchResult.threshold_info && (
                    <>
                      <div className="p-2 bg-slate-700/30 rounded">
                        <div className="text-xs text-[var(--muted)] mb-1">Threshold</div>
                        <div className="text-xl font-semibold">
                          {(searchResult.threshold_info.final_threshold * 100).toFixed(0)}%
                        </div>
                      </div>
                      <div className="p-2 bg-slate-700/30 rounded">
                        <div className="text-xs text-[var(--muted)] mb-1">Adjustment</div>
                        <div className="text-xl font-semibold">
                          {searchResult.threshold_info.adjustment >= 0 ? '+' : ''}
                          {(searchResult.threshold_info.adjustment * 100).toFixed(0)}%
                        </div>
                      </div>
                    </>
                  )}
                </div>

                {searchResult.metadata.infraestructura_5g && searchResult.metadata.infraestructura_5g.length > 0 && (
                  <div className="mb-3 p-2 bg-blue-500/10 rounded">
                    <div className="text-xs text-[var(--muted)] mb-2">🔷 Infraestructura 5G afectada:</div>
                    <div className="flex gap-2 flex-wrap">
                      {searchResult.metadata.infraestructura_5g.map((comp, i) => (
                        <span key={i} className="px-2 py-1 bg-blue-500/20 text-blue-300 text-xs rounded font-semibold">
                          {comp}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {searchResult.explanation && (
                  <details className="mt-3 cursor-pointer">
                    <summary className="text-sm font-semibold text-blue-400 hover:text-blue-300 p-2 bg-blue-500/10 rounded">
                      📋 Ver explicación detallada del modelo
                    </summary>
                    <pre className="mt-2 p-3 bg-black/40 rounded text-xs overflow-auto max-h-[400px] border border-blue-500/20">
                      {searchResult.explanation}
                    </pre>
                  </details>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Charts Row */}
        <div className="grid md:grid-cols-2 gap-6 mb-6">
          {/* Risk Distribution */}
          <Card>
            <CardHeader className="py-3">
              <CardTitle>📊 Distribución por nivel de riesgo</CardTitle>
            </CardHeader>
            <CardContent style={{ height: 300 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskChartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {riskChartData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <ReTooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Attack Vector Distribution */}
          <Card>
            <CardHeader className="py-3">
              <CardTitle>📊 Distribución por Attack Vector</CardTitle>
            </CardHeader>
            <CardContent style={{ height: 300 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={avChartData}>
                  <CartesianGrid stroke="rgba(148,163,184,.25)" strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <ReTooltip />
                  <Bar dataKey="count" fill="#3b82f6" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>

        {/* Critical by Component */}
        {componentChartData.length > 0 && (
          <Card className="mb-6">
            <CardHeader className="py-3">
              <CardTitle>📊 CVEs críticos por componente 5G</CardTitle>
            </CardHeader>
            <CardContent style={{ height: 300 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={componentChartData} layout="vertical">
                  <CartesianGrid stroke="rgba(148,163,184,.25)" strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis type="category" dataKey="name" width={100} />
                  <ReTooltip />
                  <Bar dataKey="count" fill="#dc2626" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        )}

        {/* Top Risks Table */}
        <Card>
          <CardHeader className="py-3">
            <CardTitle>🚨 Top 20 CVEs más peligrosos</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[var(--muted)] border-b border-[var(--panel-border)]">
                    <th className="py-3 px-3 text-left">#</th>
                    <th className="py-3 px-3 text-left">CVE</th>
                    <th className="py-3 px-3 text-center">Probabilidad</th>
                    <th className="py-3 px-3 text-center">Riesgo</th>
                    <th className="py-3 px-3 text-center">AV</th>
                    <th className="py-3 px-3 text-center">CVSS</th>
                    <th className="py-3 px-3 text-left">Tipo</th>
                    <th className="py-3 px-3 text-left">Infra 5G</th>
                  </tr>
                </thead>
                <tbody>
                  {topRisks.map((cve, idx) => (
                    <tr 
                      key={cve.cve_id} 
                      className="border-b border-[var(--panel-border)] hover:bg-slate-700/30 transition-colors"
                    >
                      <td className="py-3 px-3 font-semibold">{idx + 1}</td>
                      <td className="py-3 px-3 font-mono">
                        <a 
                          href={`/dashboard/${cve.cve_id}`}
                          className="text-blue-400 hover:text-blue-300 hover:underline transition-colors"
                        >
                          {cve.cve_id}
                        </a>
                      </td>
                      <td className="py-3 px-3 text-center font-bold text-lg" style={{ color: RISK_COLORS[cve.risk_level] }}>
                        {(cve.exploit_probability * 100).toFixed(1)}%
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span className="inline-flex items-center gap-1">
                          {RISK_ICONS[cve.risk_level]} <span className="font-semibold">{cve.risk_level}</span>
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center text-xl">
                        {AV_ICONS[cve.attack_vector]}
                      </td>
                      <td className="py-3 px-3 text-center font-bold">
                        {cve.cvss_score.toFixed(1)}
                      </td>
                      <td className="py-3 px-3 text-sm">{cve.tipo}</td>
                      <td className="py-3 px-3">
                        {cve.infraestructura_5g && cve.infraestructura_5g.length > 0 ? (
                          <div className="flex gap-1 flex-wrap">
                            {cve.infraestructura_5g.slice(0, 3).map((comp, i) => (
                              <span key={i} className="px-2 py-0.5 bg-blue-500/20 text-blue-300 text-xs rounded">
                                {comp}
                              </span>
                            ))}
                            {cve.infraestructura_5g.length > 3 && (
                              <span className="text-xs text-[var(--muted)] font-semibold">
                                +{cve.infraestructura_5g.length - 3}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-[var(--muted)]">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .animate-fadeIn {
          animation: fadeIn 0.3s ease-out;
        }
      `}</style>
    </div>
  );
}