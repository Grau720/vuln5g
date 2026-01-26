import React, { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { DataTable } from "@/components/ui/data-table";
import type { ColumnDef } from "@tanstack/react-table";
import { useNavigate } from "react-router-dom";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from "recharts";


// ============================================================================
// TYPES - Actualizado para nueva arquitectura
// ============================================================================
interface HttpData {
  hostname?: string;
  http_port?: number;
  url?: string;
  http_user_agent?: string;
  http_method?: string;
  protocol?: string;
  status?: number;
  length?: number;
  http_content_type?: string;
}

interface TargetAsset {
  ip: string;
  hostname?: string;
  role?: string;
  component_5g?: string;
  software?: string;
  version?: string;
  criticality?: string;
  owner?: string;
}

interface CVESuggestion {
  cve_id: string;
  nombre?: string;
  cvss_score?: number;
  tipo?: string;
  match_reason: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  requires_validation: boolean;
  warning?: string;
  infraestructura_5g?: string[];
}

interface Alert {
  _id?: string;
  timestamp: string;
  alert: {
    signature: string;
    severity: number;
    category: string;
    signature_id: number;
  };
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  proto: string;
  event_type?: string;
  http?: HttpData;
  
  // Nueva arquitectura
  vuln_type?: string;
  enrichment_status?: 'ASSET_KNOWN' | 'ASSET_UNKNOWN';
  target_asset?: TargetAsset | null;
  source_asset?: {
    ip: string;
    hostname?: string;
    is_internal: boolean;
  };
  cve_suggestions?: CVESuggestion[];
  cve_in_signature?: string;  // CVE mencionado en la firma (referencia, no correlación)
  
  // Campos legacy (para compatibilidad)
  cve_info?: any;
}

interface CVEDetail {
  cve_id: string;
  nombre?: string;
  descripcion_general?: string;
  tipo?: string;
  etiquetas?: string[];
  infraestructura_5g_afectada?: string[];
  dificultad_explotacion?: string;
  impacto_potencial?: { confidencialidad?: string; integridad?: string; disponibilidad?: string };
  recomendaciones_remediacion?: string;
  referencias_mitre?: string[];
  cvssv3?: { score: number; vector?: string };
  fecha_publicacion?: string;
  componente_afectado?: string;
  versiones_afectadas?: string[];
}

interface AlertsSummary {
  by_severity: Record<number, number>;
  by_vuln_type: Record<string, number>;
  by_category: Record<string, number>;
  by_enrichment: Record<string, number>;
}

// ============================================================================
// CONSTANTS
// ============================================================================
const SEVERITY_COLORS: Record<number, string> = {
  1: "bg-red-600 text-white",
  2: "bg-orange-500 text-white",
  3: "bg-yellow-500 text-black",
};

const SEVERITY_LABELS: Record<number, string> = {
  1: "CRÍTICA",
  2: "ALTA",
  3: "MEDIA",
};

const CONFIDENCE_COLORS: Record<string, string> = {
  HIGH: "bg-green-600 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-gray-500 text-white",
};

const ENRICHMENT_COLORS: Record<string, string> = {
  ASSET_KNOWN: "bg-green-600/20 text-green-400 border-green-500/30",
  ASSET_UNKNOWN: "bg-orange-600/20 text-orange-400 border-orange-500/30",
};

const PIE_COLORS = ['#dc2626', '#f97316', '#facc15', '#22c55e'];

// ============================================================================
// HELPERS
// ============================================================================
const getDate = (iso: string): string => {
  try {
    return new Date(iso).toLocaleDateString("es-ES", {
      day: "2-digit", month: "2-digit", year: "numeric"
    });
  } catch { return iso; }
};

const getTime = (iso: string): string => {
  try {
    return new Date(iso).toLocaleTimeString("es-ES", {
      hour: "2-digit", minute: "2-digit", second: "2-digit"
    });
  } catch { return iso; }
};

const dateToComparable = (dateStr: string): number => {
  if (!dateStr) return 0;
  const parts = dateStr.split('/');
  if (parts.length !== 3) return 0;
  return parseInt(`${parts[2]}${parts[1]}${parts[0]}`, 10);
};

const fmtFecha = (iso: string) => {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso?.slice(0, 10) || "";
  return d.toLocaleDateString("es-ES");
};

const cvssSeverity = (s: number) => (s >= 9 ? "crit" : s >= 7 ? "high" : s >= 4 ? "med" : "low");
const formatScore = (s: number | undefined) => (typeof s === "number" ? s.toFixed(1) : "N/A");

const detectMaliciousPatterns = (url: string): { pattern: string; description: string }[] => {
  const patterns = [
    { regex: /\.\.\//g, pattern: "../", description: "Path Traversal" },
    { regex: /\.\.\\/g, pattern: "..\\", description: "Path Traversal (Windows)" },
    { regex: /(\'|\")\s*(OR|AND)\s*(\'|\")/gi, pattern: "OR/AND", description: "SQL Injection" },
    { regex: /union|select|insert|delete|drop|update/gi, pattern: "SQL Keywords", description: "SQL Injection" },
    { regex: /<script|<img|onerror|onload|<svg/gi, pattern: "<script>", description: "XSS" },
    { regex: /;|`|\||&&|\$\(|`/g, pattern: ";/`/|", description: "Command Injection" },
    { regex: /exec|system|passthru|shell_exec|proc_open/gi, pattern: "exec", description: "Code Execution" }
  ];

  const detected: { pattern: string; description: string }[] = [];
  patterns.forEach(p => {
    if (p.regex.test(url)) {
      detected.push({ pattern: p.pattern, description: p.description });
    }
  });
  return detected;
};

// ============================================================================
// CVE DETAIL MODAL
// ============================================================================
function CVEDetailModal({ cveId, onClose }: { cveId: string; onClose: () => void }) {
  const [cve, setCve] = useState<CVEDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchCVE = async () => {
      setLoading(true);
      setError("");
      try {
        const res = await fetch(`/api/v1/cves?q=cve_id:${cveId}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const match = data.cves?.find((c: CVEDetail) => c.cve_id === cveId);
        if (match) setCve(match);
        else setError("CVE no encontrado en la base de datos");
      } catch (e: any) {
        setError(e.message || "Error al cargar CVE");
      } finally {
        setLoading(false);
      }
    };
    fetchCVE();
  }, [cveId]);

  return (
    <div className="fixed inset-0 z-[60]">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="absolute right-0 top-0 h-full w-full max-w-xl panel overflow-y-auto p-4">
        <div className="flex items-start justify-between mb-3">
          <h2 className="text-lg font-semibold">{cveId}</h2>
          <Button className="btn-outline" onClick={onClose}>Cerrar</Button>
        </div>

        {loading && (
          <div className="flex items-center justify-center py-8">
            <div className="text-center">
              <div className="text-3xl mb-2 animate-pulse">🔍</div>
              <p className="text-sm text-[var(--muted)]">Cargando detalles...</p>
            </div>
          </div>
        )}

        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg">
            <p className="text-red-400">{error}</p>
          </div>
        )}

        {cve && !loading && (
          <div className="space-y-4 text-sm">
            {cve.nombre && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Nombre</div>
                <p className="font-medium">{cve.nombre}</p>
              </div>
            )}

            {cve.descripcion_general && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Descripción</div>
                <p className="whitespace-pre-wrap text-sm">{cve.descripcion_general}</p>
              </div>
            )}

            <div className="flex items-center gap-2">
              <span className={`badge badge-${cvssSeverity(cve.cvssv3?.score ?? 0)}`}>
                CVSS: {formatScore(cve.cvssv3?.score)}
              </span>
              {cve.cvssv3?.vector && (
                <span className="chip chip-muted text-xs">{cve.cvssv3.vector}</span>
              )}
            </div>

            {cve.tipo && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Tipo</div>
                <Badge variant="secondary">{cve.tipo}</Badge>
              </div>
            )}

            {cve.componente_afectado && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Componente afectado</div>
                <p>{cve.componente_afectado}</p>
              </div>
            )}

            {Array.isArray(cve.versiones_afectadas) && cve.versiones_afectadas.length > 0 && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Versiones afectadas</div>
                <ul className="list-disc pl-5">
                  {cve.versiones_afectadas.map((v, idx) => <li key={idx}>{v}</li>)}
                </ul>
              </div>
            )}

            {Array.isArray(cve.etiquetas) && cve.etiquetas.length > 0 && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Etiquetas</div>
                <div className="flex flex-wrap gap-2">
                  {cve.etiquetas.map((t) => <span className="chip chip-info" key={t}>{t}</span>)}
                </div>
              </div>
            )}

            {Array.isArray(cve.infraestructura_5g_afectada) && cve.infraestructura_5g_afectada.length > 0 && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Infraestructura 5G afectada</div>
                <div className="flex flex-wrap gap-2">
                  {cve.infraestructura_5g_afectada.map((i) => <span className="chip chip-success" key={i}>{i}</span>)}
                </div>
              </div>
            )}

            {cve.dificultad_explotacion && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Dificultad de explotación</div>
                <p>{cve.dificultad_explotacion}</p>
              </div>
            )}

            {cve.impacto_potencial && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Impacto potencial</div>
                <ul className="list-disc pl-5">
                  <li><strong>Confidencialidad:</strong> {cve.impacto_potencial.confidencialidad || "—"}</li>
                  <li><strong>Integridad:</strong> {cve.impacto_potencial.integridad || "—"}</li>
                  <li><strong>Disponibilidad:</strong> {cve.impacto_potencial.disponibilidad || "—"}</li>
                </ul>
              </div>
            )}

            {cve.fecha_publicacion && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Fecha de publicación</div>
                <p>{fmtFecha(cve.fecha_publicacion)}</p>
              </div>
            )}

            {cve.recomendaciones_remediacion && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Recomendaciones de remediación</div>
                <p className="whitespace-pre-wrap">{cve.recomendaciones_remediacion}</p>
              </div>
            )}

            {cve.referencias_mitre && cve.referencias_mitre.length > 0 && (
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Referencias</div>
                <ul className="list-disc pl-5">
                  {cve.referencias_mitre.slice(0, 5).map((r) => (
                    <li key={r}>
                      <a href={r} target="_blank" rel="noreferrer" className="text-blue-400 hover:text-blue-300 underline text-xs break-all">
                        {r}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="flex gap-2 pt-2 border-t border-[var(--panel-border)]">
              <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noopener noreferrer"
                className="text-blue-400 hover:text-blue-300 underline text-xs">Ver en NVD →</a>
              <a href={`/dashboard/${cveId}`} className="text-blue-400 hover:text-blue-300 underline text-xs">
                Ver en Dashboard →</a>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================
export default function AlertasDashboard() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [summary, setSummary] = useState<AlertsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<number | null>(null);
  const [enrichmentFilter, setEnrichmentFilter] = useState<string>("all");
  const [vulnTypeFilter, setVulnTypeFilter] = useState<string>("all");
  const [dateFromFilter, setDateFromFilter] = useState("");
  const [dateToFilter, setDateToFilter] = useState("");
  const [timeRange, setTimeRange] = useState("24");
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [selectedCVE, setSelectedCVE] = useState<string | null>(null);
  const [whitelistedCount, setWhitelistedCount] = useState(0);
  
  // Paginación
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(10);
  
  const navigate = useNavigate();

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(true), 30000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const loadData = async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);

    try {
      const params = new URLSearchParams();
      params.set('limit', '500');
      if (selectedSeverity !== null) params.set('severity', String(selectedSeverity));
      if (enrichmentFilter !== 'all') params.set('enrichment_status', enrichmentFilter);
      if (vulnTypeFilter !== 'all') params.set('vuln_type', vulnTypeFilter);

      const alertsRes = await fetch(`/api/v1/alerts/?${params.toString()}`);

      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        setAlerts(alertsData.alerts || []);
        setSummary(alertsData.summary || null);
        setWhitelistedCount(alertsData.whitelisted_count || 0);
      }
    } catch (error) {
      console.error("Error loading alerts:", error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  // Filtrar alertas
  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      if (searchTerm) {
        const searchLower = searchTerm.toLowerCase();
        const matches = (
          alert.alert.signature.toLowerCase().includes(searchLower) ||
          alert.src_ip.includes(searchLower) ||
          alert.dest_ip.includes(searchLower) ||
          alert.vuln_type?.toLowerCase().includes(searchLower) ||
          alert.alert.category.toLowerCase().includes(searchLower) ||
          alert.http?.url?.toLowerCase().includes(searchLower) ||
          alert.target_asset?.hostname?.toLowerCase().includes(searchLower) ||
          alert.cve_suggestions?.some(s => s.cve_id.toLowerCase().includes(searchLower))
        );
        if (!matches) return false;
      }

      if (dateFromFilter || dateToFilter) {
        const alertDate = getDate(alert.timestamp);
        const alertDateNum = dateToComparable(alertDate);
        
        if (dateFromFilter) {
          const fromDate = dateFromFilter.split('-').reverse().join('/');
          const fromDateNum = dateToComparable(fromDate);
          if (alertDateNum < fromDateNum) return false;
        }
        
        if (dateToFilter) {
          const toDate = dateToFilter.split('-').reverse().join('/');
          const toDateNum = dateToComparable(toDate);
          if (alertDateNum > toDateNum) return false;
        }
      }

      return true;
    });
  }, [alerts, searchTerm, dateFromFilter, dateToFilter]);

  // Paginación
  const maxPages = Math.max(1, Math.ceil(filteredAlerts.length / perPage));
  const paginatedAlerts = useMemo(() => {
    return filteredAlerts.slice((page - 1) * perPage, page * perPage);
  }, [filteredAlerts, page, perPage]);

  useEffect(() => { setPage(1); }, [searchTerm, dateFromFilter, dateToFilter, selectedSeverity]);

  // Obtener tipos de vulnerabilidad únicos
  const vulnTypes = useMemo(() => {
    const types = new Set<string>();
    alerts.forEach(a => { if (a.vuln_type) types.add(a.vuln_type); });
    return Array.from(types).sort();
  }, [alerts]);

  // COLUMNAS - Actualizadas para nueva arquitectura
  const columns: ColumnDef<Alert>[] = [
    {
      accessorKey: "alert.severity",
      header: "Sev.",
      size: 80,
      cell: ({ row }) => (
        <Badge className={SEVERITY_COLORS[row.original.alert.severity]}>
          {SEVERITY_LABELS[row.original.alert.severity]}
        </Badge>
      )
    },
    {
      id: "vuln_type",
      header: "Tipo Vuln.",
      cell: ({ row }) => (
        <span className="text-sm font-medium">
          {row.original.vuln_type || "—"}
        </span>
      )
    },
    {
      id: "enrichment",
      header: "Asset",
      size: 100,
      cell: ({ row }) => {
        const status = row.original.enrichment_status;
        const asset = row.original.target_asset;
        
        if (status === 'ASSET_KNOWN' && asset) {
          return (
            <div className="flex flex-col">
              <span className="text-xs text-green-400 font-medium">{asset.hostname || asset.ip}</span>
              {asset.component_5g && (
                <span className="text-[10px] text-blue-400">{asset.component_5g}</span>
              )}
            </div>
          );
        }
        return (
          <span className="text-xs text-orange-400">⚠️ Desconocido</span>
        );
      }
    },
    {
      id: "cve_suggestions",
      header: "CVEs Sugeridos",
      cell: ({ row }) => {
        const suggestions = row.original.cve_suggestions || [];
        if (suggestions.length === 0) {
          return <span className="text-gray-500 text-xs">—</span>;
        }
        
        const topSuggestion = suggestions[0];
        return (
          <div className="flex items-center gap-1">
            <button
              onClick={(e) => {
                e.stopPropagation();
                setSelectedCVE(topSuggestion.cve_id);
              }}
              className="text-blue-400 underline text-xs font-mono hover:text-blue-300"
            >
              {topSuggestion.cve_id}
            </button>
            <span className={cn(
              "px-1 py-0.5 rounded text-[10px] font-semibold",
              CONFIDENCE_COLORS[topSuggestion.confidence]
            )}>
              {topSuggestion.confidence}
            </span>
            {suggestions.length > 1 && (
              <span className="text-[10px] text-gray-400">+{suggestions.length - 1}</span>
            )}
          </div>
        );
      }
    },
    {
      accessorKey: "src_ip",
      header: "Origen",
      cell: ({ row }) => (
        <code className="text-xs bg-gray-700/30 px-2 py-1 rounded-lg">
          {row.original.src_ip}
        </code>
      )
    },
    {
      accessorKey: "dest_ip",
      header: "Destino",
      cell: ({ row }) => (
        <code className="text-xs bg-gray-700/30 px-2 py-1 rounded-lg">
          {row.original.dest_ip}:{row.original.dest_port}
        </code>
      )
    },
    {
      id: "timestamp",
      header: "Fecha/Hora",
      cell: ({ row }) => (
        <span className="text-xs">
          {getDate(row.original.timestamp)} {getTime(row.original.timestamp)}
        </span>
      )
    }
  ];

  // KPIs
  const kpis = useMemo(() => {
    const total = filteredAlerts.length;
    const criticas = filteredAlerts.filter(a => a.alert.severity === 1).length;
    const assetKnown = filteredAlerts.filter(a => a.enrichment_status === 'ASSET_KNOWN').length;
    const assetUnknown = filteredAlerts.filter(a => a.enrichment_status === 'ASSET_UNKNOWN').length;
    const withSuggestions = filteredAlerts.filter(a => (a.cve_suggestions?.length || 0) > 0).length;
    const uniqueIps = new Set(filteredAlerts.map(a => a.src_ip)).size;

    return { total, criticas, assetKnown, assetUnknown, withSuggestions, uniqueIps };
  }, [filteredAlerts]);

  // Datos para gráficos
  const chartsData = useMemo(() => {
    // Timeline por día
    const timelineMap = new Map<string, number>();
    filteredAlerts.forEach(a => {
      const day = getDate(a.timestamp);
      timelineMap.set(day, (timelineMap.get(day) || 0) + 1);
    });
    const timeline = Array.from(timelineMap.entries()).map(([date, total]) => ({ date, total }));

    // Por severidad
    const bySeverity = [
      { name: "Crítica", value: filteredAlerts.filter(a => a.alert.severity === 1).length },
      { name: "Alta", value: filteredAlerts.filter(a => a.alert.severity === 2).length },
      { name: "Media", value: filteredAlerts.filter(a => a.alert.severity === 3).length },
    ];

    // Por tipo de vulnerabilidad
    const vulnMap = new Map<string, number>();
    filteredAlerts.forEach(a => {
      const type = a.vuln_type || 'Unknown';
      vulnMap.set(type, (vulnMap.get(type) || 0) + 1);
    });
    const byVulnType = Array.from(vulnMap.entries())
      .map(([type, total]) => ({ type, total }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 10);

    // Por estado de enriquecimiento
    const byEnrichment = [
      { name: "Asset Conocido", value: filteredAlerts.filter(a => a.enrichment_status === 'ASSET_KNOWN').length },
      { name: "Asset Desconocido", value: filteredAlerts.filter(a => a.enrichment_status === 'ASSET_UNKNOWN').length },
    ];

    return { timeline, bySeverity, byVulnType, byEnrichment };
  }, [filteredAlerts]);

  if (loading) {
    return (
      <div className="global-bg flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="text-4xl mb-4 animate-pulse">🚨</div>
          <p className="text-lg">Cargando alertas de seguridad...</p>
          <p className="text-sm text-[var(--muted)] mt-2">Conectándose a Suricata...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="global-bg">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8">
        {/* HEADER */}
        <header className="mb-6">
          <div className="panel rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="text-center md:text-left mx-auto md:mx-0">
              <h1 className="text-2xl font-semibold">📡 Eventos de Seguridad</h1>
              <p className="text-xs text-[var(--muted)] -mt-1">
                Alertas IDS con enriquecimiento de Asset Inventory
              </p>
            </div>

            <div className="flex items-center gap-2 flex-wrap justify-center md:justify-end">
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="rounded-lg border border-[var(--panel-border)] px-3 py-2 text-sm"
              >
                <option value="1">Última hora</option>
                <option value="6">Últimas 6 horas</option>
                <option value="24">Últimas 24 horas</option>
                <option value="168">Última semana</option>
              </select>

              <Button className="btn-ghost" onClick={() => loadData()} disabled={refreshing}>
                {refreshing ? "Actualizando..." : "🔄 Actualizar"}
              </Button>
            </div>
          </div>
        </header>

        {/* Whitelisted banner */}
        {whitelistedCount > 0 && (
          <div className="mb-4 panel p-3 bg-slate-800/40 border border-slate-700 rounded-lg flex items-center justify-between">
            <span className="text-sm text-slate-400">
              🔇 <strong>{whitelistedCount}</strong> alertas filtradas por whitelist (conexiones esperadas)
            </span>
            <a href="/assets" className="text-xs text-blue-400 hover:underline">
              Gestionar whitelist →
            </a>
          </div>
        )}

        {/* KPIs */}
        <div className="mb-6 grid grid-cols-2 md:grid-cols-6 gap-4">
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Total eventos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{kpis.total}</CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Críticos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-red-500">{kpis.criticas}</CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Asset Conocido</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-green-400">{kpis.assetKnown}</CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Asset Desconocido</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-orange-400">{kpis.assetUnknown}</CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Con CVE sugerido</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-blue-400">{kpis.withSuggestions}</CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">IPs únicas</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{kpis.uniqueIps}</CardContent>
          </Card>
        </div>

        {/* FILTROS */}
        <Card className="mb-6 rounded-lg">
          <CardHeader className="py-3">
            <CardTitle className="text-base">Filtros</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input
              placeholder="Buscar por CVE, IP, firma, URL, hostname..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="rounded-lg"
            />

            <div className="flex flex-wrap gap-3 items-end">
              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">Desde</label>
                <Input type="date" value={dateFromFilter} onChange={(e) => setDateFromFilter(e.target.value)} className="rounded-lg" />
              </div>

              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">Hasta</label>
                <Input type="date" value={dateToFilter} onChange={(e) => setDateToFilter(e.target.value)} className="rounded-lg" />
              </div>

              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">Tipo Vuln.</label>
                <select
                  value={vulnTypeFilter}
                  onChange={(e) => { setVulnTypeFilter(e.target.value); loadData(); }}
                  className="rounded-lg border border-[var(--panel-border)] px-3 py-2 text-sm"
                >
                  <option value="all">Todos</option>
                  {vulnTypes.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>

              <div>
                <label className="text-xs text-[var(--muted)] block mb-1">Asset</label>
                <select
                  value={enrichmentFilter}
                  onChange={(e) => { setEnrichmentFilter(e.target.value); loadData(); }}
                  className="rounded-lg border border-[var(--panel-border)] px-3 py-2 text-sm"
                >
                  <option value="all">Todos</option>
                  <option value="ASSET_KNOWN">✅ Conocido</option>
                  <option value="ASSET_UNKNOWN">⚠️ Desconocido</option>
                </select>
              </div>

              <div className="flex gap-2 flex-wrap">
                <Button size="sm" variant={selectedSeverity === null ? "default" : "outline"}
                  onClick={() => setSelectedSeverity(null)} className="rounded-lg">Todas</Button>
                <Button size="sm" variant={selectedSeverity === 1 ? "default" : "outline"}
                  onClick={() => setSelectedSeverity(1)} className="rounded-lg">🔴 Críticas</Button>
                <Button size="sm" variant={selectedSeverity === 2 ? "default" : "outline"}
                  onClick={() => setSelectedSeverity(2)} className="rounded-lg">🟠 Altas</Button>
                <Button size="sm" variant={selectedSeverity === 3 ? "default" : "outline"}
                  onClick={() => setSelectedSeverity(3)} className="rounded-lg">🟡 Medias</Button>
              </div>

              <Button size="sm" variant="outline" className="rounded-lg ml-auto"
                onClick={() => { setSearchTerm(""); setDateFromFilter(""); setDateToFilter(""); setSelectedSeverity(null); setEnrichmentFilter("all"); setVulnTypeFilter("all"); }}>
                Limpiar
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* TABLA */}
        <Card className="rounded-lg mb-6">
          <CardHeader className="py-3">
            <CardTitle className="text-base">
              Eventos ({filteredAlerts.length} registros)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <DataTable
                columns={columns}
                data={paginatedAlerts}
                onRowClick={(row) => { setSelectedAlert(row); setDetailOpen(true); }}
              />
            </div>

            {/* Paginación */}
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <div className="text-sm text-[var(--muted)]">
                Página <strong>{page}</strong> · Mostrando <strong>{paginatedAlerts.length}</strong> de <strong>{filteredAlerts.length}</strong>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-sm">Por página</label>
                <select value={perPage} onChange={(e) => { setPerPage(Number(e.target.value)); setPage(1); }}
                  className="rounded-lg border border-[var(--panel-border)] px-2 py-2 text-sm">
                  <option value={5}>5</option>
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                </select>
                <Button className="btn-outline" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))} size="sm">Anterior</Button>
                <Button className="btn-outline" disabled={page >= maxPages} onClick={() => setPage(p => Math.min(maxPages, p + 1))} size="sm">Siguiente</Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Gráficos */}
        <Card className="mb-6">
          <CardHeader className="py-3">
            <CardTitle className="text-base">Análisis visual</CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="timeline">
              <TabsList className="mb-4">
                <TabsTrigger value="timeline">📈 Timeline</TabsTrigger>
                <TabsTrigger value="vulntype">🔓 Por Tipo</TabsTrigger>
                <TabsTrigger value="enrichment">📦 Por Asset</TabsTrigger>
              </TabsList>

              <TabsContent value="timeline">
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={chartsData.timeline}>
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip />
                    <Area dataKey="total" stroke="#38bdf8" fill="#38bdf880" />
                  </AreaChart>
                </ResponsiveContainer>
              </TabsContent>

              <TabsContent value="vulntype">
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={chartsData.byVulnType}>
                    <XAxis dataKey="type" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="total" fill="#60a5fa" />
                  </BarChart>
                </ResponsiveContainer>
              </TabsContent>

              <TabsContent value="enrichment">
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie data={chartsData.byEnrichment} dataKey="value" nameKey="name" outerRadius={100} label>
                      {chartsData.byEnrichment.map((_, idx) => (
                        <Cell key={idx} fill={idx === 0 ? '#22c55e' : '#f97316'} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {/* PANEL DETALLE */}
        {detailOpen && selectedAlert && (
          <div className="fixed inset-0 z-50">
            <div className="absolute inset-0 bg-black/40" onClick={() => setDetailOpen(false)} />
            <div className="absolute right-0 top-0 h-full w-full max-w-4xl panel overflow-y-auto p-4 rounded-l-lg">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold">Detalles del Evento</h2>
                <Button variant="outline" onClick={() => setDetailOpen(false)} className="rounded-lg">✕ Cerrar</Button>
              </div>

              <div className="space-y-4 text-sm">
                {/* Encabezado con badges */}
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge className={SEVERITY_COLORS[selectedAlert.alert.severity]}>
                    {SEVERITY_LABELS[selectedAlert.alert.severity]}
                  </Badge>
                  {selectedAlert.vuln_type && (
                    <Badge variant="secondary">{selectedAlert.vuln_type}</Badge>
                  )}
                  {selectedAlert.enrichment_status && (
                    <span className={cn("px-2 py-1 rounded text-xs border", ENRICHMENT_COLORS[selectedAlert.enrichment_status])}>
                      {selectedAlert.enrichment_status === 'ASSET_KNOWN' ? '✅ Asset Conocido' : '⚠️ Asset Desconocido'}
                    </span>
                  )}
                </div>

                {/* Firma */}
                <div>
                  <p className="text-[var(--muted)] text-xs mb-1">Firma de Alerta</p>
                  <p className="font-semibold text-sm break-words">{selectedAlert.alert.signature}</p>
                </div>

                {/* Target Asset - NUEVO */}
                {selectedAlert.target_asset ? (
                  <div className="panel p-3 bg-green-900/20 border border-green-500/30 rounded-lg">
                    <p className="text-green-400 text-xs font-bold mb-2">✅ Asset Objetivo (Conocido)</p>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div><strong>IP:</strong> {selectedAlert.target_asset.ip}</div>
                      <div><strong>Hostname:</strong> {selectedAlert.target_asset.hostname || '—'}</div>
                      <div><strong>Rol:</strong> {selectedAlert.target_asset.role || '—'}</div>
                      <div><strong>Componente 5G:</strong> {selectedAlert.target_asset.component_5g || '—'}</div>
                      <div><strong>Software:</strong> {selectedAlert.target_asset.software || '—'}</div>
                      <div><strong>Versión:</strong> {selectedAlert.target_asset.version || '—'}</div>
                      <div><strong>Criticidad:</strong> {selectedAlert.target_asset.criticality || '—'}</div>
                      <div><strong>Owner:</strong> {selectedAlert.target_asset.owner || '—'}</div>
                    </div>
                  </div>
                ) : (
                  <div className="panel p-3 bg-orange-900/20 border border-orange-500/30 rounded-lg">
                    <p className="text-orange-400 text-xs font-bold mb-2">⚠️ Asset Objetivo Desconocido</p>
                    <p className="text-xs text-orange-300">
                      El destino <code className="bg-orange-950 px-1 rounded">{selectedAlert.dest_ip}</code> no está registrado en el Asset Inventory.
                      Las sugerencias de CVE tienen menor fiabilidad.
                    </p>
                    <Button size="sm" variant="outline" className="mt-2 text-xs"
                      onClick={() => navigate(`/assets?register=${selectedAlert.dest_ip}`)}>
                      Registrar Asset
                    </Button>
                  </div>
                )}

                {/* Redes */}
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="text-[var(--muted)] text-xs mb-1">Origen (Atacante)</p>
                    <code className="bg-gray-700/30 px-2 py-1 rounded-lg block">
                      {selectedAlert.src_ip}:{selectedAlert.src_port}
                    </code>
                    {selectedAlert.source_asset?.is_internal && (
                      <span className="text-[10px] text-yellow-400">⚠️ Interno: {selectedAlert.source_asset.hostname}</span>
                    )}
                  </div>
                  <div>
                    <p className="text-[var(--muted)] text-xs mb-1">Destino (Víctima)</p>
                    <code className="bg-gray-700/30 px-2 py-1 rounded-lg block">
                      {selectedAlert.dest_ip}:{selectedAlert.dest_port}
                    </code>
                  </div>
                </div>

                {/* Timestamp y categoría */}
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <p className="text-[var(--muted)] text-xs mb-1">Fecha</p>
                    <p>{getDate(selectedAlert.timestamp)}</p>
                  </div>
                  <div>
                    <p className="text-[var(--muted)] text-xs mb-1">Hora</p>
                    <p>{getTime(selectedAlert.timestamp)}</p>
                  </div>
                  <div>
                    <p className="text-[var(--muted)] text-xs mb-1">Categoría</p>
                    <p className="font-mono">{selectedAlert.alert.category}</p>
                  </div>
                </div>

                {/* CVE SUGGESTIONS - NUEVO */}
                {selectedAlert.cve_suggestions && selectedAlert.cve_suggestions.length > 0 && (
                  <div className="panel p-3 bg-blue-900/20 border border-blue-500/30 rounded-lg">
                    <p className="text-blue-400 text-xs font-bold mb-2">
                      🔍 CVEs Potencialmente Aplicables ({selectedAlert.cve_suggestions.length})
                    </p>
                    <p className="text-[10px] text-blue-300 mb-3">
                      ⚠️ Estas son SUGERENCIAS basadas en el tipo de ataque{selectedAlert.target_asset ? ' y el asset conocido' : ''}.
                      Requieren validación manual.
                    </p>
                    <div className="space-y-2">
                      {selectedAlert.cve_suggestions.map((sug) => (
                        <div key={sug.cve_id} className="flex items-center justify-between bg-slate-800/40 p-2 rounded">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => setSelectedCVE(sug.cve_id)}
                              className="font-mono text-blue-400 hover:text-blue-300 underline text-sm"
                            >
                              {sug.cve_id}
                            </button>
                            {sug.cvss_score && (
                              <span className={`badge badge-${cvssSeverity(sug.cvss_score)} text-xs`}>
                                {sug.cvss_score.toFixed(1)}
                              </span>
                            )}
                            <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-semibold", CONFIDENCE_COLORS[sug.confidence])}>
                              {sug.confidence}
                            </span>
                          </div>
                          <span className="text-[10px] text-slate-400 max-w-xs truncate" title={sug.match_reason}>
                            {sug.match_reason}
                          </span>
                        </div>
                      ))}
                    </div>
                    {selectedAlert.cve_suggestions.some(s => s.warning) && (
                      <div className="mt-2 p-2 bg-orange-900/20 border border-orange-500/20 rounded text-[10px] text-orange-300">
                        ⚠️ {selectedAlert.cve_suggestions.find(s => s.warning)?.warning}
                      </div>
                    )}
                  </div>
                )}

                {/* HTTP Data */}
                {selectedAlert.http && (
                  <div className="mt-4 pt-4 border-t border-[var(--panel-border)]">
                    <p className="text-[var(--muted)] text-xs mb-3 font-semibold">📡 Petición HTTP</p>

                    <div className="bg-gray-900/40 p-3 rounded-lg border border-[var(--panel-border)] font-mono text-xs mb-3 overflow-x-auto">
                      <div className="flex gap-2 text-blue-400">
                        <span className="font-bold">{selectedAlert.http.http_method || "GET"}</span>
                        <span className="text-yellow-400 break-all">{selectedAlert.http.url || "/"}</span>
                        <span className="text-green-400">{selectedAlert.http.protocol || "HTTP/1.1"}</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3 mb-3">
                      {selectedAlert.http.hostname && (
                        <div>
                          <p className="text-[var(--muted)] text-xs mb-1">Host</p>
                          <code className="bg-gray-700/30 px-2 py-1 rounded-lg block text-xs">
                            {selectedAlert.http.hostname}:{selectedAlert.http.http_port || 80}
                          </code>
                        </div>
                      )}
                      {selectedAlert.http.status !== undefined && (
                        <div>
                          <p className="text-[var(--muted)] text-xs mb-1">Status Code</p>
                          <span className={`px-2 py-1 rounded-lg font-bold ${selectedAlert.http.status >= 400 ? 'text-red-400' : 'text-green-400'}`}>
                            {selectedAlert.http.status}
                          </span>
                        </div>
                      )}
                    </div>

                    {selectedAlert.http.http_user_agent && (
                      <div className="mb-3">
                        <p className="text-[var(--muted)] text-xs mb-1">User-Agent</p>
                        <code className="bg-gray-700/30 px-2 py-1 rounded-lg block text-xs break-all">
                          {selectedAlert.http.http_user_agent}
                        </code>
                      </div>
                    )}

                    {selectedAlert.http.url && detectMaliciousPatterns(selectedAlert.http.url).length > 0 && (
                      <div className="bg-red-900/20 border border-red-500/30 p-3 rounded-lg mb-3">
                        <p className="text-red-400 text-xs font-bold mb-2">⚠️ Patrones Maliciosos Detectados:</p>
                        <div className="space-y-1">
                          {detectMaliciousPatterns(selectedAlert.http.url).map((p, i) => (
                            <div key={i} className="text-xs text-red-300">
                              • <span className="font-mono bg-red-950/40 px-1 rounded">{p.pattern}</span> - {p.description}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* MODAL DE CVE */}
        {selectedCVE && (
          <CVEDetailModal cveId={selectedCVE} onClose={() => setSelectedCVE(null)} />
        )}
      </div>
    </div>
  );
}