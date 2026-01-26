// components/AttackGroupsDashboard.tsx
// Dashboard de grupos de ataque con la nueva arquitectura:
// - cve_suggestions en lugar de cve_info (sugerencias, no correlaciones automáticas)
// - enrichment_status para mostrar si el asset es conocido
// - target_asset para información del asset
// - confirmed_cves para CVEs vinculados manualmente

import React, { useEffect, useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DataTable } from "@/components/ui/data-table";
import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "@/lib/utils";
import { useNavigate } from "react-router-dom";

// ============================================================================
// TYPES - Nueva arquitectura
// ============================================================================
type CVESuggestion = {
  cve_id: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  reason: string;
  cvss_score?: number;
  tipo?: string;
};

type TargetAsset = {
  ip: string;
  hostname?: string;
  component_type?: string;
  component_5g?: string;
  software?: string;
  version?: string;
  known?: boolean;  // Hacer opcional
  tags?: string[];
};

type AttackGroup = {
  _id: string;
  group_id: string;
  src_ip: string;
  dest_ip: string;
  category: string;
  attack_type?: string;
  vuln_type?: string;
  severity: number;
  first_alert: { $date: string } | string;
  last_alert: { $date: string } | string;
  alert_count: number;
  duration_seconds?: number;
  status: "active" | "resolved" | "re-opened";
  pattern: string;
  cve_suggestions?: CVESuggestion[];
  confirmed_cves?: string[];
  target_asset?: TargetAsset;
  enrichment_status?: "enriched" | "partial" | "unknown";
  created_at: { $date: string } | string;
};

type PaginatedResponse = {
  groups: AttackGroup[];
  pagination: {
    page: number;
    per_page: number;
    total: number;
    pages: number;
  };
  stats?: {
    total_groups: number;
    active_count: number;
    total_alerts: number;
    critical_count: number;
    by_pattern: Record<string, number>;
    by_enrichment: Record<string, number>;
  };
};

// ============================================================================
// CONSTANTS
// ============================================================================
const SEVERITY_LABELS: Record<number, string> = {
  1: "Critical",
  2: "High",
  3: "Medium",
  4: "Low",
};

const SEVERITY_COLORS: Record<number, string> = {
  1: "bg-red-600 text-white",
  2: "bg-orange-500 text-white",
  3: "bg-yellow-400 text-black",
  4: "bg-green-500 text-white",
};

const STATUS_COLORS: Record<string, string> = {
  active: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  resolved: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  "re-opened": "bg-rose-500/20 text-rose-300 border-rose-500/40",
};

const PATTERN_ICONS: Record<string, string> = {
  reconnaissance: "🔍",
  exploitation: "💥",
  "post-exploit": "👑",
  persistence: "🔗",
  exfiltration: "📤",
  unknown: "❓",
};

const ENRICHMENT_COLORS: Record<string, string> = {
  enriched: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  partial: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  unknown: "bg-slate-500/20 text-slate-300 border-slate-500/40",
};

const ENRICHMENT_LABELS: Record<string, string> = {
  enriched: "✓ Conocido",
  partial: "⚠ Parcial",
  unknown: "? Desconocido",
};

// ============================================================================
// HELPERS
// ============================================================================
const fmtDate = (dateObj: { $date: string } | string) => {
  const dateStr = typeof dateObj === "string" ? dateObj : dateObj?.$date;
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleString("es-ES");
};

const fmtDateShort = (dateObj: { $date: string } | string) => {
  const dateStr = typeof dateObj === "string" ? dateObj : dateObj?.$date;
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("es-ES");
};

const formatDuration = (seconds: number) => {
  if (!seconds || seconds < 0) return "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
};

const getTimeAgo = (dateObj: { $date: string } | string) => {
  const dateStr = typeof dateObj === "string" ? dateObj : dateObj?.$date;
  if (!dateStr) return "";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `hace ${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `hace ${hours}h`;
  return `hace ${Math.floor(hours / 24)}d`;
};

// ============================================================================
// MAIN COMPONENT
// ============================================================================
export default function AttackGroupsDashboard() {
  const [data, setData] = useState<PaginatedResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Filtros
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(15);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [enrichmentFilter, setEnrichmentFilter] = useState<string>("all");
  const [patternFilter, setPatternFilter] = useState<string>("all");
  const [vulnTypeFilter, setVulnTypeFilter] = useState<string>("all");
  const [srcIpFilter, setSrcIpFilter] = useState("");
  const [destIpFilter, setDestIpFilter] = useState("");

  const navigate = useNavigate();

  // Fetch grupos
  const fetchGroups = async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      params.set("page", String(page));
      params.set("per_page", String(perPage));

      if (statusFilter !== "all") params.set("status", statusFilter);
      if (severityFilter !== "all") params.set("severity", severityFilter);
      if (enrichmentFilter !== "all") params.set("enrichment_status", enrichmentFilter);
      if (patternFilter !== "all") params.set("pattern", patternFilter);
      if (vulnTypeFilter !== "all") params.set("vuln_type", vulnTypeFilter);
      if (srcIpFilter.trim()) params.set("src_ip", srcIpFilter.trim());
      if (destIpFilter.trim()) params.set("dest_ip", destIpFilter.trim());

      const res = await fetch(`/api/v1/alerts/groups?${params.toString()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const json = await res.json();
      setData(json);
    } catch (e: any) {
      setError(e?.message || "Error cargando grupos");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchGroups();
  }, [page, perPage, statusFilter, severityFilter, enrichmentFilter, patternFilter, vulnTypeFilter]);

  // Aplicar filtros de IP
  const applyFilters = () => {
    setPage(1);
    fetchGroups();
  };

  const clearFilters = () => {
    setStatusFilter("all");
    setSeverityFilter("all");
    setEnrichmentFilter("all");
    setPatternFilter("all");
    setVulnTypeFilter("all");
    setSrcIpFilter("");
    setDestIpFilter("");
    setPage(1);
  };

  // Estadísticas
  const stats = data?.stats;
  const groups = data?.groups || [];
  const pagination = data?.pagination;
  const totalPages = pagination?.pages || 1;

  // Derivados locales si no vienen del backend
  const localStats = useMemo(() => {
    const activeCount = groups.filter((g) => g.status === "active").length;
    const totalAlerts = groups.reduce((sum, g) => sum + g.alert_count, 0);
    const criticalCount = groups.filter((g) => g.severity === 1).length;
    const enrichedCount = groups.filter((g) => g.enrichment_status === "enriched").length;
    const unknownCount = groups.filter((g) => g.enrichment_status === "unknown" || !g.enrichment_status).length;
    const withConfirmedCVE = groups.filter((g) => (g.confirmed_cves?.length || 0) > 0).length;
    const withSuggestions = groups.filter((g) => (g.cve_suggestions?.length || 0) > 0).length;

    return {
      total: stats?.total_groups || groups.length,
      activeCount: stats?.active_count || activeCount,
      totalAlerts: stats?.total_alerts || totalAlerts,
      criticalCount: stats?.critical_count || criticalCount,
      enrichedCount,
      unknownCount,
      withConfirmedCVE,
      withSuggestions,
    };
  }, [groups, stats]);

  // Tipos de vulnerabilidad únicos
  const vulnTypes = useMemo(() => {
    const types = new Set<string>();
    groups.forEach((g) => {
      if (g.vuln_type) types.add(g.vuln_type);
      if (g.attack_type) types.add(g.attack_type);
    });
    return Array.from(types).sort();
  }, [groups]);

  // Columnas de tabla
  const columns: ColumnDef<AttackGroup>[] = [
    {
      accessorKey: "severity",
      header: () => <span className="sr-only">Sev</span>,
      size: 8,
      cell: ({ row }) => {
        const sev = row.original.severity;
        return (
          <div
            className={cn(
              "w-1.5 h-full min-h-[48px] rounded-l -ml-3",
              sev === 1 ? "bg-red-500" : sev === 2 ? "bg-orange-500" : sev === 3 ? "bg-yellow-500" : "bg-green-500"
            )}
          />
        );
      },
    },
    {
      accessorKey: "group_id",
      header: "Incidente",
      cell: ({ row }) => {
        const g = row.original;
        const isRecent = (() => {
          const dateStr = typeof g.last_alert === "string" ? g.last_alert : g.last_alert?.$date;
          if (!dateStr) return false;
          return Date.now() - new Date(dateStr).getTime() < 3600000;
        })();

        return (
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-2">
              <span className="text-lg">{PATTERN_ICONS[g.pattern] || "❓"}</span>
              <button
                onClick={() => navigate(`/alerts/groups/${g._id}`)}
                className="font-mono text-sm text-blue-400 hover:text-blue-300 hover:underline transition-colors"
              >
                {g.group_id}
              </button>
              {isRecent && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" title="Actividad reciente" />}
            </div>
            <span className="text-xs text-slate-400">{g.vuln_type || g.attack_type || g.category}</span>
          </div>
        );
      },
    },
    {
      accessorKey: "src_ip",
      header: "Atacante",
      cell: ({ row }) => (
        <code className="text-sm text-rose-400">{row.original.src_ip}</code>
      ),
    },
    {
      accessorKey: "dest_ip",
      header: "Víctima",
      cell: ({ row }) => {
        const g = row.original;
        const asset = g.target_asset;
        const isKnown = g.enrichment_status === "enriched" || asset?.hostname || asset?.component_5g;

        return (
          <div className="flex flex-col gap-0.5">
            <code className="text-sm text-blue-400">{g.dest_ip}</code>
            {isKnown ? (
              <span className="text-xs text-emerald-400">
                {asset?.component_5g || asset?.component_type || asset?.hostname || "Asset conocido"}
              </span>
            ) : (
              <span className="text-xs text-slate-500 italic">Desconocido</span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: "enrichment_status",
      header: "Asset",
      size: 100,
      cell: ({ row }) => {
        const g = row.original;
        const asset = g.target_asset;
        
        // Determinar el estado real basándose en la información disponible
        let status = "unknown";
        if (g.enrichment_status === "enriched" || asset?.hostname || asset?.component_5g) {
          status = "enriched";
        } else if (asset?.ip && !asset?.hostname) {
          status = "partial";
        }
        
        return (
          <span className={cn("px-2 py-0.5 rounded text-xs border", ENRICHMENT_COLORS[status])}>
            {ENRICHMENT_LABELS[status]}
          </span>
        );
      },
    },
    {
      id: "cves",
      header: "CVEs",
      cell: ({ row }) => {
        const g = row.original;
        const confirmed = g.confirmed_cves?.length || 0;
        const suggestions = g.cve_suggestions?.length || 0;

        if (confirmed === 0 && suggestions === 0) {
          return <span className="text-slate-500 text-xs">—</span>;
        }

        return (
          <div className="flex flex-col gap-1">
            {confirmed > 0 && (
              <span className="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                ✓ {confirmed} confirmado{confirmed > 1 ? "s" : ""}
              </span>
            )}
            {suggestions > 0 && (
              <span className="px-2 py-0.5 rounded text-xs bg-amber-500/20 text-amber-300 border border-amber-500/40">
                💡 {suggestions} sugerencia{suggestions > 1 ? "s" : ""}
              </span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: "alert_count",
      header: "Eventos",
      size: 80,
      cell: ({ row }) => (
        <span className="font-semibold text-lg">{row.original.alert_count}</span>
      ),
    },
    {
      accessorKey: "status",
      header: "Estado",
      size: 100,
      cell: ({ row }) => (
        <span className={cn("px-2 py-0.5 rounded text-xs border capitalize", STATUS_COLORS[row.original.status])}>
          {row.original.status}
        </span>
      ),
    },
    {
      accessorKey: "last_alert",
      header: "Última actividad",
      cell: ({ row }) => (
        <div className="flex flex-col gap-0.5 text-right">
          <span className="text-xs">{fmtDateShort(row.original.last_alert)}</span>
          <span className="text-[10px] text-slate-400">{getTimeAgo(row.original.last_alert)}</span>
        </div>
      ),
    },
  ];

  return (
    <div className="global-bg">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8">
        {/* Header */}
        <header className="mb-4">
          <div className="panel px-4 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="text-center md:text-left mx-auto md:mx-0">
              <h1 className="text-2xl font-semibold">🚨 Incidentes de Ataque</h1>
              <p className="text-xs text-[var(--muted)] -mt-1">
                Alertas correlacionadas por origen, destino y tipo de ataque
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button className="btn-ghost" onClick={() => navigate("/alerts")}>
                📡 Alertas individuales
              </Button>
              <Button className="btn-solid" onClick={fetchGroups} disabled={loading}>
                {loading ? "Cargando..." : "🔄 Actualizar"}
              </Button>
            </div>
          </div>
        </header>

        {/* KPIs */}
        <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-8">
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Total</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{localStats.total}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Activos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-amber-400">{localStats.activeCount}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Críticos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-red-500">{localStats.criticalCount}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Alertas</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{localStats.totalAlerts}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Asset ✓</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-emerald-400">{localStats.enrichedCount}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Asset ?</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-slate-400">{localStats.unknownCount}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">CVE ✓</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-emerald-400">{localStats.withConfirmedCVE}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">CVE 💡</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-amber-400">{localStats.withSuggestions}</CardContent>
          </Card>
        </div>

        {/* Filtros */}
        <Card className="mb-6">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Filtros</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-12 gap-3">
            {/* Estado */}
            <div className="md:col-span-2">
              <Label className="text-xs">Estado</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                value={statusFilter}
                onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
              >
                <option value="all">Todos</option>
                <option value="active">🟡 Activos</option>
                <option value="resolved">✅ Resueltos</option>
                <option value="re-opened">🔴 Reabiertos</option>
              </select>
            </div>

            {/* Severidad */}
            <div className="md:col-span-2">
              <Label className="text-xs">Severidad</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                value={severityFilter}
                onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
              >
                <option value="all">Todas</option>
                <option value="1">🔴 Critical</option>
                <option value="2">🟠 High</option>
                <option value="3">🟡 Medium</option>
                <option value="4">🟢 Low</option>
              </select>
            </div>

            {/* Enriquecimiento */}
            <div className="md:col-span-2">
              <Label className="text-xs">Asset</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                value={enrichmentFilter}
                onChange={(e) => { setEnrichmentFilter(e.target.value); setPage(1); }}
              >
                <option value="all">Todos</option>
                <option value="enriched">✅ Conocido</option>
                <option value="partial">⚠️ Parcial</option>
                <option value="unknown">❓ Desconocido</option>
              </select>
            </div>

            {/* Tipo de vulnerabilidad */}
            <div className="md:col-span-2">
              <Label className="text-xs">Tipo Vuln.</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                value={vulnTypeFilter}
                onChange={(e) => { setVulnTypeFilter(e.target.value); setPage(1); }}
              >
                <option value="all">Todos</option>
                {vulnTypes.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>

            {/* IP Origen */}
            <div className="md:col-span-2">
              <Label className="text-xs">IP Atacante</Label>
              <Input
                className="mt-1 text-sm"
                placeholder="172.22.0.55"
                value={srcIpFilter}
                onChange={(e) => setSrcIpFilter(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && applyFilters()}
              />
            </div>

            {/* IP Destino */}
            <div className="md:col-span-2">
              <Label className="text-xs">IP Víctima</Label>
              <Input
                className="mt-1 text-sm"
                placeholder="172.22.0.52"
                value={destIpFilter}
                onChange={(e) => setDestIpFilter(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && applyFilters()}
              />
            </div>

            {/* Acciones */}
            <div className="md:col-span-12 flex justify-end gap-2">
              <Button className="btn-outline" onClick={clearFilters}>
                Limpiar
              </Button>
              <Button className="btn-solid" onClick={applyFilters}>
                🔎 Aplicar
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Error banner */}
        {error && (
          <div className="panel p-3 mb-3 text-sm text-red-300 bg-red-900/20 border border-red-500/30 flex items-center justify-between rounded-lg">
            <span>⚠️ {error}</span>
            <div className="flex gap-2">
              <Button className="btn-outline" onClick={fetchGroups}>Reintentar</Button>
              <Button className="btn-ghost" onClick={() => setError("")}>Cerrar</Button>
            </div>
          </div>
        )}

        {/* Tabla */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center justify-between">
              <span>Incidentes Detectados</span>
              {pagination && (
                <span className="text-sm font-normal text-[var(--muted)]">
                  {pagination.total} total
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading && !groups.length ? (
              <div className="text-center py-8">
                <div className="text-4xl mb-2 animate-pulse">🔄</div>
                <p className="text-[var(--muted)]">Cargando incidentes...</p>
              </div>
            ) : groups.length === 0 ? (
              <div className="text-center py-8">
                <div className="text-4xl mb-2">📭</div>
                <p className="text-[var(--muted)]">No hay incidentes que coincidan con los filtros.</p>
              </div>
            ) : (
              <>
                <DataTable
                  columns={columns}
                  data={groups}
                  onRowClick={(row) => navigate(`/alerts/groups/${row._id}`)}
                />

                {/* Paginador */}
                <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                  <div className="text-sm text-[var(--muted)]">
                    Página <strong>{page}</strong> de <strong>{totalPages}</strong> ·
                    Mostrando <strong>{groups.length}</strong>
                    {pagination && <> de <strong>{pagination.total}</strong></>}
                  </div>
                  <div className="flex items-center gap-2">
                    <Label className="text-sm">Por página</Label>
                    <select
                      className="rounded-md border px-2 py-1 text-sm"
                      value={perPage}
                      onChange={(e) => {
                        setPerPage(Number(e.target.value));
                        setPage(1);
                      }}
                    >
                      <option value={10}>10</option>
                      <option value={15}>15</option>
                      <option value={25}>25</option>
                      <option value={50}>50</option>
                    </select>
                    <Button
                      className="btn-outline px-3 py-1"
                      disabled={page <= 1}
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                    >
                      ← Anterior
                    </Button>
                    <Button
                      className="btn-outline px-3 py-1"
                      disabled={page >= totalPages}
                      onClick={() => setPage((p) => p + 1)}
                    >
                      Siguiente →
                    </Button>
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}