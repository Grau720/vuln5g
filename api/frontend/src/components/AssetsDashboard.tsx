// components/AssetsDashboard.tsx
// Dashboard de Asset Inventory con soporte para infraestructura 5G
// Integrado con la nueva arquitectura de alertas (enrichment_status, cve_suggestions)

import React, { useEffect, useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { ColumnDef } from "@tanstack/react-table";
import { useNavigate, useSearchParams } from "react-router-dom";
import { cn } from "@/lib/utils";

import AssetRegisterModal from "./AssetRegisterModal";

// ============================================================================
// TYPES
// ============================================================================
type Asset = {
  _id: string;
  ip: string;
  hostname: string;
  role: string;
  owner?: string;
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  // Campos 5G específicos
  component_5g?: string;
  component_type?: string;
  software?: string;
  version?: string;
  // Servicios y metadatos
  services?: { name: string; port: number; protocol?: string }[];
  tags?: string[];
  created_at?: string;
  updated_at?: string;
};

type AttackGroup = {
  _id: string;
  dest_ip: string;
  alert_count: number;
  severity: number;
  status: string;
  vuln_type?: string;
  confirmed_cves?: string[];
  cve_suggestions?: { cve_id: string; confidence: string }[];
};

type AssetRow = Asset & {
  alerts_24h: number;
  active_incidents: number;
  confirmed_cves: number;
  pending_suggestions: number;
  status: "NORMAL" | "NOISE" | "SUSPICIOUS" | "UNDER_ATTACK";
};

type UnknownAssetRow = {
  ip: string;
  alerts: number;
  incidents: number;
  max_severity: number;
  vuln_types: string[];
  pending_suggestions: number;
};

// ============================================================================
// CONSTANTS
// ============================================================================
const STATUS_COLORS: Record<string, string> = {
  NORMAL: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  NOISE: "bg-slate-500/20 text-slate-300 border-slate-500/40",
  SUSPICIOUS: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  UNDER_ATTACK: "bg-red-500/20 text-red-300 border-red-500/40",
};

const STATUS_LABELS: Record<string, string> = {
  NORMAL: "✅ Normal",
  NOISE: "📊 Ruido",
  SUSPICIOUS: "⚠️ Sospechoso",
  UNDER_ATTACK: "🔴 Bajo ataque",
};

const CRITICALITY_COLORS: Record<string, string> = {
  LOW: "bg-slate-500/20 text-slate-300 border-slate-500/40",
  MEDIUM: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  CRITICAL: "bg-red-500/20 text-red-300 border-red-500/40",
};

const SEVERITY_COLORS: Record<number, string> = {
  1: "text-red-400",
  2: "text-orange-400",
  3: "text-yellow-400",
  4: "text-emerald-400",
};

const COMPONENT_5G_OPTIONS = [
  "AMF", "SMF", "UPF", "AUSF", "UDM", "UDR", "PCF", "NRF", "NSSF", "NEF", "SMSF",
  "gNB", "CU", "DU", "RU", "RIC", "O-RAN Controller",
  "HSS", "MME", "SGW", "PGW",  // Legacy 4G
  "SCP", "SEPP", "BSF",  // Service-based
  "DNS", "NTP", "Logging", "Monitoring",  // Support
  "Other"
];

// ============================================================================
// MAIN COMPONENT
// ============================================================================
export default function AssetsDashboard() {
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [unknownAssets, setUnknownAssets] = useState<UnknownAssetRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Filtros
  const [searchFilter, setSearchFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [criticalityFilter, setCriticalityFilter] = useState<string>("all");
  const [component5gFilter, setComponent5gFilter] = useState<string>("all");

  // Modal de registro
  const [registerModal, setRegisterModal] = useState<{
    ip: string;
    maxSeverity: number;
    vuln_types?: string[];
  } | null>(null);

  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Abrir modal si viene de ?register=IP
  useEffect(() => {
    const registerIp = searchParams.get("register");
    if (registerIp) {
      setRegisterModal({ ip: registerIp, maxSeverity: 3 });
    }
  }, [searchParams]);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [assetsRes, groupsRes] = await Promise.all([
        fetch("/api/v1/assets/list"),
        fetch("/api/v1/alerts/groups?per_page=1000"),
      ]);

      if (!assetsRes.ok) throw new Error("Error cargando assets");
      if (!groupsRes.ok) throw new Error("Error cargando grupos");

      const assetsJson = await assetsRes.json();
      const groupsJson = await groupsRes.json();

      const groups: AttackGroup[] = groupsJson.groups || [];
      const knownIps = new Set((assetsJson.assets || []).map((a: Asset) => a.ip));

      // =====================
      // Known assets - enriquecer con datos de incidentes
      // =====================
      const enriched: AssetRow[] = (assetsJson.assets || []).map((a: Asset) => {
        const related = groups.filter((g) => g.dest_ip === a.ip);
        const alerts = related.reduce((sum, g) => sum + g.alert_count, 0);
        const confirmedCves = related.reduce((sum, g) => sum + (g.confirmed_cves?.length || 0), 0);
        const pendingSuggestions = related.reduce((sum, g) => sum + (g.cve_suggestions?.length || 0), 0);

        let status: AssetRow["status"] = "NORMAL";
        if (related.some((g) => g.status === "active")) status = "UNDER_ATTACK";
        else if (alerts > 20) status = "SUSPICIOUS";
        else if (alerts > 0) status = "NOISE";

        return {
          ...a,
          alerts_24h: alerts,
          active_incidents: related.filter((g) => g.status === "active").length,
          confirmed_cves: confirmedCves,
          pending_suggestions: pendingSuggestions,
          status,
        };
      });

      // =====================
      // Unknown assets - detectados por actividad de red
      // =====================
      const unknownMap: Record<string, UnknownAssetRow> = {};

      groups.forEach((g) => {
        if (!knownIps.has(g.dest_ip)) {
          if (!unknownMap[g.dest_ip]) {
            unknownMap[g.dest_ip] = {
              ip: g.dest_ip,
              alerts: 0,
              incidents: 0,
              max_severity: g.severity,
              vuln_types: [],
              pending_suggestions: 0,
            };
          }
          unknownMap[g.dest_ip].alerts += g.alert_count;
          unknownMap[g.dest_ip].incidents += 1;
          unknownMap[g.dest_ip].max_severity = Math.min(
            unknownMap[g.dest_ip].max_severity,
            g.severity
          );
          if (g.vuln_type && !unknownMap[g.dest_ip].vuln_types.includes(g.vuln_type)) {
            unknownMap[g.dest_ip].vuln_types.push(g.vuln_type);
          }
          unknownMap[g.dest_ip].pending_suggestions += g.cve_suggestions?.length || 0;
        }
      });

      setAssets(enriched);
      setUnknownAssets(
        Object.values(unknownMap).sort((a, b) => a.max_severity - b.max_severity)
      );
    } catch (e: any) {
      setError(e?.message || "Error cargando datos");
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  // Filtrar assets
  const filteredAssets = useMemo(() => {
    return assets.filter((a) => {
      if (searchFilter) {
        const search = searchFilter.toLowerCase();
        const matches =
          a.ip.toLowerCase().includes(search) ||
          a.hostname?.toLowerCase().includes(search) ||
          a.role?.toLowerCase().includes(search) ||
          a.component_5g?.toLowerCase().includes(search) ||
          a.software?.toLowerCase().includes(search);
        if (!matches) return false;
      }
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (criticalityFilter !== "all" && a.criticality !== criticalityFilter) return false;
      if (component5gFilter !== "all" && a.component_5g !== component5gFilter) return false;
      return true;
    });
  }, [assets, searchFilter, statusFilter, criticalityFilter, component5gFilter]);

  // Componentes 5G únicos para el filtro
  const uniqueComponents = useMemo(() => {
    const comps = new Set<string>();
    assets.forEach((a) => {
      if (a.component_5g) comps.add(a.component_5g);
    });
    return Array.from(comps).sort();
  }, [assets]);

  // KPIs
  const stats = useMemo(() => {
    return {
      total: assets.length,
      critical: assets.filter((a) => a.criticality === "CRITICAL").length,
      underAttack: assets.filter((a) => a.status === "UNDER_ATTACK").length,
      suspicious: assets.filter((a) => a.status === "SUSPICIOUS").length,
      unknown: unknownAssets.length,
      totalCves: assets.reduce((sum, a) => sum + a.confirmed_cves, 0),
      pendingSuggestions: assets.reduce((sum, a) => sum + a.pending_suggestions, 0),
    };
  }, [assets, unknownAssets]);

  // ========================================================================
  // TABLES
  // ========================================================================
  const assetColumns: ColumnDef<AssetRow>[] = [
    {
      id: "status_indicator",
      header: () => <span className="sr-only">Estado</span>,
      size: 8,
      cell: ({ row }) => {
        const status = row.original.status;
        const color =
          status === "UNDER_ATTACK" ? "bg-red-500" :
          status === "SUSPICIOUS" ? "bg-amber-500" :
          status === "NOISE" ? "bg-slate-500" : "bg-emerald-500";
        return <div className={cn("w-1.5 h-full min-h-[48px] rounded-l -ml-3", color)} />;
      },
    },
    {
      accessorKey: "ip",
      header: "Asset",
      cell: ({ row }) => (
        <div className="flex flex-col gap-0.5">
          <code className="text-sm text-blue-400 font-medium">{row.original.ip}</code>
          <span className="text-xs text-slate-400">{row.original.hostname}</span>
        </div>
      ),
    },
    {
      accessorKey: "component_5g",
      header: "Componente 5G",
      cell: ({ row }) => {
        const comp = row.original.component_5g;
        if (!comp) return <span className="text-slate-500 text-xs">—</span>;
        return (
          <span className="px-2 py-0.5 rounded text-xs bg-blue-500/20 text-blue-300 border border-blue-500/40">
            {comp}
          </span>
        );
      },
    },
    {
      accessorKey: "role",
      header: "Rol",
      cell: ({ row }) => <span className="text-sm">{row.original.role}</span>,
    },
    {
      accessorKey: "software",
      header: "Software",
      cell: ({ row }) => {
        const sw = row.original.software;
        const ver = row.original.version;
        if (!sw) return <span className="text-slate-500 text-xs">—</span>;
        return (
          <div className="flex flex-col gap-0.5">
            <span className="text-sm">{sw}</span>
            {ver && <span className="text-xs text-slate-400">v{ver}</span>}
          </div>
        );
      },
    },
    {
      accessorKey: "criticality",
      header: "Criticidad",
      cell: ({ row }) => (
        <span className={cn("px-2 py-0.5 rounded text-xs border", CRITICALITY_COLORS[row.original.criticality])}>
          {row.original.criticality}
        </span>
      ),
    },
    {
      accessorKey: "alerts_24h",
      header: "Alertas",
      cell: ({ row }) => (
        <span className={cn("font-semibold", row.original.alerts_24h > 0 ? "text-amber-400" : "text-slate-400")}>
          {row.original.alerts_24h}
        </span>
      ),
    },
    {
      accessorKey: "active_incidents",
      header: "Incidentes",
      cell: ({ row }) => (
        <span className={cn("font-semibold", row.original.active_incidents > 0 ? "text-red-400" : "text-slate-400")}>
          {row.original.active_incidents}
        </span>
      ),
    },
    {
      id: "cves",
      header: "CVEs",
      cell: ({ row }) => {
        const confirmed = row.original.confirmed_cves;
        const pending = row.original.pending_suggestions;
        if (confirmed === 0 && pending === 0) {
          return <span className="text-slate-500 text-xs">—</span>;
        }
        return (
          <div className="flex flex-col gap-0.5">
            {confirmed > 0 && (
              <span className="text-xs text-emerald-400">✓ {confirmed}</span>
            )}
            {pending > 0 && (
              <span className="text-xs text-amber-400">💡 {pending}</span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: "status",
      header: "Estado",
      cell: ({ row }) => (
        <span className={cn("px-2 py-0.5 rounded text-xs border", STATUS_COLORS[row.original.status])}>
          {STATUS_LABELS[row.original.status]}
        </span>
      ),
    },
  ];

  const unknownColumns: ColumnDef<UnknownAssetRow>[] = [
    {
      accessorKey: "ip",
      header: "IP detectada",
      cell: ({ row }) => <code className="text-sm text-amber-400 font-medium">{row.original.ip}</code>,
    },
    {
      accessorKey: "vuln_types",
      header: "Tipos de ataque",
      cell: ({ row }) => {
        const types = row.original.vuln_types;
        if (!types.length) return <span className="text-slate-500 text-xs">—</span>;
        return (
          <div className="flex flex-wrap gap-1 max-w-xs">
            {types.slice(0, 2).map((t) => (
              <span key={t} className="text-xs px-1.5 py-0.5 bg-slate-700/50 rounded">
                {t}
              </span>
            ))}
            {types.length > 2 && (
              <span className="text-xs text-slate-400">+{types.length - 2}</span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: "alerts",
      header: "Alertas",
      cell: ({ row }) => <span className="font-semibold">{row.original.alerts}</span>,
    },
    {
      accessorKey: "incidents",
      header: "Incidentes",
      cell: ({ row }) => <span className="font-semibold">{row.original.incidents}</span>,
    },
    {
      accessorKey: "max_severity",
      header: "Sev. máx",
      cell: ({ row }) => (
        <span className={cn("font-semibold text-lg", SEVERITY_COLORS[row.original.max_severity])}>
          {row.original.max_severity}
        </span>
      ),
    },
    {
      accessorKey: "pending_suggestions",
      header: "CVE 💡",
      cell: ({ row }) => {
        const pending = row.original.pending_suggestions;
        if (!pending) return <span className="text-slate-500">—</span>;
        return <span className="text-amber-400 font-medium">{pending}</span>;
      },
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <Button
          className="btn-solid text-xs"
          onClick={(e) => {
            e.stopPropagation();
            setRegisterModal({
              ip: row.original.ip,
              maxSeverity: row.original.max_severity,
              vuln_types: row.original.vuln_types,
            });
          }}
        >
          ➕ Registrar
        </Button>
      ),
    },
  ];

  return (
    <div className="global-bg">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8">
        {/* Header */}
        <header className="mb-6">
          <div className="panel px-4 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <h1 className="text-2xl font-semibold">🧩 Asset Inventory</h1>
              <p className="text-xs text-[var(--muted)]">
                Inventario de infraestructura 5G con detección automática de assets
              </p>
            </div>
            <div className="flex gap-2">
              <Button className="btn-ghost" onClick={() => navigate("/alerts/groups")}>
                🚨 Ver Incidentes
              </Button>
              <Button className="btn-solid" onClick={load} disabled={loading}>
                {loading ? "Cargando..." : "🔄 Actualizar"}
              </Button>
            </div>
          </div>
        </header>

        {/* Error */}
        {error && (
          <div className="mb-4 panel p-3 bg-red-900/20 border border-red-500/30 text-red-300 flex items-center justify-between rounded-lg">
            <span>⚠️ {error}</span>
            <Button className="btn-ghost text-xs" onClick={() => setError("")}>Cerrar</Button>
          </div>
        )}

        {/* KPIs */}
        <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7">
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Assets</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{stats.total}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Críticos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-red-400">{stats.critical}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Bajo ataque</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-red-400">{stats.underAttack}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Sospechosos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-amber-400">{stats.suspicious}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Desconocidos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-slate-400">{stats.unknown}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">CVEs ✓</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-emerald-400">{stats.totalCves}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">CVEs 💡</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-amber-400">{stats.pendingSuggestions}</CardContent>
          </Card>
        </div>

        {/* Filtros */}
        <Card className="mb-6">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Filtros</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-1 md:grid-cols-12 gap-3">
            <div className="md:col-span-4">
              <Label className="text-xs">Buscar</Label>
              <Input
                className="mt-1"
                placeholder="IP, hostname, rol, software..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
              />
            </div>
            <div className="md:col-span-2">
              <Label className="text-xs">Estado</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="all">Todos</option>
                <option value="UNDER_ATTACK">🔴 Bajo ataque</option>
                <option value="SUSPICIOUS">⚠️ Sospechoso</option>
                <option value="NOISE">📊 Ruido</option>
                <option value="NORMAL">✅ Normal</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <Label className="text-xs">Criticidad</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                value={criticalityFilter}
                onChange={(e) => setCriticalityFilter(e.target.value)}
              >
                <option value="all">Todas</option>
                <option value="CRITICAL">🔴 Critical</option>
                <option value="HIGH">🟠 High</option>
                <option value="MEDIUM">🔵 Medium</option>
                <option value="LOW">⚪ Low</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <Label className="text-xs">Componente 5G</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                value={component5gFilter}
                onChange={(e) => setComponent5gFilter(e.target.value)}
              >
                <option value="all">Todos</option>
                {uniqueComponents.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
            <div className="md:col-span-2 flex items-end">
              <Button
                className="btn-outline w-full"
                onClick={() => {
                  setSearchFilter("");
                  setStatusFilter("all");
                  setCriticalityFilter("all");
                  setComponent5gFilter("all");
                }}
              >
                Limpiar
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Known assets */}
        <Card className="mb-6">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center justify-between">
              <span>Assets Registrados</span>
              <span className="text-sm font-normal text-[var(--muted)]">
                {filteredAssets.length} de {assets.length}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-center py-8">
                <div className="text-4xl mb-2 animate-pulse">🔄</div>
                <p className="text-[var(--muted)]">Cargando assets...</p>
              </div>
            ) : filteredAssets.length === 0 ? (
              <div className="text-center py-8">
                <div className="text-4xl mb-2">📭</div>
                <p className="text-[var(--muted)]">No hay assets que coincidan con los filtros</p>
              </div>
            ) : (
              <DataTable
                columns={assetColumns}
                data={filteredAssets}
                onRowClick={(row) => navigate(`/assets/${row.ip}`)}
              />
            )}
          </CardContent>
        </Card>

        {/* Unknown assets */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              🚩 Assets Detectados No Registrados
              {unknownAssets.length > 0 && (
                <span className="px-2 py-0.5 rounded text-xs bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  {unknownAssets.length} pendientes
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {unknownAssets.length === 0 ? (
              <div className="text-center py-6">
                <div className="text-3xl mb-2">✅</div>
                <p className="text-[var(--muted)]">No se han detectado assets desconocidos</p>
              </div>
            ) : (
              <>
                <div className="mb-3 p-3 bg-amber-900/20 border border-amber-500/30 rounded-lg text-xs text-amber-300">
                  ⚠️ Estos assets han sido detectados como destino de ataques pero no están en el inventario.
                  Registrarlos mejora la precisión de las correlaciones de CVE.
                </div>
                <DataTable columns={unknownColumns} data={unknownAssets} />
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Modal */}
      {registerModal && (
        <AssetRegisterModal
          ip={registerModal.ip}
          maxSeverity={registerModal.maxSeverity}
          vulnTypes={registerModal.vuln_types}
          onClose={() => setRegisterModal(null)}
          onRegistered={() => {
            setRegisterModal(null);
            load();
          }}
        />
      )}
    </div>
  );
}