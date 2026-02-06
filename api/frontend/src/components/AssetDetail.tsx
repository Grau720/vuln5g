// components/AssetDetail.tsx
// Vista detallada de un asset con información 5G y CVEs asociados
// 🆕 Mejorado con CVEs correlacionados automáticamente

import React, { useEffect, useState, useMemo } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DataTable } from "@/components/ui/data-table";
import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "@/lib/utils";

// ============================================================================
// TYPES
// ============================================================================
type Asset = {
  _id: string;
  ip: string;
  hostname?: string;
  role?: string;
  owner?: string;
  os?: string;
  criticality?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  component_5g?: string;
  component_type?: string;
  software?: string;
  version?: string;
  version_confidence?: "HIGH" | "MEDIUM" | "LOW";
  version_method?: string;
  services?: { name: string; port: number; protocol?: string }[];
  tags?: string[];
  created_at?: string;
  updated_at?: string;
  last_scanned?: string;
  version_history?: Array<{
    version: string;
    detected_at: string;
    confidence: string;
    method: string;
  }>;
};

type CVESuggestion = {
  cve_id: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  reason: string;
  cvss_score?: number;
  tipo?: string;
};

type AttackGroup = {
  _id: string;
  group_id: string;
  src_ip: string;
  dest_ip: string;
  vuln_type?: string;
  attack_type?: string;
  severity: number;
  alert_count: number;
  status: "active" | "resolved" | "re-opened";
  pattern?: string;
  last_alert: { $date: string } | string;
  confirmed_cves?: string[];
  cve_suggestions?: CVESuggestion[];
};

type CVEDetail = {
  cve_id: string;
  nombre?: string;
  descripcion_general?: string;
  tipo?: string;
  cvssv3?: { score: number; vector?: string };
  infraestructura_5g_afectada?: string[];
  match_method?: string;
  confidence?: "HIGH" | "MEDIUM" | "LOW";
  match_reason?: string;
  ia_analysis?: {
    exploit_probability?: number;
    weaponization_score?: number;
  };
};

// ============================================================================
// CONSTANTS
// ============================================================================
const SEVERITY_COLORS: Record<number, string> = {
  1: "bg-red-500/20 text-red-300 border-red-500/40",
  2: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  3: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  4: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
};

const STATUS_COLORS: Record<string, string> = {
  active: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  resolved: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  "re-opened": "bg-rose-500/20 text-rose-300 border-rose-500/40",
};

const CRITICALITY_COLORS: Record<string, string> = {
  LOW: "bg-slate-500/20 text-slate-300 border-slate-500/40",
  MEDIUM: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  CRITICAL: "bg-red-500/20 text-red-300 border-red-500/40",
};

const CONFIDENCE_COLORS: Record<string, string> = {
  HIGH: "bg-emerald-600 text-white",
  MEDIUM: "bg-amber-500 text-black",
  LOW: "bg-slate-500 text-white",
};

const PATTERN_ICONS: Record<string, string> = {
  reconnaissance: "🔍",
  exploitation: "💥",
  "post-exploit": "👑",
  persistence: "🔗",
  exfiltration: "📤",
  unknown: "❓",
};

// ============================================================================
// HELPERS
// ============================================================================
const fmtDate = (d: any) => {
  const dateStr = typeof d === "string" ? d : d?.$date;
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleString("es-ES");
};

const fmtDateShort = (d: any) => {
  const dateStr = typeof d === "string" ? d : d?.$date;
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("es-ES");
};

const getTimeAgo = (d: any) => {
  const dateStr = typeof d === "string" ? d : d?.$date;
  if (!dateStr) return "";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `hace ${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `hace ${hours}h`;
  return `hace ${Math.floor(hours / 24)}d`;
};

const cvssSeverity = (s: number) => (s >= 9 ? "crit" : s >= 7 ? "high" : s >= 4 ? "med" : "low");
const getCVSSSeverity = (score: number): string => {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
};

// ============================================================================
// CVE DETAIL MODAL
// ============================================================================
function CVEDetailModal({ cveId, onClose }: { cveId: string; onClose: () => void }) {
  const [cve, setCve] = useState<CVEDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCVE = async () => {
      try {
        const res = await fetch(`/api/v1/cves?q=cve_id:${cveId}`);
        const data = await res.json();
        const match = data.cves?.find((c: CVEDetail) => c.cve_id === cveId);
        setCve(match || null);
      } catch (e) {
        console.error(e);
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
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">{cveId}</h2>
          <Button className="btn-outline" onClick={onClose}>Cerrar</Button>
        </div>

        {loading ? (
          <div className="text-center py-8">
            <div className="text-3xl animate-pulse">🔍</div>
          </div>
        ) : cve ? (
          <div className="space-y-4 text-sm">
            {cve.cvssv3?.score && (
              <span className={`badge badge-${cvssSeverity(cve.cvssv3.score)} text-lg px-3 py-1`}>
                CVSS {cve.cvssv3.score.toFixed(1)}
              </span>
            )}
            {cve.nombre && <p className="font-medium">{cve.nombre}</p>}
            {cve.descripcion_general && (
              <p className="text-slate-300 whitespace-pre-wrap">{cve.descripcion_general}</p>
            )}
            {cve.tipo && <p><strong>Tipo:</strong> {cve.tipo}</p>}
            {cve.infraestructura_5g_afectada?.length && (
              <div>
                <strong>Infraestructura 5G:</strong>
                <div className="flex gap-1 flex-wrap mt-1">
                  {cve.infraestructura_5g_afectada.map((i) => (
                    <span key={i} className="chip chip-success text-xs">{i}</span>
                  ))}
                </div>
              </div>
            )}
            <div className="flex gap-2 pt-2">
              <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noopener"
                className="text-blue-400 hover:underline text-xs">Ver en NVD →</a>
              <a href={`/dashboard/${cveId}`} className="text-blue-400 hover:underline text-xs">
                Ver en Dashboard →</a>
            </div>
          </div>
        ) : (
          <p className="text-slate-400">CVE no encontrado en la base de datos</p>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// VERSION HISTORY COMPONENT
// ============================================================================
function VersionHistory({ history }: { history?: Array<any> }) {
  if (!history || history.length === 0) {
    return <p className="text-sm text-slate-500">No hay historial de versiones</p>;
  }

  return (
    <div className="space-y-2">
      {history.map((item, idx) => (
        <div key={idx} className="flex items-center gap-3 text-sm pb-2 border-b border-slate-700/50 last:border-0">
          <div className="flex-1">
            <code className="text-emerald-400 font-medium">v{item.version}</code>
            <span className="text-xs text-slate-400 ml-2">
              via {item.method?.replace('_', ' ') || 'unknown'}
            </span>
          </div>
          <span className={cn(
            "px-2 py-0.5 rounded text-xs",
            item.confidence === 'HIGH' ? 'bg-emerald-500/20 text-emerald-300' :
            item.confidence === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300' :
            'bg-slate-500/20 text-slate-300'
          )}>
            {item.confidence}
          </span>
          <span className="text-xs text-slate-500">
            {fmtDateShort(item.detected_at)}
          </span>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================
export default function AssetDetail() {
  const { ip } = useParams<{ ip: string }>();
  const navigate = useNavigate();

  const [asset, setAsset] = useState<Asset | null>(null);
  const [groups, setGroups] = useState<AttackGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Edit mode
  const [editMode, setEditMode] = useState(false);
  const [editForm, setEditForm] = useState<Partial<Asset>>({});
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // CVE Modal
  const [selectedCVE, setSelectedCVE] = useState<string | null>(null);
  
  // Version history panel
  const [showVersionHistory, setShowVersionHistory] = useState(false);

  // 🆕 Correlated CVEs
  const [correlatedCVEs, setCorrelatedCVEs] = useState<CVEDetail[]>([]);
  const [loadingCVEs, setLoadingCVEs] = useState(false);
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError("");
      try {
        const [assetRes, groupsRes] = await Promise.all([
          fetch(`/api/v1/assets/${ip}`),
          fetch(`/api/v1/alerts/groups?dest_ip=${ip}&per_page=100`),
        ]);

        if (!assetRes.ok) throw new Error("Asset no encontrado");

        const assetJson = await assetRes.json();
        const groupsJson = await groupsRes.json();

        setAsset(assetJson);
        setGroups(groupsJson.groups || []);
        setEditForm(assetJson);
      } catch (e: any) {
        setError(e?.message || "Error cargando asset");
      } finally {
        setLoading(false);
      }
    };

    if (ip) load();
  }, [ip]);

  // 🆕 Fetch correlated CVEs
  useEffect(() => {
    if (!ip) return;

    const fetchCorrelatedCVEs = async () => {
      try {
        setLoadingCVEs(true);
        const response = await fetch(`/api/v1/assets/${ip}/cves`);
        if (response.ok) {
          const data = await response.json();
          setCorrelatedCVEs(data.cves || []);
        }
      } catch (err) {
        console.error("Error fetching correlated CVEs:", err);
      } finally {
        setLoadingCVEs(false);
      }
    };

    fetchCorrelatedCVEs();
  }, [ip]);

  // 🆕 Refresh CVEs manually
  const refreshCVEs = async () => {
    if (!ip) return;
    
    try {
      setLoadingCVEs(true);
      const response = await fetch(`/api/v1/assets/${ip}/cves`);
      if (response.ok) {
        const data = await response.json();
        setCorrelatedCVEs(data.cves || []);
      }
    } catch (err) {
      console.error("Error refreshing CVEs:", err);
    } finally {
      setLoadingCVEs(false);
    }
  };

  // Stats
  const stats = useMemo(() => {
    const activeIncidents = groups.filter((g) => g.status === "active").length;
    const totalAlerts = groups.reduce((sum, g) => sum + g.alert_count, 0);
    const criticalIncidents = groups.filter((g) => g.severity === 1).length;
    const confirmedCves = new Set<string>();
    const suggestedCves = new Set<string>();

    groups.forEach((g) => {
      g.confirmed_cves?.forEach((c) => confirmedCves.add(c));
      g.cve_suggestions?.forEach((s) => suggestedCves.add(s.cve_id));
    });

    return {
      totalIncidents: groups.length,
      activeIncidents,
      totalAlerts,
      criticalIncidents,
      confirmedCves: confirmedCves.size,
      suggestedCves: suggestedCves.size,
      confirmedCvesList: Array.from(confirmedCves),
      suggestedCvesList: Array.from(suggestedCves),
    };
  }, [groups]);

  // 🆕 Filter correlated CVEs by severity
  const filteredCVEs = useMemo(() => {
    if (selectedSeverity === "all") return correlatedCVEs;

    const minScores: Record<string, number> = {
      critical: 9.0,
      high: 7.0,
      medium: 4.0,
    };

    const minScore = minScores[selectedSeverity] || 0;
    const maxScore = selectedSeverity === "critical" ? 10.0 : 
                     selectedSeverity === "high" ? 8.9 : 
                     selectedSeverity === "medium" ? 6.9 : 10.0;

    return correlatedCVEs.filter((cve) => {
      const score = cve.cvssv3?.score || 0;
      return score >= minScore && score <= maxScore;
    });
  }, [correlatedCVEs, selectedSeverity]);

  // 🆕 Count CVEs by severity
  const cveSeverityStats = useMemo(() => {
    const stats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    correlatedCVEs.forEach((cve) => {
      const score = cve.cvssv3?.score || 0;
      if (score >= 9.0) stats.critical++;
      else if (score >= 7.0) stats.high++;
      else if (score >= 4.0) stats.medium++;
      else stats.low++;
    });

    return stats;
  }, [correlatedCVEs]);

  // Save edits
  const saveChanges = async () => {
    if (!asset) return;
    setSaving(true);
    try {
      const res = await fetch(`/api/v1/assets/${ip}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editForm),
      });
      if (!res.ok) throw new Error("Error guardando cambios");
      
      const refreshRes = await fetch(`/api/v1/assets/${ip}`);
      const refreshedAsset = await refreshRes.json();
      
      setAsset(refreshedAsset);
      setEditForm(refreshedAsset);
      setEditMode(false);
    } catch (e: any) {
      alert(e?.message || "Error guardando");
    } finally {
      setSaving(false);
    }
  };

  // Delete asset
  const deleteAsset = async () => {
    try {
      const res = await fetch(`/api/v1/assets/${ip}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Error eliminando");
      navigate("/assets");
    } catch (e: any) {
      alert(e?.message || "Error eliminando");
    }
  };

  // Columns for incidents table
  const columns: ColumnDef<AttackGroup>[] = [
    {
      id: "severity_bar",
      header: () => <span className="sr-only">Sev</span>,
      size: 8,
      cell: ({ row }) => {
        const sev = row.original.severity;
        const color = sev === 1 ? "bg-red-500" : sev === 2 ? "bg-orange-500" : sev === 3 ? "bg-yellow-500" : "bg-emerald-500";
        return <div className={cn("w-1.5 h-full min-h-[40px] rounded-l -ml-3", color)} />;
      },
    },
    {
      accessorKey: "group_id",
      header: "Incidente",
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <span>{PATTERN_ICONS[row.original.pattern || "unknown"]}</span>
          <button
            onClick={() => navigate(`/alerts/groups/${row.original._id}`)}
            className="font-mono text-sm text-blue-400 hover:underline"
          >
            {row.original.group_id}
          </button>
        </div>
      ),
    },
    {
      accessorKey: "src_ip",
      header: "Atacante",
      cell: ({ row }) => <code className="text-sm text-rose-400">{row.original.src_ip}</code>,
    },
    {
      accessorKey: "vuln_type",
      header: "Tipo",
      cell: ({ row }) => (
        <span className="text-sm">{row.original.vuln_type || row.original.attack_type || "—"}</span>
      ),
    },
    {
      accessorKey: "severity",
      header: "Sev",
      cell: ({ row }) => (
        <span className={cn("px-2 py-0.5 rounded text-xs border", SEVERITY_COLORS[row.original.severity])}>
          {row.original.severity}
        </span>
      ),
    },
    {
      accessorKey: "alert_count",
      header: "Alertas",
      cell: ({ row }) => <span className="font-semibold">{row.original.alert_count}</span>,
    },
    {
      id: "cves",
      header: "CVEs",
      cell: ({ row }) => {
        const confirmed = row.original.confirmed_cves?.length || 0;
        const suggestions = row.original.cve_suggestions?.length || 0;
        if (!confirmed && !suggestions) return <span className="text-slate-500">—</span>;
        return (
          <div className="flex gap-1">
            {confirmed > 0 && <span className="text-xs text-emerald-400">✓{confirmed}</span>}
            {suggestions > 0 && <span className="text-xs text-amber-400">💡{suggestions}</span>}
          </div>
        );
      },
    },
    {
      accessorKey: "status",
      header: "Estado",
      cell: ({ row }) => (
        <span className={cn("px-2 py-0.5 rounded text-xs border capitalize", STATUS_COLORS[row.original.status])}>
          {row.original.status}
        </span>
      ),
    },
    {
      accessorKey: "last_alert",
      header: "Última",
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span className="text-xs">{fmtDateShort(row.original.last_alert)}</span>
          <span className="text-[10px] text-slate-400">{getTimeAgo(row.original.last_alert)}</span>
        </div>
      ),
    },
  ];

  if (loading) {
    return (
      <div className="global-bg min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-5xl mb-3 animate-pulse">🔄</div>
          <p>Cargando asset...</p>
        </div>
      </div>
    );
  }

  if (error || !asset) {
    return (
      <div className="global-bg">
        <div className="mx-auto max-w-[1200px] p-6">
          <Card className="bg-red-900/20 border-red-500/30">
            <CardContent className="pt-6">
              <p className="text-red-400 mb-3">{error || "Asset no encontrado"}</p>
              <Button className="btn-outline" onClick={() => navigate("/assets")}>
                ← Volver a Assets
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="global-bg">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8">
        {/* Header */}
        <header className="mb-6">
          <div className="panel px-4 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-2xl font-semibold">🧩 {asset.ip}</h1>
                {asset.component_5g && (
                  <span className="px-2 py-1 rounded text-sm bg-blue-500/20 text-blue-300 border border-blue-500/40">
                    {asset.component_5g}
                  </span>
                )}
                {asset.criticality && (
                  <span className={cn("px-2 py-1 rounded text-xs border", CRITICALITY_COLORS[asset.criticality])}>
                    {asset.criticality}
                  </span>
                )}
                {asset.version && asset.version !== 'unknown' && (
                  <span className="px-2 py-1 rounded text-xs bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    v{asset.version}
                  </span>
                )}
              </div>
              <p className="text-sm text-[var(--muted)]">
                {asset.hostname} · {asset.role || "Sin rol definido"}
                {asset.last_scanned && (
                  <span className="ml-2 text-xs">
                    · Último scan: {fmtDateShort(asset.last_scanned)}
                  </span>
                )}
              </p>
            </div>
            <div className="flex gap-2">
              <Button className="btn-ghost" onClick={() => navigate("/assets")}>
                ← Volver
              </Button>
              {!editMode && (
                <Button className="btn-outline" onClick={() => setEditMode(true)}>
                  ✏️ Editar
                </Button>
              )}
            </div>
          </div>
        </header>

        {/* KPIs */}
        <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-6">
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Incidentes</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{stats.totalIncidents}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Activos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-amber-400">{stats.activeIncidents}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Alertas</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{stats.totalAlerts}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">Críticos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-red-400">{stats.criticalIncidents}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">CVE ✓</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-emerald-400">{stats.confirmedCves}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs text-[var(--muted)]">CVE 💡</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-amber-400">{stats.suggestedCves}</CardContent>
          </Card>
        </div>

        {/* Asset Info */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {/* Basic Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Información del Asset</CardTitle>
            </CardHeader>
            <CardContent>
              {editMode ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <Label className="text-xs">Hostname</Label>
                      <Input
                        value={editForm.hostname || ""}
                        onChange={(e) => setEditForm({ ...editForm, hostname: e.target.value })}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <Label className="text-xs">Rol</Label>
                      <Input
                        value={editForm.role || ""}
                        onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <Label className="text-xs">Owner</Label>
                      <Input
                        value={editForm.owner || ""}
                        onChange={(e) => setEditForm({ ...editForm, owner: e.target.value })}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <Label className="text-xs">Criticidad</Label>
                      <select
                        className="mt-1 w-full rounded-md border px-2 py-2 text-sm bg-slate-900 border-slate-700"
                        value={editForm.criticality || ""}
                        onChange={(e) => setEditForm({ ...editForm, criticality: e.target.value as any })}
                      >
                        <option value="LOW">LOW</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="HIGH">HIGH</option>
                        <option value="CRITICAL">CRITICAL</option>
                      </select>
                    </div>
                  </div>
                  <div className="flex gap-2 pt-2">
                    <Button className="btn-solid" onClick={saveChanges} disabled={saving}>
                      {saving ? "Guardando..." : "✓ Guardar"}
                    </Button>
                    <Button className="btn-outline" onClick={() => { setEditMode(false); setEditForm(asset); setConfirmDelete(false); }}>
                      Cancelar
                    </Button>
                    
                    {!confirmDelete ? (
                      <Button 
                        className="btn-ghost text-red-400 ml-auto" 
                        onClick={() => setConfirmDelete(true)}
                      >
                        🗑️ Eliminar
                      </Button>
                    ) : (
                      <div className="flex gap-2 ml-auto">
                        <Button className="btn-ghost text-slate-400" onClick={() => setConfirmDelete(false)}>
                          Cancelar
                        </Button>
                        <Button className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded" onClick={deleteAsset}>
                          ⚠️ Confirmar
                        </Button>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div><span className="text-[var(--muted)]">Hostname:</span> <span className="font-medium">{asset.hostname || "—"}</span></div>
                  <div><span className="text-[var(--muted)]">Rol:</span> <span className="font-medium">{asset.role || "—"}</span></div>
                  <div><span className="text-[var(--muted)]">Owner:</span> <span className="font-medium">{asset.owner || "—"}</span></div>
                  <div><span className="text-[var(--muted)]">OS:</span> <span className="font-medium">{asset.os || "—"}</span></div>
                  <div><span className="text-[var(--muted)]">Criticidad:</span> <span className={cn("px-2 py-0.5 rounded text-xs border ml-1", CRITICALITY_COLORS[asset.criticality || "MEDIUM"])}>{asset.criticality || "—"}</span></div>
                  <div><span className="text-[var(--muted)]">Tags:</span> <span className="font-medium">{asset.tags?.join(", ") || "—"}</span></div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* 5G Info + Version */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-base">📡 Información 5G</CardTitle>
              {asset.version_history && asset.version_history.length > 0 && (
                <Button 
                  className="btn-ghost text-xs"
                  onClick={() => setShowVersionHistory(!showVersionHistory)}
                >
                  {showVersionHistory ? '📋 Ocultar historial' : '📋 Ver historial'}
                </Button>
              )}
            </CardHeader>
            <CardContent>
              {editMode ? (
                <div className="grid grid-cols-2 gap-3 mb-4">
                  <div>
                    <Label className="text-xs">Componente 5G</Label>
                    <Input
                      value={editForm.component_5g || ""}
                      onChange={(e) => setEditForm({ ...editForm, component_5g: e.target.value })}
                      className="mt-1"
                      placeholder="AMF, SMF, UPF..."
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Tipo</Label>
                    <Input
                      value={editForm.component_type || ""}
                      onChange={(e) => setEditForm({ ...editForm, component_type: e.target.value })}
                      className="mt-1"
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Software</Label>
                    <Input
                      value={editForm.software || ""}
                      onChange={(e) => setEditForm({ ...editForm, software: e.target.value })}
                      className="mt-1"
                      placeholder="open5gs, free5gc..."
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Versión</Label>
                    <Input
                      value={editForm.version || ""}
                      onChange={(e) => setEditForm({ ...editForm, version: e.target.value })}
                      className="mt-1"
                      placeholder="2.7.0"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-[var(--muted)]">Componente 5G:</span>
                      {asset.component_5g ? (
                        <span className="ml-2 px-2 py-0.5 rounded text-xs bg-blue-500/20 text-blue-300 border border-blue-500/40">
                          {asset.component_5g}
                        </span>
                      ) : (
                        <span className="ml-2 text-slate-500">No definido</span>
                      )}
                    </div>
                    <div><span className="text-[var(--muted)]">Tipo:</span> <span className="font-medium ml-2">{asset.component_type || "—"}</span></div>
                  </div>

                  <div className="pt-3 border-t border-[var(--panel-border)]">
                    <h4 className="text-xs text-[var(--muted)] mb-2">Software y Versión:</h4>
                    
                    {asset.software || asset.version ? (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          {asset.software && (
                            <code className="text-emerald-400 font-medium text-sm">
                              {asset.software}
                            </code>
                          )}
                          {asset.version && asset.version !== 'unknown' && (
                            <code className="text-blue-400 text-sm">
                              v{asset.version}
                            </code>
                          )}
                          {asset.version === 'unknown' && (
                            <span className="text-slate-500 text-xs italic">
                              (versión desconocida)
                            </span>
                          )}
                        </div>
                        
                        {asset.version_confidence && asset.version !== 'unknown' && (
                          <div className="flex items-center gap-2 text-xs">
                            <span className={cn(
                              "px-2 py-0.5 rounded",
                              asset.version_confidence === 'HIGH' ? 'bg-emerald-500/20 text-emerald-300' :
                              asset.version_confidence === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300' :
                              'bg-slate-500/20 text-slate-300'
                            )}>
                              {asset.version_confidence === 'HIGH' ? '✓' :
                               asset.version_confidence === 'MEDIUM' ? '~' : '?'} 
                              {asset.version_confidence}
                            </span>
                            {asset.version_method && (
                              <span className="text-slate-500">
                                detectado via {asset.version_method.replace('_', ' ')}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    ) : (
                      <p className="text-sm text-slate-500">No definido</p>
                    )}
                  </div>

                  {showVersionHistory && (
                    <div className="pt-3 border-t border-[var(--panel-border)]">
                      <h4 className="text-xs text-[var(--muted)] mb-3">Historial de Versiones:</h4>
                      <VersionHistory history={asset.version_history} />
                    </div>
                  )}
                </div>
              )}

              <div className="mt-4 pt-4 border-t border-[var(--panel-border)]">
                <h4 className="text-xs text-[var(--muted)] mb-2">Servicios Expuestos:</h4>
                {asset.services?.length ? (
                  <div className="flex flex-wrap gap-2">
                    {asset.services.map((s, i) => (
                      <span key={i} className="px-2 py-1 bg-slate-700/50 rounded text-xs">
                        {s.name} ({s.protocol || "TCP"}:{s.port})
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-slate-500">No definidos</p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* 🆕 CVEs Section - MEJORADO CON CORRELACIÓN */}
        <Card className="mb-6">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-base">🔗 Vulnerabilidades Detectadas</CardTitle>
            <Button 
              className="btn-ghost text-xs" 
              onClick={refreshCVEs}
              disabled={loadingCVEs}
            >
              {loadingCVEs ? '🔄 Actualizando...' : '🔄 Actualizar'}
            </Button>
          </CardHeader>
          <CardContent>
            {/* 🆕 Tabs: Correlacionados vs Alertas */}
            <div className="mb-4 flex gap-2 border-b border-slate-700 pb-2">
              <button
                onClick={() => setSelectedSeverity("all")}
                className={cn(
                  "px-3 py-1.5 rounded-t text-sm font-medium transition-colors",
                  selectedSeverity === "all" 
                    ? "bg-slate-700 text-white" 
                    : "text-slate-400 hover:text-white hover:bg-slate-800"
                )}
              >
                Todos ({correlatedCVEs.length})
              </button>
              <button
                onClick={() => setSelectedSeverity("critical")}
                className={cn(
                  "px-3 py-1.5 rounded-t text-sm font-medium transition-colors",
                  selectedSeverity === "critical" 
                    ? "bg-red-600 text-white" 
                    : "text-red-400 hover:text-white hover:bg-red-900/30"
                )}
              >
                Critical ({cveSeverityStats.critical})
              </button>
              <button
                onClick={() => setSelectedSeverity("high")}
                className={cn(
                  "px-3 py-1.5 rounded-t text-sm font-medium transition-colors",
                  selectedSeverity === "high" 
                    ? "bg-orange-600 text-white" 
                    : "text-orange-400 hover:text-white hover:bg-orange-900/30"
                )}
              >
                High ({cveSeverityStats.high})
              </button>
              <button
                onClick={() => setSelectedSeverity("medium")}
                className={cn(
                  "px-3 py-1.5 rounded-t text-sm font-medium transition-colors",
                  selectedSeverity === "medium" 
                    ? "bg-yellow-600 text-white" 
                    : "text-yellow-400 hover:text-white hover:bg-yellow-900/30"
                )}
              >
                Medium ({cveSeverityStats.medium})
              </button>
            </div>

            {/* 🆕 CVEs Correlacionados */}
            {loadingCVEs ? (
              <div className="text-center py-8">
                <div className="text-3xl animate-pulse mb-2">🔍</div>
                <p className="text-slate-400">Correlacionando vulnerabilidades...</p>
              </div>
            ) : filteredCVEs.length === 0 ? (
              <div className="text-center py-8">
                <div className="text-4xl mb-2">✅</div>
                <p className="text-[var(--muted)]">
                  {selectedSeverity === "all" 
                    ? "No se detectaron vulnerabilidades para este asset" 
                    : `No hay vulnerabilidades con severidad ${selectedSeverity.toUpperCase()}`
                  }
                </p>
              </div>
            ) : (
              <div className="space-y-3 max-h-[500px] overflow-y-auto">
                {filteredCVEs.map((cve, idx) => (
                  <div
                    key={idx}
                    className="border border-slate-700 rounded-lg p-3 hover:bg-slate-800/50 transition-colors"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setSelectedCVE(cve.cve_id)}
                          className="font-mono text-sm text-blue-400 hover:underline font-semibold"
                        >
                          {cve.cve_id}
                        </button>
                        
                        {cve.confidence && (
                          <span className={cn("px-2 py-0.5 rounded text-xs", CONFIDENCE_COLORS[cve.confidence])}>
                            {cve.confidence === 'HIGH' ? '✓' : cve.confidence === 'MEDIUM' ? '~' : '?'} {cve.confidence}
                          </span>
                        )}
                        
                        {cve.match_method && (
                          <span className="px-2 py-0.5 rounded text-xs bg-slate-700 text-slate-300 border border-slate-600">
                            {cve.match_method.replace('_', ' ')}
                          </span>
                        )}
                      </div>

                      {cve.cvssv3?.score && (
                        <span className={`badge badge-${cvssSeverity(cve.cvssv3.score)} text-sm px-2 py-0.5`}>
                          {cve.cvssv3.score.toFixed(1)} {getCVSSSeverity(cve.cvssv3.score)}
                        </span>
                      )}
                    </div>

                    <p className="text-sm text-slate-300 mb-2">
                      {cve.descripcion_general || cve.nombre || "Sin descripción"}
                    </p>

                    {cve.match_reason && (
                      <div className="flex items-start gap-2 text-xs text-slate-400 bg-blue-900/20 border border-blue-500/30 p-2 rounded mb-2">
                        <span>🎯</span>
                        <span>{cve.match_reason}</span>
                      </div>
                    )}

                    {cve.ia_analysis?.exploit_probability !== undefined && (
                      <div className="flex items-center gap-2 text-xs mb-2">
                        <span>⚡</span>
                        <span className="text-slate-400">Probabilidad de exploit:</span>
                        <span className={cn(
                          "px-2 py-0.5 rounded",
                          cve.ia_analysis.exploit_probability > 0.7 ? "bg-red-500/20 text-red-300" :
                          cve.ia_analysis.exploit_probability > 0.4 ? "bg-yellow-500/20 text-yellow-300" :
                          "bg-emerald-500/20 text-emerald-300"
                        )}>
                          {(cve.ia_analysis.exploit_probability * 100).toFixed(0)}%
                        </span>
                      </div>
                    )}

                    <div className="flex gap-2 mt-2">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-blue-400 hover:underline"
                      >
                        Ver en NVD →
                      </a>
                      <button
                        onClick={() => setSelectedCVE(cve.cve_id)}
                        className="text-xs text-blue-400 hover:underline"
                      >
                        Ver detalles →
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Divider */}
            {(stats.confirmedCves > 0 || stats.suggestedCves > 0) && correlatedCVEs.length > 0 && (
              <div className="my-6 border-t border-slate-700/50" />
            )}

            {/* Original CVEs de Alertas */}
            {(stats.confirmedCves > 0 || stats.suggestedCves > 0) && (
              <div>
                <h4 className="text-sm font-semibold mb-3 text-slate-300">CVEs de Alertas Suricata:</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <h5 className="text-xs text-emerald-300 mb-2 font-semibold">✓ Confirmados ({stats.confirmedCves})</h5>
                    {stats.confirmedCvesList.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {stats.confirmedCvesList.map((cve) => (
                          <button
                            key={cve}
                            onClick={() => setSelectedCVE(cve)}
                            className="px-2 py-1 bg-emerald-900/30 border border-emerald-500/40 rounded text-xs text-emerald-300 hover:bg-emerald-900/50 font-mono"
                          >
                            {cve}
                          </button>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-slate-500">Ninguno</p>
                    )}
                  </div>

                  <div>
                    <h5 className="text-xs text-amber-300 mb-2 font-semibold">💡 Sugeridos ({stats.suggestedCves})</h5>
                    {stats.suggestedCvesList.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {stats.suggestedCvesList.map((cve) => (
                          <button
                            key={cve}
                            onClick={() => setSelectedCVE(cve)}
                            className="px-2 py-1 bg-amber-900/30 border border-amber-500/40 rounded text-xs text-amber-300 hover:bg-amber-900/50 font-mono"
                          >
                            {cve}
                          </button>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-slate-500">Ninguno</p>
                    )}
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Incidents */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">🚨 Incidentes Relacionados</CardTitle>
          </CardHeader>
          <CardContent>
            {groups.length === 0 ? (
              <div className="text-center py-8">
                <div className="text-4xl mb-2">✅</div>
                <p className="text-[var(--muted)]">No hay incidentes asociados a este asset</p>
              </div>
            ) : (
              <DataTable
                columns={columns}
                data={groups}
                onRowClick={(row) => navigate(`/alerts/groups/${row._id}`)}
              />
            )}
          </CardContent>
        </Card>
      </div>

      {/* CVE Modal */}
      {selectedCVE && (
        <CVEDetailModal cveId={selectedCVE} onClose={() => setSelectedCVE(null)} />
      )}
    </div>
  );
}