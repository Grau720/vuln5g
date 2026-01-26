// components/AssetDetail.tsx
// Vista detallada de un asset con información 5G y CVEs asociados
// Integrado con la nueva arquitectura de alertas

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
  // 5G specific
  component_5g?: string;
  component_type?: string;
  software?: string;
  version?: string;
  // Services & metadata
  services?: { name: string; port: number; protocol?: string }[];
  tags?: string[];
  created_at?: string;
  updated_at?: string;
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
      const updated = await res.json();
      setAsset(updated);
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
              </div>
              <p className="text-sm text-[var(--muted)]">
                {asset.hostname} · {asset.role || "Sin rol definido"}
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
                        className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
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

          {/* 5G Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">📡 Información 5G</CardTitle>
            </CardHeader>
            <CardContent>
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
                <div><span className="text-[var(--muted)]">Software:</span> <span className="font-medium ml-2">{asset.software || "—"}</span></div>
                <div><span className="text-[var(--muted)]">Versión:</span> <span className="font-medium ml-2">{asset.version || "—"}</span></div>
              </div>

              {/* Services */}
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

        {/* CVEs Section */}
        {(stats.confirmedCves > 0 || stats.suggestedCves > 0) && (
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="text-base">🔗 CVEs Asociados</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Confirmed */}
                <div>
                  <h4 className="text-xs text-emerald-300 mb-2 font-semibold">✓ Confirmados ({stats.confirmedCves})</h4>
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

                {/* Suggested */}
                <div>
                  <h4 className="text-xs text-amber-300 mb-2 font-semibold">💡 Sugeridos ({stats.suggestedCves})</h4>
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
            </CardContent>
          </Card>
        )}

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