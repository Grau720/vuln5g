// components/AttackGroupDetail.tsx
// Detalle de un grupo de ataque con la nueva arquitectura:
// - cve_suggestions con acciones de confirmar/descartar
// - enrichment_status para mostrar si el asset es conocido
// - target_asset para información del asset
// - confirmed_cves para CVEs vinculados manualmente
// - Endpoints: POST /groups/{id}/link-cve y /unlink-cve

import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DataTable } from "@/components/ui/data-table";
import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "@/lib/utils";

// ============================================================================
// TYPES - Nueva arquitectura
// ============================================================================
type CVESuggestion = {
  cve_id: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  reason: string;
  cvss_score?: number;
  tipo?: string;
  infraestructura_5g?: string[];
  warning?: string;
  requires_validation: boolean;
};

type TargetAsset = {
  ip: string;
  hostname?: string;
  role?: string;
  component_type?: string;
  component_5g?: string;
  software?: string;
  version?: string;
  criticality?: string;
  owner?: string;
  known: boolean;
  tags?: string[];
};

type AlertGroup = {
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
  // Nueva arquitectura
  cve_suggestions?: CVESuggestion[];
  confirmed_cves?: string[];
  discarded_cves?: string[];
  target_asset?: TargetAsset;
  source_asset?: {
    ip: string;
    hostname?: string;
    is_internal: boolean;
  };
  enrichment_status?: "enriched" | "partial" | "unknown";
  created_at: { $date: string } | string;
};

type Alert = {
  _id: string;
  timestamp: string;
  alert: {
    signature: string;
    signature_id: number;
    category: string;
    severity: number;
  };
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  proto: string;
  vuln_type?: string;
  cve_in_signature?: string;
  http?: {
    hostname?: string;
    url?: string;
    http_method?: string;
    status?: number;
    http_user_agent?: string;
  };
  ingested_at: { $date: string };
  source: string;
};

type CVEDetail = {
  cve_id: string;
  nombre: string;
  descripcion_general?: string;
  tipo?: string;
  etiquetas?: string[];
  infraestructura_5g_afectada?: string[];
  dificultad_explotacion?: string;
  impacto_potencial?: { confidencialidad?: string; integridad?: string; disponibilidad?: string };
  recomendaciones_remediacion?: string;
  referencias_mitre?: string[];
  cvssv3?: { score: number; vector?: string };
  fecha_publicacion: string;
  componente_afectado?: string;
  versiones_afectadas?: string[];
};

type DetailResponse = {
  group: AlertGroup;
  alerts: Alert[];
  pagination: {
    page: number;
    per_page: number;
    total: number;
    pages: number;
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

const CONFIDENCE_COLORS: Record<string, string> = {
  HIGH: "bg-emerald-600 text-white",
  MEDIUM: "bg-amber-500 text-black",
  LOW: "bg-slate-500 text-white",
};

const ENRICHMENT_LABELS: Record<string, { label: string; color: string }> = {
  enriched: { label: "✅ Asset Conocido", color: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40" },
  partial: { label: "⚠️ Parcialmente Conocido", color: "bg-amber-500/20 text-amber-300 border-amber-500/40" },
  unknown: { label: "❓ Asset Desconocido", color: "bg-slate-500/20 text-slate-300 border-slate-500/40" },
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
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
};

const cvssSeverity = (s: number) => (s >= 9 ? "crit" : s >= 7 ? "high" : s >= 4 ? "med" : "low");

// ============================================================================
// CVE DETAIL MODAL COMPONENT
// ============================================================================
function CVEDetailModal({
  cveId,
  onClose,
}: {
  cveId: string;
  onClose: () => void;
}) {
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
        if (match) {
          setCve(match);
        } else {
          setError("CVE no encontrado en la base de datos");
        }
      } catch (e: any) {
        setError(e?.message || "Error cargando CVE");
      } finally {
        setLoading(false);
      }
    };

    if (cveId) fetchCVE();
  }, [cveId]);

  return (
    <div className="fixed inset-0 z-[60]">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="absolute right-0 top-0 h-full w-full max-w-2xl bg-[#0d1117] border-l border-slate-700 overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-[#0d1117] border-b border-slate-700 px-4 py-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold">{cveId}</h2>
          <Button className="btn-outline" onClick={onClose}>
            ✕ Cerrar
          </Button>
        </div>

        {/* Content */}
        <div className="p-4">
          {loading && (
            <div className="text-center py-8">
              <div className="text-4xl mb-2 animate-pulse">🔍</div>
              <p className="text-[var(--muted)]">Cargando CVE...</p>
            </div>
          )}

          {error && (
            <div className="panel p-4 bg-red-900/20 border border-red-500/30 rounded">
              <p className="text-red-400">{error}</p>
            </div>
          )}

          {cve && (
            <div className="space-y-4 text-sm">
              {/* Score badge */}
              <div className="flex items-center gap-3">
                <span className={`badge badge-${cvssSeverity(cve.cvssv3?.score ?? 0)} text-lg px-3 py-1`}>
                  {cve.cvssv3?.score?.toFixed(1) || "N/A"}
                </span>
                {cve.cvssv3?.vector && (
                  <span className="chip chip-muted text-xs">{cve.cvssv3.vector}</span>
                )}
              </div>

              {/* Nombre */}
              {cve.nombre && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Nombre</div>
                  <p className="font-medium">{cve.nombre}</p>
                </div>
              )}

              {/* Descripción */}
              {cve.descripcion_general && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Descripción</div>
                  <p className="whitespace-pre-wrap text-slate-300">{cve.descripcion_general}</p>
                </div>
              )}

              {/* Tipo */}
              {cve.tipo && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Tipo</div>
                  <span className="chip chip-info">{cve.tipo}</span>
                </div>
              )}

              {/* Componente afectado */}
              {cve.componente_afectado && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Componente Afectado</div>
                  <p>{cve.componente_afectado}</p>
                </div>
              )}

              {/* Versiones afectadas */}
              {cve.versiones_afectadas && cve.versiones_afectadas.length > 0 && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Versiones Afectadas</div>
                  <ul className="list-disc pl-5 text-xs">
                    {cve.versiones_afectadas.map((v, i) => (
                      <li key={i}>{v}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Etiquetas */}
              {cve.etiquetas && cve.etiquetas.length > 0 && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Etiquetas</div>
                  <div className="flex flex-wrap gap-1">
                    {cve.etiquetas.map((t) => (
                      <span key={t} className="chip chip-info text-xs">{t}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Infraestructura 5G */}
              {cve.infraestructura_5g_afectada && cve.infraestructura_5g_afectada.length > 0 && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Infraestructura 5G Afectada</div>
                  <div className="flex flex-wrap gap-1">
                    {cve.infraestructura_5g_afectada.map((i) => (
                      <span key={i} className="chip chip-success text-xs">{i}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* Dificultad */}
              {cve.dificultad_explotacion && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Dificultad de Explotación</div>
                  <p>{cve.dificultad_explotacion}</p>
                </div>
              )}

              {/* Impacto */}
              {cve.impacto_potencial && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Impacto Potencial</div>
                  <ul className="list-disc pl-5 text-xs">
                    <li><strong>Confidencialidad:</strong> {cve.impacto_potencial.confidencialidad || "—"}</li>
                    <li><strong>Integridad:</strong> {cve.impacto_potencial.integridad || "—"}</li>
                    <li><strong>Disponibilidad:</strong> {cve.impacto_potencial.disponibilidad || "—"}</li>
                  </ul>
                </div>
              )}

              {/* Remediación */}
              {cve.recomendaciones_remediacion && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Remediación</div>
                  <div className="panel p-3 bg-green-900/20 border border-green-500/30 rounded text-xs">
                    {cve.recomendaciones_remediacion}
                  </div>
                </div>
              )}

              {/* Fecha */}
              <div>
                <div className="text-xs text-[var(--muted)] mb-1">Fecha de Publicación</div>
                <p>{fmtDateShort(cve.fecha_publicacion)}</p>
              </div>

              {/* Referencias */}
              {cve.referencias_mitre && cve.referencias_mitre.length > 0 && (
                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Referencias</div>
                  <ul className="list-disc pl-5 text-xs">
                    {cve.referencias_mitre.slice(0, 5).map((r, i) => (
                      <li key={i}>
                        <a href={r} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline break-all">
                          {r.length > 60 ? r.slice(0, 60) + "..." : r}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Links externos */}
              <div className="flex gap-3 pt-3 border-t border-[var(--panel-border)]">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300 underline text-xs"
                >
                  Ver en NVD →
                </a>
                <a
                  href={`/dashboard/${cveId}`}
                  className="text-blue-400 hover:text-blue-300 underline text-xs"
                >
                  Ver en Dashboard →
                </a>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================
export default function AttackGroupDetail() {
  const { groupId } = useParams<{ groupId: string }>();
  const navigate = useNavigate();

  const [data, setData] = useState<DetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(25);

  // Modal states
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [alertDetailOpen, setAlertDetailOpen] = useState(false);
  const [selectedCVE, setSelectedCVE] = useState<string | null>(null);
  const [cveDetailOpen, setCveDetailOpen] = useState(false);

  // Estados para modal de resolución
  const [resolutionModal, setResolutionModal] = useState(false);
  const [resolutionForm, setResolutionForm] = useState({
    reason: '',
    type: 'mitigated' as 'mitigated' | 'false_positive' | 'accepted_risk'
  });

  // Estados para modal de reapertura
  const [reopenModal, setReopenModal] = useState(false);
  const [reopenReason, setReopenReason] = useState('')

  // CVE linking
  const [linkingCVE, setLinkingCVE] = useState(false);
  const [manualCVEInput, setManualCVEInput] = useState("");

  // Status update
  const [updatingStatus, setUpdatingStatus] = useState(false);

  // Fetch grupo y alertas
  const fetchGroupDetail = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await fetch(
        `/api/v1/alerts/groups/${groupId}?page=${page}&per_page=${perPage}`
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(json);
    } catch (e: any) {
      setError(e?.message || "Error cargando grupo");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (groupId) fetchGroupDetail();
  }, [groupId, page, perPage]);

  // Handler para abrir CVE en modal
  const openCVEDetail = (cveId: string) => {
    setSelectedCVE(cveId);
    setCveDetailOpen(true);
  };

  // Confirmar CVE sugerido
  const confirmCVE = async (cveId: string) => {
    setLinkingCVE(true);
    try {
      const res = await fetch(`/api/v1/alerts/groups/${groupId}/link-cve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cve_id: cveId }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${res.status}`);
      }
      await fetchGroupDetail(); // Refresh
    } catch (e: any) {
      alert(`Error al vincular CVE: ${e.message}`);
    } finally {
      setLinkingCVE(false);
    }
  };

  // Descartar CVE sugerido
  const discardCVE = async (cveId: string) => {
    setLinkingCVE(true);
    try {
      const res = await fetch(`/api/v1/alerts/groups/${groupId}/discard-cve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cve_id: cveId }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${res.status}`);
      }
      await fetchGroupDetail();
    } catch (e: any) {
      alert(`Error al descartar CVE: ${e.message}`);
    } finally {
      setLinkingCVE(false);
    }
  };

  // Desvincular CVE confirmado
  const unlinkCVE = async (cveId: string) => {
    if (!confirm(`¿Desvincular ${cveId} de este incidente?`)) return;
    setLinkingCVE(true);
    try {
      const res = await fetch(`/api/v1/alerts/groups/${groupId}/unlink-cve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cve_id: cveId }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${res.status}`);
      }
      await fetchGroupDetail();
    } catch (e: any) {
      alert(`Error al desvincular CVE: ${e.message}`);
    } finally {
      setLinkingCVE(false);
    }
  };

  // Vincular CVE manual
  const linkManualCVE = async () => {
    const cveId = manualCVEInput.trim().toUpperCase();
    if (!cveId.match(/^CVE-\d{4}-\d+$/)) {
      alert("Formato inválido. Usa CVE-YYYY-NNNNN");
      return;
    }
    await confirmCVE(cveId);
    setManualCVEInput("");
  };

  // Cambiar estado del incidente
  const updateStatus = async (newStatus: "active" | "resolved" | "re-opened") => {
    // Si es resolved o re-opened, abrir modal en vez de llamar directamente
    if (newStatus === 'resolved') {
      setResolutionModal(true);
      return;
    }
    
    if (newStatus === 're-opened') {
      setReopenModal(true);
      return;
    }
    
    // Para 'active', llamar directamente
    setUpdatingStatus(true);
    try {
      const res = await fetch(`/api/v1/alerts/groups/${groupId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'active' })
      });
      
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await fetchGroupDetail();
    } catch (e: any) {
      alert(`Error al actualizar estado: ${e.message}`);
    } finally {
      setUpdatingStatus(false);
    }
  };

  // Nueva función para resolver con el modal
  const confirmResolve = async () => {
    setUpdatingStatus(true);
    try {
      const res = await fetch(`/api/v1/alerts/groups/${groupId}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          confirmed: true,
          reason: resolutionForm.reason || 'Resuelto manualmente',
          resolution_type: resolutionForm.type
        })
      });
      
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      
      await fetchGroupDetail();
      setResolutionModal(false);
      setResolutionForm({ reason: '', type: 'mitigated' });
    } catch (e: any) {
      alert(`Error al resolver incidente: ${e.message}`);
    } finally {
      setUpdatingStatus(false);
    }
  };

  // Nueva función para reabrir con el modal
  const confirmReopen = async () => {
    setUpdatingStatus(true);
    try {
      const res = await fetch(`/api/v1/alerts/groups/${groupId}/reopen`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason: reopenReason || 'Reabierto manualmente'
        })
      });
      
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      
      await fetchGroupDetail();
      setReopenModal(false);
      setReopenReason('');
    } catch (e: any) {
      alert(`Error al reabrir incidente: ${e.message}`);
    } finally {
      setUpdatingStatus(false);
    }
  };

  if (loading && !data) {
    return (
      <div className="global-bg min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-6xl mb-4 animate-bounce">🔄</div>
          <p className="text-lg">Cargando incidente...</p>
        </div>
      </div>
    );
  }

  if (!data || !data.group) {
    return (
      <div className="global-bg">
        <div className="mx-auto max-w-[1600px] p-4">
          <Card className="bg-red-900/20 border-red-500/30">
            <CardContent className="pt-6">
              <p className="text-red-400 mb-3">{error || "Incidente no encontrado"}</p>
              <Button className="btn-outline" onClick={() => navigate("/alerts/groups")}>
                ← Volver a incidentes
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const group = data.group;
  const alerts = data.alerts;
  const pagination = data.pagination;

  const enrichmentInfo = ENRICHMENT_LABELS[group.enrichment_status || "unknown"];
  const durationFormatted = formatDuration(group.duration_seconds || 0);

  const lastAlertDate = typeof group.last_alert === "string"
    ? group.last_alert
    : group.last_alert?.$date;
  const timeSinceLastAlert = lastAlertDate
    ? Math.floor((Date.now() - new Date(lastAlertDate).getTime()) / 1000)
    : Infinity;
  const isRecentlyActive = timeSinceLastAlert < 3600;

  // Columnas de tabla de alertas
  const columns: ColumnDef<Alert>[] = [
    {
      accessorKey: "timestamp",
      header: "Fecha/Hora",
      cell: ({ row }) => <span className="text-xs">{fmtDate(row.original.timestamp)}</span>,
    },
    {
      accessorKey: "alert.signature",
      header: "Firma de Alerta",
      cell: ({ row }) => (
        <span className="text-sm max-w-xs truncate block" title={row.original.alert.signature}>
          {row.original.alert.signature}
        </span>
      ),
    },
    {
      accessorKey: "vuln_type",
      header: "Tipo",
      cell: ({ row }) => (
        <span className="text-xs">{row.original.vuln_type || "—"}</span>
      ),
    },
    {
      accessorKey: "src_ip",
      header: "Origen",
      cell: ({ row }) => (
        <code className="text-xs">{row.original.src_ip}:{row.original.src_port}</code>
      ),
    },
    {
      accessorKey: "dest_ip",
      header: "Destino",
      cell: ({ row }) => (
        <code className="text-xs">{row.original.dest_ip}:{row.original.dest_port}</code>
      ),
    },
    {
      accessorKey: "proto",
      header: "Proto",
      cell: ({ row }) => <span className="text-xs font-semibold">{row.original.proto}</span>,
    },
    {
      accessorKey: "alert.severity",
      header: "Severidad",
      cell: ({ row }) => {
        const sev = row.original.alert.severity;
        return (
          <span className={cn("px-2 py-0.5 rounded text-xs font-semibold", SEVERITY_COLORS[sev])}>
            {SEVERITY_LABELS[sev]}
          </span>
        );
      },
    },
  ];

  const totalPages = pagination.pages;

  return (
    <div className="global-bg">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8">
        {/* Header */}
        <header className="mb-4 flex items-start justify-between flex-wrap gap-3">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className="text-2xl">{PATTERN_ICONS[group.pattern] || "❓"}</span>
              <h1 className="text-2xl font-semibold">{group.group_id}</h1>
              {isRecentlyActive && (
                <span className="w-3 h-3 rounded-full bg-red-500 animate-pulse" title="Actividad reciente" />
              )}
            </div>
            <p className="text-sm text-[var(--muted)]">
              {group.vuln_type || group.attack_type || group.category} · {group.pattern}
            </p>
          </div>
          <div className="flex gap-2">
            <Button className="btn-ghost" onClick={() => navigate("/alerts/groups")}>
              ← Volver
            </Button>
            <Button className="btn-outline" onClick={fetchGroupDetail} disabled={loading}>
              🔄
            </Button>
          </div>
        </header>

        {/* KPIs del grupo */}
        <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-6">
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">Estado</CardTitle>
            </CardHeader>
            <CardContent>
              <span className={cn("px-2 py-1 rounded text-xs font-semibold border", STATUS_COLORS[group.status])}>
                {group.status}
              </span>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">Severidad</CardTitle>
            </CardHeader>
            <CardContent>
              <span className={cn("px-2 py-1 rounded text-xs font-semibold", SEVERITY_COLORS[group.severity])}>
                {SEVERITY_LABELS[group.severity]}
              </span>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">Total Alertas</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{group.alert_count}</CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">Duración</CardTitle>
            </CardHeader>
            <CardContent className="text-sm font-semibold">{durationFormatted}</CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">Primera Alerta</CardTitle>
            </CardHeader>
            <CardContent className="text-xs">{fmtDateShort(group.first_alert)}</CardContent>
          </Card>

          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">Última Alerta</CardTitle>
            </CardHeader>
            <CardContent className="text-xs">
              {fmtDateShort(group.last_alert)}
              {isRecentlyActive && <span className="text-red-400 ml-1">🔴</span>}
            </CardContent>
          </Card>
        </div>

        {/* Detalles del ataque y Asset */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
          {/* Origen y destino */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Información de Red</CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-4">
              {/* Origen */}
              <div className="panel p-4 rounded-lg bg-rose-900/20 border border-rose-500/30">
                <div className="text-xs text-rose-300 mb-2 font-semibold">🔴 IP Atacante</div>
                <div className="text-xl font-mono font-bold text-rose-400 mb-2">{group.src_ip}</div>
                {group.source_asset?.is_internal && (
                  <div className="text-xs text-yellow-400">
                    ⚠️ Interno: {group.source_asset.hostname}
                  </div>
                )}
              </div>

              {/* Destino */}
              <div className="panel p-4 rounded-lg bg-blue-900/20 border border-blue-500/30">
                <div className="text-xs text-blue-300 mb-2 font-semibold">🔵 IP Víctima</div>
                <div className="text-xl font-mono font-bold text-blue-400 mb-2">{group.dest_ip}</div>
              </div>
            </CardContent>
          </Card>

          {/* Asset Info */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center justify-between">
                <span>Asset Objetivo</span>
                <span className={cn("px-2 py-1 rounded text-xs border", enrichmentInfo.color)}>
                  {enrichmentInfo.label}
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {group.target_asset?.known ? (
                <div className="panel p-4 rounded-lg bg-emerald-900/20 border border-emerald-500/30">
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div><span className="text-emerald-300 text-xs">Hostname:</span> <span className="font-medium">{group.target_asset.hostname || "—"}</span></div>
                    <div><span className="text-emerald-300 text-xs">Rol:</span> <span className="font-medium">{group.target_asset.role || "—"}</span></div>
                    <div><span className="text-emerald-300 text-xs">Componente 5G:</span> <span className="font-medium">{group.target_asset.component_5g || "—"}</span></div>
                    <div><span className="text-emerald-300 text-xs">Software:</span> <span className="font-medium">{group.target_asset.software || "—"}</span></div>
                    <div><span className="text-emerald-300 text-xs">Versión:</span> <span className="font-medium">{group.target_asset.version || "—"}</span></div>
                    <div><span className="text-emerald-300 text-xs">Criticidad:</span> <span className="font-medium">{group.target_asset.criticality || "—"}</span></div>
                  </div>
                </div>
              ) : (
                <div className="panel p-4 rounded-lg bg-amber-900/20 border border-amber-500/30">
                  <p className="text-amber-300 text-sm mb-3">
                    ⚠️ El destino <code className="bg-amber-950/50 px-1 rounded">{group.dest_ip}</code> no está registrado en el Asset Inventory.
                  </p>
                  <p className="text-xs text-amber-200/70 mb-3">
                    Las sugerencias de CVE tienen menor fiabilidad cuando el asset es desconocido.
                  </p>
                  <Button
                    className="btn-outline text-xs"
                    onClick={() => navigate(`/assets?register=${group.dest_ip}`)}
                  >
                    📝 Registrar Asset
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* CVEs Section */}
        <Card className="mb-6">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">🔗 CVEs Vinculados</CardTitle>
          </CardHeader>
          <CardContent>
            {/* CVEs confirmados */}
            {group.confirmed_cves && group.confirmed_cves.length > 0 ? (
              <div className="mb-4">
                <div className="text-xs text-emerald-300 mb-2 font-semibold">✅ Confirmados por analista:</div>
                <div className="flex flex-wrap gap-2">
                  {group.confirmed_cves.map((cve) => (
                    <div key={cve} className="flex items-center gap-1 px-3 py-1.5 bg-emerald-900/30 border border-emerald-500/40 rounded-lg">
                      <button
                        onClick={() => openCVEDetail(cve)}
                        className="font-mono text-sm text-emerald-300 hover:text-emerald-200 underline"
                      >
                        {cve}
                      </button>
                      <button
                        onClick={() => unlinkCVE(cve)}
                        className="text-emerald-400/50 hover:text-red-400 ml-2 text-xs"
                        title="Desvincular"
                        disabled={linkingCVE}
                      >
                        ✕
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="mb-4 text-sm text-slate-400">
                No hay CVEs confirmados para este incidente.
              </div>
            )}

            {/* Vincular CVE manual */}
            <div className="flex items-center gap-2 mb-4 pt-3 border-t border-[var(--panel-border)]">
              <Input
                className="max-w-xs text-sm"
                placeholder="CVE-2024-XXXXX"
                value={manualCVEInput}
                onChange={(e) => setManualCVEInput(e.target.value.toUpperCase())}
                onKeyDown={(e) => e.key === "Enter" && linkManualCVE()}
              />
              <Button className="btn-outline text-xs" onClick={linkManualCVE} disabled={linkingCVE || !manualCVEInput}>
                ➕ Vincular CVE
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* CVE Suggestions */}
        {group.cve_suggestions && group.cve_suggestions.length > 0 && (
          <Card className="mb-6">
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                💡 Sugerencias de CVE
                <span className="text-xs font-normal text-amber-300">
                  (requieren validación manual)
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {!group.target_asset?.known && (
                <div className="mb-4 p-3 bg-amber-900/20 border border-amber-500/30 rounded-lg text-xs text-amber-300">
                  ⚠️ <strong>Advertencia:</strong> El asset destino es desconocido. Estas sugerencias tienen <strong>menor fiabilidad</strong>.
                  Registra el asset para mejorar la precisión de las correlaciones.
                </div>
              )}

              <div className="space-y-3">
                {group.cve_suggestions.map((sug) => (
                  <div
                    key={sug.cve_id}
                    className="flex items-center justify-between p-3 bg-slate-800/40 border border-slate-700 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => openCVEDetail(sug.cve_id)}
                        className="font-mono text-sm text-blue-400 hover:text-blue-300 underline"
                      >
                        {sug.cve_id}
                      </button>
                      {sug.cvss_score && (
                        <span className={`badge badge-${cvssSeverity(sug.cvss_score)} text-xs`}>
                          {sug.cvss_score.toFixed(1)}
                        </span>
                      )}
                      <span className={cn("px-2 py-0.5 rounded text-xs font-semibold", CONFIDENCE_COLORS[sug.confidence])}>
                        {sug.confidence}
                      </span>
                      {sug.tipo && (
                        <span className="text-xs text-slate-400">{sug.tipo}</span>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-400 max-w-xs truncate hidden md:block" title={sug.reason}>
                        {sug.reason}
                      </span>
                      <Button
                        className="btn-outline text-xs px-2 py-1"
                        onClick={() => confirmCVE(sug.cve_id)}
                        disabled={linkingCVE}
                        title="Confirmar CVE"
                      >
                        ✓
                      </Button>
                      <Button
                        className="btn-ghost text-xs px-2 py-1"
                        onClick={() => discardCVE(sug.cve_id)}
                        disabled={linkingCVE}
                        title="Descartar sugerencia"
                      >
                        ✕
                      </Button>
                    </div>
                  </div>
                ))}
              </div>

              {group.cve_suggestions.some((s) => s.warning) && (
                <div className="mt-3 p-2 bg-amber-900/20 border border-amber-500/20 rounded text-xs text-amber-300">
                  ⚠️ {group.cve_suggestions.find((s) => s.warning)?.warning}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Acciones del incidente */}
        <Card className="mb-6">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">⚙️ Acciones</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              {group.status !== "resolved" && (
                <Button
                  className="btn-solid bg-emerald-600 hover:bg-emerald-700"
                  onClick={() => updateStatus("resolved")}
                  disabled={updatingStatus}
                >
                  ✅ Marcar como resuelto
                </Button>
              )}
              {group.status === "resolved" && (
                <Button
                  className="btn-outline"
                  onClick={() => updateStatus("re-opened")}
                  disabled={updatingStatus}
                >
                  🔄 Reabrir incidente
                </Button>
              )}
              {group.status === "re-opened" && (
                <Button
                  className="btn-outline"
                  onClick={() => updateStatus("active")}
                  disabled={updatingStatus}
                >
                  ⚡ Marcar como activo
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Tabla de alertas */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">
              📋 Alertas del Incidente ({pagination.total} total)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={columns}
              data={alerts}
              onRowClick={(row) => {
                setSelectedAlert(row);
                setAlertDetailOpen(true);
              }}
            />

            {/* Paginador */}
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm text-[var(--muted)]">
                Página <strong>{page}</strong> de <strong>{totalPages}</strong> ·
                Mostrando <strong>{alerts.length}</strong> de <strong>{pagination.total}</strong>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-sm">Por página</label>
                <select
                  className="rounded-md border px-2 py-1 text-sm"
                  value={perPage}
                  onChange={(e) => {
                    setPerPage(Number(e.target.value));
                    setPage(1);
                  }}
                >
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
                <Button
                  className="btn-outline px-2 py-1"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  ← Anterior
                </Button>
                <Button
                  className="btn-outline px-2 py-1"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Siguiente →
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Modal detalle de alerta */}
        {alertDetailOpen && selectedAlert && (
          <div className="fixed inset-0 z-50">
            <div className="absolute inset-0 bg-black/40" onClick={() => setAlertDetailOpen(false)} />
            <div className="absolute right-0 top-0 h-full w-full max-w-2xl bg-[#0d1117] border-l border-slate-700 overflow-y-auto p-4">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-lg font-semibold">Detalles de Alerta</h2>
                <Button className="btn-outline" onClick={() => setAlertDetailOpen(false)}>
                  Cerrar
                </Button>
              </div>

              <div className="space-y-4 text-sm">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-xs text-[var(--muted)] mb-1">Timestamp</div>
                    <div className="font-mono text-xs">{fmtDate(selectedAlert.timestamp)}</div>
                  </div>
                  <div>
                    <div className="text-xs text-[var(--muted)] mb-1">Tipo Vulnerabilidad</div>
                    <span className="text-sm font-medium">{selectedAlert.vuln_type || "—"}</span>
                  </div>
                </div>

                <div>
                  <div className="text-xs text-[var(--muted)] mb-1">Firma de Alerta</div>
                  <div className="panel p-2 bg-slate-800/40 rounded text-xs">
                    {selectedAlert.alert.signature}
                  </div>
                </div>

                {selectedAlert.cve_in_signature && (
                  <div>
                    <div className="text-xs text-[var(--muted)] mb-1">CVE en firma (referencia)</div>
                    <button
                      onClick={() => {
                        setAlertDetailOpen(false);
                        openCVEDetail(selectedAlert.cve_in_signature!);
                      }}
                      className="font-mono text-sm text-blue-400 hover:text-blue-300 underline"
                    >
                      {selectedAlert.cve_in_signature}
                    </button>
                    <span className="text-xs text-amber-400 ml-2">
                      (solo referencia, no correlación automática)
                    </span>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-xs text-[var(--muted)] mb-1">Origen</div>
                    <div className="font-mono text-xs">
                      {selectedAlert.src_ip}:{selectedAlert.src_port}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-[var(--muted)] mb-1">Destino</div>
                    <div className="font-mono text-xs">
                      {selectedAlert.dest_ip}:{selectedAlert.dest_port}
                    </div>
                  </div>
                </div>

                {selectedAlert.http && (
                  <div className="panel p-3 bg-slate-800/40 rounded">
                    <div className="text-xs text-[var(--muted)] mb-2 font-semibold">📡 HTTP Data</div>
                    <div className="text-xs space-y-1">
                      {selectedAlert.http.http_method && (
                        <div><strong>Método:</strong> {selectedAlert.http.http_method}</div>
                      )}
                      {selectedAlert.http.url && (
                        <div><strong>URL:</strong> <code className="bg-slate-900 px-1 rounded break-all">{selectedAlert.http.url}</code></div>
                      )}
                      {selectedAlert.http.hostname && (
                        <div><strong>Host:</strong> {selectedAlert.http.hostname}</div>
                      )}
                      {selectedAlert.http.status && (
                        <div><strong>Status:</strong> {selectedAlert.http.status}</div>
                      )}
                      {selectedAlert.http.http_user_agent && (
                        <div><strong>User-Agent:</strong> <span className="break-all">{selectedAlert.http.http_user_agent}</span></div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Modal detalle de CVE */}
        {cveDetailOpen && selectedCVE && (
          <CVEDetailModal
            cveId={selectedCVE}
            onClose={() => {
              setCveDetailOpen(false);
              setSelectedCVE(null);
            }}
          />
        )}

        {/* Modal de Resolución */}
        {resolutionModal && (
          <div className="fixed inset-0 z-[70]">
            <div className="absolute inset-0 bg-black/60" onClick={() => setResolutionModal(false)} />
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md panel p-6">
              <h3 className="text-lg font-semibold mb-4">Resolver Incidente</h3>
              
              <div className="space-y-4">
                <div>
                  <Label className="text-sm mb-2">Tipo de Resolución</Label>
                  <select
                    className="w-full mt-1 rounded-md border px-3 py-2 text-sm bg-slate-900 border-slate-700"
                    value={resolutionForm.type}
                    onChange={(e) => setResolutionForm({
                      ...resolutionForm, 
                      type: e.target.value as any
                    })}
                  >
                    <option value="mitigated">✅ Mitigado</option>
                    <option value="false_positive">❌ Falso Positivo</option>
                    <option value="accepted_risk">⚠️ Riesgo Aceptado</option>
                  </select>
                </div>
                
                <div>
                  <Label className="text-sm mb-2">Motivo (opcional)</Label>
                  <textarea
                    className="w-full mt-1 rounded-md border px-3 py-2 text-sm bg-slate-900 border-slate-700 min-h-[100px]"
                    placeholder="Ej: Aplicado parche de seguridad, regla de firewall actualizada..."
                    value={resolutionForm.reason}
                    onChange={(e) => setResolutionForm({...resolutionForm, reason: e.target.value})}
                  />
                </div>
                
                <div className="flex gap-2 justify-end pt-2">
                  <Button
                    className="btn-outline"
                    onClick={() => {
                      setResolutionModal(false);
                      setResolutionForm({ reason: '', type: 'mitigated' });
                    }}
                  >
                    Cancelar
                  </Button>
                  <Button
                    className="btn-solid bg-emerald-600 hover:bg-emerald-700"
                    onClick={confirmResolve}
                    disabled={updatingStatus}
                  >
                    {updatingStatus ? 'Resolviendo...' : '✅ Confirmar Resolución'}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Modal de Reapertura */}
        {reopenModal && (
          <div className="fixed inset-0 z-[70]">
            <div className="absolute inset-0 bg-black/60" onClick={() => setReopenModal(false)} />
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md panel p-6">
              <h3 className="text-lg font-semibold mb-4">Reabrir Incidente</h3>
              
              <div className="space-y-4">
                <div>
                  <Label className="text-sm mb-2">Motivo de Reapertura (opcional)</Label>
                  <textarea
                    className="w-full mt-1 rounded-md border px-3 py-2 text-sm bg-slate-900 border-slate-700 min-h-[100px]"
                    placeholder="Ej: Se detectó nueva actividad, incidente no completamente resuelto..."
                    value={reopenReason}
                    onChange={(e) => setReopenReason(e.target.value)}
                  />
                </div>
                
                <div className="flex gap-2 justify-end pt-2">
                  <Button
                    className="btn-outline"
                    onClick={() => {
                      setReopenModal(false);
                      setReopenReason('');
                    }}
                  >
                    Cancelar
                  </Button>
                  <Button
                    className="btn-solid bg-amber-600 hover:bg-amber-700"
                    onClick={confirmReopen}
                    disabled={updatingStatus}
                  >
                    {updatingStatus ? 'Reabriendo...' : '🔄 Confirmar Reapertura'}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}