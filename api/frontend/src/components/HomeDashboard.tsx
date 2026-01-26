import React, { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useNavigate } from "react-router-dom";

// ============================================================================
// TYPES
// ============================================================================
type Alert = {
  _id: string;
  timestamp: string;
  src_ip: string;
  dest_ip: string;
  alert: {
    signature: string;
    category: string;
    severity: number;
  };
};

type AttackGroup = {
  _id: string;
  group_id: string;
  src_ip: string;
  dest_ip: string;
  category: string;
  attack_type?: string;
  severity: number;
  alert_count: number;
  status: "active" | "resolved" | "re-opened";
};

type CVE = {
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

// ============================================================================
// CONSTANTS
// ============================================================================
const SEVERITY_COLORS: Record<number, string> = {
  1: "bg-red-600 text-white",
  2: "bg-orange-500 text-white",
  3: "bg-yellow-400 text-black",
  4: "bg-green-500 text-white",
};

const SEVERITY_LABELS: Record<number, string> = {
  1: "Critical",
  2: "High",
  3: "Medium",
  4: "Low",
};

// ============================================================================
// HELPERS
// ============================================================================
const fmtDate = (iso: string) => {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso?.slice(0, 10) || "";
  return d.toLocaleString("es-ES");
};

const fmtDateShort = (dateObj: { $date: string } | string) => {
  const dateStr = typeof dateObj === "string" ? dateObj : dateObj?.$date;
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("es-ES");
};

const cvssSeverity = (s: number) => (s >= 9 ? "crit" : s >= 7 ? "high" : s >= 4 ? "med" : "low");

// ============================================================================
// CVE DETAIL MODAL COMPONENT
// ============================================================================
function CVEDetailModal({ 
  cve, 
  onClose 
}: { 
  cve: CVE; 
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="absolute right-0 top-0 h-full w-full max-w-2xl bg-[#0d1117] border-l border-slate-700 overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-[#0d1117] border-b border-slate-700 px-4 py-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold">{cve.cve_id}</h2>
          <Button className="btn-outline" onClick={onClose}>
            ✕ Cerrar
          </Button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4 text-sm">
          {/* Score badge */}
          <div className="flex items-center gap-3">
            <span className={`badge badge-${cvssSeverity(cve.cvssv3?.score ?? 0)} text-lg px-3 py-1`}>
              {cve.cvssv3?.score?.toFixed(1) || "N/A"}
            </span>
            {cve.cvssv3?.vector && (
              <span className="chip chip-muted text-xs">{cve.cvssv3.vector}</span>
            )}
          </div>

          {/* Descripción */}
          <div>
            <div className="text-xs text-[var(--muted)] mb-1">Descripción</div>
            <p className="whitespace-pre-wrap text-slate-300">
              {cve.descripcion_general || cve.nombre}
            </p>
          </div>

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
                    <a href={r} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline">
                      {r.length > 60 ? r.slice(0, 60) + "..." : r}
                    </a>
                  </li>
                ))}
              </ul>
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
export default function HomeDashboard() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [groups, setGroups] = useState<AttackGroup[]>([]);
  const [criticalCVEs, setCriticalCVEs] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCVE, setSelectedCVE] = useState<CVE | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsRes, groupsRes, cvesRes] = await Promise.all([
          fetch("/api/v1/alerts?limit=5&enrich=true"),
          fetch("/api/v1/alerts/groups?page=1&per_page=10"),
          fetch("/api/v1/cves?min_score=9")
        ]);

        const alertsJson = await alertsRes.json();
        const groupsJson = await groupsRes.json();
        const cvesJson = await cvesRes.json();

        setAlerts(alertsJson.alerts || []);
        setGroups(groupsJson.groups || []);
        setCriticalCVEs(cvesJson.cves || []);
      } catch (e) {
        console.error("❌ Error cargando datos iniciales", e);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  // KPIs derivados
  const activeGroupsCount = groups.filter((g) => g.status === "active").length;
  const totalEventos = groups.reduce((sum, g) => sum + g.alert_count, 0);
  const criticalGroupsCount = groups.filter((g) => g.severity === 1).length;

  if (loading) {
    return (
      <div className="global-bg min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-6xl mb-4 animate-pulse">📊</div>
          <p className="text-lg">Cargando dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="global-bg">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8">
        <header className="mb-6">
          <h1 className="text-2xl font-semibold">📌 Resumen General</h1>
          <p className="text-sm text-[var(--muted)]">
            Visión rápida de vulnerabilidades y ataques
          </p>
        </header>

        {/* KPIs */}
        <div className="mb-6 grid grid-cols-2 md:grid-cols-4 gap-3">
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">Eventos Totales</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{totalEventos}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">Grupos Activos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-yellow-400">
              {activeGroupsCount}
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">CVEs Críticas</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-red-600">
              {criticalCVEs.length}
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle className="text-xs">Grupos Críticos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold text-red-600">
              {criticalGroupsCount}
            </CardContent>
          </Card>
        </div>

        {/* Acciones rápidas */}
        <div className="mb-6 flex flex-wrap gap-3">
          <Button className="btn-outline" onClick={() => navigate("/alerts/events")}>
            👁️ Ver todos los eventos
          </Button>
          <Button className="btn-outline" onClick={() => navigate("/alerts/groups")}>
            🚨 Ver grupos activos
          </Button>
          <Button className="btn-outline" onClick={() => navigate("/dashboard")}>
            📊 Dashboard CVEs
          </Button>
        </div>

        {/* Últimos Eventos */}
        <Card className="mb-6">
          <CardHeader className="py-2 flex items-center justify-between">
            <CardTitle>Últimos 5 Eventos</CardTitle>
            <Button className="btn-ghost text-xs" onClick={() => navigate("/alerts/events")}>
              Ver todos →
            </Button>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[var(--muted)] border-b border-[var(--panel-border)]">
                  <th className="py-2 px-2 text-left">Timestamp</th>
                  <th className="py-2 px-2 text-left">Firma</th>
                  <th className="py-2 px-2 text-left">Origen → Destino</th>
                  <th className="py-2 px-2 text-center">Severidad</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-3 text-center text-[var(--muted)]">
                      Sin eventos recientes
                    </td>
                  </tr>
                ) : (
                  alerts.map((a) => (
                    <tr
                      key={a._id}
                      className="border-b border-[var(--panel-border)] hover:bg-slate-700/20 transition-colors cursor-pointer"
                      onClick={() => navigate("/alerts/events")}
                    >
                      <td className="py-2 px-2 text-xs">{fmtDate(a.timestamp)}</td>
                      <td className="py-2 px-2 max-w-xs truncate text-xs">
                        {a.alert.signature}
                      </td>
                      <td className="py-2 px-2 font-mono text-xs">
                        {a.src_ip} → {a.dest_ip}
                      </td>
                      <td className="py-2 px-2 text-center">
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_COLORS[a.alert.severity]}`}>
                          {SEVERITY_LABELS[a.alert.severity]}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </CardContent>
        </Card>

        {/* Grupos Activos */}
        <Card className="mb-6">
          <CardHeader className="py-2 flex items-center justify-between">
            <CardTitle>Grupos Activos ({activeGroupsCount})</CardTitle>
            <Button className="btn-ghost text-xs" onClick={() => navigate("/alerts/groups")}>
              Ver todos →
            </Button>
          </CardHeader>
          <CardContent>
            {groups.filter((g) => g.status === "active").length === 0 ? (
              <p className="text-sm text-[var(--muted)]">
                No hay grupos activos en este momento
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {groups
                  .filter((g) => g.status === "active")
                  .slice(0, 3)
                  .map((g) => (
                    <div
                      key={g._id}
                      onClick={() => navigate(`/alerts/groups/${g._id}`)}
                      className="panel p-3 rounded-lg border border-yellow-500/30 hover:border-yellow-400 transition-colors cursor-pointer hover:bg-yellow-900/10"
                    >
                      <div className="flex items-start justify-between mb-2">
                        <span className="font-mono font-bold text-yellow-400">
                          {g.group_id}
                        </span>
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_COLORS[g.severity] || SEVERITY_COLORS[4]}`}>
                          {SEVERITY_LABELS[g.severity] || "Unknown"}
                        </span>
                      </div>
                      <div className="text-xs space-y-1">
                        <div>
                          <span className="text-[var(--muted)]">Origen:</span> {g.src_ip}
                        </div>
                        <div>
                          <span className="text-[var(--muted)]">Destino:</span> {g.dest_ip}
                        </div>
                        <div className="pt-1 border-t border-[var(--panel-border)]">
                          <span className="text-[var(--muted)]">Eventos:</span>{" "}
                          <strong className="text-blue-400">{g.alert_count}</strong>
                        </div>
                      </div>
                    </div>
                  ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* CVEs Críticas */}
        <Card>
          <CardHeader className="py-2 flex items-center justify-between">
            <CardTitle>Top CVEs Críticas</CardTitle>
            <Button className="btn-ghost text-xs" onClick={() => navigate("/dashboard?min_score=9")}>
              Ver todas →
            </Button>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[var(--muted)] border-b border-[var(--panel-border)]">
                  <th className="py-2 px-2 text-left">CVE ID</th>
                  <th className="py-2 px-2 text-left">Nombre</th>
                  <th className="py-2 px-2 text-right">CVSS</th>
                </tr>
              </thead>
              <tbody>
                {criticalCVEs.slice(0, 5).map((c) => (
                  <tr
                    key={c.cve_id}
                    className="border-b border-[var(--panel-border)] hover:bg-slate-700/20 transition-colors cursor-pointer"
                    onClick={() => setSelectedCVE(c)}
                  >
                    <td className="py-2 px-2 font-mono text-blue-400 hover:text-blue-300">
                      {c.cve_id}
                    </td>
                    <td className="py-2 px-2 max-w-xs truncate">{c.nombre}</td>
                    <td className="py-2 px-2 text-right">
                      <span className="bg-red-600 text-white px-2 py-0.5 rounded text-xs font-semibold">
                        {c.cvssv3?.score.toFixed(1) || "N/A"}
                      </span>
                    </td>
                  </tr>
                ))}
                {criticalCVEs.length === 0 && (
                  <tr>
                    <td colSpan={3} className="py-3 text-center text-[var(--muted)]">
                      Sin CVEs críticas
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </CardContent>
        </Card>

        {/* Modal de CVE */}
        {selectedCVE && (
          <CVEDetailModal
            cve={selectedCVE}
            onClose={() => setSelectedCVE(null)}
          />
        )}
      </div>
    </div>
  );
}