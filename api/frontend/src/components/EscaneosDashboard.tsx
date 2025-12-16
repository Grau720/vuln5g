// components/EscaneosDashboard.tsx
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Popover, PopoverTrigger, PopoverContent } from "@/components/ui/popover";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { DataTable } from "@/components/ui/data-table";
import type { ColumnDef } from "@tanstack/react-table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ResponsiveContainer, BarChart, Bar, CartesianGrid, XAxis, YAxis, Tooltip as ReTooltip } from "recharts";
import { cn } from "@/lib/utils";
import { useNavigate } from "react-router-dom";

/* ============================
   Tipos
============================ */
type ScanJob = {
  job_id: string;
  created_at: string;
  profile: string;
  status: "queued" | "running" | "finished" | "error";
  progress: number;
  targets: Record<string, string[]>;
  plugins?: string[];
  metrics?: {
    criticity?: {
      coverage: number;
      avg_score: number;
      max_score: number;
    };
  };
};

type Finding = {
  finding_id: string;
  component: string;
  interface?: string;
  protocol?: string;
  cve_ids?: string[];            // legado
  cve_candidates?: string[];     // <-- nuevo: sugeridos por correlator
  risk: { cvss_v3: number; label: string };
  summary: string;
  recommendation?: string;
};  

type Plugin = { id: string; component: string; interfaces: string[]; profile: string };

type Schedule = {
  schedule_id: string;
  name: string;
  enabled: boolean;
  profile: string;
  targets: Record<string, string[]>;
  plugins: string[];
  tz: string;
  rrule?: string | null;
  start_at?: string | null;
  run_at?: string | null;
  next_run?: string | null;
  last_run?: string | null;
  created_at?: string;
  updated_at?: string;
};

/* ============================
   Constantes & helpers
============================ */
const PAGE_CHOICES = [5, 10, 25, 50] as const;
type StatusFilter = "all" | "queued" | "running" | "finished" | "error";
const statusMatch = (s: ScanJob["status"], f: StatusFilter) => f === "all" || s === f;
const isActiveStatus = (s: ScanJob["status"]) => s === "queued" || s === "running";
const canCancel = (s: ScanJob["status"]) => s === "queued" || s === "running";
const canRerun  = (s: ScanJob["status"]) => s === "finished" || s === "error";

/* ============================
   Componente principal
============================ */
export default function EscaneosDashboard({
  endpointJobs = "/api/scan/jobs",
  endpointFindings = "/api/scan/jobs",
  endpointPlugins = "/api/scan/plugins",
}: {
  endpointJobs?: string;
  endpointFindings?: string;
  endpointPlugins?: string;
}) {
  // ---- Estado base ----
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [selJob, setSelJob] = useState<ScanJob | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const [critCountByJob, setCritCountByJob] = useState<Record<string, number>>({});
  const [tab, setTab] = useState<"active" | "finished" | "findings" | "charts" | "planner">("active");
  const [showNew, setShowNew] = useState(false);
  const [showNewSched, setShowNewSched] = useState(false);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(false);
  const [filterText, setFilterText] = useState("");          // buscar por job_id
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [profileFilter, setProfileFilter] = useState("");    // fast/standard/exhaustive
  const [errMsg, setErrMsg] = useState<string>("");          // banner de error
  const [exportOpen, setExportOpen] = useState(false);

  // acciones en curso por job (bloquea botones de ese job y evita dobles clicks)
  const [jobBusy, setJobBusy] = useState<Record<string, boolean>>({});

  // ---- Refs para SSE/poll ----
  const sseRefs = useRef<Record<string, EventSource>>({});
  const hasSSE = typeof window !== "undefined" && "EventSource" in window;

  // ---- Derivados ----
  const filteredJobs = useMemo(() => {
    const t = filterText.trim().toLowerCase();
    const p = profileFilter.trim().toLowerCase();
    return jobs.filter(j =>
      statusMatch(j.status, statusFilter) &&
      (!t || j.job_id.toLowerCase().includes(t)) &&
      (!p || j.profile.toLowerCase().includes(p))
    );
  }, [jobs, filterText, statusFilter, profileFilter]);

  const jobsActiveFiltered   = useMemo(() => filteredJobs.filter(j => isActiveStatus(j.status)), [filteredJobs]);
  const jobsFinishedFiltered = useMemo(() => filteredJobs.filter(j => !isActiveStatus(j.status)), [filteredJobs]);

  const totalJobs     = jobs.length;
  const finishedCount = jobs.filter(j => j.status === "finished").length;
  const avgProgress   = jobs.reduce((a, b) => a + (b.progress || 0), 0) / Math.max(1, totalJobs);
  const criticalFinds = findings.filter(f => ["Critical", "High"].includes(f.risk.label)).length;

  // Navegación
  const navigate = useNavigate();

  // ---- Paginaciones ----
  // Activos
  const [perPageJobsActive, setPerPageJobsActive] = useState<number>(() => Number(localStorage.getItem("scan:pp:active") || 10));
  const [pageJobsActive, setPageJobsActive] = useState(1);
  useEffect(() => { localStorage.setItem("scan:pp:active", String(perPageJobsActive)); }, [perPageJobsActive]);

  // Finalizados
  const [perPageJobsFin, setPerPageJobsFin] = useState<number>(() => {
    const v = Number(localStorage.getItem("scan:pp:fin"));
    return Number.isFinite(v) && v > 0 ? v : 10;
  });
  const [pageJobsFin, setPageJobsFin] = useState(1);
  useEffect(() => { localStorage.setItem("scan:pp:fin", String(perPageJobsFin)); }, [perPageJobsFin]);

  // Sidebar (lista de jobs en Hallazgos)
  const [perPageSide, setPerPageSide] = useState<number>(() => {
    const v = Number(localStorage.getItem("scan:pp:side"));
    return Number.isFinite(v) && v > 0 ? v : 10;
  });
  const [pageSide, setPageSide] = useState(1);
  useEffect(() => { localStorage.setItem("scan:pp:side", String(perPageSide)); }, [perPageSide]);


  // Activos
  const maxPagesActive = Math.max(1, Math.ceil(jobsActiveFiltered.length / perPageJobsActive));
  const jobsActivePage = useMemo(
    () => jobsActiveFiltered.slice((pageJobsActive - 1) * perPageJobsActive, pageJobsActive * perPageJobsActive),
    [jobsActiveFiltered, pageJobsActive, perPageJobsActive]
  );

  // Finalizados
  const maxPagesFin = Math.max(1, Math.ceil(jobsFinishedFiltered.length / perPageJobsFin));
  const jobsFinishedPage = useMemo(
    () => jobsFinishedFiltered.slice((pageJobsFin - 1) * perPageJobsFin, pageJobsFin * perPageJobsFin),
    [jobsFinishedFiltered, pageJobsFin, perPageJobsFin]
  );

  // Sidebar (hallazgos)
  const maxSidePages = Math.max(1, Math.ceil(filteredJobs.length / perPageSide));
  const jobsSide = useMemo(
    () => filteredJobs.slice((pageSide - 1) * perPageSide, pageSide * perPageSide),
    [filteredJobs, pageSide, perPageSide]
  );

  useEffect(() => { setPageJobsFin(p => Math.min(Math.max(1, p), maxPagesFin)); }, [maxPagesFin]);
  useEffect(() => { setPageSide(p => Math.min(Math.max(1, p), maxSidePages)); }, [maxSidePages]);

  // ---- Fetchers ----
  const fetchJobs = async () => {
    setLoading(true);
    try {
      const r = await fetch(endpointJobs);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setJobs(j.jobs || j || []);
      setErrMsg(""); // limpia error si se recupera
    } catch (e) {
      setErrMsg("No se pudo cargar la lista de jobs. Revisa conectividad o el backend.");
    } finally {
      setLoading(false);
    }
  };

  const fetchPlugins = async () => {
    try {
      const r = await fetch(endpointPlugins);
      const j = await r.json();
      setPlugins(j.plugins || []);
    } catch {}
  };

  const fetchSchedules = async () => {
    try {
      const r = await fetch("/api/scan/schedules");
      const j = await r.json();
      setSchedules(j.schedules || []);
    } catch {}
  };

  const fetchFindings = async (jobId: string) => {
    try {
      const r = await fetch(`${endpointFindings}/${jobId}/findings`);
      const j = await r.json();
      const fins = j.findings || [];
      setFindings(fins);
      const n = fins.filter((f: any) => ["High", "Critical"].includes(f?.risk?.label)).length;
      setCritCountByJob(prev => ({ ...prev, [jobId]: n }));
    } catch {}
  };

  // ---- Acciones por job ----
  const handleJobAction = async (jobId: string, action: "rerun" | "cancel" | "delete") => {
    setJobBusy(prev => ({ ...prev, [jobId]: true }));
    try {
      await fetch(`/api/scan/jobs/${jobId}/action`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      });
      if (action === "delete" && selJob?.job_id === jobId) {
        setSelJob(null);
        setFindings([]);
      }
      await fetchJobs();
    } finally {
      setJobBusy(prev => ({ ...prev, [jobId]: false }));
    }
  };

  // ---- Inicialización ----
  useEffect(() => { fetchJobs(); fetchPlugins(); fetchSchedules(); }, []);

  // ---- SSE (tiempo real) + fallback polling ----
  useEffect(() => {
    if (!hasSSE) return;
    const active = jobs.filter(j => isActiveStatus(j.status));

    // crear ES por cada activo
    active.forEach(j => {
      if (sseRefs.current[j.job_id]) return;
      const es = new EventSource(`/api/scan/jobs/${j.job_id}/stream`);
      es.onmessage = (ev) => {
        try {
          const updated = JSON.parse(ev.data);
          setJobs(prev => prev.map(x => x.job_id === updated.job_id ? { ...x, ...updated } : x));
        } catch {}
      };
      es.addEventListener("gone", () => { es.close(); delete sseRefs.current[j.job_id]; });
      es.onerror = () => { es.close(); delete sseRefs.current[j.job_id]; };
      sseRefs.current[j.job_id] = es;
    });

    // cerrar ES no activos
    Object.keys(sseRefs.current).forEach(id => {
      const stillActive = active.some(j => j.job_id === id);
      if (!stillActive) { sseRefs.current[id].close(); delete sseRefs.current[id]; }
    });

    // limpieza on unmount
    return () => {
      Object.values(sseRefs.current).forEach(es => es.close());
      sseRefs.current = {};
    };
  }, [jobs, hasSSE]);

  // Fallback polling sólo si NO hay SSE
  useEffect(() => {
    if (hasSSE) return;
    const active = jobs.some(j => isActiveStatus(j.status));
    if (!active) return;

    const t = setInterval(fetchJobs, 5000);
    return () => clearInterval(t);
  }, [jobs, hasSSE]);

  // ---- Deep-link (tab + job) ----
  useEffect(() => {
    if (!restoredFromURL.current) return;  // 👈 no tocar la URL hasta que se haya restaurado
    const sp = new URLSearchParams(window.location.search);
    sp.set("tab", tab);
    if (selJob?.job_id) sp.set("job", selJob.job_id); else sp.delete("job");
    window.history.replaceState({}, "", `${window.location.pathname}?${sp.toString()}`);
  }, [tab, selJob]);

  const restoredFromURL = useRef(false);
  useEffect(() => {
    if (restoredFromURL.current || !jobs.length) return;
    const sp = new URLSearchParams(window.location.search);

    // Tab directo
    const t = sp.get("tab");
    if (t === "active" || t === "finished" || t === "findings" || t === "charts" || t === "planner") {
      setTab(t as any);
    }

    // Selección de job
    const jobId = sp.get("job");
    if (t === "findings" && jobId) {
      const j = jobs.find(x => x.job_id === jobId);
      if (j) {
        restoredFromURL.current = true;
        setSelJob(j);
        fetchFindings(j.job_id);
        return;
      }
    }

    // Abrir modal de nuevo escaneo desde ?new=1
    if (sp.get("new") === "1") {
      setShowNew(true);
    }

    restoredFromURL.current = true;
  }, [jobs]);

  // ---- Selección de job (carga hallazgos) ----
  const selectJob = async (j: ScanJob) => {
    setSelJob(j);
    await fetchFindings(j.job_id);
    setTab("findings");
  };

  // ---- Columnas de tablas ----
  const columnsJobs: ColumnDef<ScanJob>[] = [
    {
      accessorKey: "job_id",
      header: "Job ID",
      cell: ({ row }) => <code>{row.original.job_id}</code>,
    },
    {
      accessorKey: "profile",
      header: () => <div className="text-left">Perfil</div>,
      cell: ({ row }) => <span className="text-left block">{row.original.profile}</span>,
    },
    {
      accessorKey: "status",
      header: () => <div className="text-center">Estado</div>,
      cell: ({ row }) => {
        const s = row.original.status;
        const chip =
          s === "finished" ? "chip-success" :
          s === "running"  ? "chip-warning" :
          s === "queued"   ? "chip-muted"   : "chip-danger";
        return <span className={cn("chip", chip)}>{s}</span>;
      },
    },
    {
      accessorKey: "progress",
      header: () => <div className="text-center">Progreso</div>,
      cell: ({ row }) => (
        <div className="w-full bg-gray-200/30 rounded h-3">
          <div
            className="bg-blue-500 h-3 rounded"
            style={{ width: `${row.original.progress || 0}%` }}
          />
        </div>
      ),
    },
    {
      id: "criticity",
      header: () => <div className="text-center">Criticidad</div>,
      cell: ({ row }) => {
        const crit = row.original.metrics?.criticity;
        if (!crit) return <span className="text-gray-400">—</span>;

        let color = "bg-gray-500";
        if (crit.avg_score >= 9) color = "bg-red-600";
        else if (crit.avg_score >= 7) color = "bg-orange-500";
        else if (crit.avg_score >= 4) color = "bg-yellow-400 text-black";
        else color = "bg-green-500";

        return (
          <div className="flex flex-col text-xs items-center">
            <span className={`px-2 py-0.5 rounded ${color} text-white font-semibold`}>
              Avg {crit.avg_score.toFixed(1)}
            </span>
            <span className="text-[11px] text-gray-500">
              {Math.round((crit.coverage || 0) * 100)}% High+
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: "created_at",
      header: () => <div className="text-right">Creado</div>,
      cell: ({ row }) => (
        <span className="block text-right">
          {new Date(row.original.created_at).toLocaleString("es-ES")}
        </span>
      ),
    },
    {
      id: "critical",
      header: () => <div className="text-center">Críticos</div>,
      cell: ({ row }) => {
        const id = row.original.job_id;
        const n = critCountByJob[id] ?? 0;
        return (
          <span className={cn("chip", n > 0 ? "chip-danger" : "chip-muted")}>
            {n}
          </span>
        );
      },
    },
    {
      id: "row_actions",
      header: () => <div className="text-center">Acciones</div>,
      size: 220,
      cell: ({ row }) => {
        const j = row.original;
        const busy = !!jobBusy[j.job_id];
        return (
          <div className="flex gap-2 justify-end">
            <Button
              className="btn-outline px-2 py-1"
              title="Relanzar"
              disabled={!canRerun(j.status) || busy}
              onClick={(e) => { e.stopPropagation(); handleJobAction(j.job_id, "rerun"); }}
            >
              ↻
            </Button>
            <Button
              className="btn-outline px-2 py-1"
              title="Cancelar"
              disabled={!canCancel(j.status) || busy}
              onClick={(e) => { e.stopPropagation(); handleJobAction(j.job_id, "cancel"); }}
            >
              ⛔
            </Button>
            <Button
              className="btn-outline px-2 py-1"
              title="Borrar"
              disabled={busy}
              onClick={(e) => { e.stopPropagation(); handleJobAction(j.job_id, "delete"); }}
            >
              🗑
            </Button>
          </div>
        );
      },
    }
  ];

  const columnsFinds: ColumnDef<Finding>[] = [
    {
      accessorKey: "finding_id",
      header: () => <div className="text-left">ID</div>,
      cell: ({ row }) => <code className="text-left block">{row.original.finding_id}</code>,
    },
    {
      accessorKey: "component",
      header: () => <div className="text-left">Componente</div>,
      cell: ({ row }) => <span className="text-left block">{row.original.component}</span>,
    },
    {
      accessorKey: "interface",
      header: () => <div className="text-left">Interfaz</div>,
      cell: ({ row }) => <span className="text-left block">{row.original.interface || "—"}</span>,
    },
    {
      accessorKey: "protocol",
      header: () => <div className="text-left">Protocolo</div>,
      cell: ({ row }) => <span className="text-left block">{row.original.protocol || "—"}</span>,
    },
    {
      accessorKey: "risk.label",
      header: () => <div className="text-center">Riesgo</div>,
      cell: ({ row }) => {
        const r = row.original.risk?.label || "Info";
        const badge =
          r === "Critical" ? "bg-red-600 text-white" :
          r === "High"     ? "bg-orange-500 text-white" :
          r === "Medium"   ? "bg-yellow-400 text-black" :
                            "bg-gray-400 text-black";
        return (
          <span className={cn("px-2 py-0.5 rounded text-xs font-semibold", badge)}>
            {r}
          </span>
        );
      },
    },
    {
      accessorKey: "summary",
      header: () => <div className="text-left">Resumen</div>,
      cell: ({ row }) => <span className="text-left block">{row.original.summary}</span>,
    },
    {
      id: "cves",
      header: () => <div className="text-left">CVEs correlacionados</div>,
      cell: ({ row }) => {
        const cves = (row.original as any).cve_candidates || [];
        return (
          <div className="flex flex-wrap gap-1">
            {cves.map((cve: string) => (
              <button
                key={cve}
                onClick={(e) => {
                  e.stopPropagation();
                  window.open(`/dashboard/${cve}?fromJob=${selJob?.job_id}`, "_blank");
                }}
                className="text-blue-400 underline hover:text-blue-300"
              >
                {cve}
              </button>
            ))}
          </div>
        );
      },
    },
  ];

  // ---- Export de hallazgos ----
  const exportFindings = () => {
    const blob = new Blob([JSON.stringify(findings, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `findings_${selJob?.job_id || "job"}.json`;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
    a.remove();
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const exportFindingsFmt = async (fmt: "json"|"csv"|"xml") => {
    if (!selJob) return;
    try {
      const r = await fetch(`/api/scan/jobs/${selJob.job_id}/export?fmt=${fmt}`);
      if (!r.ok) {
        const t = await r.text();
        alert(`No se pudo exportar (${fmt}). ${t || r.status}`);
        return;
      }
      const blob = await r.blob();
      downloadBlob(blob, `${selJob.job_id}.${fmt}`);
    } finally {
      setExportOpen(false);
    }
  };


  // ---- UI ----
  return (
    <div className="global-bg">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8 text-[15px]">
        {/* Header */}
        <header className="mb-4">
          <div className="panel px-4 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="text-center md:text-left mx-auto md:mx-0">
              <h1 className="text-2xl font-semibold">🛰️ Dashboard de Escaneos 5G</h1>
              <p className="text-xs text-[var(--muted)] -mt-1">Jobs, hallazgos y progreso en tiempo real</p>
            </div>
            <div className="flex items-center gap-2 justify-center md:justify-end">
              <Button className="btn-ghost" onClick={fetchJobs} disabled={loading}>{loading ? "Actualizando…" : "Actualizar"}</Button>
              <Button className="btn-solid" onClick={() => setShowNew(true)}>➕ Nuevo escaneo</Button>
            </div>
          </div>
        </header>

        {/* KPIs */}
        <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Card><CardHeader className="py-3"><CardTitle>Total jobs</CardTitle></CardHeader><CardContent className="text-2xl font-bold">{totalJobs}</CardContent></Card>
          <Card><CardHeader className="py-3"><CardTitle>Finalizados</CardTitle></CardHeader><CardContent className="text-2xl font-bold">{finishedCount}</CardContent></Card>
          <Card><CardHeader className="py-3"><CardTitle>Progreso medio</CardTitle></CardHeader><CardContent className="text-2xl font-bold">{avgProgress.toFixed(1)}%</CardContent></Card>
          <Card><CardHeader className="py-3"><CardTitle>Críticos detectados</CardTitle></CardHeader><CardContent className="text-2xl font-bold">{criticalFinds}</CardContent></Card>
        </div>

        {/* Filtros */}
        <div className="panel p-3 mb-3 flex flex-wrap items-center gap-2">
          <Input
            placeholder="Buscar por Job ID…"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            className="w-52"
          />
          <Input
            placeholder="Perfil (fast / standard / exhaustive)"
            value={profileFilter}
            onChange={(e) => setProfileFilter(e.target.value)}
            className="w-64"
          />
          <div className="flex items-center gap-1">
            {(["all","queued","running","finished","error"] as StatusFilter[]).map(v => (
              <button
                key={v}
                className={cn("chip", statusFilter===v ? "chip-info" : "chip-muted")}
                onClick={() => setStatusFilter(v)}
              >
                {v}
              </button>
            ))}
          </div>
          <Button
            className="btn-ghost ml-auto"
            onClick={() => { setFilterText(""); setProfileFilter(""); setStatusFilter("all"); }}
          >
            Limpiar
          </Button>
        </div>

        {/* Banner de error */}
        {errMsg && (
          <div className="panel p-3 mb-3 text-sm text-red-300 flex items-center justify-between">
            <span>{errMsg}</span>
            <div className="flex gap-2">
              <Button className="btn-outline" onClick={() => fetchJobs()}>Reintentar</Button>
              <Button className="btn-outline" onClick={() => setErrMsg("")}>Cerrar</Button>
            </div>
          </div>
        )}


        {/* Tabs controladas */}
        <Tabs value={tab} onValueChange={(v) => setTab(v as any)}>
          <TabsList className="mb-3">
            <TabsTrigger value="active">Activos</TabsTrigger>
            <TabsTrigger value="finished">Finalizados</TabsTrigger>
            <TabsTrigger value="findings" disabled={!selJob}>Hallazgos</TabsTrigger>
            {/* <TabsTrigger value="charts">Gráficos</TabsTrigger> */}
            <TabsTrigger value="planner">Planificador</TabsTrigger>
          </TabsList>

          {/* Activos */}
          <TabsContent value="active">
            <DataTable
              columns={columnsJobs}
              data={jobsActivePage}
              onRowClick={(row) => { selectJob(row); setTab("findings"); }}
            />
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm text-[var(--muted)]">
                Página <strong>{pageJobsActive}</strong> · Mostrando <strong>{jobsActivePage.length}</strong> de <strong>{jobsActiveFiltered.length}</strong>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm">Por página</span>
                <select
                  className="rounded-md border px-2 py-1 text-sm"
                  value={perPageJobsActive}
                  onChange={(e) => { setPerPageJobsActive(Number(e.target.value)); setPageJobsActive(1); }}
                >
                  {PAGE_CHOICES.map(n => <option key={n} value={n}>{n}</option>)}
                </select>
                <Button className="btn-outline" disabled={pageJobsActive <= 1} onClick={() => setPageJobsActive(p => Math.max(1, p - 1))}>Anterior</Button>
                <Button className="btn-outline" disabled={pageJobsActive >= maxPagesActive} onClick={() => setPageJobsActive(p => Math.min(maxPagesActive, p + 1))}>Siguiente</Button>
              </div>
            </div>
          </TabsContent>

          {/* Finalizados */}
          <TabsContent value="finished">
            <DataTable
              columns={columnsJobs}
              data={jobsFinishedPage}
              onRowClick={(row) => { selectJob(row); setTab("findings"); }}
            />
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm text-[var(--muted)]">
                Página <strong>{pageJobsFin}</strong> · Mostrando <strong>{jobsFinishedPage.length}</strong> de <strong>{jobsFinishedFiltered.length}</strong>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm">Por página</span>
                <select
                  className="rounded-md border px-2 py-1 text-sm"
                  value={perPageJobsFin}
                  onChange={(e) => { setPerPageJobsFin(Number(e.target.value)); setPageJobsFin(1); }}
                >
                  {PAGE_CHOICES.map(n => <option key={n} value={n}>{n}</option>)}
                </select>
                <Button className="btn-outline" disabled={pageJobsFin <= 1} onClick={() => setPageJobsFin(p => Math.max(1, p - 1))}>Anterior</Button>
                <Button className="btn-outline" disabled={pageJobsFin >= maxPagesFin} onClick={() => setPageJobsFin(p => Math.min(maxPagesFin, p + 1))}>Siguiente</Button>
              </div>
            </div>
          </TabsContent>

          {/* Hallazgos */}
          <TabsContent value="findings">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              {/* Sidebar: lista de jobs */}
              <aside className="lg:col-span-4 xl:col-span-3 panel p-3 max-h-[74vh] overflow-auto text-[14px]">
                <div className="mb-2 text-xs text-[var(--muted)]">Jobs</div>
                <div className="flex flex-col gap-1">
                  {jobsSide.map(j => {
                    const active = selJob?.job_id === j.job_id;
                    return (
                      <button
                        key={j.job_id}
                        onClick={() => selectJob(j)}
                        className={cn(
                          "w-full rounded-lg px-3 py-2 text-left transition-colors border",
                          active
                            ? "bg-slate-800/60 border-slate-600/60 ring-1 ring-slate-500/30"
                            : "bg-slate-800/20 border-transparent hover:bg-slate-800/35"
                        )}
                        aria-pressed={active}
                        title={`${j.job_id} • ${j.status}`}
                      >
                        <div className="font-mono text-[11px]">{j.job_id}</div>
                        <div className="flex items-center justify-between text-xs opacity-80">
                          <span>{j.profile}</span>
                          <span>{j.status}</span>
                        </div>
                        <div className="mt-2 h-1.5 w-full bg-slate-700/60 rounded">
                          <div className="h-1.5 bg-sky-400 rounded" style={{ width: `${j.progress || 0}%` }} />
                        </div>
                      </button>
                    );
                  })}
                </div>

                {/* paginación/selector sidebar */}
                <div className="mt-3 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span>Por página</span>
                    <select
                      className="rounded-md border px-2 py-1"
                      value={perPageSide}
                      onChange={(e) => { setPerPageSide(Number(e.target.value)); setPageSide(1); }}
                    >
                      {PAGE_CHOICES.map(n => <option key={n} value={n}>{n}</option>)}
                    </select>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button className="btn-outline px-2 py-1" disabled={pageSide <= 1} onClick={() => setPageSide(p => Math.max(1, p - 1))}>←</Button>
                    <span>Pág. {pageSide}/{maxSidePages}</span>
                    <Button className="btn-outline px-2 py-1" disabled={pageSide >= maxSidePages} onClick={() => setPageSide(p => Math.min(maxSidePages, p + 1))}>→</Button>
                  </div>
                </div>
              </aside>

              {/* Detalle de hallazgos */}
              <section className="lg:col-span-8 xl:col-span-9">
                {selJob ? (
                  <Card>
                    <CardHeader className="flex items-center justify-between">
                      <CardTitle>Hallazgos de {selJob.job_id}</CardTitle>

                      <div className="flex gap-2">
                        <Popover open={exportOpen} onOpenChange={setExportOpen}>
                          <PopoverTrigger asChild>
                            <Button className="btn-outline">Exportar ▾</Button>
                          </PopoverTrigger>

                          <PopoverContent align="end" className="w-44 p-1">
                            <div className="panel p-1">
                              <button className="block w-full text-left px-3 py-2 text-sm hover:bg-slate-800/40 rounded"
                                      onClick={() => exportFindingsFmt("json")}>
                                JSON (.json)
                              </button>
                              <button className="block w-full text-left px-3 py-2 text-sm hover:bg-slate-800/40 rounded"
                                      onClick={() => exportFindingsFmt("csv")}>
                                CSV (.csv)
                              </button>
                              <button className="block w-full text-left px-3 py-2 text-sm hover:bg-slate-800/40 rounded"
                                      onClick={() => exportFindingsFmt("xml")}>
                                XML (.xml)
                              </button>
                            </div>
                          </PopoverContent>
                        </Popover>

                        {/* puedes dejar otros botones aquí si quieres */}
                      </div>
                    </CardHeader>

                    <CardContent className="text-[14px]">
                      <DataTable columns={columnsFinds} data={findings} />
                    </CardContent>
                  </Card>
                ) : (
                  <p className="text-sm text-[var(--muted)]">Elige un job a la izquierda para ver sus hallazgos.</p>
                )}
              </section>
            </div>
          </TabsContent>

          {/* Planner */}
          <TabsContent value="planner">
            <PlannerTab schedules={schedules} plugins={plugins} fetchSchedules={fetchSchedules} />
          </TabsContent>

          {/* Gráficos */}
          {/* <TabsContent value="charts">
            <div style={{ height: 300 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={jobs.map((j) => ({ job: j.job_id, progreso: j.progress }))}>
                  <CartesianGrid stroke="rgba(148,163,184,.25)" strokeDasharray="3 3" />
                  <XAxis dataKey="job" />
                  <YAxis />
                  <Bar dataKey="progreso" fill="#3b82f6" />
                  <ReTooltip />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </TabsContent> */}
        </Tabs>
      </div>

      {/* Modal: Nuevo escaneo */}
      {showNew && (
        <NewScanModal
          plugins={plugins}
          onClose={() => setShowNew(false)}
          onCreated={async () => { setShowNew(false); await fetchJobs(); }}
          endpointCreate={endpointJobs}
        />
      )}
    </div>
  );
}

/* ============================
   Planner (extraído para limpiar)
============================ */
function PlannerTab({
  schedules, plugins, fetchSchedules
}: { schedules: Schedule[]; plugins: Plugin[]; fetchSchedules: () => Promise<void> | void }) {
  const scheduleAction = async (sid: string, action: "pause"|"resume"|"run_now"|"delete") => {
    await fetch(`/api/scan/schedules/${sid}/action`, {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ action })
    });
    await fetchSchedules();
  };

  const [showNewSched, setShowNewSched] = useState(false);

  return (
    <>
      <Card>
        <CardHeader className="flex items-center justify-between">
          <CardTitle>Planificaciones</CardTitle>
          <div className="flex gap-2">
            <Button className="btn-ghost" onClick={() => fetchSchedules()}>🔄 Actualizar</Button>
            <Button className="btn-solid" onClick={() => setShowNewSched(true)}>➕ Nueva planificación</Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-[var(--muted)]">
                <tr>
                  <th className="py-2 pr-4">Nombre</th>
                  <th className="py-2 pr-4">RRULE / One-shot</th>
                  <th className="py-2 pr-4">Siguiente</th>
                  <th className="py-2 pr-4">Estado</th>
                  <th className="py-2 pr-4">Acciones</th>
                </tr>
              </thead>
              <tbody>
                {schedules.map(s => (
                  <tr key={s.schedule_id} className="border-t border-[var(--panel-border)]">
                    <td className="py-2 pr-4">
                      <div className="font-medium">{s.name}</div>
                      <div className="text-xs opacity-70">
                        {s.profile} · core: {(s.targets?.core||[]).join(", ") || "—"} · ran: {(s.targets?.ran_oam||[]).join(", ") || "—"}
                      </div>
                      <div className="text-xs opacity-70">plugins: {(s.plugins||[]).join(", ") || "—"}</div>
                    </td>
                    <td className="py-2 pr-4">
                      {s.rrule ? <code className="text-xs">{s.rrule}</code> : <span>One-shot {s.run_at ? `@ ${new Date(s.run_at).toLocaleString()}`:""}</span>}
                    </td>
                    <td className="py-2 pr-4">{s.next_run ? new Date(s.next_run).toLocaleString() : "—"}</td>
                    <td className="py-2 pr-4">
                      <span className={cn("chip", s.enabled ? "chip-success":"chip-muted")}>
                        {s.enabled ? "habilitado" : "pausado"}
                      </span>
                    </td>
                    <td className="py-2 pr-4">
                      <div className="flex gap-2">
                        <Button className="btn-outline" onClick={() => scheduleAction(s.schedule_id, "run_now")}>▶ Ejecutar ahora</Button>
                        {s.enabled ? (
                          <Button className="btn-outline" onClick={() => scheduleAction(s.schedule_id, "pause")}>⏸ Pausar</Button>
                        ) : (
                          <Button className="btn-outline" onClick={() => scheduleAction(s.schedule_id, "resume")}>▶ Reanudar</Button>
                        )}
                        <Button className="btn-outline" onClick={() => scheduleAction(s.schedule_id, "delete")}>🗑 Borrar</Button>
                      </div>
                    </td>
                  </tr>
                ))}
                {!schedules.length && (
                  <tr><td className="py-4 text-[var(--muted)]" colSpan={5}>Sin planificaciones.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {showNewSched && (
        <NewScheduleModal
          onClose={() => setShowNewSched(false)}
          onCreated={async () => { setShowNewSched(false); await fetchSchedules(); }}
          plugins={plugins}
        />
      )}
    </>
  );
}

/* ============================
   Modal: Nuevo escaneo con Discovery
============================ */

interface DiscoveryResult {
  active_hosts: {
    core: string[];
    ran_oam: string[];
    transport: string[];
    support: string[];
  };
  summary: {
    total_scanned: number;
    total_active: number;
    duration_sec: number;
  };
}

function NewScanModal({
  plugins, onClose, onCreated, endpointCreate,
}: {
  plugins: Plugin[];
  onClose: () => void;
  onCreated: () => Promise<void> | void;
  endpointCreate: string;
}) {
  const [step, setStep] = useState<number>(1);
  const [profile, setProfile] = useState<"fast"|"standard"|"exhaustive">("standard");
  const [targetsCore, setTargetsCore] = useState<string>("172.22.0.0/24");
  const [targetsRan, setTargetsRan] = useState<string>("");
  const [selPlugins, setSelPlugins] = useState<string[]>(["smart_discovery","diameter_check","http2_sba_check","pfcp_check"]);
  const [force, setForce] = useState<boolean>(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string>("");
  
  // 🆕 Estado para discovery
  const [discovering, setDiscovering] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState<DiscoveryResult | null>(null);
  const [discoveryMethod, setDiscoveryMethod] = useState<"docker" | "network">("docker");
  const [useDiscovered, setUseDiscovered] = useState(true);

  const LS_KEY = "scan:last";

  useEffect(() => {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (!raw) return;
      const j = JSON.parse(raw);
      if (j.profile) setProfile(j.profile);
      if (typeof j.targetsCore === "string") setTargetsCore(j.targetsCore);
      if (typeof j.targetsRan === "string") setTargetsRan(j.targetsRan);
      if (Array.isArray(j.selPlugins)) setSelPlugins(j.selPlugins);
      if (typeof j.force === "boolean") setForce(j.force);
    } catch {}
  }, []);

  useEffect(() => {
    localStorage.setItem(LS_KEY, JSON.stringify({ profile, targetsCore, targetsRan, selPlugins, force }));
  }, [profile, targetsCore, targetsRan, selPlugins, force]);

  // 🆕 Discovery por Docker
  const discoverFromDocker = async () => {
    setDiscovering(true);
    setErr("");
    try {
      const response = await fetch('/api/scan/targets/docker?network=docker_open5gs_default');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      
      const result: DiscoveryResult = {
        active_hosts: {
          core: data.targets.core || [],
          ran_oam: [],
          transport: data.targets.transport || [],
          support: data.targets.support || []
        },
        summary: {
          total_scanned: data.summary?.total_containers || 0,
          total_active: data.summary?.total_containers || 0,
          duration_sec: 0.1
        }
      };
      
      setDiscoveryResult(result);
    } catch (e: any) {
      setErr(`Error en discovery Docker: ${e.message}. Intenta con discovery de red.`);
    } finally {
      setDiscovering(false);
    }
  };

  // 🆕 Discovery por red
  const discoverFromNetwork = async () => {
    setDiscovering(true);
    setErr("");
    try {
      const toArr = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);
      
      const response = await fetch('/api/scan/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targets: {
            core: toArr(targetsCore),
            ran_oam: toArr(targetsRan)
          },
          profile: 'fast'
        })
      });
      
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      setDiscoveryResult(data);
    } catch (e: any) {
      setErr(`Error en discovery: ${e.message}`);
    } finally {
      setDiscovering(false);
    }
  };

  // 🆕 Ejecutar discovery
  const runDiscovery = async () => {
    if (discoveryMethod === "docker") {
      await discoverFromDocker();
    } else {
      await discoverFromNetwork();
    }
  };

  const payload = useMemo(() => {
    const toArr = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);
    
    // Si hay discovery y está activado
    if (useDiscovered && discoveryResult) {
      return {
        profile,
        targets: {
          core: discoveryResult.active_hosts.core,
          ran_oam: discoveryResult.active_hosts.ran_oam
        },
        plugins: selPlugins,
      };
    }
    
    // Modo manual
    return {
      profile,
      targets: { core: toArr(targetsCore), ran_oam: toArr(targetsRan) },
      plugins: selPlugins,
    };
  }, [profile, targetsCore, targetsRan, selPlugins, useDiscovered, discoveryResult]);

  const create = async () => {
    try {
      setLoading(true);
      setErr("");
      const url = `${endpointCreate}${force ? "?force=1" : ""}`;
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      await onCreated();
    } catch (e: any) {
      setErr(e?.message || "Error desconocido");
      setLoading(false);
    }
  };

  const next = () => setStep((s) => Math.min(5, s + 1));
  const prev = () => setStep((s) => Math.max(1, s - 1));

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="absolute right-0 top-0 h-full w-full max-w-2xl panel overflow-y-auto p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">🛰️ Nuevo escaneo</h2>
          <div className="flex gap-2">
            <Button
              className="btn-outline"
              onClick={() => {
                localStorage.removeItem(LS_KEY);
                setProfile("standard");
                setTargetsCore("172.22.0.0/24");
                setTargetsRan("");
                setSelPlugins(["smart_discovery","diameter_check","http2_sba_check","pfcp_check"]);
                setForce(false);
                setDiscoveryResult(null);
                setUseDiscovered(true);
              }}
            >
              Restablecer
            </Button>
            <Button className="btn-outline" onClick={onClose}>Cerrar</Button>
          </div>
        </div>

        {/* Pasos */}
        <div className="mb-3 flex items-center gap-2 text-xs">
          <StepDot on={step>=1} label="Scope" /><StepLine />
          <StepDot on={step>=2} label="Discovery" /><StepLine />
          <StepDot on={step>=3} label="Perfil" /><StepLine />
          <StepDot on={step>=4} label="Plugins" /><StepLine />
          <StepDot on={step>=5} label="Revisar" />
        </div>

        {/* Paso 1: Scope */}
        {step === 1 && (
          <div className="space-y-3">
            <p className="text-sm text-[var(--muted)]">
              Define el alcance inicial. En el siguiente paso descubrirás hosts activos.
            </p>
            <div>
              <label className="block text-sm mb-1">Targets Core</label>
              <Input 
                value={targetsCore} 
                onChange={(e) => setTargetsCore(e.target.value)} 
                placeholder="172.22.0.0/24, 10.0.1.10" 
              />
              <p className="text-xs text-[var(--muted)] mt-1">
                💡 Usa CIDR (172.22.0.0/24) para escanear rangos completos
              </p>
            </div>
            <div>
              <label className="block text-sm mb-1">Targets RAN/OAM (opcional)</label>
              <Input 
                value={targetsRan} 
                onChange={(e) => setTargetsRan(e.target.value)} 
                placeholder="10.20.0.0/24" 
              />
            </div>
          </div>
        )}

        {/* Paso 2: Discovery */}
        {step === 2 && (
          <div className="space-y-4">
            <p className="text-sm text-[var(--muted)]">
              Descubre hosts activos antes de escanear. Ahorra tiempo y recursos.
            </p>

            <div>
              <label className="block text-sm mb-2">Método de discovery:</label>
              <div className="flex gap-2">
                <button
                  className={cn("chip", discoveryMethod === "docker" ? "chip-info" : "chip-muted")}
                  onClick={() => setDiscoveryMethod("docker")}
                >
                  🐳 Docker
                </button>
                <button
                  className={cn("chip", discoveryMethod === "network" ? "chip-info" : "chip-muted")}
                  onClick={() => setDiscoveryMethod("network")}
                >
                  🌐 Red
                </button>
              </div>
              <p className="text-xs text-[var(--muted)] mt-1">
                {discoveryMethod === "docker" 
                  ? "Lee contenedores de Docker (instantáneo)"
                  : "TCP probe en puertos comunes (~3-5s)"}
              </p>
            </div>

            <Button
              className="btn-solid w-full"
              onClick={runDiscovery}
              disabled={discovering}
            >
              {discovering ? "🔍 Descubriendo..." : "🔍 Descubrir hosts activos"}
            </Button>

            {discoveryResult && (
              <div className="panel p-3 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-sm">✅ Discovery completado</h3>
                  <span className="text-xs text-[var(--muted)]">
                    {discoveryResult.summary.duration_sec.toFixed(2)}s
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="panel p-2">
                    <div className="text-[var(--muted)] text-xs">Escaneados</div>
                    <div className="text-lg font-bold">{discoveryResult.summary.total_scanned}</div>
                  </div>
                  <div className="panel p-2">
                    <div className="text-[var(--muted)] text-xs">Activos</div>
                    <div className="text-lg font-bold text-green-400">
                      {discoveryResult.summary.total_active}
                    </div>
                  </div>
                </div>

                {discoveryResult.active_hosts.core.length > 0 && (
                  <div>
                    <div className="text-xs font-semibold mb-1">
                      Core ({discoveryResult.active_hosts.core.length}):
                    </div>
                    <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
                      {discoveryResult.active_hosts.core.map(ip => (
                        <span key={ip} className="chip chip-success text-xs font-mono">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {discoveryResult.active_hosts.transport.length > 0 && (
                  <div>
                    <div className="text-xs font-semibold mb-1">
                      Transport ({discoveryResult.active_hosts.transport.length}):
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {discoveryResult.active_hosts.transport.map(ip => (
                        <span key={ip} className="chip chip-info text-xs font-mono">
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <label className="inline-flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useDiscovered}
                    onChange={(e) => setUseDiscovered(e.target.checked)}
                  />
                  <span className="font-medium">
                    Usar solo hosts descubiertos ({discoveryResult.summary.total_active} IPs)
                  </span>
                </label>
                
                {!useDiscovered && (
                  <p className="text-xs text-yellow-400">
                    ⚠️ Se usará el alcance manual ({targetsCore})
                  </p>
                )}
              </div>
            )}

            <div className="text-center">
              <button
                className="text-xs text-[var(--muted)] hover:text-blue-400 underline"
                onClick={next}
              >
                Saltar discovery → usar alcance manual
              </button>
            </div>
          </div>
        )}

        {/* Paso 3: Perfil */}
        {step === 3 && (
          <div className="space-y-3">
            <p className="text-sm text-[var(--muted)]">Nivel de profundidad del escaneo.</p>
            <div className="flex gap-2 flex-wrap">
              {(["fast","standard","exhaustive"] as const).map(p => (
                <button 
                  key={p} 
                  className={cn("chip", profile===p ? "chip-success" : "chip-muted")} 
                  onClick={() => setProfile(p)}
                >
                  {p === "fast" ? "⚡ Rápido" : p==="standard" ? "🎯 Estándar" : "🔬 Exhaustivo"}
                </button>
              ))}
            </div>
            
            {discoveryResult && useDiscovered && (
              <div className="panel p-3 text-xs">
                <div className="text-[var(--muted)] mb-1">Tiempo estimado:</div>
                <div className="font-semibold">
                  {profile === "fast" && `~${Math.ceil(discoveryResult.summary.total_active * 0.5)}s`}
                  {profile === "standard" && `~${Math.ceil(discoveryResult.summary.total_active * 1.5)}s`}
                  {profile === "exhaustive" && `~${Math.ceil(discoveryResult.summary.total_active * 3)}s`}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Paso 4: Plugins */}
        {step === 4 && (
          <div className="space-y-3">
            <p className="text-sm text-[var(--muted)]">Selecciona los chequeos.</p>
            <div className="flex flex-wrap gap-2 max-h-64 overflow-y-auto">
              {plugins.map(pl => {
                const on = selPlugins.includes(pl.id);
                return (
                  <label key={pl.id} className={cn("chip", on ? "chip-info" : "chip-muted","cursor-pointer")}>
                    <input
                      type="checkbox"
                      className="mr-2"
                      checked={on}
                      onChange={(e) => {
                        const checked = e.currentTarget.checked;
                        setSelPlugins(prev => checked ? [...prev, pl.id] : prev.filter(x => x !== pl.id));
                      }}
                    />
                    <span className="font-mono text-xs">{pl.id}</span>
                  </label>
                );
              })}
            </div>
          </div>
        )}

        {/* Paso 5: Revisar */}
        {step === 5 && (
          <div className="space-y-3">
            <p className="text-sm text-[var(--muted)]">Revisa y confirma.</p>
            
            {discoveryResult && useDiscovered && (
              <div className="panel p-3 bg-green-900/20 border border-green-500/30">
                <div className="text-sm font-semibold text-green-400 mb-1">
                  ✅ Usando hosts descubiertos
                </div>
                <div className="text-xs text-[var(--muted)]">
                  {discoveryResult.summary.total_active} hosts activos en lugar de expandir todo el CIDR
                </div>
              </div>
            )}
            
            <pre className="panel p-3 text-xs overflow-auto max-h-64">
              {JSON.stringify(payload, null, 2)}
            </pre>
            
            <label className="inline-flex items-center gap-2 text-sm">
              <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} />
              <span>Forzar nuevo (ignorar deduplicación 30 min)</span>
            </label>
          </div>
        )}

        {err && (
          <div className="mt-3 panel p-3 bg-red-900/20 border border-red-500/30">
            <div className="text-sm text-red-400">{err}</div>
          </div>
        )}

        <div className="mt-4 flex items-center justify-between">
          <div className="text-xs text-[var(--muted)]">Paso {step} de 5</div>
          <div className="flex gap-2">
            <Button className="btn-outline" disabled={step===1} onClick={prev}>← Atrás</Button>
            {step < 5 ? (
              <Button className="btn-solid" onClick={next}>Siguiente →</Button>
            ) : (
              <Button className="btn-solid" disabled={loading || selPlugins.length === 0} onClick={create}>
                {loading ? "🚀 Creando..." : "🚀 Crear escaneo"}
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============================
   Modal: Nueva planificación
============================ */
function NewScheduleModal({
  onClose, onCreated, plugins
}: { onClose: () => void; onCreated: () => Promise<void>|void; plugins: Plugin[] }) {
  const [name, setName] = useState("Scan diario Core");
  const [profile, setProfile] = useState<"fast"|"standard"|"exhaustive">("standard");
  const [targetsCore, setTargetsCore] = useState("10.0.0.0/24");
  const [targetsRan, setTargetsRan] = useState("");
  const [selPlugins, setSelPlugins] = useState<string[]>(["http2_sba_check","pfcp_check"]);
  const [tz, setTz] = useState("Europe/Madrid");

  const [mode, setMode] = useState<"once"|"daily"|"weekly"|"custom">("daily");
  const [timeHH, setTimeHH] = useState("03");
  const [timeMM, setTimeMM] = useState("00");
  const [weekday, setWeekday] = useState("MO");
  const [customRR, setCustomRR] = useState("");

  const buildRRULE = () => {
    if (mode === "daily")  return `FREQ=DAILY;BYHOUR=${Number(timeHH)};BYMINUTE=${Number(timeMM)};BYSECOND=0`;
    if (mode === "weekly") return `FREQ=WEEKLY;BYDAY=${weekday};BYHOUR=${Number(timeHH)};BYMINUTE=${Number(timeMM)};BYSECOND=0`;
    if (mode === "custom") return customRR.trim() || null;
    return null;
  };

  const toArr = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);

  const create = async () => {
    const body: any = {
      name,
      enabled: true,
      profile,
      targets: { core: toArr(targetsCore), ran_oam: toArr(targetsRan) },
      plugins: selPlugins,
      tz,
    };
    const rrule = buildRRULE();
    if (rrule) body.rrule = rrule;
    else {
      const now = new Date();
      const rt = new Date(now); rt.setHours(Number(timeHH), Number(timeMM), 0, 0);
      body.run_at = rt.toISOString();
    }

    const r = await fetch("/api/scan/schedules", {
      method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body)
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    await onCreated();
  };

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/40" onClick={onClose}/>
      <div className="absolute right-0 top-0 h-full w-full max-w-2xl panel overflow-y-auto p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">Nueva planificación</h2>
          <Button className="btn-outline" onClick={onClose}>Cerrar</Button>
        </div>

        <div className="grid gap-3">
          <div>
            <label className="text-sm">Nombre</label>
            <Input className="mt-1" value={name} onChange={e => setName(e.target.value)} />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="text-sm">Perfil</label>
              <div className="flex gap-2 mt-1">
                {(["fast","standard","exhaustive"] as const).map(p => (
                  <button key={p} className={cn("chip", profile===p?"chip-success":"chip-muted")} onClick={() => setProfile(p)}>
                    {p}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="text-sm">TZ</label>
              <Input className="mt-1" value={tz} onChange={e => setTz(e.target.value)} placeholder="Europe/Madrid" />
            </div>
          </div>

          <div>
            <label className="text-sm">Targets Core</label>
            <Input className="mt-1" value={targetsCore} onChange={e => setTargetsCore(e.target.value)} placeholder="10.0.0.0/24, 10.0.1.10" />
          </div>
          <div>
            <label className="text-sm">Targets RAN/OAM</label>
            <Input className="mt-1" value={targetsRan} onChange={e => setTargetsRan(e.target.value)} placeholder="10.20.0.0/24" />
          </div>

          <div>
            <div className="text-sm mb-1">Plugins</div>
            <div className="flex flex-wrap gap-2">
              {plugins.map(pl => {
                const on = selPlugins.includes(pl.id);
                return (
                  <label key={pl.id} className={cn("chip", on ? "chip-info":"chip-muted","cursor-pointer")}>
                    <input type="checkbox" className="mr-2" checked={on}
                      onChange={(e) => {
                        const checked = e.currentTarget.checked;
                        setSelPlugins(prev => checked ? [...prev, pl.id] : prev.filter(x => x !== pl.id));
                      }} />
                    <span className="font-mono text-xs">{pl.id}</span>
                  </label>
                );
              })}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="text-sm">Modo</label>
              <select className="mt-1 w-full rounded-md border px-2 py-2" value={mode} onChange={e => setMode(e.target.value as any)}>
                <option value="once">Una vez (hoy)</option>
                <option value="daily">Diario</option>
                <option value="weekly">Semanal</option>
                <option value="custom">RRULE avanzada</option>
              </select>
            </div>
            <div>
              <label className="text-sm">Hora (HH:MM)</label>
              <div className="flex gap-2 mt-1">
                <Input value={timeHH} onChange={e => setTimeHH(e.target.value)} placeholder="03" />
                <Input value={timeMM} onChange={e => setTimeMM(e.target.value)} placeholder="00" />
              </div>
            </div>
            {mode === "weekly" && (
              <div>
                <label className="text-sm">Día (BYDAY)</label>
                <select className="mt-1 w-full rounded-md border px-2 py-2" value={weekday} onChange={e => setWeekday(e.target.value)}>
                  {["MO","TU","WE","TH","FR","SA","SU"].map(d => <option key={d} value={d}>{d}</option>)}
                </select>
              </div>
            )}
          </div>

          {mode === "custom" && (
            <div>
              <label className="text-sm">RRULE</label>
              <Input className="mt-1" value={customRR} onChange={e => setCustomRR(e.target.value)} placeholder="FREQ=DAILY;BYHOUR=3;BYMINUTE=0;BYSECOND=0" />
              <div className="text-xs text-[var(--muted)] mt-1">Usa formato iCal RRULE.</div>
            </div>
          )}

          <div className="flex justify-end">
            <Button className="btn-solid" onClick={create}>Crear planificación</Button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ============================
   UI auxiliares
============================ */
function StepDot({ on, label }: { on: boolean; label: string }) {
  return (
    <div className="flex items-center gap-1">
      <div className={cn("h-2.5 w-2.5 rounded-full", on ? "bg-blue-500" : "bg-gray-400")} />
      <span className="opacity-75">{label}</span>
    </div>
  );
}
function StepLine() { return <div className="h-px w-6 bg-[var(--panel-border)]" />; }
