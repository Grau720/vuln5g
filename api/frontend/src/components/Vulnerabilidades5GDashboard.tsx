import React, { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Slider } from "@/components/ui/slider";
import { Checkbox } from "@/components/ui/checkbox";
import { DataTable } from "@/components/ui/data-table";
import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "@/lib/utils";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useParams, useNavigate } from "react-router-dom";
import {
  ResponsiveContainer,
  AreaChart, Area,
  XAxis, YAxis, CartesianGrid,
  Tooltip as ReTooltip,
  BarChart, Bar,
  PieChart, Pie, Legend
} from "recharts";

export type CVE = {
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
  cvssv3: { score: number; vector?: string };
  fecha_publicacion: string; // ISO
  fecha_registro_mitre?: string;
  version?: number;
  versiones_afectadas?: string[];
  componente_afectado?: string;
};


type DashboardProps = {
  endpoint?: string;
  initialData?: CVE[];
};

const fmtFecha = (iso: string) => {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso?.slice(0, 10) || "";
  return d.toLocaleDateString("es-ES");
};

type MetaResp = {
  by_month: { month: string; total: number }[];
  by_tipo: { tipo: string; total: number }[];
  by_infra: { infra: string; total: number }[];
  cvss_hist: { bucket: string; total: number }[];
  options: {
    years: string[];
    tipos: string[];
    etiquetas: string[];
    infraestructura: string[];
  };
};

// FAVS
const LS_FAVS_KEY = "vuln5g:favs";
const LS_TAGS_KEY = "vuln5g:userTags";

type UserTags = Record<string, string[]>; // cve_id -> etiquetas usuario

// --- HEATMAP UTILS ---
type ByMonth = { month: string; total: number };

const MES_LABELS = ["Ene","Feb","Mar","Abr","May","Jun","Jul","Ago","Sep","Oct","Nov","Dic"];
const pad2 = (n: number) => (n < 10 ? `0${n}` : `${n}`);

// Convierte meta.by_month (YYYY-MM) a matriz Años×Meses con ceros donde falte
function buildHeatmapMatrix(byMonth: ByMonth[]) {
  const map = new Map<string, number>();
  const yearsSet = new Set<number>();
  let maxVal = 0;

  for (const { month, total } of byMonth) {
    const [y, m] = month.split("-").map((x) => parseInt(x, 10));
    if (!y || !m) continue;
    yearsSet.add(y);
    map.set(`${y}-${pad2(m)}`, total);
    if (total > maxVal) maxVal = total;
  }

  const years = Array.from(yearsSet).sort((a, b) => b - a);
  const months = Array.from({ length: 12 }, (_, i) => i + 1);

  const rows = years.map((y) => {
    const cells = months.map((m) => {
      const key = `${y}-${pad2(m)}`;
      const total = map.get(key) || 0;
      return { year: y, month: m, total, key };
    });
    return { year: y, cells };
  });

  return { rows, years, maxVal };
}

// Color en buckets (0 = gris claro, más alto = azul fuerte)
function colorFor(v: number, max: number) {
  if (v <= 0) return "#f1f5f9";
  if (max <= 0) return "#dbeafe";
  const r = v / max;
  if (r < 0.15) return "#dbeafe";
  if (r < 0.30) return "#bfdbfe";
  if (r < 0.45) return "#93c5fd";
  if (r < 0.60) return "#60a5fa";
  if (r < 0.80) return "#3b82f6";
  return "#1d4ed8";
}

// --- HEATMAP COMPONENT ---
function Heatmap({
  data,
  title = "Heatmap mensual",
}: {
  data: ByMonth[];
  title?: string;
}) {
  const { rows, maxVal } = React.useMemo(() => buildHeatmapMatrix(data || []), [data]);

  const cell = 26;
  const gap = 4;
  const leftLabelW = 56;
  const topLabelH = 24;

  const cols = 12;
  const rowsCount = rows.length;

  const width = leftLabelW + cols * cell + (cols - 1) * gap + 8;
  const height = topLabelH + rowsCount * cell + (rowsCount - 1) * gap + 8;

  const [tt, setTt] = React.useState<{ x: number; y: number; text: string } | null>(null);

  return (
    <div className="relative">
      <div className="mb-2 text-sm text-[var(--muted)]">{title}</div>
      <svg width={width} height={height} role="img" aria-label={title}>
        {/* Labels meses (arriba) */}
        {MES_LABELS.map((m, i) => {
          const x = leftLabelW + i * (cell + gap) + cell / 2;
          const y = topLabelH - 8;
          return (
            <text key={m} x={x} y={y} textAnchor="middle" fontSize="11" fill="var(--muted)">
              {m}
            </text>
          );
        })}

        {/* Filas por año */}
        {rows.map((row, rIdx) => {
          const yBase = topLabelH + rIdx * (cell + gap);

          return (
            <g key={row.year}>
              {/* label del año (izquierda) */}
              <text
                x={leftLabelW - 8}
                y={yBase + cell / 2 + 4}
                textAnchor="end"
                fontSize="12"
                fill="var(--muted)"
              >
                {row.year}
              </text>

              {/* celdas */}
              {row.cells.map((c, cIdx) => {
                const xBase = leftLabelW + cIdx * (cell + gap);
                const fill = colorFor(c.total, maxVal);

                return (
                  <rect
                    key={c.key}
                    x={xBase}
                    y={yBase}
                    width={cell}
                    height={cell}
                    rx={6}
                    fill={fill}
                    stroke="var(--panel-border)"
                    onMouseEnter={(e) => {
                      const bounds = (e.target as SVGRectElement).getBoundingClientRect();
                      setTt({
                        x: bounds.left + bounds.width / 2,
                        y: bounds.top - 8,
                        text: `${c.year}-${pad2(c.month)}: ${c.total} CVEs`,
                      });
                    }}
                    onMouseLeave={() => setTt(null)}
                  />
                );
              })}
            </g>
          );
        })}
      </svg>

      {/* Tooltip */}
      {tt && (
        <div
          className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded-md bg-black px-2 py-1 text-xs text-white shadow"
          style={{ left: tt.x, top: tt.y }}
        >
          {tt.text}
        </div>
      )}

      {/* Leyenda simple */}
      <div className="mt-3 flex items-center gap-2 text-xs text-[var(--muted)]">
        <span>Menos</span>
        <div className="h-3 w-5 rounded" style={{ background: colorFor(1, 6) }} />
        <div className="h-3 w-5 rounded" style={{ background: colorFor(2, 6) }} />
        <div className="h-3 w-5 rounded" style={{ background: colorFor(3, 6) }} />
        <div className="h-3 w-5 rounded" style={{ background: colorFor(4, 6) }} />
        <div className="h-3 w-5 rounded" style={{ background: colorFor(5, 6) }} />
        <div className="h-3 w-5 rounded" style={{ background: colorFor(6, 6) }} />
        <span>Más</span>
        <span className="ml-2 opacity-70">(máx: {maxVal})</span>
      </div>
    </div>
  );
}

/* ===== helpers de CVSS (AQUÍ) ===== */
const cvssSeverity = (s: number) => (s >= 9 ? "crit" : s >= 7 ? "high" : s >= 4 ? "med" : "low");
const formatScore = (s: number | undefined) => (typeof s === "number" ? s.toFixed(1) : "N/A");

export default function Vulnerabilidades5GDashboard({
  endpoint = "/api/v1/cves",
  initialData = [],
}: DashboardProps) {
  // datos resultantes (página actual)
  const [data, setData] = useState<CVE[]>(initialData);
  const [total, setTotal] = useState<number>(initialData.length);
  const [meta, setMeta] = useState<MetaResp | null>(null);

  // Navegacion
  const { cveId } = useParams<{ cveId?: string }>();
  const navigate = useNavigate();

  // // THEME: light/dark con persistencia
  // const [theme, setTheme] = useState<"light"|"dark">(
  //   () => (localStorage.getItem("theme") as "light"|"dark") || "light"
  // );
  // useEffect(() => { localStorage.setItem("theme", theme); }, [theme]);

  // filtros
  const [year, setYear] = useState<string>("");
  const [minScore, setMinScore] = useState<number>(0);
  const [tipo, setTipo] = useState<string>("");
  const [etiquetasSel, setEtiquetasSel] = useState<string[]>([]);
  const [infraSel, setInfraSel] = useState<string[]>([]);
  const [q, setQ] = useState<string>("");
  const [showCheat, setShowCheat] = useState<boolean>(false); // <--- NUEVO

  // paginación / orden
  const [page, setPage] = useState<number>(1);
  const [perPage, setPerPage] = useState<number>(20);
  const [sortBy, setSortBy] = useState<string>("fecha_publicacion");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  // detalle
  const [sel, setSel] = useState<CVE | null>(null);
  const [sheetOpen, setSheetOpen] = useState<boolean>(false);

  const [favs, setFavs] = useState<string[]>(
    () => JSON.parse(localStorage.getItem(LS_FAVS_KEY) || "[]")
  );
  const [userTags, setUserTags] = useState<UserTags>(
    () => JSON.parse(localStorage.getItem(LS_TAGS_KEY) || "{}")
  );
  const [onlyFavs, setOnlyFavs] = useState<boolean>(false);
  const [newTag, setNewTag] = useState<string>("");
  const [myTagFilter, setMyTagFilter] = useState<string>("");

  // [ADD] Persistencia
  useEffect(() => { localStorage.setItem(LS_FAVS_KEY, JSON.stringify(favs)); }, [favs]);
  useEffect(() => { localStorage.setItem(LS_TAGS_KEY, JSON.stringify(userTags)); }, [userTags]);

  // Navegacion cves
  useEffect(() => {
    if (cveId) {
      // si ya lo tenemos cargado en data
      const target = data.find(c => c.cve_id === cveId);
      if (target) {
        setSel(target);
        setSheetOpen(true);
      } else {
        // 🚀 pedirlo directo a la API
        fetch(`/api/v1/cves?q=cve_id:${cveId}`)
          .then(r => r.json())
          .then(j => {
            const match = j.cves?.find((c: CVE) => c.cve_id === cveId);
            if (match) {
              setSel(match);
              setSheetOpen(true);
            }
          });
      }
    } else {
      setSheetOpen(false);
    }
  }, [cveId, data]);

  // lee filtros iniciales desde la URL
  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    setYear(sp.get("year") || "");
    setMinScore(Number(sp.get("min_score") || "0") || 0);
    setTipo(sp.get("tipo") || "");
    setQ(sp.get("q") || "");
    const et = sp.getAll("etiquetas");
    const inf = sp.getAll("infra");
    if (et.length) setEtiquetasSel(et);
    if (inf.length) setInfraSel(inf);
  }, []);

  // construir params (solo filtros, para URL/export)
  const buildFilterParams = () => {
    const params = new URLSearchParams();
    if (year) params.set("year", year);
    if (minScore > 0) params.set("min_score", minScore.toFixed(1));
    if (tipo) params.set("tipo", tipo);
    etiquetasSel.forEach((e) => params.append("etiquetas", e));
    infraSel.forEach((i) => params.append("infra", i));
    if (q.trim()) params.set("q", q.trim());
    return params;
  };

  // filtros + página + orden
  const buildQueryParams = () => {
    const params = buildFilterParams();
    params.set("page", String(page));
    params.set("per_page", String(perPage));
    params.set("sort_by", sortBy);
    params.set("sort_dir", sortDir);
    return params;
  };

  // fetch server-side
  const fetchData = async () => {
    const params = buildQueryParams();
    const url = `${endpoint}?${params.toString()}`;

    // sincroniza URL /dashboard sin paginación/orden
    const dashParams = buildFilterParams();
    const { pathname, hash } = window.location;
    window.history.replaceState({}, "", `${pathname}?${dashParams.toString()}${hash}`); 

    const res = await fetch(url);
    const j = await res.json();
    setData(j.cves || []);
    setTotal(j.total || 0);
    setMeta(j.meta || null);
  };

  // primer load + cuando cambien página/orden
  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, perPage, sortBy, sortDir]);

  // Transicion de hallazgos a cve
  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    const vulnId = sp.get("vuln");
    if (vulnId && data.length > 0) {
      const match = data.find((d) => d.cve_id === vulnId);
      if (match) {
        setSel(match);
        setSheetOpen(true);
      }
    }
  }, [data]);


  // aplicar/limpiar desde UI
  const aplicarFiltros = async () => {
    setPage(1);
    await fetchData();
  };
  const limpiar = async () => {
    setYear("");
    setMinScore(0);
    setTipo("");
    setEtiquetasSel([]);
    setInfraSel([]);
    setQ("");
    setSortBy("fecha_publicacion");
    setSortDir("desc");
    setPage(1);
    await fetchData();
  };

  // export
  const exportParams = buildFilterParams().toString();
  const hrefCSV  = `/api/v1/export/csv${exportParams ? "?" + exportParams : ""}`;
  const hrefJSON = `/api/v1/export/json${exportParams ? "?" + exportParams : ""}`;
  const hrefSTIX = `/api/v1/export/stix${exportParams ? "?" + exportParams : ""}`;

  // ordenar al clicar cabecera
  const handleRequestSort = (key: string) => {
    setPage(1);
    if (sortBy === key) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(key);
      setSortDir("desc");
    }
  };

  // [ADD] Helpers favoritos / tags
  const isFav = (id: string) => favs.includes(id);
  const toggleFav = (id: string) =>
    setFavs(prev => (prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]));

  const addUserTag = (id: string, tag: string) => {
    const t = tag.trim();
    if (!t) return;
    setUserTags(prev => {
      const existing = new Set(prev[id] || []);
      existing.add(t);
      return { ...prev, [id]: Array.from(existing).sort() };
    });
    setNewTag("");
  };

  const removeUserTag = (id: string, tag: string) => {
    setUserTags(prev => {
      const arr = (prev[id] || []).filter(x => x !== tag);
      const next = { ...prev, [id]: arr };
      if (arr.length === 0) delete next[id];
      return next;
    });
  };

  // columnas
  const columns: ColumnDef<CVE>[] = [
    {
      id: "fav",
      header: "★",
      cell: ({ row }) => {
        const id = row.original.cve_id;
        const on = isFav(id);
        return (
          <button
            title={on ? "Quitar de favoritos" : "Añadir a favoritos"}
            onClick={(e) => { e.stopPropagation(); toggleFav(id); }}
            className="text-lg"
            aria-pressed={on}
          >
            {on ? "★" : "☆"}
          </button>
        );
      },
      size: 40,
    },
    {
      accessorKey: "cve_id",
      header: "CVE ID",
      meta: { sortKey: "cve_id" },
      cell: ({ row }) => <code>{row.original.cve_id}</code>,
    },
    {
      accessorKey: "nombre",
      header: "Nombre",
      meta: { sortKey: "nombre" },
      cell: ({ row }) => (
        <span title={row.original.descripcion_general}>{row.original.nombre}</span>
      ),
    },
    {
      accessorKey: "cvssv3.score",
      header: "Score",
      meta: { sortKey: "cvss" },
      cell: ({ row }) => {
        const s = row.original.cvssv3?.score ?? 0;
        const badge =
          s >= 9
            ? "bg-red-600 text-white"
            : s >= 7
            ? "bg-amber-400 text-black"
            : s >= 4
            ? "bg-sky-400 text-black"
            : "bg-gray-500 text-white";
        return (
          <span className={cn("px-2 py-0.5 rounded text-xs font-semibold", badge)}>
            {s.toFixed(1)}
          </span>
        );
      },
    },
    { accessorKey: "tipo", header: "Tipo", meta: { sortKey: "tipo" } },
    {
      accessorKey: "fecha_publicacion",
      header: "Fecha",
      meta: { sortKey: "fecha_publicacion" },
      cell: ({ row }) => fmtFecha(row.original.fecha_publicacion),
    },
  ];

  // kpis (sobre la página actual)
  const totalPagina = data.length;
  const media =
    data.reduce((a, b) => a + (b.cvssv3?.score || 0), 0) / Math.max(1, totalPagina);
  const max = data.reduce((a, b) => Math.max(a, b.cvssv3?.score || 0), 0);
  const last = data[0]?.cve_id || "—";

  // gráficas desde meta
  const serieTiempo = meta?.by_month || [];
  const serieTipo = meta?.by_tipo || [];
  const serieInfra = meta?.by_infra || [];
  const serieCvss = meta?.cvss_hist || [];

  // opciones base (para selects/checks)
  const yearsFromBase = meta?.options.years || [];
  const tiposFromBase = meta?.options.tipos || [];
  const etiquetasFromBase = meta?.options.etiquetas || [];
  const infraFromBase = meta?.options.infraestructura || [];

  const isDark = document.documentElement.classList.contains("theme-cosmos");
  const chartTokens = {
    grid: isDark ? "rgba(148,163,184,.25)" : "rgba(2,6,23,.08)",
    axis: isDark ? "#cbd5e1" : "#475569",
    areaStroke: isDark ? "#38bdf8" : "#0284c7",
    areaFill: isDark ? "rgba(56,189,248,.28)" : "rgba(2,132,199,.35)",
    barFill: isDark ? "#60a5fa" : "#3b82f6",
    pie: isDark
      ? ["#38bdf8","#a78bfa","#34d399","#f472b6","#f59e0b","#22d3ee"]
      : ["#0284c7","#7c3aed","#059669","#db2777","#d97706","#06b6d4"],
  };

  // aplica la clase de tema al <html>
  // useEffect(() => {
  //   const root = document.documentElement;
  //   root.classList.remove("theme-cosmos","theme-light");
  //   root.classList.add(theme === "dark" ? "theme-cosmos" : "theme-light");
  //   return () => root.classList.remove("theme-cosmos","theme-light");
  // }, [theme]);

  // [ADD] Derivados: aplicar "solo favoritos" en cliente
  const pageData = useMemo(() => {
    let filtered = data;
    if (onlyFavs) {
      const favSet = new Set(favs);
      filtered = filtered.filter(d => favSet.has(d.cve_id));
    }
    if (myTagFilter) {
      filtered = filtered.filter(d => (userTags[d.cve_id] || []).includes(myTagFilter));
    }
    return filtered;
  }, [data, favs, onlyFavs, myTagFilter, userTags]);

  return (
    <div className="global-bg">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8">
        {/* header */}
        <header className="mb-4">
          <div className="panel px-4 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div className="text-center md:text-left mx-auto md:mx-0">
              <h1 className="text-2xl font-semibold">📊 Dashboard de Vulnerabilidades 5G</h1>
              <p className="text-xs text-[var(--muted)] -mt-1">Filtros avanzados, gráficos y paginación server-side</p>
            </div>
            <div className="flex items-center gap-2 justify-center md:justify-end">
              <a className="btn btn-ghost" href={hrefCSV}>📥 Exportar CSV</a>
              <a className="btn btn-ghost" href={hrefJSON}>📥 Exportar JSON</a>
              <a className="btn btn-ghost" href={hrefSTIX}>🧩 Exportar STIX</a>
            </div>
          </div>
        </header>

        {/* filtros */}
        <Card className="mb-6">
          <CardHeader className="pb-2">
            <CardTitle className="text-base md:text-lg">Filtros</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-12">
            {/* Año */}
            <div className="md:col-span-2">
              <Label>Año</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2"
                value={year}
                onChange={(e) => setYear(e.target.value)}
              >
                <option value="">Todos</option>
                {yearsFromBase.map((y) => (
                  <option key={y} value={y}>{y}</option>
                ))}
              </select>
            </div>

            {/* CVSS mínimo */}
            <div className="md:col-span-3">
              <Label>
                CVSS mínimo: <span className="font-medium">{minScore.toFixed(1)}</span>
              </Label>
              <div className="px-1 pt-2">
                <Slider value={[minScore]} min={0} max={10} step={0.1} onValueChange={(v) => setMinScore(v[0])} />
              </div>
            </div>

            {/* Tipo */}
            <div className="md:col-span-3">
              <Label>Tipo</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2"
                value={tipo}
                onChange={(e) => setTipo(e.target.value)}
              >
                <option value="">Todos</option>
                {tiposFromBase.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>

            {/* Búsqueda avanzada */}
            <div className="md:col-span-4">
              <Label className="flex items-center justify-between">
                Búsqueda avanzada
                <button
                  type="button"
                  className="btn btn-ghost ml-2 px-2 py-1 text-xs"
                  onClick={() => setShowCheat((s) => !s)}
                  aria-expanded={showCheat}
                  aria-controls="busqueda-cheatsheet"
                  title="Ayuda de consulta"
                >
                  {showCheat ? "Ocultar ayuda" : "¿Cómo buscar?"}
                </button>
              </Label>

              <Input
                className="mt-1"
                placeholder={`Ej: tipo:RCE OR proto:"HTTP/2" score>=7 NOT bluetooth`}
                value={q}
                onChange={(e) => setQ(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") aplicarFiltros();
                }}
              />

              {showCheat && (
                <div
                  id="busqueda-cheatsheet"
                  className="mt-2 panel text-xs leading-relaxed"
                >
                  <div className="font-semibold mb-1">Sintaxis soportada</div>
                  <ul className="list-disc pl-5 space-y-1">
                    <li>
                      Booleanos: <code>AND</code>, <code>OR</code>, <code>NOT</code>
                      {" "}(<em>espacio</em> equivale a <code>AND</code>)
                    </li>
                    <li>
                      Frases: usa comillas — p. ej. <code>nombre:"buffer overflow"</code>
                    </li>
                    <li>
                      Comparadores de score: <code>score&gt;=7</code>, <code>score&gt;9</code>,{" "}
                      <code>score&lt;=5</code>
                    </li>
                    <li>
                      Campos:
                      {" "}
                      <code>cve_id:</code>, <code>nombre:</code>, <code>descripcion:</code>,
                      {" "}
                      <code>tipo:</code>, <code>riesgo:</code> (<code>alto</code>/<code>medio</code>/<code>bajo</code>),
                      {" "}
                      <code>proto:</code>/<code>protocolo:</code>, <code>interfaz:</code>/<code>interfaces:</code>,
                      {" "}
                      <code>etiquetas:</code>, <code>infra:</code>/<code>infraestructura:</code>
                    </li>
                    <li>
                      Paréntesis para agrupar: <code>(tipo:RCE OR tipo:DoS) AND score&gt;=7</code>
                    </li>
                  </ul>

                  <div className="font-semibold mt-2 mb-1">Ejemplos</div>
                  <ul className="list-disc pl-5 space-y-1">
                    <li><code>tipo:RCE OR tipo:DoS</code></li>
                    <li><code>proto:"HTTP/2" AND riesgo:alto AND score&gt;=7</code></li>
                    <li><code>kernel AND NOT bluetooth</code></li>
                    <li><code>etiquetas:Open5GS AND infra:Core</code></li>
                  </ul>

                  <div className="mt-2 text-[var(--muted)]">
                    Nota: lo que escribas aquí se combina por <strong>AND</strong> con el resto de filtros (Año, CVSS, Tipo, etc.).
                  </div>
                </div>
              )}
            </div>


            {/* Etiquetas */}
            <div className="md:col-span-12">
              <div className="rounded-xl border p-3">
                <strong className="block mb-2">Etiquetas:</strong>
                <div className="flex flex-wrap gap-3 max-h-44 overflow-auto">
                  {etiquetasFromBase.map((e) => {
                    const checked = etiquetasSel.includes(e);
                    return (
                      <label key={e} className="inline-flex items-center gap-2 text-sm">
                        <Checkbox
                          checked={checked}
                          onChange={(ev) => {
                            const on = (ev.target as HTMLInputElement).checked;
                            setEtiquetasSel((prev) => (on ? [...prev, e] : prev.filter((x) => x !== e)));
                          }}
                        />
                        <span>{e}</span>
                      </label>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Infraestructura */}
            <div className="md:col-span-12">
              <div className="rounded-xl border p-3">
                <strong className="block mb-2">Infraestructura 5G afectada:</strong>
                <div className="flex flex-wrap gap-3 max-h-44 overflow-auto">
                  {infraFromBase.map((i) => {
                    const checked = infraSel.includes(i);
                    return (
                      <label key={i} className="inline-flex items-center gap-2 text-sm">
                        <Checkbox
                          checked={checked}
                          onChange={(ev) => {
                            const on = (ev.target as HTMLInputElement).checked;
                            setInfraSel((prev) => (on ? [...prev, i] : prev.filter((x) => x !== i)));
                          }}
                        />
                        <span>{i}</span>
                      </label>
                    );
                  })}
                </div>
              </div>
            </div>
            
            {/* Acciones */}
            <div className="md:col-span-12 flex flex-wrap items-center justify-between gap-4">
              {/* Col izquierda: Solo favoritos + Mis etiquetas */}
              <div className="flex items-center gap-4 flex-wrap">
                <label className="inline-flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={onlyFavs}
                    onChange={(e) => { setOnlyFavs(e.target.checked); setPage(1); }}
                  />
                  <span>Solo favoritos</span>
                </label>

                <div className="flex items-center gap-2">
                  <label htmlFor="myTagFilter" className="text-sm">Mis etiquetas:</label>
                  <select
                    id="myTagFilter"
                    className="rounded-md border px-2 py-1 text-sm"
                    value={myTagFilter}
                    onChange={(e) => { setMyTagFilter(e.target.value); setPage(1); }}
                  >
                    <option value="">Todas</option>
                    {Array.from(new Set(Object.values(userTags).flat())).map((tag) => (
                      <option key={tag} value={tag}>{tag}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Col derecha: Botones */}
              <div className="flex gap-2">
                <Button className="btn-outline" onClick={limpiar}>Limpiar</Button>
                <Button className="btn-solid" onClick={aplicarFiltros}>🔎 Filtrar</Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* KPIs */}
        <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Card>
            <CardHeader className="py-3"><CardTitle className="text-sm">Total filtrados</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{total}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-3"><CardTitle className="text-sm">Media CVSS (página)</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{media.toFixed(2)}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-3"><CardTitle className="text-sm">Máx. CVSS (página)</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{max.toFixed(1)}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-3"><CardTitle className="text-sm">Primera CVE (página)</CardTitle></CardHeader>
            <CardContent className="text-xl font-semibold">{last}</CardContent>
          </Card>
        </div>

        {/* Tabs de gráficos */}
        <Card className="mb-6">
          <CardHeader className="py-3">
            <CardTitle className="text-sm">Análisis</CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="tendencia">
              <TabsList className="mb-3">
                <TabsTrigger value="tendencia">Tendencia</TabsTrigger>
                <TabsTrigger value="cvss">Distribución CVSS</TabsTrigger>
                <TabsTrigger value="tipo">Por tipo</TabsTrigger>
                <TabsTrigger value="infra">Por infraestructura</TabsTrigger>
                <TabsTrigger value="heatmap">Heatmap</TabsTrigger>
              </TabsList>

              <TabsContent value="tendencia">
                <div style={{ height: 300 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={serieTiempo}>
                      <CartesianGrid stroke={chartTokens.grid} strokeDasharray="3 3" />
                      <XAxis dataKey="month" tick={{ fill: chartTokens.axis, fontSize: 12 }} />
                      <YAxis tick={{ fill: chartTokens.axis, fontSize: 12 }} />
                      <Area type="monotone" dataKey="total" stroke={chartTokens.areaStroke} fill={chartTokens.areaFill} />
                      <ReTooltip />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </TabsContent>

              <TabsContent value="cvss">
                <div style={{ height: 300 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={serieCvss}>
                      <CartesianGrid stroke={chartTokens.grid} strokeDasharray="3 3" />
                      <XAxis dataKey="bucket" tick={{ fill: chartTokens.axis, fontSize: 12 }} />
                      <YAxis tick={{ fill: chartTokens.axis, fontSize: 12 }} />
                      <Bar dataKey="total" fill={chartTokens.barFill} />
                      <ReTooltip />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </TabsContent>

              <TabsContent value="tipo">
                <div style={{ height: 300 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={serieTipo.slice(0, 12)}>
                      <CartesianGrid stroke={chartTokens.grid} strokeDasharray="3 3" />
                      <XAxis dataKey="tipo" tick={{ fill: chartTokens.axis, fontSize: 12 }} />
                      <YAxis allowDecimals={false} tick={{ fill: chartTokens.axis, fontSize: 12 }} />
                      <Bar dataKey="total" fill={chartTokens.barFill} />
                      <ReTooltip />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </TabsContent>

              <TabsContent value="infra">
                <div style={{ height: 300 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={serieInfra.slice(0, 12)}>
                      <CartesianGrid stroke={chartTokens.grid} strokeDasharray="3 3" />
                      <XAxis dataKey="infra" tick={{ fill: chartTokens.axis, fontSize: 12 }} />
                      <YAxis allowDecimals={false} tick={{ fill: chartTokens.axis, fontSize: 12 }} />
                      <Bar dataKey="total" fill={chartTokens.barFill} />
                      <ReTooltip />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </TabsContent>

              <TabsContent value="heatmap">
                {serieTiempo && serieTiempo.length > 0 ? (
                  <Heatmap data={serieTiempo} title="CVEs por mes (Años × Meses)" />
                ) : (
                  <div className="text-sm text-[var(--muted)]">No hay datos para este rango.</div>
                )}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {/* Tabla + paginador */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base md:text-lg">Listado</CardTitle>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={columns}
              data={pageData}
              onRowClick={(row) => {
                navigate(`/dashboard/${row.cve_id}`);
              }}
              sortBy={sortBy}
              sortDir={sortDir}
              onRequestSort={handleRequestSort}
            />
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm text-[var(--muted)]">
                Página <strong>{page}</strong> · Mostrando <strong>{pageData.length}</strong> de{" "}
                <strong>{total}</strong>
                {onlyFavs && " (solo favoritos)"}
                {myTagFilter && ` (etiqueta: ${myTagFilter})`}
              </div>
              <div className="flex items-center gap-2">
                <Label className="mr-1">Por página</Label>
                <select
                  className="rounded-md border px-2 py-2"
                  value={perPage}
                  onChange={(e) => {
                    setPerPage(Number(e.target.value));
                    setPage(1);
                  }}
                >
                  <option>10</option>
                  <option>20</option>
                  <option>50</option>
                  <option>100</option>
                </select>
                <Button
                  className="btn-outline"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  Anterior
                </Button>
                <Button
                  className="btn-outline"
                  disabled={page * perPage >= total}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Siguiente
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Panel lateral */}
        {sheetOpen && sel && (
          <div className="fixed inset-0 z-50">
            <div className="absolute inset-0 bg-black/40" onClick={() => setSheetOpen(false)} />
            <div className="absolute right-0 top-0 h-full w-full max-w-xl panel overflow-y-auto p-4">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <h2 className="text-lg font-semibold">{sel.cve_id}</h2>
                  {sel.version && sel.version > 1 && (
                    <span className="chip chip-warning text-xs">
                      v{sel.version}
                    </span>
                  )}
                </div>
                <Button
                  className="btn-outline"
                  onClick={() => {
                    const sp = new URLSearchParams(window.location.search);
                    const fromJob = sp.get("fromJob");
                    if (fromJob) {
                      navigate(`/scan?job=${fromJob}&tab=findings`);
                    } else {
                      navigate("/dashboard");
                    }
                  }}
                >
                  Cerrar
                </Button>

              </div>
              <div className="space-y-4 text-sm">
                <p className="whitespace-pre-wrap">{sel.descripcion_general}</p>

                {/* SCORE + VECTOR */}
                <div className="flex items-center gap-2">
                  <span className={`badge badge-${cvssSeverity(sel.cvssv3?.score ?? 0)}`}>
                    {formatScore(sel.cvssv3?.score)}
                  </span>
                  {sel.cvssv3?.vector && <span className="chip chip-muted">{sel.cvssv3.vector}</span>}
                </div>

                {sel.tipo && (
                  <p><strong>Tipo:</strong> {sel.tipo}</p>
                )}

                {typeof sel.componente_afectado === "string" && (
                  <p>
                    <strong>Componente afectado:</strong>{" "}
                    {sel.componente_afectado && sel.componente_afectado.trim()
                      ? sel.componente_afectado
                      : "Desconocido"}
                  </p>
                )}

                {Array.isArray(sel.versiones_afectadas) && sel.versiones_afectadas.length > 0 && (
                  <div>
                    <div className="text-xs text-[var(--muted)] mb-1">Versiones afectadas</div>
                    <ul className="list-disc pl-5">
                      {sel.versiones_afectadas.map((v, idx) => (
                        <li key={idx}>{v}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {/* ETIQUETAS */}
                {Array.isArray(sel.etiquetas) && sel.etiquetas.length > 0 && (
                  <div>
                    <div className="text-xs text-[var(--muted)] mb-1">Etiquetas</div>
                    <div className="flex flex-wrap gap-2">
                      {sel.etiquetas.map((t) => (
                        <span className="chip chip-info" key={t}>{t}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* [ADD] Etiquetas personales */}
                <div className="mt-4">
                  <div className="text-xs text-[var(--muted)] mb-1">Tus etiquetas</div>
                  <div className="flex flex-wrap gap-2 mb-2">
                    {(userTags[sel.cve_id] || []).map((t) => (
                      <span key={t} className="chip chip-warning inline-flex items-center gap-2">
                        {t}
                        <button
                          className="text-xs opacity-70 hover:opacity-100"
                          title="Quitar etiqueta"
                          onClick={() => removeUserTag(sel.cve_id, t)}
                        >
                          ✕
                        </button>
                      </span>
                    ))}
                    {!(userTags[sel.cve_id]?.length) && <span className="text-xs text-[var(--muted)]">No tienes etiquetas para este CVE.</span>}
                  </div>
                  <div className="flex gap-2">
                    <input
                      className="flex-1 rounded-md border px-2 py-1 text-sm"
                      placeholder="Añade una etiqueta (p. ej. 'auditar', 'prioridad-alta')"
                      value={newTag}
                      onChange={(e) => setNewTag(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") addUserTag(sel.cve_id, newTag); }}
                    />
                    <Button className="btn-outline" onClick={() => addUserTag(sel.cve_id, newTag)}>Añadir</Button>
                  </div>
                </div>

                {/* INFRA */}
                {Array.isArray(sel.infraestructura_5g_afectada) && sel.infraestructura_5g_afectada.length > 0 && (
                  <div>
                    <div className="text-xs text-[var(--muted)] mb-1">Infraestructura 5G</div>
                    <div className="flex flex-wrap gap-2">
                      {sel.infraestructura_5g_afectada.map((i) => (
                        <span className="chip chip-success" key={i}>{i}</span>
                      ))}
                    </div>
                  </div>
                )}

                {sel.dificultad_explotacion && (
                  <p><strong>Dificultad de explotación:</strong> {sel.dificultad_explotacion}</p>
                )}

                {sel.impacto_potencial && (
                  <ul className="list-disc pl-5">
                    <li><strong>Confidencialidad:</strong> {sel.impacto_potencial.confidencialidad || "—"}</li>
                    <li><strong>Integridad:</strong> {sel.impacto_potencial.integridad || "—"}</li>
                    <li><strong>Disponibilidad:</strong> {sel.impacto_potencial.disponibilidad || "—"}</li>
                  </ul>
                )}

                <p><strong>Fecha publicación:</strong> {fmtFecha(sel.fecha_publicacion)}</p>
                {sel.fecha_registro_mitre && <p><strong>Registro MITRE:</strong> {sel.fecha_registro_mitre}</p>}
                {sel.recomendaciones_remediacion && (
                  <div>
                    <div className="text-xs text-[var(--muted)] mb-1">Remediación</div>
                    <p className="whitespace-pre-wrap">{sel.recomendaciones_remediacion}</p>
                  </div>
                )}

                {sel.referencias_mitre && sel.referencias_mitre.length > 0 && (
                  <div>
                    <strong>Referencias MITRE:</strong>
                    <ul className="list-disc pl-5">
                      {sel.referencias_mitre.map((r) => (
                        <li key={r}>
                          <a href={r} target="_blank" rel="noreferrer" className="underline">
                            {r}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        <p className="text-sm text-[var(--muted)] mt-3">
          Mostrando {data.length} de {total} vulnerabilidades
        </p>
      </div>
    </div>
  );
}
