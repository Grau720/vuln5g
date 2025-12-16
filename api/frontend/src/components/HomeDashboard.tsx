// src/components/HomeDashboard.tsx
import React, { useEffect, useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip as ReTooltip,
  BarChart,
  Bar
} from "recharts";
import { useNavigate } from "react-router-dom";

type ScanJob = {
  job_id: string;
  created_at: string;
  status: string;
  profile: string;
  progress: number;
  metrics?: {
    criticity?: {
      coverage: number;
      avg_score: number;
      max_score: number;
    };
    severities?: {
      Critical: number;
      High: number;
      Medium: number;
      Info: number;
    };
  };
};

type CVE = {
  cve_id: string;
  nombre: string;
  fecha_publicacion: string;
  cvssv3?: { score: number };
};

export default function HomeDashboard() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [criticalCVEs, setCriticalCVEs] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [jobsRes, cvesRes] = await Promise.all([
          fetch("/api/scan/jobs"),
          fetch("/api/v1/cves?min_score=9"),
        ]);
        const jobsJson = await jobsRes.json();
        const cvesJson = await cvesRes.json();
        setJobs(jobsJson.jobs || []);
        setCriticalCVEs(cvesJson.cves || []);
      } catch (e) {
        console.error("Error cargando datos iniciales", e);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  // últimos 5 jobs
  const recentJobs = jobs.slice(0, 5);

  // criticidad promedio de los jobs
  const criticidadPromedio = useMemo(() => {
    const fins = jobs.filter((j) => j.metrics?.criticity);
    if (!fins.length) return 0;
    const avg = fins.reduce((acc, j) => acc + (j.metrics!.criticity!.avg_score || 0), 0) / fins.length;
    return avg;
  }, [jobs]);

  // severidades acumuladas para gráfico
  const severitiesData = useMemo(() => {
    const total = { Critical: 0, High: 0, Medium: 0, Info: 0 };
    jobs.forEach((j) => {
      const s = j.metrics?.severities || {};
      total.Critical += s.Critical || 0;
      total.High += s.High || 0;
      total.Medium += s.Medium || 0;
      total.Info += s.Info || 0;
    });
    return [total];
  }, [jobs]);

  // serie temporal para críticos (por mes, con CVEs como placeholder)
  const criticalSeries = (() => {
    const map: Record<string, number> = {};
    criticalCVEs.forEach((cve) => {
      const m = (cve.fecha_publicacion || "").slice(0, 7); // YYYY-MM
      if (m) map[m] = (map[m] || 0) + 1;
    });
    return Object.entries(map).map(([month, total]) => ({ month, total }));
  })();

  if (loading) {
    return <p className="p-4">Cargando dashboard...</p>;
  }

  return (
    <div className="global-bg">
      <div className="mx-auto max-w-[1600px] p-4 md:p-6 lg:p-8">
        <header className="mb-6">
          <h1 className="text-2xl font-semibold">📌 Resumen general</h1>
          <p className="text-sm text-[var(--muted)]">
            Visión rápida de escaneos y vulnerabilidades
          </p>
        </header>

        {/* KPIs */}
        <div className="mb-6 grid grid-cols-2 md:grid-cols-4 gap-3">
          <Card>
            <CardHeader className="py-2">
              <CardTitle>Total escaneos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{jobs.length}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle>Jobs activos</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">
              {jobs.filter((j) => j.status === "queued" || j.status === "running").length}
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle>Vuln. críticas</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">{criticalCVEs.length}</CardContent>
          </Card>
          <Card>
            <CardHeader className="py-2">
              <CardTitle>Criticidad promedio</CardTitle>
            </CardHeader>
            <CardContent className="text-2xl font-bold">
              {criticidadPromedio.toFixed(1)}
            </CardContent>
          </Card>
        </div>

        {/* Acciones rápidas */}
        <div className="mb-6 flex flex-wrap gap-3">
          <Button className="btn-solid" onClick={() => navigate("/scan?new=1")}>
            ➕ Nuevo escaneo
          </Button>
          <Button className="btn-outline" onClick={() => navigate("/dashboard")}>
            📊 Ver vulnerabilidades
          </Button>
          <Button className="btn-outline" onClick={() => navigate("/scan?tab=planner")}>
            📅 Planificador
          </Button>
        </div>

        {/* Gráfico severidades */}
        {/* <Card className="mb-6">
          <CardHeader className="py-2">
            <CardTitle>Distribución de severidades</CardTitle>
          </CardHeader>
          <CardContent style={{ height: 300 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severitiesData}>
                <CartesianGrid stroke="rgba(148,163,184,.25)" strokeDasharray="3 3" />
                <XAxis dataKey={() => "Jobs"} />
                <YAxis allowDecimals={false} />
                <Bar dataKey="Critical" stackId="a" fill="#dc2626" />
                <Bar dataKey="High" stackId="a" fill="#f97316" />
                <Bar dataKey="Medium" stackId="a" fill="#facc15" />
                <Bar dataKey="Info" stackId="a" fill="#9ca3af" />
                <ReTooltip />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card> */}

        {/* Gráfica críticos en el tiempo */}
        {/* <Card className="mb-6">
          <CardHeader className="py-2">
            <CardTitle>Tendencia de CVEs críticos</CardTitle>
          </CardHeader>
          <CardContent style={{ height: 300 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={criticalSeries}>
                <CartesianGrid stroke="rgba(148,163,184,.25)" strokeDasharray="3 3" />
                <XAxis dataKey="month" />
                <YAxis allowDecimals={false} />
                <Line type="monotone" dataKey="total" stroke="#ef4444" strokeWidth={2} />
                <ReTooltip />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card> */}

        {/* Últimos jobs */}
        <Card>
          <CardHeader className="py-2">
            <CardTitle>Últimos escaneos</CardTitle>
          </CardHeader>
          <CardContent>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[var(--muted)]">
                  <th className="py-1 px-2 text-left">Job ID</th>
                  <th className="py-1 px-2">Estado</th>
                  <th className="py-1 px-2">Perfil</th>
                  <th className="py-1 px-2">Creado</th>
                </tr>
              </thead>
              <tbody>
                {recentJobs.map((j) => (
                  <tr key={j.job_id} className="border-t border-[var(--panel-border)]">
                    <td className="py-1 px-2 font-mono">
                        <button
                            onClick={(e) => {
                            e.stopPropagation();
                            window.location.href = `/scan?tab=findings&job=${j.job_id}`;
                            }}
                            className="text-blue-500 underline hover:text-blue-400"
                        >
                            {j.job_id}
                        </button>
                    </td>

                    <td className="py-1 px-2">{j.status}</td>
                    <td className="py-1 px-2">{j.profile}</td>
                    <td className="py-1 px-2">
                      {new Date(j.created_at).toLocaleString("es-ES")}
                    </td>
                  </tr>
                ))}
                {!recentJobs.length && (
                  <tr>
                    <td colSpan={4} className="py-3 text-center text-[var(--muted)]">
                      No hay jobs aún
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
