// components/AssetDiscoveryDashboard.tsx
import React, { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

/* ============================
   Tipos
============================ */
type DiscoveredAsset = {
  ip: string;
  hostname: string;
  role: string;
  services: Array<{ name: string; port: number; protocol: string }>;
  tags: string[];
  discovery_method: string;
  discovered_at: string;
  status: "pending" | "approved" | "rejected";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  evidence?: any;
  already_registered?: boolean;
  registered_at?: string;
};

/* ============================
   Componente principal
============================ */
export default function AssetDiscoveryDashboard() {
  const [pendingAssets, setPendingAssets] = useState<DiscoveredAsset[]>([]);
  const [loading, setLoading] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [editingAsset, setEditingAsset] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<any>({});
  const [filterText, setFilterText] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "new" | "registered">("all");
  
  // Estado para targets de discovery
  const [discoveryTargets, setDiscoveryTargets] = useState({
    core: "172.22.0.0/24",
    ran_oam: "",
    transport: ""
  });
  const [discoveryProfile, setDiscoveryProfile] = useState<"fast" | "standard" | "exhaustive">("fast");

  // ---- Fetch pending assets ----
  const fetchPendingAssets = async () => {
    setLoading(true);
    try {
      const r = await fetch('/api/v1/assets/discovery/pending');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setPendingAssets(j.assets || []);
    } catch (e: any) {
      console.error("Error loading pending assets:", e);
    } finally {
      setLoading(false);
    }
  };

  // 🆕 Cargar configuración auto-detectada
  const loadConfig = async () => {
    try {
      const r = await fetch('/api/v1/assets/discovery/config');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      
      const data = await r.json();
      const config = data.config;
      
      // Auto-rellenar con targets sugeridos
      if (config.default_targets.core.length > 0) {
        setDiscoveryTargets({
          core: config.default_targets.core.join(', '),
          ran_oam: config.default_targets.ran_oam.join(', '),
          transport: config.default_targets.transport.join(', ')
        });
      }
      
      console.log('✅ Configuración auto-detectada:', config);
      
    } catch (e: any) {
      console.error('Error cargando config:', e);
    }
  };

  // Run network discovery (profesional)
  const runDiscovery = async () => {
    setDiscovering(true);
    try {
      const targets: any = {};
      
      // Parsear targets desde el input
      if (discoveryTargets.core.trim()) {
        targets.core = discoveryTargets.core.split(',').map(s => s.trim()).filter(Boolean);
      }
      if (discoveryTargets.ran_oam.trim()) {
        targets.ran_oam = discoveryTargets.ran_oam.split(',').map(s => s.trim()).filter(Boolean);
      }
      if (discoveryTargets.transport.trim()) {
        targets.transport = discoveryTargets.transport.split(',').map(s => s.trim()).filter(Boolean);
      }
      
      const r = await fetch('/api/v1/assets/discovery/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          targets,
          profile: discoveryProfile
        })
      });
      
      if (!r.ok) {
        const err = await r.json();
        throw new Error(err.detail || err.error || `HTTP ${r.status}`);
      }
      
      const result = await r.json();
      
      await fetchPendingAssets();
      
      // Mejorar el mensaje con el método usado
      const methodEmoji = result.method_used === 'docker' ? '🐳' : '🌐';
      const methodName = result.method_used === 'docker' ? 'Docker Inspect' : 'Network Scan';
      
      alert(
        `✅ Discovery completado via ${methodEmoji} ${methodName}\n\n` +
        `${result.discovered_count} hosts activos encontrados\n` +
        `${result.total_pending} assets pendientes de revisión`
      );
    } catch (e: any) {
      alert(`❌ Error en discovery: ${e.message}`);
    } finally {
      setDiscovering(false);
    }
  };

  // ---- Approve asset ----
  const approveAsset = async (ip: string, overrides: any = {}) => {
    try {
      const r = await fetch(`/api/v1/assets/discovery/${ip}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(overrides)
      });
      
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      
      await fetchPendingAssets();
      setEditingAsset(null);
      setEditForm({});
    } catch (e: any) {
      alert(`Error aprobando asset: ${e.message}`);
    }
  };

  // ---- Reject asset ----
  const rejectAsset = async (ip: string) => {
    if (!confirm(`¿Rechazar asset ${ip}?`)) return;
    
    try {
      const r = await fetch(`/api/v1/assets/discovery/${ip}/reject`, {
        method: 'POST'
      });
      
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      
      await fetchPendingAssets();
    } catch (e: any) {
      alert(`Error rechazando asset: ${e.message}`);
    }
  };

  // 🆕 Initial load con auto-config
  useEffect(() => {
    fetchPendingAssets();
    loadConfig();  // 👈 CARGA AUTOMÁTICA DE CONFIGURACIÓN
  }, []);

  // 🆕 Filtered assets con filtro de estado
  const filteredAssets = pendingAssets.filter(asset => {
    const search = filterText.toLowerCase();
    const matchesSearch = (
      asset.ip.toLowerCase().includes(search) ||
      asset.hostname.toLowerCase().includes(search) ||
      asset.role.toLowerCase().includes(search)
    );
    
    const matchesStatus = 
      statusFilter === "all" ? true :
      statusFilter === "new" ? !asset.already_registered :
      statusFilter === "registered" ? asset.already_registered : true;
    
    return matchesSearch && matchesStatus;
  });

  // 🆕 Contadores
  const newAssetsCount = pendingAssets.filter(a => !a.already_registered).length;
  const registeredAssetsCount = pendingAssets.filter(a => a.already_registered).length;
  const highConfidenceCount = pendingAssets.filter(a => a.confidence === 'HIGH').length;

  return (
    <div className="space-y-6">
      {/* Header */}

      {/* 🆕 Stats con 4 columnas */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="py-3">
            <CardTitle className="text-sm">Pending Review</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-amber-400">
              {pendingAssets.length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="py-3">
            <CardTitle className="text-sm">Ya Registrados</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-blue-400">
              {registeredAssetsCount}
            </div>
            <p className="text-xs text-slate-500 mt-1">Sin cambios</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="py-3">
            <CardTitle className="text-sm">Nuevos Descubiertos</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-green-400">
              {newAssetsCount}
            </div>
            <p className="text-xs text-slate-500 mt-1">Requieren revisión</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="py-3">
            <CardTitle className="text-sm">High Confidence</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-purple-400">
              {highConfidenceCount}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Discovery Configuration Panel */}
      <Card>
        <CardHeader>
          <CardTitle>🌐 Network Discovery Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">
                Core Network (CIDR o IPs)
              </label>
              <Input
                value={discoveryTargets.core}
                onChange={(e) => setDiscoveryTargets({...discoveryTargets, core: e.target.value})}
                placeholder="172.22.0.0/24, 10.0.0.0/24"
                disabled={discovering}
              />
              <p className="text-xs text-slate-500 mt-1">
                💡 Rango donde están AMF, SMF, UDM, etc.
              </p>
            </div>
            
            <div>
              <label className="text-sm font-medium mb-2 block">
                RAN/OAM (opcional)
              </label>
              <Input
                value={discoveryTargets.ran_oam}
                onChange={(e) => setDiscoveryTargets({...discoveryTargets, ran_oam: e.target.value})}
                placeholder="192.168.100.0/24"
                disabled={discovering}
              />
              <p className="text-xs text-slate-500 mt-1">
                gNodeB, eNodeB, elementos RAN
              </p>
            </div>
            
            <div>
              <label className="text-sm font-medium mb-2 block">
                Transport/UPF (opcional)
              </label>
              <Input
                value={discoveryTargets.transport}
                onChange={(e) => setDiscoveryTargets({...discoveryTargets, transport: e.target.value})}
                placeholder="10.10.0.0/24"
                disabled={discovering}
              />
              <p className="text-xs text-slate-500 mt-1">
                User Plane Functions, routers
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex-1">
              <label className="text-sm font-medium mb-2 block">
                Discovery Profile
              </label>
              <div className="flex gap-2">
                {(["fast", "standard", "exhaustive"] as const).map(profile => (
                  <button
                    key={profile}
                    onClick={() => setDiscoveryProfile(profile)}
                    disabled={discovering}
                    className={cn(
                      "chip cursor-pointer",
                      discoveryProfile === profile ? "chip-success" : "chip-muted",
                      discovering && "opacity-50 cursor-not-allowed"
                    )}
                  >
                    {profile === "fast" && "⚡ Fast (~3-5 min)"}
                    {profile === "standard" && "🎯 Standard (~5-10 min)"}
                    {profile === "exhaustive" && "🔬 Exhaustive (~15-30 min)"}
                  </button>
                ))}
              </div>
            </div>

            <div className="pt-6">
              <Button 
                className="btn-solid px-6" 
                onClick={runDiscovery}
                disabled={discovering}
              >
                {discovering ? "🔍 Escaneando red..." : "🔍 Start Discovery"}
              </Button>
            </div>
          </div>

          {discovering && (
            <div className="panel p-4 bg-blue-900/20 border border-blue-500/30">
              <div className="flex items-center gap-3">
                <div className="animate-spin text-2xl">⏳</div>
                <div>
                  <div className="text-sm font-medium text-blue-400">
                    Discovery en progreso...
                  </div>
                  <div className="text-xs text-slate-400">
                    Escaneando red con perfil <strong>{discoveryProfile}</strong>. 
                    Esto puede tardar varios minutos.
                  </div>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 🆕 Filter con filtro de estado */}
      <div className="panel p-3 flex flex-col md:flex-row items-start md:items-center gap-3">
        <Input
          placeholder="🔍 Buscar por IP, hostname o rol..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="max-w-md"
        />
        
        <div className="flex gap-2">
          <button
            onClick={() => setStatusFilter("all")}
            className={cn("chip cursor-pointer", statusFilter === "all" ? "chip-info" : "chip-muted")}
          >
            Todos ({pendingAssets.length})
          </button>
          <button
            onClick={() => setStatusFilter("new")}
            className={cn("chip cursor-pointer", statusFilter === "new" ? "chip-success" : "chip-muted")}
          >
            ✨ Nuevos ({newAssetsCount})
          </button>
          <button
            onClick={() => setStatusFilter("registered")}
            className={cn("chip cursor-pointer", statusFilter === "registered" ? "chip-info" : "chip-muted")}
          >
            ✓ Registrados ({registeredAssetsCount})
          </button>
        </div>
      </div>

      {/* Assets list */}
      <Card>
        <CardHeader>
          <CardTitle>
            Assets Descubiertos ({filteredAssets.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {filteredAssets.map((asset) => (
              <div 
                key={asset.ip} 
                className="panel p-4 hover:bg-slate-800/30 transition-colors"
              >
                {editingAsset === asset.ip ? (
                  // 📝 Edit mode
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-xs text-[var(--muted)]">Hostname</label>
                        <Input
                          value={editForm.hostname || asset.hostname}
                          onChange={(e) => setEditForm({...editForm, hostname: e.target.value})}
                          className="mt-1"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-[var(--muted)]">Role</label>
                        <Input
                          value={editForm.role || asset.role}
                          onChange={(e) => setEditForm({...editForm, role: e.target.value})}
                          className="mt-1"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-[var(--muted)]">Criticality</label>
                        <select
                          value={editForm.criticality || 'MEDIUM'}
                          onChange={(e) => setEditForm({...editForm, criticality: e.target.value})}
                          className="mt-1 w-full rounded-md border px-3 py-2 text-sm bg-slate-900 border-slate-700"
                        >
                          <option value="LOW">LOW</option>
                          <option value="MEDIUM">MEDIUM</option>
                          <option value="HIGH">HIGH</option>
                          <option value="CRITICAL">CRITICAL</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-xs text-[var(--muted)]">Owner</label>
                        <Input
                          value={editForm.owner || 'unknown'}
                          onChange={(e) => setEditForm({...editForm, owner: e.target.value})}
                          className="mt-1"
                          placeholder="team-name"
                        />
                      </div>
                    </div>
                    
                    <div className="flex gap-2 justify-end">
                      <Button
                        className="btn-solid px-3 py-1.5"
                        onClick={() => approveAsset(asset.ip, editForm)}
                      >
                        ✓ Approve with changes
                      </Button>
                      <Button
                        className="btn-outline px-3 py-1.5"
                        onClick={() => {
                          setEditingAsset(null);
                          setEditForm({});
                        }}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  // 👁️ View mode
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      {/* Header line */}
                      <div className="flex items-center gap-2 mb-2">
                        <code className="text-base font-mono font-semibold text-amber-400">
                          {asset.ip}
                        </code>
                        
                        {/* 🆕 Badge si ya está registrado */}
                        {asset.already_registered && (
                          <span className="chip chip-info text-xs">
                            ✓ Ya registrado
                          </span>
                        )}
                        {!asset.already_registered && (
                          <span className="chip chip-success text-xs animate-pulse">
                            ✨ Nuevo
                          </span>
                        )}
                        
                        <span className={cn(
                          "chip text-xs",
                          asset.confidence === 'HIGH' ? 'chip-success' :
                          asset.confidence === 'MEDIUM' ? 'chip-warning' : 'chip-muted'
                        )}>
                          {asset.confidence}
                        </span>
                        {asset.tags?.map((tag: string) => (
                          <span key={tag} className="chip chip-muted text-xs">
                            {tag}
                          </span>
                        ))}
                      </div>

                      {/* Main info */}
                      <div className="text-sm mb-2">
                        <strong className="text-slate-200">{asset.hostname}</strong>
                        <span className="text-slate-500 mx-2">•</span>
                        <span className="text-slate-400">{asset.role}</span>
                      </div>

                      {/* Services */}
                      {asset.services && asset.services.length > 0 && (
                        <div className="text-xs text-slate-400 mb-2">
                          <span className="font-semibold text-slate-500">Services:</span>{' '}
                          {asset.services.map((s: any, idx: number) => (
                            <span key={idx}>
                              {idx > 0 && ', '}
                              <code className="text-amber-400/80">
                                {s.name}:{s.port}/{s.protocol}
                              </code>
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Evidence (puertos abiertos) */}
                      {asset.evidence?.open_ports && asset.evidence.open_ports.length > 0 && (
                        <div className="text-xs text-slate-500 mb-2">
                          <span className="font-semibold">Puertos detectados:</span>{' '}
                          <code className="text-xs">
                            {asset.evidence.open_ports.slice(0, 10).join(', ')}
                            {asset.evidence.open_ports.length > 10 && ` (+${asset.evidence.open_ports.length - 10} más)`}
                          </code>
                        </div>
                      )}

                      {/* Metadata */}
                      <div className="text-xs text-slate-500 flex items-center gap-3">
                        <span>
                          Discovered: {new Date(asset.discovered_at).toLocaleString('es-ES')}
                        </span>
                        <span>•</span>
                        <span>via {asset.discovery_method || 'unknown'}</span>
                        {asset.registered_at && (
                          <>
                            <span>•</span>
                            <span>Registrado: {new Date(asset.registered_at).toLocaleString('es-ES')}</span>
                          </>
                        )}
                      </div>
                    </div>

                    {/* 🆕 Actions según estado */}
                    <div className="flex gap-2">
                      {asset.already_registered ? (
                        // Si ya está registrado, mostrar botón para ver/descartar
                        <>
                          <Button
                            className="btn-outline px-3 py-1.5"
                            onClick={() => window.open(`/assets/${asset.ip}`, '_blank')}
                            title="Ver en inventario"
                          >
                            👁️ Ver
                          </Button>
                          <Button
                            className="btn-outline px-3 py-1.5"
                            onClick={() => rejectAsset(asset.ip)}
                            title="Descartar de pending"
                          >
                            ✓ Descartar
                          </Button>
                        </>
                      ) : (
                        // Si es nuevo, mostrar opciones de aprobación
                        <>
                          <Button
                            className="btn-solid px-3 py-1.5"
                            onClick={() => approveAsset(asset.ip)}
                            title="Aprobar con datos automáticos"
                          >
                            ✓ Quick Approve
                          </Button>
                          <Button
                            className="btn-outline px-3 py-1.5"
                            onClick={() => {
                              setEditingAsset(asset.ip);
                              setEditForm({});
                            }}
                            title="Editar antes de aprobar"
                          >
                            ✏️ Edit
                          </Button>
                          <Button
                            className="btn-outline px-3 py-1.5"
                            onClick={() => rejectAsset(asset.ip)}
                            title="Rechazar asset"
                          >
                            ✗ Reject
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))}

            {filteredAssets.length === 0 && !loading && (
              <div className="text-center py-16">
                <div className="text-6xl mb-4">🔍</div>
                <p className="text-lg text-slate-400 mb-2">
                  {filterText 
                    ? "No se encontraron assets con ese filtro" 
                    : statusFilter === "new"
                    ? "No hay assets nuevos pendientes"
                    : statusFilter === "registered"
                    ? "No hay assets ya registrados en pending"
                    : "No hay assets pendientes de aprobación"
                  }
                </p>
                <p className="text-sm text-slate-500">
                  {!filterText && statusFilter === "all" && "Configura los rangos de red arriba y ejecuta un discovery"}
                </p>
              </div>
            )}

            {loading && (
              <div className="text-center py-16">
                <div className="text-4xl mb-4">⏳</div>
                <p className="text-slate-400">Cargando assets...</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}