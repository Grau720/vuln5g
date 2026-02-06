// components/AssetDiscoveryDashboard.tsx
// VERSIÓN CORREGIDA CON DEBUG
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
  software?: string;
  version?: string;
  version_confidence?: "HIGH" | "MEDIUM" | "LOW";
  version_method?: "http_header" | "api_endpoint" | "ssh_banner" | "port_inference" | null;
  
  registered_data?: {
    hostname?: string;
    role?: string;
    services?: Array<{ name: string; port: number; protocol: string }>;
    tags?: string[];
    software?: string;
    version?: string;
    criticality?: string;
    owner?: string;
  };
  
  changes?: {
    hostname?: { old: string; new: string };
    role?: { old: string; new: string };
    software?: { old: string; new: string };
    version?: { old: string; new: string };
    services_added?: Array<{ name: string; port: number; protocol: string }>;
    services_removed?: Array<{ name: string; port: number; protocol: string }>;
    tags_added?: string[];
    tags_removed?: string[];
  };
};

/* ============================
   Componente de Diff Visual
============================ */
function ChangesDiff({ changes }: { changes: DiscoveredAsset['changes'] }) {
  if (!changes) {
    console.log("ChangesDiff: No changes object");
    return null;
  }
  
  // ✅ VERIFICAR SI HAY CAMBIOS CON CONTENIDO REAL
  const hasRealChanges = (
    changes.hostname ||
    changes.role ||
    changes.software ||
    changes.version ||
    (changes.services_added && changes.services_added.length > 0) ||
    (changes.services_removed && changes.services_removed.length > 0) ||
    (changes.tags_added && changes.tags_added.length > 0) ||
    (changes.tags_removed && changes.tags_removed.length > 0)
  );
  
  if (!hasRealChanges) {
    console.log("ChangesDiff: No real changes to display (empty changes object)");
    return null;
  }
  
  console.log("ChangesDiff: Rendering changes:", changes);
  
  return (
    <div className="mt-3 p-3 bg-amber-900/20 border border-amber-500/30 rounded-md space-y-2">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-sm font-semibold text-amber-400">⚠️ Cambios detectados</span>
      </div>
      
      {changes.hostname && (
        <div className="text-xs">
          <span className="text-slate-400">Hostname:</span>{' '}
          <code className="text-red-400 line-through">{changes.hostname.old}</code>
          {' → '}
          <code className="text-green-400">{changes.hostname.new}</code>
        </div>
      )}
      
      {changes.role && (
        <div className="text-xs">
          <span className="text-slate-400">Role:</span>{' '}
          <code className="text-red-400 line-through">{changes.role.old}</code>
          {' → '}
          <code className="text-green-400">{changes.role.new}</code>
        </div>
      )}
      
      {changes.software && (
        <div className="text-xs">
          <span className="text-slate-400">Software:</span>{' '}
          <code className="text-red-400 line-through">{changes.software.old}</code>
          {' → '}
          <code className="text-green-400">{changes.software.new}</code>
        </div>
      )}
      
      {changes.version && (
        <div className="text-xs">
          <span className="text-slate-400">Version:</span>{' '}
          <code className="text-red-400 line-through">v{changes.version.old}</code>
          {' → '}
          <code className="text-green-400">v{changes.version.new}</code>
        </div>
      )}
      
      {changes.services_added && changes.services_added.length > 0 && (
        <div className="text-xs">
          <span className="text-slate-400">Services añadidos:</span>{' '}
          {changes.services_added.map((s, i) => (
            <code key={i} className="text-green-400">
              {i > 0 && ', '}
              {s.name}:{s.port}
            </code>
          ))}
        </div>
      )}
      
      {changes.services_removed && changes.services_removed.length > 0 && (
        <div className="text-xs">
          <span className="text-slate-400">Services eliminados:</span>{' '}
          {changes.services_removed.map((s, i) => (
            <code key={i} className="text-red-400">
              {i > 0 && ', '}
              {s.name}:{s.port}
            </code>
          ))}
        </div>
      )}
      
      {changes.tags_added && changes.tags_added.length > 0 && (
        <div className="text-xs">
          <span className="text-slate-400">Tags añadidos:</span>{' '}
          {changes.tags_added.map((t, i) => (
            <code key={i} className="text-green-400">
              {i > 0 && ', '}
              {t}
            </code>
          ))}
        </div>
      )}
      
      {changes.tags_removed && changes.tags_removed.length > 0 && (
        <div className="text-xs">
          <span className="text-slate-400">Tags eliminados:</span>{' '}
          {changes.tags_removed.map((t, i) => (
            <code key={i} className="text-red-400">
              {i > 0 && ', '}
              {t}
            </code>
          ))}
        </div>
      )}
    </div>
  );
}

/* ============================
   Modal de Confirmación de Cambios
============================ */
type ChangeConfirmationModalProps = {
  asset: DiscoveredAsset;
  onConfirm: (applyChanges: boolean) => void;
  onCancel: () => void;
};

function ChangeConfirmationModal({ asset, onConfirm, onCancel }: ChangeConfirmationModalProps) {
  const changes = asset.changes;
  
  console.log("ChangeConfirmationModal: Rendering for asset", asset.ip, "with changes:", changes);
  
  if (!changes) {
    console.log("ChangeConfirmationModal: No changes, not rendering");
    return null;
  }
  
  const changeCount = Object.keys(changes).length;
  
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onCancel}
      />
      
      {/* Modal */}
      <div className="relative w-full max-w-2xl mx-4 panel p-6 max-h-[80vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between mb-4 pb-4 border-b border-slate-700">
          <div>
            <h3 className="text-xl font-semibold text-amber-400">
              ⚠️ Confirmar Cambios Detectados
            </h3>
            <p className="text-sm text-slate-400 mt-1">
              Se detectaron {changeCount} cambio{changeCount !== 1 ? 's' : ''} en el asset <code className="text-blue-400">{asset.ip}</code>
            </p>
          </div>
          <button
            onClick={onCancel}
            className="text-slate-400 hover:text-white text-2xl leading-none"
          >
            ×
          </button>
        </div>
        
        {/* Asset info */}
        <div className="mb-4 p-3 bg-slate-800/50 rounded">
          <div className="text-sm">
            <strong>{asset.hostname}</strong>
            <span className="text-slate-500 mx-2">•</span>
            <span className="text-slate-400">{asset.role}</span>
          </div>
        </div>
        
        {/* Changes detail */}
        <div className="space-y-3 mb-6">
          <h4 className="text-sm font-semibold text-slate-300">Cambios a aplicar:</h4>
          
          {changes.hostname && (
            <div className="p-3 bg-amber-900/10 border border-amber-500/30 rounded">
              <div className="text-xs text-slate-400 mb-1">Hostname</div>
              <div className="flex items-center gap-2 text-sm">
                <code className="text-red-400 line-through">{changes.hostname.old}</code>
                <span className="text-slate-500">→</span>
                <code className="text-green-400 font-semibold">{changes.hostname.new}</code>
              </div>
            </div>
          )}
          
          {changes.version && (
            <div className="p-3 bg-emerald-900/10 border border-emerald-500/30 rounded">
              <div className="text-xs text-slate-400 mb-1">Versión</div>
              <div className="flex items-center gap-2 text-sm">
                <code className="text-red-400 line-through">v{changes.version.old}</code>
                <span className="text-slate-500">→</span>
                <code className="text-green-400 font-semibold">v{changes.version.new}</code>
              </div>
              <div className="mt-2 text-xs text-emerald-400">
                ✓ Se agregará al historial de versiones
              </div>
            </div>
          )}
          
          {changes.services_added && changes.services_added.length > 0 && (
            <div className="p-3 bg-emerald-900/10 border border-emerald-500/30 rounded">
              <div className="text-xs text-slate-400 mb-2">Servicios Añadidos</div>
              <div className="flex flex-wrap gap-2">
                {changes.services_added.map((s, i) => (
                  <code key={i} className="text-xs px-2 py-1 bg-emerald-500/20 text-emerald-300 rounded">
                    +{s.name}:{s.port}/{s.protocol}
                  </code>
                ))}
              </div>
            </div>
          )}
        </div>
        
        {/* Actions */}
        <div className="flex gap-3">
          <Button
            className="flex-1 btn-solid bg-amber-600 hover:bg-amber-700"
            onClick={() => onConfirm(true)}
          >
            ✓ Aplicar Cambios
          </Button>
          <Button
            className="flex-1 btn-outline"
            onClick={() => onConfirm(false)}
          >
            ✗ Ignorar y Marcar como Revisado
          </Button>
          <Button
            className="btn-ghost"
            onClick={onCancel}
          >
            Cancelar
          </Button>
        </div>
      </div>
    </div>
  );
}

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
  const [statusFilter, setStatusFilter] = useState<"all" | "new" | "registered" | "changed">("all");
  const [confirmingChanges, setConfirmingChanges] = useState<string | null>(null);
  
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
      
      console.log("📥 Assets recibidos del backend:", j.assets);
      
      // LOG: Verificar cuáles tienen changes
      j.assets.forEach((asset: DiscoveredAsset) => {
        if (asset.changes) {
          console.log(`✅ Asset ${asset.ip} TIENE CAMBIOS:`, asset.changes);
        } else {
          console.log(`❌ Asset ${asset.ip} NO tiene cambios (changes=${asset.changes})`);
        }
      });
      
      setPendingAssets(j.assets || []);
    } catch (e: any) {
      console.error("Error loading pending assets:", e);
    } finally {
      setLoading(false);
    }
  };

  const loadConfig = async () => {
    try {
      const r = await fetch('/api/v1/assets/discovery/config');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      
      const data = await r.json();
      const config = data.config;
      
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

  const runDiscovery = async () => {
    setDiscovering(true);
    try {
      const targets: any = {};
      
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

  const updateAsset = async (ip: string, applyChanges: boolean = true) => {
    const asset = pendingAssets.find(a => a.ip === ip);
    if (!asset || !asset.changes) {
      console.error(`No se puede actualizar ${ip}: asset no encontrado o sin cambios`);
      return;
    }
    
    console.log(`🔄 Actualizando asset ${ip} (apply=${applyChanges})`);
    
    try {
      const r = await fetch(`/api/v1/assets/discovery/${ip}/update`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          apply_changes: applyChanges,
          changes: asset.changes
        })
      });
      
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      
      const result = await r.json();
      
      await fetchPendingAssets();
      setConfirmingChanges(null);
      
      if (applyChanges) {
        alert(
          `✅ Asset ${ip} actualizado correctamente\n\n` +
          `Cambios aplicados: ${result.changes_applied?.join(', ') || 'ninguno'}`
        );
      } else {
        alert(`✓ Cambios ignorados. Asset ${ip} marcado como revisado.`);
      }
    } catch (e: any) {
      alert(`Error actualizando asset: ${e.message}`);
    }
  };

  const rejectAsset = async (ip: string) => {
    if (!confirm(`¿Descartar asset ${ip}?`)) return;
    
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

  useEffect(() => {
    fetchPendingAssets();
    loadConfig();
  }, []);

  // Filtered assets
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
      statusFilter === "registered" ? asset.already_registered && !asset.changes :
      statusFilter === "changed" ? asset.already_registered && asset.changes : true;
    
    return matchesSearch && matchesStatus;
  });

  // Contadores
  const newAssetsCount = pendingAssets.filter(a => !a.already_registered).length;
  const registeredAssetsCount = pendingAssets.filter(a => a.already_registered && !a.changes).length;
  const changedAssetsCount = pendingAssets.filter(a => a.already_registered && a.changes).length;
  const highConfidenceCount = pendingAssets.filter(a => a.confidence === 'HIGH').length;

  console.log("📊 Contadores:", { 
    total: pendingAssets.length,
    new: newAssetsCount, 
    registered: registeredAssetsCount, 
    changed: changedAssetsCount 
  });

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
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
            <CardTitle className="text-sm">✨ Nuevos</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-green-400">
              {newAssetsCount}
            </div>
            <p className="text-xs text-slate-500 mt-1">Requieren aprobación</p>
          </CardContent>
        </Card>

        <Card className={cn(changedAssetsCount > 0 && "ring-2 ring-amber-500/50")}>
          <CardHeader className="py-3">
            <CardTitle className="text-sm">⚠️ Cambios Detectados</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-amber-400">
              {changedAssetsCount}
            </div>
            <p className="text-xs text-slate-500 mt-1">Requieren revisión</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="py-3">
            <CardTitle className="text-sm">✓ Sin Cambios</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-blue-400">
              {registeredAssetsCount}
            </div>
            <p className="text-xs text-slate-500 mt-1">Ya registrados</p>
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

      {/* Discovery Config Panel */}
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

      {/* Filter */}
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
            onClick={() => setStatusFilter("changed")}
            className={cn(
              "chip cursor-pointer", 
              statusFilter === "changed" ? "chip-warning" : "chip-muted",
              changedAssetsCount > 0 && "animate-pulse"
            )}
          >
            ⚠️ Cambios ({changedAssetsCount})
          </button>
          <button
            onClick={() => setStatusFilter("registered")}
            className={cn("chip cursor-pointer", statusFilter === "registered" ? "chip-info" : "chip-muted")}
          >
            ✓ Sin cambios ({registeredAssetsCount})
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
            {filteredAssets.map((asset) => {
              // DEBUG: Log cada asset
              const hasChanges = asset.changes && Object.keys(asset.changes).length > 0;
              console.log(`Renderizando asset ${asset.ip}:`, {
                already_registered: asset.already_registered,
                has_changes: hasChanges,
                changes: asset.changes
              });
              
              return (
                <div 
                  key={asset.ip} 
                  className={cn(
                    "panel p-4 hover:bg-slate-800/30 transition-colors",
                    hasChanges && "ring-2 ring-amber-500/30"
                  )}
                >
                  {editingAsset === asset.ip ? (
                    // Edit mode (omitido por brevedad, igual que antes)
                    <div className="space-y-3">
                      <p>Modo edición para {asset.ip}</p>
                    </div>
                  ) : (
                    // View mode
                    <div className="space-y-3">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          {/* Header line */}
                          <div className="flex items-center gap-2 mb-2">
                            <code className="text-base font-mono font-semibold text-amber-400">
                              {asset.ip}
                            </code>
                            
                            {!asset.already_registered && (
                              <span className="chip chip-success text-xs animate-pulse">
                                ✨ Nuevo
                              </span>
                            )}
                            
                            {asset.already_registered && !hasChanges && (
                              <span className="chip chip-info text-xs">
                                ✓ Registrado
                              </span>
                            )}
                            
                            {hasChanges && (
                              <span className="chip chip-warning text-xs animate-pulse">
                                ⚠️ Cambios detectados
                              </span>
                            )}
                            
                            <span className={cn(
                              "chip text-xs",
                              asset.confidence === 'HIGH' ? 'chip-success' :
                              asset.confidence === 'MEDIUM' ? 'chip-warning' : 'chip-muted'
                            )}>
                              {asset.confidence}
                            </span>
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

                          {/* Software/Version */}
                          {(asset.software || asset.version) && (
                            <div className="text-xs mb-2 flex items-center gap-2">
                              <span className="font-semibold text-slate-500">Software:</span>
                              
                              {asset.software && (
                                <code className="text-emerald-400/90 font-medium">
                                  {asset.software}
                                </code>
                              )}
                              
                              {asset.version && asset.version !== 'unknown' && (
                                <code className="text-blue-400/90">
                                  v{asset.version}
                                </code>
                              )}
                            </div>
                          )}
                        </div>

                        {/* Actions */}
                        <div className="flex gap-2">
                          {hasChanges ? (
                            <>
                              <Button
                                className="btn-solid px-3 py-1.5 bg-amber-600 hover:bg-amber-700"
                                onClick={() => {
                                  console.log(`🖱️ Click en Revisar Cambios para ${asset.ip}`);
                                  setConfirmingChanges(asset.ip);
                                }}
                                title="Revisar cambios detectados"
                              >
                                📋 Revisar Cambios
                              </Button>
                              <Button
                                className="btn-outline px-3 py-1.5"
                                onClick={() => updateAsset(asset.ip, false)}
                                title="Ignorar cambios sin revisar"
                              >
                                ✗ Ignorar
                              </Button>
                            </>
                          ) : asset.already_registered ? (
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
                            </>
                          )}
                        </div>
                      </div>

                      {/* Diff de cambios */}
                      <ChangesDiff changes={asset.changes} />
                    </div>
                  )}
                </div>
              );
            })}

            {filteredAssets.length === 0 && !loading && (
              <div className="text-center py-16">
                <div className="text-6xl mb-4">🔍</div>
                <p className="text-lg text-slate-400 mb-2">
                  {filterText 
                    ? "No se encontraron assets con ese filtro" 
                    : statusFilter === "new"
                    ? "No hay assets nuevos pendientes"
                    : statusFilter === "registered"
                    ? "No hay assets sin cambios"
                    : statusFilter === "changed"
                    ? "No hay assets con cambios detectados"
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

      {/* Modal de confirmación */}
      {confirmingChanges && (
        <ChangeConfirmationModal
          asset={pendingAssets.find(a => a.ip === confirmingChanges)!}
          onConfirm={(apply) => {
            updateAsset(confirmingChanges, apply);
          }}
          onCancel={() => setConfirmingChanges(null)}
        />
      )}
    </div>
  );
}