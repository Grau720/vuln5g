// components/AssetRegisterModal.tsx
// Modal para registrar nuevos assets en el inventario
// Incluye campos específicos para infraestructura 5G

import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// ============================================================================
// TYPES
// ============================================================================
type Props = {
  ip: string;
  maxSeverity: number;
  vulnTypes?: string[];
  onClose: () => void;
  onRegistered: () => void;
};

type Service = {
  name: string;
  port: number;
  protocol: string;
};

// ============================================================================
// CONSTANTS
// ============================================================================
const SEVERITY_TO_CRITICALITY: Record<number, "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"> = {
  1: "CRITICAL",
  2: "HIGH",
  3: "MEDIUM",
  4: "LOW",
};

const COMPONENT_5G_OPTIONS = [
  { value: "", label: "Seleccionar..." },
  // Core Network Functions
  { value: "AMF", label: "AMF - Access and Mobility Management" },
  { value: "SMF", label: "SMF - Session Management Function" },
  { value: "UPF", label: "UPF - User Plane Function" },
  { value: "AUSF", label: "AUSF - Authentication Server Function" },
  { value: "UDM", label: "UDM - Unified Data Management" },
  { value: "UDR", label: "UDR - Unified Data Repository" },
  { value: "PCF", label: "PCF - Policy Control Function" },
  { value: "NRF", label: "NRF - Network Repository Function" },
  { value: "NSSF", label: "NSSF - Network Slice Selection Function" },
  { value: "NEF", label: "NEF - Network Exposure Function" },
  { value: "SMSF", label: "SMSF - SMS Function" },
  { value: "SCP", label: "SCP - Service Communication Proxy" },
  { value: "SEPP", label: "SEPP - Security Edge Protection Proxy" },
  { value: "BSF", label: "BSF - Binding Support Function" },
  // RAN
  { value: "gNB", label: "gNB - gNodeB (5G Base Station)" },
  { value: "CU", label: "CU - Centralized Unit" },
  { value: "DU", label: "DU - Distributed Unit" },
  { value: "RU", label: "RU - Radio Unit" },
  { value: "RIC", label: "RIC - RAN Intelligent Controller" },
  { value: "O-RAN Controller", label: "O-RAN Controller" },
  // Legacy 4G (EPC)
  { value: "HSS", label: "HSS - Home Subscriber Server (4G)" },
  { value: "MME", label: "MME - Mobility Management Entity (4G)" },
  { value: "SGW", label: "SGW - Serving Gateway (4G)" },
  { value: "PGW", label: "PGW - PDN Gateway (4G)" },
  // Support
  { value: "DNS", label: "DNS Server" },
  { value: "NTP", label: "NTP Server" },
  { value: "Logging", label: "Logging Server" },
  { value: "Monitoring", label: "Monitoring System" },
  { value: "Database", label: "Database Server" },
  { value: "Other", label: "Other / Unknown" },
];

const COMMON_SOFTWARE = [
  "Open5GS",
  "free5GC",
  "OpenAirInterface",
  "UERANSIM",
  "srsRAN",
  "Nokia",
  "Ericsson",
  "Huawei",
  "ZTE",
  "Samsung",
  "Mavenir",
  "Affirmed Networks",
  "Custom",
  "Unknown",
];

const COMMON_SERVICES = [
  { name: "HTTP/2 SBI", port: 80, protocol: "TCP" },
  { name: "HTTPS SBI", port: 443, protocol: "TCP" },
  { name: "PFCP", port: 8805, protocol: "UDP" },
  { name: "GTP-U", port: 2152, protocol: "UDP" },
  { name: "GTP-C", port: 2123, protocol: "UDP" },
  { name: "SCTP/NGAP", port: 38412, protocol: "SCTP" },
  { name: "Diameter", port: 3868, protocol: "TCP" },
  { name: "SSH", port: 22, protocol: "TCP" },
  { name: "MongoDB", port: 27017, protocol: "TCP" },
];

// ============================================================================
// COMPONENT
// ============================================================================
export default function AssetRegisterModal({
  ip,
  maxSeverity,
  vulnTypes,
  onClose,
  onRegistered,
}: Props) {
  // Basic info
  const [hostname, setHostname] = useState(ip);
  const [role, setRole] = useState("");
  const [owner, setOwner] = useState("");
  const [criticality, setCriticality] = useState(
    SEVERITY_TO_CRITICALITY[maxSeverity] || "MEDIUM"
  );

  // 5G specific
  const [component5g, setComponent5g] = useState("");
  const [software, setSoftware] = useState("");
  const [version, setVersion] = useState("");

  // Services
  const [services, setServices] = useState<Service[]>([]);
  const [newServiceName, setNewServiceName] = useState("");
  const [newServicePort, setNewServicePort] = useState("");
  const [newServiceProtocol, setNewServiceProtocol] = useState("TCP");

  // Tags
  const [tags, setTags] = useState<string[]>(["auto-registered"]);
  const [newTag, setNewTag] = useState("");

  // State
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Add service
  const addService = () => {
    if (!newServiceName || !newServicePort) return;
    const port = parseInt(newServicePort, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
      setError("Puerto inválido (1-65535)");
      return;
    }
    setServices([...services, { name: newServiceName, port, protocol: newServiceProtocol }]);
    setNewServiceName("");
    setNewServicePort("");
    setError("");
  };

  const addCommonService = (svc: typeof COMMON_SERVICES[0]) => {
    if (!services.some((s) => s.port === svc.port)) {
      setServices([...services, svc]);
    }
  };

  const removeService = (index: number) => {
    setServices(services.filter((_, i) => i !== index));
  };

  // Add tag
  const addTag = () => {
    const tag = newTag.trim().toLowerCase();
    if (tag && !tags.includes(tag)) {
      setTags([...tags, tag]);
    }
    setNewTag("");
  };

  const removeTag = (tag: string) => {
    setTags(tags.filter((t) => t !== tag));
  };

  // Submit
  const submit = async () => {
    if (!hostname.trim()) {
      setError("El hostname es requerido");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const payload: Record<string, any> = {
        ip,
        hostname: hostname.trim(),
        role: role.trim() || "Unknown",
        criticality,
        tags,
      };

      if (owner.trim()) payload.owner = owner.trim();
      if (component5g) payload.component_5g = component5g;
      if (software) payload.software = software;
      if (version.trim()) payload.version = version.trim();
      if (services.length) payload.services = services;

      const res = await fetch("/api/v1/assets/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${res.status}`);
      }

      onRegistered();
    } catch (e: any) {
      setError(e?.message || "Error registrando asset");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <Card className="w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            ➕ Registrar Asset
          </CardTitle>
          <p className="text-xs text-[var(--muted)]">
            Asset detectado automáticamente por actividad de red
          </p>
          {vulnTypes && vulnTypes.length > 0 && (
            <div className="mt-2 p-2 bg-amber-900/20 border border-amber-500/30 rounded text-xs text-amber-300">
              ⚠️ Tipos de ataque detectados: {vulnTypes.join(", ")}
            </div>
          )}
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Error */}
          {error && (
            <div className="p-2 bg-red-900/20 border border-red-500/30 rounded text-sm text-red-400">
              {error}
            </div>
          )}

          {/* Basic Info */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <Label className="text-xs">IP</Label>
              <Input value={ip} disabled className="mt-1 bg-slate-800/50" />
            </div>

            <div>
              <Label className="text-xs">Hostname *</Label>
              <Input
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                className="mt-1"
                placeholder="ej: amf-01.5g.local"
              />
            </div>

            <div>
              <Label className="text-xs">Rol</Label>
              <Input
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="mt-1"
                placeholder="ej: Core Network, RAN, Support"
              />
            </div>

            <div>
              <Label className="text-xs">Owner</Label>
              <Input
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
                className="mt-1"
                placeholder="ej: network-team, security-ops"
              />
            </div>

            <div>
              <Label className="text-xs">Criticidad</Label>
              <select
                className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                value={criticality}
                onChange={(e) => setCriticality(e.target.value as any)}
              >
                <option value="LOW">LOW - Baja</option>
                <option value="MEDIUM">MEDIUM - Media</option>
                <option value="HIGH">HIGH - Alta</option>
                <option value="CRITICAL">CRITICAL - Crítica</option>
              </select>
            </div>
          </div>

          {/* 5G Specific */}
          <div className="pt-3 border-t border-[var(--panel-border)]">
            <h3 className="text-sm font-semibold mb-3">📡 Información 5G</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <Label className="text-xs">Componente 5G</Label>
                <select
                  className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                  value={component5g}
                  onChange={(e) => setComponent5g(e.target.value)}
                >
                  {COMPONENT_5G_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <Label className="text-xs">Software</Label>
                <select
                  className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                  value={software}
                  onChange={(e) => setSoftware(e.target.value)}
                >
                  <option value="">Seleccionar...</option>
                  {COMMON_SOFTWARE.map((sw) => (
                    <option key={sw} value={sw}>{sw}</option>
                  ))}
                </select>
              </div>

              <div>
                <Label className="text-xs">Versión</Label>
                <Input
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                  className="mt-1"
                  placeholder="ej: 2.6.1, 3.0.0"
                />
              </div>
            </div>
          </div>

          {/* Services */}
          <div className="pt-3 border-t border-[var(--panel-border)]">
            <h3 className="text-sm font-semibold mb-3">🔌 Servicios Expuestos</h3>

            {/* Quick add common services */}
            <div className="mb-3">
              <Label className="text-xs text-[var(--muted)]">Añadir rápido:</Label>
              <div className="flex flex-wrap gap-1 mt-1">
                {COMMON_SERVICES.map((svc) => (
                  <button
                    key={svc.port}
                    type="button"
                    onClick={() => addCommonService(svc)}
                    disabled={services.some((s) => s.port === svc.port)}
                    className="px-2 py-0.5 text-xs rounded bg-slate-700/50 hover:bg-slate-600/50 disabled:opacity-30 disabled:cursor-not-allowed"
                  >
                    {svc.name} ({svc.port})
                  </button>
                ))}
              </div>
            </div>

            {/* Current services */}
            {services.length > 0 && (
              <div className="mb-3 flex flex-wrap gap-2">
                {services.map((svc, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center gap-1 px-2 py-1 bg-blue-500/20 text-blue-300 border border-blue-500/40 rounded text-xs"
                  >
                    {svc.name} ({svc.protocol}:{svc.port})
                    <button
                      type="button"
                      onClick={() => removeService(i)}
                      className="text-blue-400/60 hover:text-red-400"
                    >
                      ✕
                    </button>
                  </span>
                ))}
              </div>
            )}

            {/* Add custom service */}
            <div className="flex gap-2 items-end">
              <div className="flex-1">
                <Label className="text-xs">Nombre</Label>
                <Input
                  value={newServiceName}
                  onChange={(e) => setNewServiceName(e.target.value)}
                  className="mt-1"
                  placeholder="ej: HTTP API"
                />
              </div>
              <div className="w-24">
                <Label className="text-xs">Puerto</Label>
                <Input
                  value={newServicePort}
                  onChange={(e) => setNewServicePort(e.target.value)}
                  className="mt-1"
                  placeholder="8080"
                  type="number"
                  min="1"
                  max="65535"
                />
              </div>
              <div className="w-24">
                <Label className="text-xs">Proto</Label>
                <select
                  className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
                  value={newServiceProtocol}
                  onChange={(e) => setNewServiceProtocol(e.target.value)}
                >
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="SCTP">SCTP</option>
                </select>
              </div>
              <Button
                type="button"
                className="btn-outline"
                onClick={addService}
                disabled={!newServiceName || !newServicePort}
              >
                +
              </Button>
            </div>
          </div>

          {/* Tags */}
          <div className="pt-3 border-t border-[var(--panel-border)]">
            <h3 className="text-sm font-semibold mb-3">🏷️ Tags</h3>
            <div className="flex flex-wrap gap-2 mb-3">
              {tags.map((tag) => (
                <span
                  key={tag}
                  className="inline-flex items-center gap-1 px-2 py-1 bg-slate-700/50 rounded text-xs"
                >
                  {tag}
                  <button
                    type="button"
                    onClick={() => removeTag(tag)}
                    className="text-slate-400 hover:text-red-400"
                  >
                    ✕
                  </button>
                </span>
              ))}
            </div>
            <div className="flex gap-2">
              <Input
                value={newTag}
                onChange={(e) => setNewTag(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addTag()}
                placeholder="Añadir tag..."
                className="flex-1"
              />
              <Button type="button" className="btn-outline" onClick={addTag}>
                +
              </Button>
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-4 border-t border-[var(--panel-border)]">
            <Button className="btn-outline" onClick={onClose} disabled={loading}>
              Cancelar
            </Button>
            <Button className="btn-solid" onClick={submit} disabled={loading}>
              {loading ? "Registrando..." : "✓ Registrar Asset"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}