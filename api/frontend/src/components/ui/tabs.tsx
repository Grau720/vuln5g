import React, { createContext, useContext, useState } from 'react';

type Ctx = { value: string; setValue: (v: string) => void };
const TabsCtx = createContext<Ctx | null>(null);

export function Tabs({ defaultValue = '', value, onValueChange, children }:{
  defaultValue?: string; value?: string; onValueChange?: (v: string) => void; children: React.ReactNode;
}) {
  const [internal, setInternal] = useState(defaultValue);
  const current = value ?? internal;
  const setValue = (v: string) => { onValueChange?.(v); if (value === undefined) setInternal(v); };
  return <TabsCtx.Provider value={{ value: current, setValue }}>{children}</TabsCtx.Provider>;
}

export function TabsList({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn('flex gap-2 border-b', className)}>{children}</div>;
}
function cn(...c: (string | undefined)[]) { return c.filter(Boolean).join(' '); }

export function TabsTrigger({ value, children }: { value: string; children: React.ReactNode }) {
  const ctx = useContext(TabsCtx)!;
  const active = ctx.value === value;
  return (
    <button
      className={cn('px-3 py-2 text-sm', active ? 'border-b-2 border-black font-medium' : 'text-neutral-500')}
      onClick={() => ctx.setValue(value)}
    >
      {children}
    </button>
  );
}

export function TabsContent({ value, children }: { value: string; children: React.ReactNode }) {
  const ctx = useContext(TabsCtx)!;
  if (ctx.value !== value) return null;
  return <div className="pt-3">{children}</div>;
}
