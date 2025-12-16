import React, { createContext, useContext, useState } from 'react';

const Ctx = createContext<{ open: boolean; setOpen: (v: boolean) => void } | null>(null);

export function Sheet({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return <Ctx.Provider value={{ open, setOpen }}>{children}</Ctx.Provider>;
}

export function SheetTrigger({ children }: { children: React.ReactNode }) {
  const ctx = useContext(Ctx)!;
  return <span onClick={() => ctx.setOpen(true)}>{children}</span>;
}

export function SheetContent({ children, className }: { children: React.ReactNode; className?: string }) {
  const ctx = useContext(Ctx)!;
  if (!ctx.open) return null;
  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/40" onClick={() => ctx.setOpen(false)} />
      <div className={['w-full max-w-lg bg-white shadow-xl p-4 overflow-y-auto', className].filter(Boolean).join(' ')}>
        {children}
      </div>
    </div>
  );
}

export function SheetHeader({ children }: { children: React.ReactNode }) {
  return <div className="mb-3">{children}</div>;
}
export function SheetTitle({ children }: { children: React.ReactNode }) {
  return <h3 className="text-lg font-semibold">{children}</h3>;
}
