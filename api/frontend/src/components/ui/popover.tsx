// frontend/src/components/ui/popover.tsx
import React, { createContext, useContext, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

type CtxType = {
  open: boolean;
  setOpen: (v: boolean) => void;
  triggerRef: React.RefObject<HTMLSpanElement>;
};

const PopoverCtx = createContext<CtxType | null>(null);

export function Popover({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLSpanElement>(null);
  return (
    <PopoverCtx.Provider value={{ open, setOpen, triggerRef }}>
      {/* Wrapper solo para agrupar; el contenido real se porta al body */}
      <span className="inline-block">{children}</span>
    </PopoverCtx.Provider>
  );
}

export function PopoverTrigger({ children }: { children: React.ReactNode }) {
  const ctx = useContext(PopoverCtx)!;
  return (
    <span
      ref={ctx.triggerRef}
      onClick={(e) => {
        e.stopPropagation();
        ctx.setOpen(!ctx.open);
      }}
    >
      {children}
    </span>
  );
}

type PopoverContentProps = {
  children: React.ReactNode;
  className?: string;
  align?: "start" | "center" | "end";
  width?: number | string;
};

export function PopoverContent({
  children,
  className,
  align = "end",
  width,
}: PopoverContentProps) {
  const ctx = useContext(PopoverCtx)!;
  const panelRef = useRef<HTMLDivElement>(null);

  // Cerrar con click fuera y Escape
  useEffect(() => {
    if (!ctx.open) return;
    const onDown = (e: MouseEvent) => {
      const p = panelRef.current;
      const t = ctx.triggerRef.current;
      if (p && !p.contains(e.target as Node) && t && !t.contains(e.target as Node)) {
        ctx.setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") ctx.setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [ctx.open]);

  if (!ctx.open) return null;

  // Posición anclada al trigger
  const rect = ctx.triggerRef.current?.getBoundingClientRect();
  const W = typeof width === "number" ? width : 220; // ancho por defecto para cálculo
  let left = rect ? rect.left : 0;
  const top = rect ? rect.bottom + 8 : 0;

  if (rect) {
    if (align === "end") {
      left = Math.min(Math.max(rect.right - W, 8), window.innerWidth - W - 8);
    } else if (align === "center") {
      left = Math.min(
        Math.max(rect.left + rect.width / 2 - W / 2, 8),
        window.innerWidth - W - 8
      );
    } else {
      left = Math.min(Math.max(rect.left, 8), window.innerWidth - W - 8);
    }
  }

  const style: React.CSSProperties = {
    position: "fixed",
    top,
    left,
    width: typeof width !== "undefined" ? (typeof width === "number" ? `${width}px` : width) : undefined,
  };

  return createPortal(
    <div
      ref={panelRef}
      style={style}
      className={[
        // 👇 mismos colores/borde que tus cards
        "z-50 rounded-2xl border border-[var(--panel-border)] bg-[var(--panel)] text-[var(--text)]",
        "p-2 shadow-lg outline-none",
        className || "",
      ].join(" ")}
      role="dialog"
    >
      {children}
    </div>,
    document.body
  );
}
