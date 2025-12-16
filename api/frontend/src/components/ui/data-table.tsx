import React from 'react';
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from '@tanstack/react-table';

export type { ColumnDef };

export type DataTableProps<T extends object> = {
  columns: ColumnDef<T, any>[];
  data: T[];
  className?: string;
  onRowClick?: (row: T) => void;
  sortBy?: string;
  sortDir?: "asc" | "desc";
  onRequestSort?: (key: string) => void;
};

export function DataTable<T extends object>({
  columns, data, className, onRowClick, sortBy, sortDir, onRequestSort
}: DataTableProps<T>) {
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() });

  return (
    <div className={['overflow-x-auto panel', className].filter(Boolean).join(' ')}>
      <table className="data-table w-full text-sm">
        <thead>
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id}>
              {hg.headers.map((h) => {
                const content = h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext());
                const sortKey = (h.column.columnDef as any)?.meta?.sortKey as string | undefined;
                const isActive = sortKey && sortKey === sortBy;
                const arrow = isActive ? (sortDir === "asc" ? "↑" : "↓") : "";

                return (
                  <th key={h.id} className="px-3 py-2 text-left">
                    {sortKey ? (
                      <button
                        type="button"
                        className="inline-flex items-center gap-1 hover:underline"
                        onClick={() => onRequestSort?.(sortKey)}
                        title="Ordenar"
                      >
                        <span>{content}</span>
                        <span aria-hidden>{arrow}</span>
                      </button>
                    ) : content}
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr
              key={row.id}
              className={['border-b border-transparent hover:bg-transparent', onRowClick ? 'cursor-pointer' : ''].join(' ')}
              onClick={() => onRowClick?.(row.original as T)}
            >
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className="px-3 py-2">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
          {table.getRowModel().rows.length === 0 && (
            <tr><td className="px-3 py-6 text-center text-neutral-400" colSpan={columns.length}>Sin resultados</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default DataTable;
