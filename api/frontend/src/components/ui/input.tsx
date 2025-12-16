import React from 'react';
import { cn } from '@/lib/utils';

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...rest }, ref) => (
    <input ref={ref} className={cn('w-full rounded-xl border px-3 py-2 text-sm', className)} {...rest} />
  )
);
Input.displayName = 'Input';
