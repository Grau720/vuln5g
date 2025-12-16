import React from 'react';
import { cn } from '@/lib/utils';

export function Checkbox(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const { className, ...rest } = props;
  return <input type="checkbox" className={cn('h-4 w-4 rounded border', className)} {...rest} />;
}
