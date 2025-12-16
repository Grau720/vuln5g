import React from 'react';
import { cn } from '@/lib/utils';

export function Badge(props: React.HTMLAttributes<HTMLSpanElement>) {
  const { className, ...rest } = props;
  return <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-xs', className)} {...rest} />;
}
