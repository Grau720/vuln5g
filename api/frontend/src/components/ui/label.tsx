import React from 'react';
import { cn } from '@/lib/utils';

export function Label(props: React.LabelHTMLAttributes<HTMLLabelElement>) {
  const { className, ...rest } = props;
  return <label className={cn('text-sm font-medium', className)} {...rest} />;
}
