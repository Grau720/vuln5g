import React, { useCallback } from 'react';

type Props = {
  value?: number[];
  defaultValue?: number[];
  min?: number;
  max?: number;
  step?: number;
  onValueChange?: (v: number[]) => void;
  className?: string;
};
export function Slider({ value, defaultValue = [0], min = 0, max = 10, step = 0.1, onValueChange, className }: Props) {
  const v = (value ?? defaultValue)[0];
  const onChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    onValueChange?.([Number(e.target.value)]);
  }, [onValueChange]);

  return (
    <input
      type="range"
      min={min}
      max={max}
      step={step}
      value={v}
      onChange={onChange}
      className={className || 'w-full'}
    />
  );
}
