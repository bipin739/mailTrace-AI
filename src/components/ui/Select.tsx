import React from 'react';
import { ChevronDown } from 'lucide-react';
import { cn } from '../../utils/cn';

export type SelectSize = 'sm' | 'md' | 'lg';

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'size'> {
  label?: string;
  helperText?: string;
  error?: string;
  size?: SelectSize;
  options?: SelectOption[];
}

export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  (
    {
      className,
      label,
      helperText,
      error,
      size = 'md',
      options,
      children,
      disabled,
      id,
      ...props
    },
    ref
  ) => {
    const selectId = id || (label ? `select-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);
    const hasError = Boolean(error);

    const sizes: Record<SelectSize, string> = {
      sm: 'h-8 px-2.5 pr-8 text-xs',
      md: 'h-9 px-3 pr-8 text-xs',
      lg: 'h-10 px-3.5 pr-9 text-sm',
    };

    return (
      <div className="w-full space-y-1.5 font-sans">
        {label && (
          <label
            htmlFor={selectId}
            className="block text-xs font-mono font-medium text-foreground-muted uppercase tracking-wider"
          >
            {label}
          </label>
        )}

        <div className="relative flex items-center w-full">
          <select
            ref={ref}
            id={selectId}
            disabled={disabled}
            aria-invalid={hasError}
            aria-describedby={
              hasError && selectId
                ? `${selectId}-error`
                : helperText && selectId
                ? `${selectId}-helper`
                : undefined
            }
            className={cn(
              'w-full appearance-none bg-surface-secondary border rounded-control text-foreground transition-colors cursor-pointer',
              'focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary',
              'disabled:opacity-50 disabled:cursor-not-allowed disabled:bg-surface',
              sizes[size],
              hasError ? 'border-danger focus:border-danger focus:ring-danger' : 'border-border',
              className
            )}
            {...props}
          >
            {options
              ? options.map((opt) => (
                  <option key={opt.value} value={opt.value} disabled={opt.disabled} className="bg-surface text-foreground">
                    {opt.label}
                  </option>
                ))
              : children}
          </select>

          <ChevronDown className="w-4 h-4 text-foreground-muted absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
        </div>

        {hasError ? (
          <p id={`${selectId}-error`} className="text-[11px] font-mono text-danger">
            {error}
          </p>
        ) : helperText ? (
          <p id={`${selectId}-helper`} className="text-[11px] font-mono text-foreground-muted">
            {helperText}
          </p>
        ) : null}
      </div>
    );
  }
);

Select.displayName = 'Select';
