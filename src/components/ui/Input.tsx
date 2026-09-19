import React from 'react';
import { X } from 'lucide-react';
import { cn } from '../../utils/cn';

export type InputSize = 'sm' | 'md' | 'lg';

export interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
  label?: string;
  helperText?: string;
  error?: string;
  size?: InputSize;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  onClear?: () => void;
  isClearable?: boolean;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      className,
      label,
      helperText,
      error,
      size = 'md',
      leftIcon,
      rightIcon,
      onClear,
      isClearable,
      disabled,
      id,
      value,
      ...props
    },
    ref
  ) => {
    const inputId = id || (label ? `input-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);
    const hasError = Boolean(error);

    const sizes: Record<InputSize, { container: string; input: string; icon: string }> = {
      sm: { container: 'h-8 text-xs', input: 'px-2.5 py-1 text-xs', icon: 'w-3.5 h-3.5' },
      md: { container: 'h-9 text-xs', input: 'px-3 py-1.5 text-xs', icon: 'w-4 h-4' },
      lg: { container: 'h-10 text-sm', input: 'px-3.5 py-2 text-sm', icon: 'w-4 h-4' },
    };

    return (
      <div className="w-full space-y-1.5 font-sans">
        {label && (
          <label
            htmlFor={inputId}
            className="block text-xs font-mono font-medium text-foreground-muted uppercase tracking-wider"
          >
            {label}
          </label>
        )}

        <div className="relative flex items-center w-full">
          {leftIcon && (
            <div className="absolute left-3 flex items-center pointer-events-none text-foreground-muted">
              {leftIcon}
            </div>
          )}

          <input
            ref={ref}
            id={inputId}
            disabled={disabled}
            value={value}
            aria-invalid={hasError}
            aria-describedby={
              hasError && inputId
                ? `${inputId}-error`
                : helperText && inputId
                ? `${inputId}-helper`
                : undefined
            }
            className={cn(
              'w-full bg-surface-secondary border rounded-control text-foreground placeholder:text-foreground-subtle transition-colors',
              'focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary',
              'disabled:opacity-50 disabled:cursor-not-allowed disabled:bg-surface',
              sizes[size].input,
              leftIcon && 'pl-9',
              (rightIcon || (isClearable && value)) && 'pr-9',
              hasError ? 'border-danger focus:border-danger focus:ring-danger' : 'border-border',
              className
            )}
            {...props}
          />

          <div className="absolute right-2.5 flex items-center gap-1.5">
            {isClearable && value && !disabled && (
              <button
                type="button"
                onClick={onClear}
                aria-label="Clear input"
                className="p-0.5 rounded-full text-foreground-muted hover:text-foreground hover:bg-surface transition-colors cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
            {rightIcon && <div className="text-foreground-muted pointer-events-none">{rightIcon}</div>}
          </div>
        </div>

        {hasError ? (
          <p id={`${inputId}-error`} className="text-[11px] font-mono text-danger">
            {error}
          </p>
        ) : helperText ? (
          <p id={`${inputId}-helper`} className="text-[11px] font-mono text-foreground-muted">
            {helperText}
          </p>
        ) : null}
      </div>
    );
  }
);

Input.displayName = 'Input';
