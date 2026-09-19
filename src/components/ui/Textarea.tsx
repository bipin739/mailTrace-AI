import React from 'react';
import { cn } from '../../utils/cn';

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  helperText?: string;
  error?: string;
  showCount?: boolean;
  maxLength?: number;
}

export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  (
    {
      className,
      label,
      helperText,
      error,
      showCount = false,
      maxLength,
      disabled,
      id,
      value,
      ...props
    },
    ref
  ) => {
    const textareaId = id || (label ? `textarea-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);
    const hasError = Boolean(error);
    const currentLength = typeof value === 'string' ? value.length : 0;

    return (
      <div className="w-full space-y-1.5 font-sans">
        <div className="flex items-center justify-between">
          {label && (
            <label
              htmlFor={textareaId}
              className="block text-xs font-mono font-medium text-foreground-muted uppercase tracking-wider"
            >
              {label}
            </label>
          )}
          {showCount && maxLength !== undefined && (
            <span className="text-[10px] font-mono text-foreground-subtle">
              {currentLength} / {maxLength}
            </span>
          )}
        </div>

        <textarea
          ref={ref}
          id={textareaId}
          disabled={disabled}
          value={value}
          maxLength={maxLength}
          aria-invalid={hasError}
          aria-describedby={
            hasError && textareaId
              ? `${textareaId}-error`
              : helperText && textareaId
              ? `${textareaId}-helper`
              : undefined
          }
          className={cn(
            'w-full min-h-[80px] p-3 bg-surface-secondary border rounded-control text-xs text-foreground placeholder:text-foreground-subtle transition-colors resize-y',
            'focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary',
            'disabled:opacity-50 disabled:cursor-not-allowed disabled:bg-surface',
            hasError ? 'border-danger focus:border-danger focus:ring-danger' : 'border-border',
            className
          )}
          {...props}
        />

        {hasError ? (
          <p id={`${textareaId}-error`} className="text-[11px] font-mono text-danger">
            {error}
          </p>
        ) : helperText ? (
          <p id={`${textareaId}-helper`} className="text-[11px] font-mono text-foreground-muted">
            {helperText}
          </p>
        ) : null}
      </div>
    );
  }
);

Textarea.displayName = 'Textarea';
