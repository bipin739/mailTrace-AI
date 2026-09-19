import React from 'react';
import { cn } from '../../utils/cn';

export type BadgeVariant =
  | 'neutral'
  | 'primary'
  | 'success'
  | 'warning'
  | 'danger'
  | 'info'
  | 'outline';

export type BadgeSize = 'xs' | 'sm' | 'md';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
  size?: BadgeSize;
  dot?: boolean;
  pulse?: boolean;
  icon?: React.ReactNode;
}

export const Badge = React.forwardRef<HTMLSpanElement, BadgeProps>(
  (
    {
      className,
      variant = 'neutral',
      size = 'sm',
      dot = false,
      pulse = false,
      icon,
      children,
      ...props
    },
    ref
  ) => {
    const baseStyles =
      'inline-flex items-center font-mono font-medium border rounded-badge transition-colors select-none';

    const variants: Record<BadgeVariant, string> = {
      neutral: 'bg-surface-secondary text-foreground-muted border-border',
      primary: 'bg-primary-subtle text-primary border-primary/25 font-semibold',
      success: 'bg-success-surface text-success border-success-border',
      warning: 'bg-warning-surface text-warning border-warning-border',
      danger: 'bg-danger-surface text-danger border-danger-border font-semibold',
      info: 'bg-info-surface text-info border-info-border',
      outline: 'bg-transparent text-foreground border-border',
    };

    const dotColors: Record<BadgeVariant, string> = {
      neutral: 'bg-foreground-muted',
      primary: 'bg-primary',
      success: 'bg-success',
      warning: 'bg-warning',
      danger: 'bg-danger',
      info: 'bg-info',
      outline: 'bg-foreground',
    };

    const sizes: Record<BadgeSize, string> = {
      xs: 'text-[10px] px-1.5 py-0.2 gap-1 tracking-tight',
      sm: 'text-[11px] px-2 py-0.5 gap-1.5',
      md: 'text-xs px-2.5 py-1 gap-1.5',
    };

    return (
      <span ref={ref} className={cn(baseStyles, variants[variant], sizes[size], className)} {...props}>
        {dot && (
          <span
            className={cn(
              'w-1.5 h-1.5 rounded-full flex-shrink-0',
              dotColors[variant],
              pulse && 'animate-pulse'
            )}
          />
        )}
        {icon && <span className="flex-shrink-0 inline-flex items-center">{icon}</span>}
        <span>{children}</span>
      </span>
    );
  }
);

Badge.displayName = 'Badge';
