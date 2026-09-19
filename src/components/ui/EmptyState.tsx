import React from 'react';
import { cn } from '../../utils/cn';

export interface EmptyStateProps extends React.HTMLAttributes<HTMLDivElement> {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  secondaryAction?: React.ReactNode;
  variant?: 'card' | 'plain';
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
  secondaryAction,
  variant = 'card',
  className,
  ...props
}) => {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center text-center p-8 transition-colors',
        variant === 'card' && 'bg-surface border border-border rounded-card shadow-xs',
        variant === 'plain' && 'bg-transparent',
        className
      )}
      {...props}
    >
      {icon && (
        <div className="w-12 h-12 rounded-control bg-surface-secondary border border-border flex items-center justify-center text-foreground-muted mb-4 shadow-inner">
          {icon}
        </div>
      )}

      <h4 className="text-sm font-semibold font-sans text-foreground leading-tight">{title}</h4>

      {description && (
        <p className="text-xs text-foreground-muted font-sans mt-1.5 max-w-sm leading-normal">
          {description}
        </p>
      )}

      {(action || secondaryAction) && (
        <div className="flex flex-wrap items-center justify-center gap-2.5 mt-5">
          {action}
          {secondaryAction}
        </div>
      )}
    </div>
  );
};
