import React from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '../../utils/cn';
import type { ButtonVariant, ButtonSize } from './Button';

export interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  'aria-label': string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  icon?: React.ReactNode;
}

export const IconButton = React.forwardRef<HTMLButtonElement, IconButtonProps>(
  (
    {
      className,
      variant = 'secondary',
      size = 'md',
      isLoading = false,
      icon,
      children,
      disabled,
      type = 'button',
      ...props
    },
    ref
  ) => {
    const baseStyles =
      'inline-flex items-center justify-center select-none cursor-pointer transition-colors btn-press focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none rounded-control flex-shrink-0';

    const variants: Record<ButtonVariant, string> = {
      primary:
        'bg-primary hover:bg-primary-hover active:bg-primary-active text-primary-foreground border border-transparent shadow-xs',
      secondary:
        'bg-surface hover:bg-surface-secondary border border-border text-foreground hover:border-border-strong shadow-xs',
      outline:
        'bg-transparent hover:bg-surface-secondary border border-border text-foreground hover:border-border-strong',
      ghost:
        'bg-transparent hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-transparent',
      danger:
        'bg-danger hover:bg-danger-hover active:bg-danger-active text-white border border-transparent shadow-xs',
      success:
        'bg-success hover:bg-success-hover active:bg-success-active text-white border border-transparent shadow-xs',
    };

    const sizes: Record<ButtonSize, string> = {
      xs: 'w-6 h-6 text-xs p-0.5',
      sm: 'w-8 h-8 text-sm p-1.5',
      md: 'w-9 h-9 text-base p-2',
      lg: 'w-10 h-10 text-lg p-2.5',
    };

    return (
      <button
        ref={ref}
        type={type}
        disabled={disabled || isLoading}
        aria-busy={isLoading}
        className={cn(baseStyles, variants[variant], sizes[size], className)}
        {...props}
      >
        {isLoading ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
        ) : (
          icon || children
        )}
      </button>
    );
  }
);

IconButton.displayName = 'IconButton';
