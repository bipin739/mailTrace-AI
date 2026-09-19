import React from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '../../utils/cn';

export type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger' | 'success';
export type ButtonSize = 'xs' | 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'primary',
      size = 'md',
      isLoading = false,
      leftIcon,
      rightIcon,
      disabled,
      children,
      type = 'button',
      ...props
    },
    ref
  ) => {
    const baseStyles =
      'inline-flex items-center justify-center font-medium font-sans select-none cursor-pointer transition-colors btn-press focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none rounded-control';

    const variants: Record<ButtonVariant, string> = {
      primary:
        'bg-primary hover:bg-primary-hover active:bg-primary-active text-primary-foreground border border-transparent shadow-xs font-semibold',
      secondary:
        'bg-surface-secondary hover:bg-surface border border-border text-foreground hover:border-border-strong shadow-xs',
      outline:
        'bg-transparent hover:bg-surface-secondary border border-border text-foreground hover:border-border-strong',
      ghost:
        'bg-transparent hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-transparent',
      danger:
        'bg-danger hover:bg-danger-hover active:bg-danger-active text-white border border-transparent shadow-xs font-semibold',
      success:
        'bg-success hover:bg-success-hover active:bg-success-active text-white border border-transparent shadow-xs font-semibold',
    };

    const sizes: Record<ButtonSize, string> = {
      xs: 'h-6 px-2 text-[11px] gap-1 font-mono',
      sm: 'h-8 px-2.5 text-xs gap-1.5',
      md: 'h-9 px-3.5 text-xs gap-2',
      lg: 'h-10 px-4 text-sm gap-2.5',
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
          <Loader2 className="w-3.5 h-3.5 animate-spin flex-shrink-0" />
        ) : (
          leftIcon && <span className="flex-shrink-0 inline-flex items-center">{leftIcon}</span>
        )}
        {children && <span>{children}</span>}
        {!isLoading && rightIcon && (
          <span className="flex-shrink-0 inline-flex items-center">{rightIcon}</span>
        )}
      </button>
    );
  }
);

Button.displayName = 'Button';
