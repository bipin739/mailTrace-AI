import React from 'react';
import { cn } from '../../utils/cn';

export interface DividerProps extends React.HTMLAttributes<HTMLDivElement> {
  orientation?: 'horizontal' | 'vertical';
  label?: React.ReactNode;
}

export const Divider: React.FC<DividerProps> = ({
  orientation = 'horizontal',
  label,
  className,
  ...props
}) => {
  if (orientation === 'vertical') {
    return (
      <div
        role="separator"
        aria-orientation="vertical"
        className={cn('inline-block self-stretch w-px bg-border my-0.5 mx-2', className)}
        {...props}
      />
    );
  }

  if (label) {
    return (
      <div
        role="separator"
        aria-orientation="horizontal"
        className={cn('flex items-center my-4 text-xs font-mono text-foreground-muted', className)}
        {...props}
      >
        <div className="flex-grow border-t border-border" />
        <span className="px-3 text-[11px] font-mono uppercase tracking-wider text-foreground-subtle">
          {label}
        </span>
        <div className="flex-grow border-t border-border" />
      </div>
    );
  }

  return (
    <hr
      role="separator"
      aria-orientation="horizontal"
      className={cn('w-full my-3 border-t border-border', className)}
      {...props}
    />
  );
};
