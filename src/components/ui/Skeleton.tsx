import React from 'react';
import { cn } from '../../utils/cn';

export type SkeletonVariant = 'text' | 'circular' | 'rectangular';

export interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: SkeletonVariant;
  width?: string | number;
  height?: string | number;
}

export const Skeleton: React.FC<SkeletonProps> = ({
  variant = 'rectangular',
  width,
  height,
  className,
  style,
  ...props
}) => {
  const variantStyles: Record<SkeletonVariant, string> = {
    text: 'h-4 w-full rounded-control',
    circular: 'rounded-full flex-shrink-0',
    rectangular: 'rounded-card',
  };

  const inlineStyles: React.CSSProperties = {
    ...style,
    width: width !== undefined ? width : style?.width,
    height: height !== undefined ? height : style?.height,
  };

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label="Loading..."
      className={cn(
        'bg-surface-secondary/80 animate-skeleton pointer-events-none',
        variantStyles[variant],
        className
      )}
      style={inlineStyles}
      {...props}
    />
  );
};
