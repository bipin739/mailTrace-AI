import React from 'react';
import type { ThreatSeverity } from '../../types';
import { ShieldAlert, ShieldCheck, AlertTriangle, Info, AlertOctagon } from 'lucide-react';

interface RiskBadgeProps {
  severity: ThreatSeverity;
  score?: number;
  showScore?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  severity,
  score,
  showScore = false,
  size = 'md'
}) => {
  const getBadgeStyle = () => {
    switch (severity) {
      case 'CRITICAL':
        return {
          classes: 'bg-danger-surface text-danger border-danger-border',
          icon: <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" />,
          label: 'CRITICAL THREAT'
        };
      case 'HIGH':
        return {
          classes: 'bg-warning-surface text-warning border-warning-border',
          icon: <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />,
          label: 'HIGH RISK'
        };
      case 'MEDIUM':
        return {
          classes: 'bg-warning-surface/60 text-warning border-warning-border/80',
          icon: <AlertOctagon className="w-3.5 h-3.5 flex-shrink-0" />,
          label: 'SUSPICIOUS'
        };
      case 'LOW':
        return {
          classes: 'bg-info-surface text-info border-info-border',
          icon: <Info className="w-3.5 h-3.5 flex-shrink-0" />,
          label: 'LOW RISK'
        };
      case 'LEGITIMATE':
      default:
        return {
          classes: 'bg-success-surface text-success border-success-border',
          icon: <ShieldCheck className="w-3.5 h-3.5 flex-shrink-0" />,
          label: 'VERIFIED LEGITIMATE'
        };
    }
  };

  const style = getBadgeStyle();
  const sizeClasses = {
    sm: 'text-[11px] px-2 py-0.5 space-x-1',
    md: 'text-xs px-2.5 py-1 space-x-1.5 font-medium',
    lg: 'text-xs px-3 py-1.5 space-x-2 font-semibold tracking-wide'
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded-badge border font-mono transition-colors ${style.classes} ${sizeClasses}`}
    >
      {style.icon}
      <span>{style.label}</span>
      {showScore && score !== undefined && (
        <span className="ml-1 px-1.5 py-0.2 rounded-badge bg-surface/80 border border-border text-[10px] font-mono text-foreground font-semibold">
          {score}%
        </span>
      )}
    </span>
  );
};
