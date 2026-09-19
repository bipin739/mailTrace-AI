import React from 'react';
import type { SecurityProtocolStatus } from '../../types';
import { CheckCircle2, XCircle, AlertCircle, HelpCircle, ShieldCheck, ShieldAlert } from 'lucide-react';

interface HeaderProtocolStatusProps {
  protocols: SecurityProtocolStatus;
}

export const HeaderProtocolStatus: React.FC<HeaderProtocolStatusProps> = ({ protocols }) => {
  const getStatusPresentation = (status: 'PASS' | 'FAIL' | 'NEUTRAL' | 'NONE') => {
    switch (status) {
      case 'PASS':
        return {
          icon: <CheckCircle2 className="w-4 h-4 text-success flex-shrink-0" />,
          badgeClass: 'bg-success-surface text-success border-success-border',
          borderClass: 'border-border hover:border-success-border',
        };
      case 'FAIL':
        return {
          icon: <XCircle className="w-4 h-4 text-danger flex-shrink-0" />,
          badgeClass: 'bg-danger-surface text-danger border-danger-border font-bold',
          borderClass: 'border-danger-border/60 hover:border-danger-border',
        };
      case 'NEUTRAL':
        return {
          icon: <AlertCircle className="w-4 h-4 text-warning flex-shrink-0" />,
          badgeClass: 'bg-warning-surface text-warning border-warning-border',
          borderClass: 'border-warning-border/60 hover:border-warning-border',
        };
      case 'NONE':
      default:
        return {
          icon: <HelpCircle className="w-4 h-4 text-foreground-muted flex-shrink-0" />,
          badgeClass: 'bg-surface-secondary text-foreground-muted border-border',
          borderClass: 'border-border',
        };
    }
  };

  const spfStyle = getStatusPresentation(protocols.spf);
  const dkimStyle = getStatusPresentation(protocols.dkim);
  const dmarcStyle = getStatusPresentation(protocols.dmarc);

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
      {/* SPF Card */}
      <div className={`p-3.5 rounded-xl border bg-surface transition-all ${spfStyle.borderClass}`}>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-2">
            {spfStyle.icon}
            <span className="font-mono font-semibold text-xs tracking-wide text-foreground">
              SPF VALIDATION
            </span>
          </div>
          <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${spfStyle.badgeClass}`}>
            {protocols.spf}
          </span>
        </div>
        <p className="text-xs text-foreground-muted leading-relaxed font-sans">
          {protocols.spfDetails}
        </p>
      </div>

      {/* DKIM Card */}
      <div className={`p-3.5 rounded-xl border bg-surface transition-all ${dkimStyle.borderClass}`}>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-2">
            {dkimStyle.icon}
            <span className="font-mono font-semibold text-xs tracking-wide text-foreground">
              DKIM SIGNATURE
            </span>
          </div>
          <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${dkimStyle.badgeClass}`}>
            {protocols.dkim}
          </span>
        </div>
        <p className="text-xs text-foreground-muted leading-relaxed font-sans">
          {protocols.dkimDetails}
        </p>
      </div>

      {/* DMARC Card */}
      <div className={`p-3.5 rounded-xl border bg-surface transition-all ${dmarcStyle.borderClass}`}>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-2">
            {dmarcStyle.icon}
            <span className="font-mono font-semibold text-xs tracking-wide text-foreground">
              DMARC POLICY
            </span>
          </div>
          <span className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${dmarcStyle.badgeClass}`}>
            {protocols.dmarc}
          </span>
        </div>
        <p className="text-xs text-foreground-muted leading-relaxed font-sans">
          {protocols.dmarcDetails}
        </p>
      </div>

      {/* Alignment & Reply-To Bar */}
      <div className="md:col-span-3 grid grid-cols-1 sm:grid-cols-2 gap-3 mt-1">
        <div
          className={`flex items-center justify-between p-3 rounded-lg border ${
            protocols.returnPathMatch
              ? 'bg-surface border-border text-foreground'
              : 'bg-danger-surface border-danger-border text-danger'
          }`}
        >
          <div className="flex items-center space-x-2">
            {protocols.returnPathMatch ? (
              <ShieldCheck className="w-4 h-4 text-success" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-danger" />
            )}
            <span className="text-xs font-medium">Return-Path Domain Alignment</span>
          </div>
          <span
            className={`text-xs font-mono font-semibold ${
              protocols.returnPathMatch ? 'text-success' : 'text-danger'
            }`}
          >
            {protocols.returnPathMatch ? 'ALIGNED' : 'MISMATCH / SPOOFED'}
          </span>
        </div>

        <div
          className={`flex items-center justify-between p-3 rounded-lg border ${
            !protocols.replyToMismatch
              ? 'bg-surface border-border text-foreground'
              : 'bg-warning-surface border-warning-border text-warning'
          }`}
        >
          <div className="flex items-center space-x-2">
            {!protocols.replyToMismatch ? (
              <ShieldCheck className="w-4 h-4 text-success" />
            ) : (
              <ShieldAlert className="w-4 h-4 text-warning" />
            )}
            <span className="text-xs font-medium">Reply-To Address Consistency</span>
          </div>
          <span
            className={`text-xs font-mono font-semibold ${
              !protocols.replyToMismatch ? 'text-success' : 'text-warning'
            }`}
          >
            {!protocols.replyToMismatch ? 'MATCHED' : 'DECEPTIVE MISMATCH'}
          </span>
        </div>
      </div>
    </div>
  );
};
