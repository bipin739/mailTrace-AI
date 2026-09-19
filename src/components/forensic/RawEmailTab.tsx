import React from 'react';
import type { EmailAnalysis } from '../../types/forensic';
import { CopyButton } from './CopyButton';
import { Terminal, Shield } from 'lucide-react';

interface RawEmailTabProps {
  email: EmailAnalysis;
}

export const RawEmailTab: React.FC<RawEmailTabProps> = ({ email }) => {
  const rawEmail = email.raw_email || 'Raw email source unavailable.';

  const lines = rawEmail.split('\n');

  return (
    <div className="bg-surface p-5 rounded-2xl border border-border space-y-4 shadow-xs">
      <div className="flex items-center justify-between pb-2 border-b border-border">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-primary" />
          <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
            Raw EML Source Evidence ({lines.length} lines)
          </h3>
        </div>

        <CopyButton text={rawEmail} label="Copy Raw EML" />
      </div>

      <div className="flex items-center space-x-2 p-2.5 rounded-lg bg-surface-secondary border border-border text-[11px] font-mono text-foreground-muted">
        <Shield className="w-4 h-4 text-primary shrink-0" />
        <span>
          Untransformed RFC-822 raw evidence text. Preserved for chain-of-custody inspection.
        </span>
      </div>

      <div className="rounded-xl border border-border bg-surface-secondary/60 p-4 font-mono text-xs text-foreground leading-relaxed overflow-x-auto max-h-[600px] overflow-y-auto">
        <table className="w-full border-collapse">
          <tbody>
            {lines.map((line, idx) => (
              <tr key={idx} className="hover:bg-surface-secondary">
                <td className="text-foreground-subtle text-right pr-4 select-none w-10 text-[11px] align-top">
                  {idx + 1}
                </td>
                <td className="whitespace-pre-wrap break-all text-foreground">
                  {line}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
