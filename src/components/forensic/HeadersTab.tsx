import React, { useState } from 'react';
import type { EmailAnalysis } from '../../types/forensic';
import { MetadataRow } from './MetadataRow';
import { CopyButton } from './CopyButton';
import { AuthenticationSection } from './AuthenticationSection';
import { TransmissionPathSection } from './TransmissionPathSection';
import { ChevronDown, ChevronRight, FileCode, Route, Key } from 'lucide-react';

interface HeadersTabProps {
  email: EmailAnalysis;
}

export const HeadersTab: React.FC<HeadersTabProps> = ({ email }) => {
  const [showAllHeaders, setShowAllHeaders] = useState(false);

  const receivedHops = email.received || [];

  return (
    <div className="space-y-6">
      {/* Authentication Analysis Section */}
      <AuthenticationSection authentication={email.authentication} />

      {/* Relay Transmission Path Reconstruction Section */}
      <TransmissionPathSection relayAnalysis={email.relay_analysis} />

      {/* Important Individual Headers */}
      <div className="bg-surface p-5 rounded-card border border-border space-y-4 shadow-xs">
        <div className="flex items-center justify-between pb-2 border-b border-border">
          <div className="flex items-center space-x-2">
            <FileCode className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              Essential Header Metadata
            </h3>
          </div>
        </div>

        <div className="space-y-2">
          <MetadataRow label="From" value={email.from} allowCopy />
          <MetadataRow label="To" value={email.to} allowCopy />
          <MetadataRow label="Cc" value={email.cc} allowCopy />
          <MetadataRow label="Subject" value={email.subject} isMonospace={false} />
          <MetadataRow label="Date" value={email.date} allowCopy />
          <MetadataRow label="Reply-To" value={email.reply_to} allowCopy />
          <MetadataRow label="Return-Path" value={email.return_path} allowCopy />
          <MetadataRow label="Message-ID" value={email.message_id} allowCopy />
          <MetadataRow label="Authentication-Results" value={email.authentication_results} allowCopy />
        </div>
      </div>

      {/* Received Hops in Original Order */}
      <div className="bg-surface p-5 rounded-card border border-border space-y-4 shadow-xs">
        <div className="flex items-center space-x-2 pb-2 border-b border-border">
          <Route className="w-4 h-4 text-primary" />
          <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
            Received Relay Hops ({receivedHops.length})
          </h3>
        </div>

        {receivedHops.length === 0 ? (
          <p className="text-xs font-mono text-foreground-subtle italic p-3">
            No Received headers available.
          </p>
        ) : (
          <div className="space-y-3">
            {receivedHops.map((hop, index) => (
              <div
                key={index}
                className="p-3.5 rounded-control border border-border bg-surface-secondary/50 space-y-2 font-mono text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded-control bg-surface border border-border text-primary font-bold text-[11px]">
                    Received Hop {index + 1}
                  </span>
                  <CopyButton text={hop} iconOnly />
                </div>
                <pre className="text-foreground-muted whitespace-pre-wrap break-all leading-relaxed pt-1 text-[11.5px]">
                  {hop}
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Expandable View All Headers */}
      <div className="bg-surface rounded-card border border-border overflow-hidden shadow-xs">
        <button
          type="button"
          onClick={() => setShowAllHeaders(!showAllHeaders)}
          className="w-full flex items-center justify-between p-4 bg-surface-secondary/40 hover:bg-surface-secondary text-left transition-colors cursor-pointer"
        >
          <div className="flex items-center space-x-2">
            <Key className="w-4 h-4 text-primary" />
            <span className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
              View all raw parsed headers
            </span>
          </div>
          {showAllHeaders ? (
            <ChevronDown className="w-4 h-4 text-foreground-muted" />
          ) : (
            <ChevronRight className="w-4 h-4 text-foreground-muted" />
          )}
        </button>

        {showAllHeaders && (
          <div className="p-4 bg-surface border-t border-border space-y-3">
            <div className="flex justify-end">
              <CopyButton
                text={`From: ${email.from || ''}\nTo: ${email.to || ''}\nCc: ${email.cc || ''}\nSubject: ${email.subject || ''}\nDate: ${email.date || ''}\nReply-To: ${email.reply_to || ''}\nReturn-Path: ${email.return_path || ''}\nMessage-ID: ${email.message_id || ''}\nAuthentication-Results: ${email.authentication_results || ''}\n${(email.received || []).map(r => `Received: ${r}`).join('\n')}`}
                label="Copy Headers"
              />
            </div>
            <pre className="p-4 rounded-control bg-surface-secondary/70 border border-border font-mono text-xs text-foreground whitespace-pre-wrap break-all leading-relaxed max-h-96 overflow-y-auto">
{`From: ${email.from || 'N/A'}
To: ${Array.isArray(email.to) ? email.to.join(', ') : email.to || 'N/A'}
Cc: ${Array.isArray(email.cc) ? email.cc.join(', ') : email.cc || 'N/A'}
Subject: ${email.subject || 'N/A'}
Date: ${email.date || 'N/A'}
Reply-To: ${email.reply_to || 'N/A'}
Return-Path: ${email.return_path || 'N/A'}
Message-ID: ${email.message_id || 'N/A'}
Authentication-Results: ${email.authentication_results || 'N/A'}
${(email.received || []).map((r, i) => `Received [${i + 1}]: ${r}`).join('\n')}`}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
