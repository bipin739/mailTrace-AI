import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  GitMerge,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Server,
  Globe,
  Mail,
  FileCode,
  Target,
  Copy,
  Check,
  Info
} from 'lucide-react';
import type { RelatedCaseItem, SharedIndicator } from '../../types/correlation';

interface RelatedInvestigationsCardProps {
  relatedCases: RelatedCaseItem[];
  isLoading?: boolean;
  emptyMessage?: string;
  onRefresh?: () => void;
}

export const RelatedInvestigationsCard: React.FC<RelatedInvestigationsCardProps> = ({
  relatedCases,
  isLoading = false,
  emptyMessage = 'No related investigations found matching current forensic indicators.'
}) => {
  const navigate = useNavigate();
  const [expandedCaseId, setExpandedCaseId] = useState<string | null>(null);
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  const toggleExpand = (id: string) => {
    setExpandedCaseId(prev => (prev === id ? null : id));
  };

  const handleCopy = (val: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const getIndicatorIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ip':
        return <Server className="w-3.5 h-3.5 text-primary" />;
      case 'domain':
      case 'url_domain':
        return <Globe className="w-3.5 h-3.5 text-info" />;
      case 'reply_to':
      case 'sender':
        return <Mail className="w-3.5 h-3.5 text-warning" />;
      case 'attachment_hash':
        return <FileCode className="w-3.5 h-3.5 text-danger" />;
      case 'brand':
        return <Target className="w-3.5 h-3.5 text-primary" />;
      default:
        return <GitMerge className="w-3.5 h-3.5 text-foreground-muted" />;
    }
  };

  const getScoreBadge = (score: number) => {
    const pct = Math.round(score * 100);
    if (pct >= 75) {
      return {
        text: `${pct}% correlation`,
        bg: 'bg-danger/10 border-danger/30 text-danger font-semibold'
      };
    } else if (pct >= 45) {
      return {
        text: `${pct}% correlation`,
        bg: 'bg-warning/15 border-warning/30 text-warning font-medium'
      };
    } else if (pct >= 20) {
      return {
        text: `${pct}% correlation`,
        bg: 'bg-warning/10 border-warning/20 text-warning'
      };
    } else {
      return {
        text: `${pct}% correlation`,
        bg: 'bg-surface-secondary border-border text-foreground-muted'
      };
    }
  };

  return (
    <div className="bg-surface rounded-2xl border border-border p-6 shadow-sm space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-border">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
            <GitMerge className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-foreground flex items-center space-x-2">
              <span>Related Investigations</span>
              {relatedCases.length > 0 && (
                <span className="px-2 py-0.5 rounded-full text-xs font-mono font-semibold bg-primary/10 text-primary border border-primary/20">
                  {relatedCases.length} {relatedCases.length === 1 ? 'match' : 'matches'}
                </span>
              )}
            </h2>
            <p className="text-xs text-foreground-muted font-mono">Cross-case infrastructure & campaign pattern correlation</p>
          </div>
        </div>
      </div>

      {/* Body Content */}
      {isLoading ? (
        <div className="py-10 text-center text-foreground-muted text-xs font-mono flex items-center justify-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-primary animate-ping" />
          <span>Computing campaign correlations across investigations...</span>
        </div>
      ) : relatedCases.length === 0 ? (
        <div className="p-6 text-center rounded-xl bg-surface-secondary/40 border border-border space-y-2">
          <p className="text-xs text-foreground-muted">{emptyMessage}</p>
          <p className="text-[11px] text-foreground-subtle font-mono">
            No cross-case overlap observed for current IPs, domains, or attachments.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {relatedCases.map(rel => {
            const badge = getScoreBadge(rel.correlation_score);
            const isExpanded = expandedCaseId === rel.case_id;

            return (
              <div
                key={rel.case_id}
                className="bg-surface-secondary/50 border border-border rounded-xl p-4 transition-all hover:border-primary/40 space-y-3.5"
              >
                {/* Case Top Bar */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="font-mono text-xs font-extrabold text-primary tracking-wider">
                      {rel.case_number}
                    </span>
                    <span className={`px-2.5 py-0.5 rounded-full border text-xs font-mono font-medium ${badge.bg}`}>
                      {badge.text}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-surface border border-border text-foreground-muted">
                      {rel.relationship_label}
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={() => navigate(`/cases/${rel.case_id}`)}
                    className="self-start sm:self-auto flex items-center space-x-1 px-2.5 py-1 text-xs font-mono text-primary hover:bg-surface-secondary rounded-lg border border-border transition-colors btn-press"
                  >
                    <span>View Case</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* Case Title */}
                <div>
                  <h3 className="text-sm font-semibold text-foreground">{rel.title}</h3>
                </div>

                {/* Shared Evidence Summary Pills */}
                <div className="space-y-1.5 pt-1">
                  <span className="text-[11px] font-mono text-foreground-subtle uppercase tracking-wider block">
                    Shared evidence:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {rel.shared_evidence_summary.split(', ').map((pill, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-1 rounded-lg bg-surface border border-border text-xs font-mono text-foreground flex items-center space-x-1.5 shadow-xs"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-primary" />
                        <span>{pill}</span>
                      </span>
                    ))}
                  </div>
                </div>

                {/* Collapsible Details Drawer */}
                <div className="pt-1 border-t border-border">
                  <button
                    type="button"
                    onClick={() => toggleExpand(rel.case_id)}
                    className="flex items-center space-x-1.5 text-xs font-mono text-foreground-muted hover:text-foreground transition-colors"
                  >
                    {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    <span>{isExpanded ? 'Hide Shared Indicators' : `Inspect ${rel.shared_indicators.length} Shared Indicator${rel.shared_indicators.length === 1 ? '' : 's'}`}</span>
                  </button>

                  {isExpanded && (
                    <div className="mt-3 space-y-2 pt-2 border-t border-border animate-in fade-in duration-150">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {rel.shared_indicators.map((ind: SharedIndicator, i: number) => (
                          <div
                            key={i}
                            className="p-2 bg-surface rounded-lg border border-border flex items-center justify-between gap-2"
                          >
                            <div className="flex items-center space-x-2 min-w-0">
                              {getIndicatorIcon(ind.type)}
                              <div className="min-w-0">
                                <span className="text-[10px] font-mono uppercase text-foreground-subtle block leading-tight">
                                  {ind.type.replace('_', ' ')}
                                </span>
                                <span className="text-xs font-mono text-foreground truncate block font-medium">
                                  {ind.value}
                                </span>
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={(e) => handleCopy(ind.value, e)}
                              className="p-1 rounded text-foreground-muted hover:text-foreground hover:bg-surface-secondary transition-colors shrink-0"
                              title="Copy indicator"
                            >
                              {copiedValue === ind.value ? (
                                <Check className="w-3.5 h-3.5 text-success" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Non-Attribution SOC Governance Disclaimer */}
      <div className="pt-2 flex items-start space-x-2 text-[11px] text-foreground-subtle font-mono border-t border-border">
        <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-foreground-muted" />
        <span>
          Correlation is computed using explainable weighted technical indicators (IPs, domains, attachment hashes, and infrastructure). It reflects shared tooling or tactical infrastructure and avoids human identity attribution.
        </span>
      </div>
    </div>
  );
};
