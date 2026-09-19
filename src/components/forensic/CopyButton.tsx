import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface CopyButtonProps {
  text: string;
  label?: string;
  className?: string;
  iconOnly?: boolean;
}

export const CopyButton: React.FC<CopyButtonProps> = ({
  text,
  label = 'Copy',
  className = '',
  iconOnly = false
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={copied ? 'Copied to clipboard' : 'Copy to clipboard'}
      className={`inline-flex items-center space-x-1.5 px-2.5 py-1 text-xs font-mono rounded-control transition-all border border-border bg-surface-secondary hover:bg-surface text-foreground-muted hover:text-foreground cursor-pointer ${className}`}
    >
      {copied ? (
        <Check className="w-3.5 h-3.5 text-success" />
      ) : (
        <Copy className="w-3.5 h-3.5 text-primary" />
      )}
      {!iconOnly && <span>{copied ? 'Copied' : label}</span>}
    </button>
  );
};
