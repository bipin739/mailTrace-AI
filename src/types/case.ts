export type CaseStatus = 'open' | 'investigating' | 'resolved' | 'escalated';
export type CaseSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface CaseEmail {
  id: string;
  case_id: string;
  email_id: string;
  email_sha256?: string;
  subject?: string;
  sender?: string;
  threat_score?: number;
  severity?: string;
  added_at: string;
}

export interface CaseNote {
  id: string;
  case_id: string;
  author: string;
  note_text: string;
  created_at: string;
}

export interface CaseFinding {
  id: string;
  case_id: string;
  finding_type: string;
  title: string;
  description: string;
  severity: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  case_id: string;
  action: string;
  details: string;
  timestamp: string;
}

export interface AggregatedIndicators {
  domains: string[];
  ips: string[];
  urls: string[];
  attachments: string[];
}

export interface CaseListItem {
  id: string;
  case_number: string;
  title: string;
  description?: string;
  severity: CaseSeverity;
  status: CaseStatus;
  created_at: string;
  updated_at: string;
  email_count: number;
  note_count: number;
  finding_count: number;
}

export interface CaseDetail {
  id: string;
  case_number: string;
  title: string;
  description?: string;
  severity: CaseSeverity;
  status: CaseStatus;
  created_at: string;
  updated_at: string;
  emails: CaseEmail[];
  notes: CaseNote[];
  findings: CaseFinding[];
  audit_logs: AuditLog[];
  aggregated_indicators: AggregatedIndicators;
}

export interface CaseCreatePayload {
  title: string;
  description?: string;
  severity?: CaseSeverity;
  status?: CaseStatus;
  initial_email?: {
    email_id: string;
    email_sha256?: string;
    subject?: string;
    sender?: string;
    threat_score?: number;
    severity?: string;
    indicators?: Record<string, any>;
  };
}

export interface CaseNoteCreateRequest {
  author?: string;
  note_text: string;
}

export interface CaseFindingCreateRequest {
  finding_type?: string;
  title: string;
  description?: string;
  severity?: string;
}

