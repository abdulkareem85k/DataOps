export type HealthState = 'checking' | 'online' | 'offline';

export interface Assessment {
  id: string;
  name: string;
  description?: string;
  created_at?: string;
}

export interface ScopeRule {
  id?: string;
  assessment_id: string;
  allowed_targets: string[];
  exclusions: string[];
  allowed_tools: string[];
  allowed_action_classes: string[];
  notes?: string;
}

export interface ScopeCheckResult {
  target: string;
  tool: string;
  action_class: string;
  allowed: boolean;
  reason?: string;
}

export interface RawRef {
  tool_run_id?: string;
  locator?: string;
  reference_file?: string;
}

export interface EvidenceItem {
  id?: string;
  type: 'observed' | 'inference';
  content: string;
  timestamp?: string;
  raw_ref?: RawRef;
}

export interface Finding {
  id: string;
  assessment_id: string;
  title: string;
  description: string;
  category: string;
  asset_id: string;
  target_asset?: string;
  port?: number;
  protocol?: string;
  service?: string;
  url?: string;
  parameter?: string;
  source_tools: string[];
  tool_severity?: string;
  severity?: string;
  cvss_score?: number;
  cvss_vector?: string;
  cve_ids: string[];
  cwe_ids: string[];
  confidence: string;
  confidence_score: number;
  confidence_reason?: string;
  status: string;
  validation_status: string;
  risk_score?: number;
  risk_band?: string;
  risk_rationale?: string;
  risk_breakdown?: Record<string, any>;
  evidence: EvidenceItem[];
  first_seen?: string;
  last_seen?: string;
}

export interface FindingSummary {
  total_findings: number;
  severities: Record<string, number>;
  risk_bands: Record<string, number>;
  statuses: Record<string, number>;
}

export interface Approval {
  id: string;
  assessment_id: string;
  action: string;
  action_detail?: {
    finding_id?: string;
    tool?: string;
    target?: string;
    params?: Record<string, any>;
    justification?: string;
    risk?: string;
  };
  requested_by?: string;
  status: 'pending' | 'approved' | 'rejected';
  reason?: string;
  approval_token?: string;
  created_at?: string;
}

export interface AuditEvent {
  id: string;
  assessment_id: string;
  seq: number;
  timestamp: string;
  actor: string;
  event_type: string;
  outcome: string;
  detail: Record<string, any>;
  prev_hash: string;
  hash: string;
}

export interface IntegrationTool {
  name: string;
  mode: 'Live' | 'Import-only' | 'Planned';
  status: string;
  binary_found: boolean;
  version?: string;
  capabilities: string;
  limitations: string;
}

export interface PlanStep {
  action: string;
  target: string;
  rationale: string;
  arguments?: Record<string, any>;
  status?: 'proposed' | 'running' | 'completed' | 'skipped';
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  reasoning?: string;
  timestamp: string;
  tool_calls?: any[];
}
