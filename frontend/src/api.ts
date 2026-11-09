import {
  Approval,
  AuditEvent,
  Finding,
  FindingSummary,
  IntegrationTool,
  ScopeCheckResult,
  ScopeRule,
} from './types';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const errorText = await res.text();
    let detail = errorText;
    try {
      const parsed = JSON.parse(errorText);
      detail = parsed.detail || errorText;
    } catch {}
    throw new Error(detail || `HTTP error ${res.status}`);
  }
  return res.json();
}

export async function fetchHealth(): Promise<boolean> {
  try {
    const res = await fetch('/health', { headers: { Accept: 'text/plain' } });
    if (!res.ok) return false;
    const text = await res.text();
    return text.trim() === 'OK';
  } catch {
    return false;
  }
}

export async function fetchAssessments(): Promise<any[]> {
  try {
    const res = await fetch('/assessments');
    return handleResponse<any[]>(res);
  } catch {
    return [];
  }
}

export async function createAssessment(name: string, description: string): Promise<{ id: string; name: string }> {
  const res = await fetch('/assessments', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, description }),
  });
  return handleResponse(res);
}

export async function fetchScope(assessmentId: string): Promise<ScopeRule | null> {
  try {
    const res = await fetch(`/assessments/${assessmentId}/scope`);
    if (res.status === 404) return null;
    return handleResponse<ScopeRule>(res);
  } catch {
    return null;
  }
}

export async function registerScope(
  assessmentId: string,
  payload: {
    allowed_targets: string[];
    exclusions: string[];
    allowed_tools: string[];
    allowed_action_classes: string[];
    notes?: string;
  }
): Promise<ScopeRule> {
  const res = await fetch(`/assessments/${assessmentId}/scope`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return handleResponse<ScopeRule>(res);
}

export async function checkScope(
  assessmentId: string,
  target: string,
  tool: string,
  actionClass: string
): Promise<ScopeCheckResult> {
  const res = await fetch(`/assessments/${assessmentId}/scope/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target,
      tool,
      action_class: actionClass,
    }),
  });
  return handleResponse<ScopeCheckResult>(res);
}

export async function fetchFindings(assessmentId: string, sort: string = 'risk'): Promise<Finding[]> {
  const res = await fetch(`/assessments/${assessmentId}/findings?sort=${sort}`);
  return handleResponse<Finding[]>(res);
}

export async function fetchFindingsSummary(assessmentId: string): Promise<FindingSummary> {
  const res = await fetch(`/assessments/${assessmentId}/findings/summary`);
  return handleResponse<FindingSummary>(res);
}

export async function fetchApprovals(assessmentId: string): Promise<Approval[]> {
  const res = await fetch(`/assessments/${assessmentId}/approvals`);
  const rawList = await handleResponse<any[]>(res);
  return rawList.map((item) => {
    let actionDetail = {};
    try {
      actionDetail = typeof item.action === 'string' ? JSON.parse(item.action) : item.action;
    } catch {}
    return {
      ...item,
      action_detail: actionDetail,
    };
  });
}

export async function decideApproval(
  approvalId: string,
  decision: 'approve' | 'reject',
  reason: string,
  approver: string = 'analyst'
): Promise<{ status: string; approval_token?: string }> {
  const res = await fetch(`/approvals/${approvalId}/decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision, reason, approver }),
  });
  return handleResponse(res);
}

export async function fetchAuditEvents(assessmentId: string): Promise<AuditEvent[]> {
  const res = await fetch(`/assessments/${assessmentId}/audit?limit=100`);
  return handleResponse<AuditEvent[]>(res);
}

export async function verifyAuditChain(
  assessmentId: string
): Promise<{ verified: boolean; event_count: number; message: string }> {
  const res = await fetch(`/assessments/${assessmentId}/audit/verify`);
  return handleResponse(res);
}

export async function fetchIntegrations(): Promise<IntegrationTool[]> {
  const res = await fetch('/integrations');
  return handleResponse<IntegrationTool[]>(res);
}

export async function abortAssessment(
  assessmentId: string
): Promise<{ status: string; cancelled_scans: number; message: string }> {
  const res = await fetch(`/assessments/${assessmentId}/abort`, {
    method: 'POST',
  });
  return handleResponse(res);
}

export async function sendAgentChat(
  assessmentId: string,
  message: string
): Promise<{ text: string; tool_calls?: any[]; hallucinations?: string[] }> {
  const res = await fetch(`/assessments/${assessmentId}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message }),
  });
  return handleResponse(res);
}

export async function generateReport(
  assessmentId: string,
  executiveNarrative?: string
): Promise<any> {
  const res = await fetch(`/assessments/${assessmentId}/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ executive_narrative: executiveNarrative }),
  });
  return handleResponse(res);
}

