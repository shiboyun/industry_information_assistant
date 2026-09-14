import { request } from './request'

// 安全控制台使用页面内的局部加载状态，不能让一次审批查询锁住整个网站。
const securityRequestOptions = { loading: false, cancelRepeat: false, timeout: 30_000 }

export type SecurityRole = 'operator' | 'approver' | 'security_admin'

export interface ToolInvocation {
  id: string
  trace_id: string
  tool_name: string
  safe_params: Record<string, unknown>
  risk_score: number
  risk_level: string
  decision: string
  status: string
  policy_id: string
  evidence: string[]
  result_summary?: string
  created_at: string
}

export interface ApprovalRequest {
  id: string
  requester_id?: string
  approver_id?: string
  claimant_id?: string
  requester_name?: string
  claimant_name?: string
  approver_name?: string
  status: string
  comment?: string
  claimed_at?: string
  decided_at?: string
  created_at: string
  invocation?: ToolInvocation
}

export function getSecurityMe() {
  return request.get<{ user_id: string; role: SecurityRole }>('/security/me', securityRequestOptions)
}

export function detectAttack(data: { user_input?: string; web_text?: string; knowledge_text?: string }) {
  return request.post<Record<string, unknown>>('/security/attack-detect', data, securityRequestOptions)
}

export function getApprovals(filters: { statuses?: string; tool_name?: string; requester_id?: string; risk_level?: string } = {}) {
  return request.get<ApprovalRequest[]>('/security/approvals', { ...securityRequestOptions, params: filters })
}

export function getMyApprovals() {
  return request.get<ApprovalRequest[]>('/security/approvals/mine', securityRequestOptions)
}

export function invokeTool(data: {
  tool_name: string
  params: Record<string, unknown>
  trace_id?: string
  agent_name?: string
  source_type?: string
  risk_labels?: string[]
  evidence?: string[]
}) {
  return request.post<{ invocation: ToolInvocation; approval?: ApprovalRequest; result?: Record<string, unknown> }>('/security/tools/invoke', data, securityRequestOptions)
}

export function decideApproval(id: string, approved: boolean, comment?: string) {
  return request.post(`/security/approvals/${id}/decision`, { approved, comment }, securityRequestOptions)
}

export function claimApproval(id: string) {
  return request.post(`/security/approvals/${id}/claim`, {}, securityRequestOptions)
}

export function closeApproval(id: string, comment?: string) {
  return request.post(`/security/approvals/${id}/close`, { comment }, securityRequestOptions)
}

export function withdrawApproval(id: string) {
  return request.post(`/security/approvals/${id}/withdraw`, {}, securityRequestOptions)
}

// ============ 审计与安全日志（赛题方向四） ============

export interface SecurityLogLine {
  ts: string
  event_type: string
  trace_id: string
  stage?: string | null
  source_type?: string
  agent_name?: string
  tool_name?: string | null
  decision?: string
  risk_score?: number
  risk_level?: string
  labels?: string[]
  evidence?: string[]
  metadata?: Record<string, unknown>
  pid?: number
}

export interface SecurityMetrics {
  generated_at: string
  trace_id: string
  total_events: number
  trace_count: number
  by_stage: Record<string, number>
  by_decision: Record<string, number>
  by_label: Record<string, number>
  by_risk_level: Record<string, number>
  by_dimension: Record<string, number>
}

export interface EvidenceTimelineItem {
  seq: number
  ts: string
  event_type: string
  stage?: string | null
  source_type?: string
  agent_name?: string
  tool_name?: string | null
  decision?: string
  risk_score?: number
  risk_level?: string
  labels: string[]
  evidence: string[]
  event_hash?: string
  previous_event_hash?: string | null
}

export interface EvidenceBundle {
  trace_id: string
  generated_at: string
  summary: {
    event_count: number
    blocked_count: number
    modified_count: number
    tainted: boolean
    max_risk_score: number
    stages: string[]
    labels: string[]
  }
  timeline: EvidenceTimelineItem[]
  taint: { trace_id: string; flags: string[]; evidence: string[]; tainted: boolean }
  integrity: { hash_chain: { valid: boolean; event_count: number; seq?: number } }
  metrics: SecurityMetrics
}

export function getSecurityMetrics(traceId?: string) {
  return request.get<SecurityMetrics>('/security/metrics', {
    ...securityRequestOptions,
    params: traceId ? { trace_id: traceId } : {},
  })
}

export function getSecurityLogs(limit = 100) {
  return request.get<{ path: string; enabled: boolean; events: SecurityLogLine[] }>('/security/logs/tail', {
    ...securityRequestOptions,
    params: { limit },
  })
}

export function getTraceEvidence(traceId: string) {
  return request.get<EvidenceBundle>(`/security/traces/${traceId}/evidence`, securityRequestOptions)
}

export function getTrace(traceId: string) {
  return request.get<{
    trace_id: string
    invocations: ToolInvocation[]
    events: Array<{ id: string; event_type: string; payload: Record<string, unknown>; event_hash: string; created_at: string }>
    integrity: { valid: boolean; event_count: number }
  }>(`/security/traces/${traceId}`, securityRequestOptions)
}
