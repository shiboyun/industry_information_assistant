import { request } from './request'

export type EvidenceType = 'knowledge_document' | 'bidding' | 'news'

export interface EvidenceOption { id: string; title: string; summary: string; meta?: string }
export interface TaskEvidence {
  id: string
  source_type: EvidenceType
  source_id: string
  title: string
  summary: string
  metadata: Record<string, unknown>
  invocation_id?: string
  created_at: string
}
export interface TenderAnalysisTask {
  id: string
  trace_id: string
  project_name: string
  analysis_goal: string
  deadline?: string
  public_scope?: string
  conclusion_draft: string
  verification_items: string
  status: string
  created_at: string
  updated_at: string
  evidence?: TaskEvidence[]
}
export interface EvidenceOptions {
  documents: EvidenceOption[]
  bidding: EvidenceOption[]
  news: EvidenceOption[]
}

type ServiceEnvelope<T> = { status: string; message?: string; data: T }
const options = { loading: false, cancelRepeat: false, timeout: 10_000 }

function unwrap<T>(value: T | ServiceEnvelope<T>): T {
  if (value && typeof value === 'object' && 'status' in value && 'data' in value) {
    return (value as ServiceEnvelope<T>).data
  }
  return value as T
}

export async function getAvailableEvidence(): Promise<EvidenceOptions> {
  const response = await request.get<EvidenceOptions | ServiceEnvelope<EvidenceOptions>>('/tender-analysis-tasks/available-evidence', options)
  return unwrap(response.data)
}

export async function getTenderTasks(): Promise<TenderAnalysisTask[]> {
  const response = await request.get<TenderAnalysisTask[] | ServiceEnvelope<TenderAnalysisTask[]>>('/tender-analysis-tasks', options)
  return unwrap(response.data)
}

export async function getTenderTask(id: string): Promise<TenderAnalysisTask> {
  const response = await request.get<TenderAnalysisTask | ServiceEnvelope<TenderAnalysisTask>>(`/tender-analysis-tasks/${id}`, options)
  return unwrap(response.data)
}

export async function createTenderTask(data: {
  project_name: string
  analysis_goal: string
  deadline?: string
  public_scope?: string
  evidence: Array<{ source_type: EvidenceType; source_id: string }>
}): Promise<TenderAnalysisTask> {
  const response = await request.post<TenderAnalysisTask | ServiceEnvelope<TenderAnalysisTask>>('/tender-analysis-tasks', data, options)
  return unwrap(response.data)
}

export async function updateTenderDraft(
  id: string,
  data: { conclusion_draft: string; verification_items: string },
): Promise<TenderAnalysisTask> {
  const response = await request.put<TenderAnalysisTask | ServiceEnvelope<TenderAnalysisTask>>(`/tender-analysis-tasks/${id}/draft`, data, options)
  return unwrap(response.data)
}

export async function deleteTenderTask(id: string): Promise<void> {
  await request.delete(`/tender-analysis-tasks/${id}`, options)
}
