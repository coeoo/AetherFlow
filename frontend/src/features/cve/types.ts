export type CVERunProgress = {
  current_phase: string;
  completed_steps: number;
  total_steps: number;
  terminal: boolean;
  percent?: number;
  status_label?: string;
  latest_signal?: string | null;
  last_updated_at?: string | null;
  last_meaningful_update_at?: string | null;
  visited_trace_count?: number;
  downloaded_patch_count?: number;
  failed_trace_count?: number;
  active_url?: string | null;
};

export type CVERunRecentProgress = {
  step: string;
  label: string;
  status: string;
  detail: string | null;
  error_message?: string | null;
};

export type CVESourceTrace = {
  fetch_id: string;
  step: string;
  label: string;
  status: string;
  source_ref: string | null;
  url: string | null;
  request_snapshot: Record<string, unknown>;
  response_meta: Record<string, unknown>;
  error_message: string | null;
  created_at?: string;
};

export type CVEPatch = {
  patch_id: string;
  candidate_url: string;
  patch_type: string;
  download_status: string;
  artifact_id: string | null;
  duplicate_count: number;
  content_available: boolean;
  content_type: string | null;
  download_url: string | null;
};

export type CVEFixFamily = {
  family_key: string;
  title: string;
  source_url: string;
  source_host: string;
  discovery_rule: string;
  patch_count: number;
  downloaded_patch_count: number;
  primary_patch_id: string;
  patch_ids: string[];
  patch_types: string[];
  evidence_source_count: number;
  related_source_hosts: string[];
  evidence_sources: CVEFixFamilyEvidenceSource[];
};

export type CVEFixFamilyEvidenceSource = {
  source_url: string;
  source_host: string;
  discovery_rule: string;
  source_kind: string;
  order: number;
};

export type CVEChainStep = {
  url: string;
  page_role: string;
  depth: number;
};

export type CVEChainSummary = {
  chain_id: string;
  chain_type: string;
  status: string;
  steps: CVEChainStep[];
};

export type CVEBudgetUsage = {
  used: number;
  max: number;
};

export type CVESearchNode = {
  node_id: string;
  url: string;
  depth: number;
  host: string;
  page_role: string | null;
  fetch_status: string;
};

export type CVESearchEdge = {
  from_node_id: string;
  to_node_id: string;
  edge_type: string;
  selected_by: string;
};

export type CVESearchDecision = {
  decision_type: string;
  validated: boolean;
  model_name: string | null;
  node_id: string | null;
};

export type CVEFrontierStatus = {
  total_nodes: number;
  max_depth: number;
  active_node_count: number;
};

export type CVERunSummary = {
  patch_found?: boolean;
  patch_count?: number;
  runtime_kind?: string;
  primary_patch_url?: string;
  primary_family_source_url?: string;
  primary_family_source_host?: string;
  primary_family_evidence_source_count?: number;
  primary_family_related_source_hosts?: string[];
  chain_summary?: CVEChainSummary[];
  page_role_counts?: Record<string, number>;
  pages_visited?: number;
  cross_domain_hops?: number;
  budget_usage?: {
    pages?: CVEBudgetUsage;
    llm_calls?: CVEBudgetUsage;
    cross_domain?: CVEBudgetUsage;
  };
  llm_fallback_triggered?: boolean;
  llm_trigger_reason?: string;
  llm_invocation_status?: string;
  llm_skip_reason?: string;
  llm_decision?: string;
  llm_selected_candidate_key?: string;
  llm_selected_candidate_url?: string;
  llm_confidence_band?: string;
  llm_reason_summary?: string;
  llm_model?: string;
  llm_provider?: string;
  llm_verdict_source?: string;
  llm_input_candidate_count?: number;
  llm_input_source_count?: number;
  error?: string;
};

export type CVERunListItem = {
  run_id: string;
  cve_id: string;
  status: string;
  phase: string;
  stop_reason: string | null;
  summary: CVERunSummary;
  created_at: string;
};

export type CVERunDetail = {
  run_id: string;
  cve_id: string;
  status: string;
  phase: string;
  stop_reason: string | null;
  summary: CVERunSummary;
  progress: CVERunProgress;
  fix_families: CVEFixFamily[];
  recent_progress: CVERunRecentProgress[];
  source_traces: CVESourceTrace[];
  search_graph?: {
    nodes: CVESearchNode[];
    edges: CVESearchEdge[];
  };
  frontier_status?: CVEFrontierStatus;
  decision_history?: CVESearchDecision[];
  patches: CVEPatch[];
};

export type CVEPatchContent = {
  patch_id: string;
  candidate_url: string;
  content: string;
};

export type ApiEnvelope<T> = {
  code: number;
  message: string;
  data: T;
};
