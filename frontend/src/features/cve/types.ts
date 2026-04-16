export type CVERunProgress = {
  current_phase: string;
  completed_steps: number;
  total_steps: number;
  terminal: boolean;
};

export type CVERunRecentProgress = {
  step: string;
  label: string;
  status: string;
  detail: string | null;
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

export type CVERunSummary = {
  patch_found?: boolean;
  patch_count?: number;
  primary_patch_url?: string;
  primary_family_source_url?: string;
  primary_family_source_host?: string;
  primary_family_evidence_source_count?: number;
  primary_family_related_source_hosts?: string[];
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
