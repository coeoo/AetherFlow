CREATE INDEX IF NOT EXISTS idx_task_jobs_scene_status
    ON task_jobs(scene_name, status);

CREATE INDEX IF NOT EXISTS idx_task_jobs_created_at
    ON task_jobs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_task_jobs_trigger_kind
    ON task_jobs(trigger_kind);

CREATE INDEX IF NOT EXISTS idx_task_attempts_job_id
    ON task_attempts(job_id);

CREATE INDEX IF NOT EXISTS idx_delivery_records_scene_status
    ON delivery_records(scene_name, status);

CREATE INDEX IF NOT EXISTS idx_delivery_records_source_ref
    ON delivery_records(source_ref_type, source_ref_id);

CREATE INDEX IF NOT EXISTS idx_artifacts_scene_kind
    ON artifacts(scene_name, artifact_kind);

CREATE INDEX IF NOT EXISTS idx_source_fetch_records_scene_type_created
    ON source_fetch_records(scene_name, source_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_source_fetch_records_source_id_created
    ON source_fetch_records(source_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_source_fetch_records_source_ref_created
    ON source_fetch_records(source_ref, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cve_runs_cve_id_created_at
    ON cve_runs(cve_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cve_runs_status
    ON cve_runs(status);

CREATE INDEX IF NOT EXISTS idx_cve_patch_artifacts_run_id
    ON cve_patch_artifacts(run_id);

CREATE INDEX IF NOT EXISTS idx_announcement_sources_type_enabled
    ON announcement_sources(source_type, enabled);

CREATE INDEX IF NOT EXISTS idx_announcement_runs_source_id_created_at
    ON announcement_runs(source_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_announcement_runs_status
    ON announcement_runs(status);

CREATE INDEX IF NOT EXISTS idx_announcement_runs_trigger_fetch_id
    ON announcement_runs(trigger_fetch_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_announcement_documents_source_item_per_source
    ON announcement_documents(source_id, source_item_key)
    WHERE source_id IS NOT NULL AND source_item_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_announcement_documents_content_dedup_hash
    ON announcement_documents(content_dedup_hash);

CREATE INDEX IF NOT EXISTS idx_announcement_packages_document_id
    ON announcement_intelligence_packages(document_id);

CREATE INDEX IF NOT EXISTS idx_announcement_packages_run_id
    ON announcement_intelligence_packages(run_id);
