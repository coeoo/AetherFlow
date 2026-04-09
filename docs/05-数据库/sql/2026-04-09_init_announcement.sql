CREATE TABLE IF NOT EXISTS announcement_sources (
    source_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL,
    source_type VARCHAR(32) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    schedule_cron VARCHAR(64) NOT NULL,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    delivery_policy_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_success_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS announcement_runs (
    run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL UNIQUE REFERENCES task_jobs(job_id) ON DELETE CASCADE,
    entry_mode VARCHAR(32) NOT NULL,
    source_id UUID REFERENCES announcement_sources(source_id) ON DELETE SET NULL,
    trigger_fetch_id UUID REFERENCES source_fetch_records(fetch_id) ON DELETE SET NULL,
    status VARCHAR(32) NOT NULL,
    stage VARCHAR(32) NOT NULL,
    title_hint VARCHAR(256),
    input_snapshot_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS announcement_documents (
    document_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID NOT NULL UNIQUE REFERENCES announcement_runs(run_id) ON DELETE CASCADE,
    source_id UUID REFERENCES announcement_sources(source_id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    source_name VARCHAR(128) NOT NULL,
    source_url TEXT,
    published_at TIMESTAMPTZ,
    language VARCHAR(16),
    source_item_key VARCHAR(256),
    content_dedup_hash VARCHAR(128) NOT NULL,
    source_artifact_id UUID REFERENCES artifacts(artifact_id) ON DELETE SET NULL,
    normalized_text_artifact_id UUID REFERENCES artifacts(artifact_id) ON DELETE SET NULL,
    content_excerpt TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS announcement_intelligence_packages (
    package_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID NOT NULL UNIQUE REFERENCES announcement_runs(run_id) ON DELETE CASCADE,
    document_id UUID NOT NULL UNIQUE REFERENCES announcement_documents(document_id) ON DELETE CASCADE,
    confidence NUMERIC(5,4) NOT NULL,
    severity VARCHAR(32),
    affected_products_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    iocs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    remediation_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    analyst_summary TEXT NOT NULL,
    notify_recommended BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
