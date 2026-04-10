CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS task_jobs (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scene_name VARCHAR(32) NOT NULL CHECK (scene_name IN ('cve', 'announcement')),
    job_type VARCHAR(64) NOT NULL,
    trigger_kind VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS task_attempts (
    attempt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES task_jobs(job_id) ON DELETE CASCADE,
    attempt_no INT NOT NULL,
    status VARCHAR(32) NOT NULL,
    worker_name VARCHAR(128),
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    UNIQUE (job_id, attempt_no)
);

CREATE TABLE IF NOT EXISTS delivery_targets (
    target_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(128) NOT NULL,
    channel_type VARCHAR(32) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_ref VARCHAR(256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS delivery_records (
    record_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID REFERENCES delivery_targets(target_id) ON DELETE SET NULL,
    scene_name VARCHAR(32) NOT NULL,
    source_ref_type VARCHAR(64),
    source_ref_id UUID,
    status VARCHAR(32) NOT NULL,
    payload_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_snapshot_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_kind VARCHAR(32) NOT NULL,
    scene_name VARCHAR(32) NOT NULL,
    source_url TEXT,
    storage_path TEXT NOT NULL,
    content_type VARCHAR(128),
    checksum VARCHAR(128) NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS source_fetch_records (
    fetch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scene_name VARCHAR(32) NOT NULL,
    -- 平台域只保留公告源 ID 的弱引用，避免 platform_core 初始化反向依赖公告域。
    source_id UUID,
    source_type VARCHAR(64) NOT NULL,
    source_ref VARCHAR(256),
    status VARCHAR(32) NOT NULL,
    request_snapshot_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_meta_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
