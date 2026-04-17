-- 历史说明：
-- 1. 本文件创建于 2026-04-09，属于早期 CVE schema 草案。
-- 2. 当前仓库真实已落地的迁移与 ORM 以 backend/alembic 和 backend/app/models 为准。
-- 3. 下方 cve_fix_families / family_id 结构仅代表历史扩展设想，不代表当前数据库事实。
-- 4. 当前已落地的 CVE 数据边界仍是 cve_runs + cve_patch_artifacts + source_fetch_records。

CREATE TABLE IF NOT EXISTS cve_runs (
    run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL UNIQUE REFERENCES task_jobs(job_id) ON DELETE CASCADE,
    cve_id VARCHAR(32) NOT NULL,
    run_mode VARCHAR(16) NOT NULL DEFAULT 'agent',
    status VARCHAR(32) NOT NULL,
    phase VARCHAR(32) NOT NULL,
    stop_reason VARCHAR(64),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    progress_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_traces_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    langsmith_run_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cve_fix_families (
    family_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID NOT NULL REFERENCES cve_runs(run_id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    confidence NUMERIC(5,4),
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    family_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cve_patch_artifacts (
    patch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID NOT NULL REFERENCES cve_runs(run_id) ON DELETE CASCADE,
    family_id UUID REFERENCES cve_fix_families(family_id) ON DELETE SET NULL,
    candidate_url TEXT NOT NULL,
    patch_type VARCHAR(32) NOT NULL,
    download_status VARCHAR(32) NOT NULL,
    artifact_id UUID REFERENCES artifacts(artifact_id) ON DELETE SET NULL,
    patch_meta_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
