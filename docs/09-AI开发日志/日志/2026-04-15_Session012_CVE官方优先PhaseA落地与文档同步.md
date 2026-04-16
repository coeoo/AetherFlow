# 2026-04-15 Session012 - CVE 官方优先 Phase A 落地与文档同步

状态: ✅ 已完成

## 做了什么

- 落地 `CVE 官方记录优先` 的多源 seed 聚合主链
- 新增独立 `reference_matcher`，把非 NVD 规则从 `page_analyzer` 中拆出
- 让 `page_analyzer` 接入 matcher，并补上 Bugzilla detail 页 raw attachment 单页提取
- 固化 Debian BTS、Red Hat Bugzilla、Openwall 三类离线 regression fixture
- 补齐运行时、worker、API 与前端对新增 `patch_type` 和 `source_results` 的回归
- 将本轮 CVE Phase A 相关改动按 3 个中文 commit 提交
- 同步更新相关设计文档、使用说明和技术状态文档

## 本次更新的代码

- `backend/app/cve/seed_sources.py`
- `backend/app/cve/seed_resolver.py`
- `backend/app/cve/reference_matcher.py`
- `backend/app/cve/page_analyzer.py`
- `backend/tests/test_seed_sources.py`
- `backend/tests/test_seed_resolver.py`
- `backend/tests/test_reference_matcher.py`
- `backend/tests/test_page_analyzer.py`
- `backend/tests/test_cve_regressions.py`
- `backend/tests/fixtures/cve_regressions/*`
- `backend/tests/test_cve_runtime.py`
- `backend/tests/test_worker_cve_flow.py`
- `backend/tests/test_cve_api.py`
- `backend/tests/conftest.py`
- `frontend/src/features/cve/presentation.ts`
- `frontend/src/features/cve/components/CVEPatchList.tsx`
- `frontend/src/test/cve-pages.test.tsx`

## 本次更新的文档

- `docs/superpowers/specs/2026-04-15-cve-official-seed-phase-a-design.md`
- `docs/superpowers/plans/2026-04-15-cve-official-seed-phase-a.md`
- `docs/04-功能设计/M101-CVE检索工作台功能设计.md`
- `docs/04-功能设计/M102-CVE运行详情与补丁证据功能设计.md`
- `docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`
- `docs/02-使用指南/CVE检索工作台使用说明.md`
- `docs/03-系统架构/技术链设计.md`
- `docs/09-AI开发日志/日志/2026-04-15_Session012_CVE官方优先PhaseA落地与文档同步.md`

## 关键决策

- 当前实时主链选择 **CVE 官方记录 API** 作为第一来源，而不是 `cvelistV5 releases zip`
- 多源执行保持严格串行，不引入并发、重试和退避，优先保证行为稳定可测
- `source_fetch_records` 继续作为当前主链唯一 trace 落表边界，不引入新表
- Bugzilla raw attachment 只做 detail 页单页提取，不扩展到多跳导航
- 本轮明确不做 graph、fix family、LLM fallback 和多跳 Debian tracker 导航

## 提交记录

- `7e3de97` `CVE：接入官方优先的多源 seed 聚合`
- `75d2e32` `CVE：补齐非 NVD 规则库与页面回归`
- `41536ee` `CVE：收口运行链与前端补丁展示`

## 验证

- `TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests/test_seed_sources.py backend/tests/test_seed_resolver.py -q`
  - 结果：`7 passed`
- `timeout 60s ./.venv/bin/python -m pytest backend/tests/test_reference_matcher.py backend/tests/test_page_analyzer.py backend/tests/test_cve_regressions.py -q`
  - 结果：`21 passed`
- `TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests/test_cve_runtime.py backend/tests/test_worker_cve_flow.py backend/tests/test_cve_api.py -q`
  - 结果：`23 passed`
- `TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests -q`
  - 结果：`111 passed`
- `timeout 60s npm --prefix frontend test -- --run`
  - 结果：`19 passed`
- `timeout 180s npm --prefix frontend run build`
  - 结果：成功

## 下次计划

1. 评估是否要引入离线 `cvelistV5 releases zip` 基线同步，用于批量补录和缓存预热
2. 评估 graph / fix family / LLM fallback 是否需要作为下一阶段单独 Phase 推进
3. 继续收口并行中的 `announcement` 场景改动，避免与当前 CVE 文档和代码状态混淆
