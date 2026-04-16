# 2026-04-16 Session013 - CVE 详情 Fix Family 最小切片落地

状态: ✅ 已完成

## 做了什么

- 先按当前代码事实修正全局文档，收口 CVE 仍是实时 fast-first 主链、未落地 graph runtime / fix family 持久化 / LLM fallback / 离线 `cvelistV5` 基线
- 新增下一阶段 CVE 设计规格与实施计划，明确把 **Fix Family 最小切片** 作为下一阶段实现目标
- 按 TDD 先补后端失败测试，再实现 family 所需发现元数据透传与详情聚合
- 为详情接口新增 `fix_families` 视图字段
- 为详情页新增最小 `Fix Family Summary` 区块，放在 Patch List 之前
- 回写 `M102` 与 `P102`，同步当前已落地的 family summary 边界

## 本次更新的代码

- `backend/app/cve/runtime.py`
- `backend/app/cve/patch_downloader.py`
- `backend/app/cve/detail_service.py`
- `backend/tests/test_cve_runtime.py`
- `backend/tests/test_cve_api.py`
- `backend/tests/test_cve_detail_service.py`
- `frontend/src/features/cve/types.ts`
- `frontend/src/features/cve/components/CVEFixFamilySummary.tsx`
- `frontend/src/routes/CVERunDetailPage.tsx`
- `frontend/src/test/cve-pages.test.tsx`

## 本次更新的文档

- `docs/01-产品介绍/产品概述.md`
- `docs/01-产品介绍/快速开始.md`
- `docs/03-系统架构/架构设计.md`
- `docs/03-系统架构/数据库设计.md`
- `docs/04-功能设计/README.md`
- `docs/04-功能设计/M102-CVE运行详情与补丁证据功能设计.md`
- `docs/13-界面设计/P102-CVE运行详情页面设计.md`
- `docs/superpowers/specs/2026-04-16-cve-fix-family-phase-b1-design.md`
- `docs/superpowers/plans/2026-04-16-cve-fix-family-phase-b1.md`
- `docs/09-AI开发日志/日志/2026-04-16_Session013_CVE详情FixFamily最小切片落地.md`

## 关键决策

- 继续坚持 **实时获取**，不引入离线 `cvelistV5` 基线
- 当前只实现 **虚拟 family 聚合视图**，不新增 `cve_fix_families` 表
- family 的最小分组键为 `discovered_from_url`，缺失时退化为 `candidate_url`
- 运行时通过 `patch_meta_json` 透传：
  - `discovered_from_url`
  - `discovered_from_host`
  - `discovery_rule`
- 当前 family 只是详情聚合层增强，不等价于 graph runtime
- LLM fallback 保持在后续 Phase，避免和本轮混做

## 验证

- `TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests/test_cve_runtime.py -q`
  - 结果：`9 passed`
- `TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev timeout 60s ./.venv/bin/python -m pytest backend/tests/test_cve_detail_service.py backend/tests/test_cve_api.py -q`
  - 结果：`14 passed`

## 下次计划

1. 继续跑 CVE 范围回归，包括 `test_worker_cve_flow.py`
2. 如回归通过，再评估是否需要把 family summary 继续增强为更丰富的来源阅读入口
3. 单独评估受限 LLM fallback 的触发边界与配置接入，不与当前 family 视图混做
