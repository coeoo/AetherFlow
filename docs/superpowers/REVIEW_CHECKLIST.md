# Superpowers 过程资产审查清单

> 使用 Superpowers 生成或继续执行 spec / plan / review 前，先按本清单做只读审查。

## Spec 审查

- 是否有明确目标和非目标？
- 是否说明当前状态：`draft` / `active` / `completed` / `superseded` / `archived`？
- 是否指向相关主文档，且未替代 `docs/` 主文档权威性？
- 是否包含当前事实，而不是只写期望设计？
- 是否列出风险、暂停条件或回滚策略？
- 是否有可执行的验收标准？
- 是否避免把 prompt 调优当成架构替代？
- 若被新 spec 替代，是否写明 `Superseded by`？

## Plan 审查

- 是否指向唯一 active spec？
- 是否有明确当前 phase、当前 task 和下一步 checkpoint？
- 每个 task 是否能独立验证？
- 每个 task 是否有文件范围、测试命令和提交边界？
- checkbox 状态是否与当前代码、测试和 git diff 一致？
- 是否标注不可提交产物，如 `backend/results/` 和真实密钥？
- 是否引用了已废弃 spec、旧术语或已删除文件？
- 是否说明 baseline 或回归验证命令？

## Review / Closure 审查

- 是否说明验证环境、模型供应商、数据库和关键参数？
- 是否列出通过、失败、跳过样本？
- 是否归因失败，而不是只记录现象？
- 是否说明剩余风险和下一步行动？
- 是否需要回写主文档？
- 是否更新 `STATUS.md` 和 `DECISIONS.md`？

## 执行前最小门禁

1. 读 `docs/superpowers/STATUS.md`。
2. 读 active spec 和 active plan。
3. 核对 `git status --short --branch`。
4. 检查计划中的当前 task 是否仍匹配代码现状。
5. 确认验证命令和不可提交产物。

## 执行后最小门禁

1. 更新 active plan checkbox。
2. 记录验证命令和结果。
3. 如产生新决策，更新 `DECISIONS.md`。
4. 如阶段完成，写入 `reviews/` 或更新已有 closure。
5. 更新 `STATUS.md` 的当前 phase、next checkpoint 和 last baseline。
