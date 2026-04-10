# SQL 目录说明

> **数据库初始化与迁移 SQL 入口**

---

## 命名规则

- 文件命名格式：`YYYY-MM-DD_<动作>_<主题>.sql`
- 首轮初始化按领域拆分：
  - `2026-04-09_init_platform_core.sql`
  - `2026-04-09_init_cve.sql`
  - `2026-04-09_init_announcement.sql`
  - `2026-04-09_init_indexes.sql`

---

## 执行顺序

1. `2026-04-09_init_platform_core.sql`
2. `2026-04-09_init_cve.sql`
3. `2026-04-09_init_announcement.sql`
4. `2026-04-09_init_indexes.sql`

唯一允许的初始化顺序是 `platform_core -> cve -> announcement -> indexes`。

---

## 原则

- 平台表先于场景表
- 每个 SQL 文件可独立阅读
- 索引独立放在最后一份脚本中
- 平台域弱引用：`source_fetch_records.source_id` 只保存场景侧 `source_id`，`platform_core` 不对 `announcement_sources` 建硬外键
- 公告域强外键：`announcement_runs.source_id`、`announcement_runs.trigger_fetch_id` 以及公告域内部结果链路在 `announcement.sql` 中保持强外键
- SQL 与部署文档都必须坚持同一初始化顺序，不能在 `platform_core` 提前引用公告域表

---

## 🔄 变更记录

### v1.0 - 2026-04-09
- 初始化 SQL 目录说明

### v1.1 - 2026-04-10
- 固定 `platform_core -> cve -> announcement -> indexes` 初始化顺序
- 明确平台域弱引用与公告域强外键的边界
