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

---

## 原则

- 平台表先于场景表
- 每个 SQL 文件可独立阅读
- 索引独立放在最后一份脚本中

---

## 🔄 变更记录

### v1.0 - 2026-04-09
- 初始化 SQL 目录说明

