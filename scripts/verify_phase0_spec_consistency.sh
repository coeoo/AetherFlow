#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_pattern() {
    local pattern="$1"
    local relative_path="$2"
    local description="$3"

    if ! rg -qi "$pattern" "$ROOT_DIR/$relative_path"; then
        echo "缺少约定：${description} (${relative_path})" >&2
        exit 1
    fi
}

forbid_pattern() {
    local pattern="$1"
    local relative_path="$2"
    local description="$3"

    if rg -qi "$pattern" "$ROOT_DIR/$relative_path"; then
        echo "发现冲突表述：${description} (${relative_path})" >&2
        exit 1
    fi
}

main() {
    require_pattern "source_id UUID," \
        "docs/05-数据库/sql/2026-04-09_init_platform_core.sql" \
        "platform core 中的 source_fetch_records.source_id 应为弱引用字段"
    forbid_pattern "source_id UUID REFERENCES announcement_sources\\(source_id\\)" \
        "docs/05-数据库/sql/2026-04-09_init_platform_core.sql" \
        "platform core 不应反向依赖 announcement_sources 硬外键"

    require_pattern "platform_core -> cve -> announcement -> indexes" \
        "docs/05-数据库/sql/README.md" \
        "SQL README 应固定初始化顺序"
    require_pattern "平台域.*弱引用" \
        "docs/05-数据库/sql/README.md" \
        "SQL README 应写明平台域弱引用"
    require_pattern "公告域.*强外键" \
        "docs/05-数据库/sql/README.md" \
        "SQL README 应写明公告域强外键"

    require_pattern "平台域.*弱引用" \
        "docs/03-系统架构/数据库设计.md" \
        "数据库设计应区分平台域弱引用"
    require_pattern "公告域.*强外键" \
        "docs/03-系统架构/数据库设计.md" \
        "数据库设计应区分公告域强外键"
    require_pattern "source_fetch_records.*source_id.*弱引用" \
        "docs/03-系统架构/数据库设计.md" \
        "数据库设计应说明 source_fetch_records.source_id 是弱引用"
    require_pattern "trigger_fetch_id.*强外键|announcement_runs.*强外键" \
        "docs/03-系统架构/数据库设计.md" \
        "数据库设计应说明公告域强外键关系"

    require_pattern "不依赖.*消息队列.*外部调度基础设施|单机.单实例优先.*不依赖.*消息队列.*外部调度基础设施" \
        "docs/00-总设计/总体项目设计.md" \
        "总体设计应统一 v1 运行前提"
    require_pattern "逻辑角色" \
        "docs/03-系统架构/架构设计.md" \
        "架构设计应使用逻辑角色口径"
    require_pattern "可同进程运行|可拆分.*本地进程|逻辑角色可拆分" \
        "docs/03-系统架构/架构设计.md" \
        "架构设计应允许逻辑角色按调试需要拆分"
    require_pattern "scheduler.*(逻辑角色|entrypoint|保留入口|heartbeat)" \
        "docs/07-部署运维/部署手册.md" \
        "部署手册应说明 scheduler 的早期角色"
    require_pattern "不依赖.*消息队列.*外部调度基础设施|单机.单实例优先" \
        "docs/07-部署运维/部署手册.md" \
        "部署手册应说明 v1 的运行前提"
    require_pattern "scheduler.*(保留入口|entrypoint|heartbeat)" \
        "docs/04-功能设计/M002-平台任务执行与调度中心功能设计.md" \
        "M002 应说明 scheduler 在早期阶段只保留入口与 heartbeat"
    require_pattern "scheduler.*(保留入口|entrypoint|heartbeat)" \
        "docs/04-功能设计/M203-安全公告调度运行与结果功能设计.md" \
        "M203 应说明 scheduler 在早期阶段的保留角色"

    forbid_pattern "单进程，不引入消息队列和独立调度服务" \
        "docs/00-总设计/总体项目设计.md" \
        "总体设计中的旧部署口径"
    forbid_pattern "Web/API/Worker/Scheduler 分进程运行" \
        "docs/03-系统架构/架构设计.md" \
        "架构设计中的硬编码分进程表述"
    forbid_pattern "独立调度服务" \
        "docs/04-功能设计/M002-平台任务执行与调度中心功能设计.md" \
        "M002 中的旧 scheduler 口径"
    forbid_pattern "独立调度服务" \
        "docs/04-功能设计/M203-安全公告调度运行与结果功能设计.md" \
        "M203 中的旧 scheduler 口径"

    require_pattern "实现阶段顺序" \
        "docs/04-功能设计/M901-功能模块关系与开发顺序设计.md" \
        "M901 应明确实现阶段顺序"
    require_pattern "平台最小底座" \
        "docs/04-功能设计/M901-功能模块关系与开发顺序设计.md" \
        "M901 应包含平台最小底座"
    require_pattern "安全公告手动提取.*正文模式.*(首个可运行垂直切片|首个切片|首个闭环)" \
        "docs/04-功能设计/M901-功能模块关系与开发顺序设计.md" \
        "M901 应说明正文模式是首个可运行垂直切片"
    require_pattern "安全公告 URL 模式" \
        "docs/04-功能设计/M901-功能模块关系与开发顺序设计.md" \
        "M901 应包含 URL 模式阶段"
    require_pattern "监控.*投递|投递.*监控" \
        "docs/04-功能设计/M901-功能模块关系与开发顺序设计.md" \
        "M901 应把监控与投递放在后续阶段"

    require_pattern "实现阶段顺序" \
        "docs/04-功能设计/README.md" \
        "功能设计总索引应补充实现阶段顺序"
    require_pattern "平台最小底座" \
        "docs/04-功能设计/README.md" \
        "功能设计总索引应包含平台最小底座"
    require_pattern "正文模式.*(首个可运行垂直切片|首个切片)" \
        "docs/04-功能设计/M201-安全公告手动提取功能设计.md" \
        "M201 应说明正文模式是首个切片"
    require_pattern "URL 模式.*(随后接入|第二阶段|正文模式稳定后)" \
        "docs/04-功能设计/M201-安全公告手动提取功能设计.md" \
        "M201 应说明 URL 模式在正文模式之后接入"
    require_pattern "CVE.*首个公告切片稳定后接入|首个公告切片稳定后.*CVE" \
        "docs/04-功能设计/M101-CVE检索工作台功能设计.md" \
        "M101 应说明 CVE 在首个公告切片稳定后接入"

    forbid_pattern "先完成 CVE 场景，再扩公告场景实现" \
        "docs/04-功能设计/M901-功能模块关系与开发顺序设计.md" \
        "M901 中的旧实现顺序"
    forbid_pattern "先完成 CVE 场景，再扩公告场景实现" \
        "docs/04-功能设计/README.md" \
        "功能设计总索引中的旧实现顺序"
    forbid_pattern "URL.*正文.*同等优先" \
        "docs/04-功能设计/M201-安全公告手动提取功能设计.md" \
        "M201 中 URL 与正文同优先级的旧表述"

    echo "Phase 0 规范一致性验证通过"
}

main "$@"
