#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTAINER_NAME="${AETHERFLOW_PHASE0_PG_CONTAINER:-aetherflow-phase0-pg}"
DB_NAME="${AETHERFLOW_PHASE0_PG_DB:-aetherflow_phase0}"
DB_PORT="${AETHERFLOW_PHASE0_PG_PORT:-55432}"
DB_USER="${AETHERFLOW_PHASE0_PG_USER:-postgres}"
DB_PASSWORD="${AETHERFLOW_PHASE0_PG_PASSWORD:-postgres}"
DB_IMAGE="${AETHERFLOW_PHASE0_PG_IMAGE:-}"

SELF_MANAGED=0
PSQL_CMD=()

cleanup() {
    if [ "$SELF_MANAGED" -eq 1 ]; then
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
}

run_sql_file() {
    local relative_path="$1"

    if [ "${#PSQL_CMD[@]}" -gt 0 ]; then
        "${PSQL_CMD[@]}" -v ON_ERROR_STOP=1 -f "$ROOT_DIR/$relative_path"
        return
    fi

    docker exec -i "$CONTAINER_NAME" \
        psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -f - \
        < "$ROOT_DIR/$relative_path"
}

run_sql_query() {
    local query="$1"

    if [ "${#PSQL_CMD[@]}" -gt 0 ]; then
        "${PSQL_CMD[@]}" -Atqc "$query"
        return
    fi

    docker exec -i "$CONTAINER_NAME" \
        psql -U "$DB_USER" -d "$DB_NAME" -Atqc "$query"
}

prepare_database() {
    if [ -n "${DATABASE_URL:-}" ]; then
        if ! command -v psql >/dev/null 2>&1; then
            echo "检测到 DATABASE_URL，但当前环境没有可用的 psql。" >&2
            echo "请安装 psql，或不传 DATABASE_URL 以便脚本自管临时 PostgreSQL。" >&2
            exit 1
        fi

        PSQL_CMD=(psql "$DATABASE_URL")
        return
    fi

    if ! command -v docker >/dev/null 2>&1; then
        echo "未找到 docker，无法自管临时 PostgreSQL。" >&2
        exit 1
    fi

    if [ -z "$DB_IMAGE" ]; then
        if docker image inspect pgvector/pgvector:pg16 >/dev/null 2>&1; then
            DB_IMAGE="pgvector/pgvector:pg16"
        else
            DB_IMAGE="postgres:16-alpine"
        fi
    fi

    SELF_MANAGED=1
    trap cleanup EXIT

    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker run --rm -d \
        --name "$CONTAINER_NAME" \
        -e "POSTGRES_PASSWORD=$DB_PASSWORD" \
        -e "POSTGRES_DB=$DB_NAME" \
        -p "$DB_PORT:5432" \
        "$DB_IMAGE" >/dev/null

    until docker exec "$CONTAINER_NAME" pg_isready -U "$DB_USER" >/dev/null 2>&1; do
        sleep 1
    done

    # pgvector 镜像沿用官方 entrypoint，初始化阶段会短暂拉起临时实例再重启一次。
    # 这里要求连续两次查询成功，避免在“正在关闭”的瞬间提前执行 SQL。
    local ready_checks=0
    while [ "$ready_checks" -lt 2 ]; do
        if docker exec -i "$CONTAINER_NAME" \
            psql -U "$DB_USER" -d "$DB_NAME" -Atqc "SELECT 1" >/dev/null 2>&1; then
            ready_checks=$((ready_checks + 1))
            sleep 1
            continue
        fi

        ready_checks=0
        sleep 1
    done
}

verify_tables_exist() {
    local required_tables=(
        "task_jobs"
        "source_fetch_records"
        "announcement_sources"
    )

    local table_name
    for table_name in "${required_tables[@]}"; do
        if [ -z "$(run_sql_query "SELECT to_regclass('public.${table_name}');")" ]; then
            echo "缺少预期数据表：${table_name}" >&2
            exit 1
        fi
    done
}

main() {
    local sql_files=(
        "docs/05-数据库/sql/2026-04-09_init_platform_core.sql"
        "docs/05-数据库/sql/2026-04-09_init_cve.sql"
        "docs/05-数据库/sql/2026-04-09_init_announcement.sql"
        "docs/05-数据库/sql/2026-04-09_init_indexes.sql"
    )

    prepare_database

    local sql_file
    for sql_file in "${sql_files[@]}"; do
        run_sql_file "$sql_file"
    done

    verify_tables_exist
    echo "SQL 初始化顺序验证通过"
}

main "$@"
