import argparse
import time

from app.config import load_settings
from app.db.session import create_session_factory
from app.worker.runtime import process_once


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aetherflow-worker")
    parser.add_argument("--once", action="store_true", help="执行一次占位轮询后退出")
    parser.add_argument("--worker-name", help="覆盖默认 worker 名称")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    settings = load_settings()
    if not settings.database_url:
        raise RuntimeError("缺少数据库连接信息，无法启动 worker。")

    session_factory = create_session_factory(settings.database_url)
    worker_name = args.worker_name or settings.worker_name
    if args.once:
        process_once(session_factory, worker_name=worker_name)
        return 0

    while True:
        processed = process_once(session_factory, worker_name=worker_name)
        if not processed:
            time.sleep(2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
