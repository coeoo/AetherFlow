import argparse

from app.config import load_settings
from app.worker.runtime import run_worker_once


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aetherflow-worker")
    parser.add_argument("--once", action="store_true", help="执行一次占位轮询后退出")
    parser.add_argument("--worker-name", help="覆盖默认 worker 名称")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.once:
        run_worker_once(load_settings(), worker_name=args.worker_name)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
