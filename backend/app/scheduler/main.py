import argparse

from app.config import load_settings
from app.scheduler.runtime import run_scheduler_once


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aetherflow-scheduler")
    parser.add_argument("--once", action="store_true", help="执行一次占位调度后退出")
    parser.add_argument("--instance-name", help="覆盖默认 scheduler 实例名")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.once:
        run_scheduler_once(load_settings(), instance_name=args.instance_name)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
