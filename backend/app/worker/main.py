import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aetherflow-worker")
    parser.add_argument("--once", action="store_true", help="执行一次占位轮询后退出")
    return parser


def main() -> int:
    build_parser().parse_args()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
