import argparse
import logging
import sys

from nta.agent import AgentConfig, TrafficCaptureAgent, scan_local_hosts
from nta.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def build_config(args: argparse.Namespace) -> AgentConfig:
    return AgentConfig(
        api_base_url=args.api_base_url or settings.api_base_url,
        mode=args.mode,
        interval_seconds=args.interval,
        batch_size=args.batch_size,
        interface=args.interface,
        retry_seconds=args.retry_seconds,
        subnet_prefix=args.subnet_prefix,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Network traffic capture agent")
    parser.add_argument("--api-base-url", default=settings.api_base_url)
    parser.add_argument("--mode", choices=["sample", "live", "scan"], default=settings.agent_mode)
    parser.add_argument("--daemon", action="store_true", help="Run continuously as a background service")
    parser.add_argument("--count", type=int, default=20, help="Logs/packets for one-shot mode")
    parser.add_argument("--interval", type=float, default=settings.agent_interval_seconds)
    parser.add_argument("--batch-size", type=int, default=settings.agent_batch_size)
    parser.add_argument("--interface", default=settings.agent_interface)
    parser.add_argument("--subnet-prefix", default=settings.agent_subnet_prefix)
    parser.add_argument("--retry-seconds", type=float, default=settings.agent_retry_seconds)
    args = parser.parse_args()

    if args.mode == "scan":
        scan_local_hosts(args.subnet_prefix)
        return

    config = build_config(args)
    agent = TrafficCaptureAgent(config)

    if args.daemon:
        if args.mode not in {"sample", "live"}:
            print("Daemon mode supports sample and live capture only.", file=sys.stderr)
            sys.exit(1)
        agent.run_daemon()
        return

    if args.mode == "sample":
        agent.run_once_sample(args.count, args.interval)
    elif args.mode == "live":
        agent.run_once_live(args.interface, args.count)


if __name__ == "__main__":
    main()
