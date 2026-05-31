#!/usr/bin/env python3
"""Run poc_extreme_campaign.rb target-by-target in parallel and merge CSV output."""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def read_targets(registry: Path, include_confirmed: bool, only: set[str] | None) -> list[str]:
    targets: set[str] = set()
    with registry.open(newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("poc_source") == "none":
                continue
            if row.get("poc_status") == "confirmed" and not include_confirmed:
                continue
            poc_id = row.get("poc_id") or ""
            if not poc_id:
                continue
            if only is not None and poc_id not in only:
                continue
            targets.add(poc_id)
    return sorted(targets)


def run_target(args: argparse.Namespace, target: str, index: int, part_dir: Path) -> tuple[str, int]:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in target)
    output = part_dir / f"{index:04d}_{safe}.csv"
    stdout_log = part_dir / f"{index:04d}_{safe}.stdout.log"
    stderr_log = part_dir / f"{index:04d}_{safe}.stderr.log"
    cmd = [
        args.host_ruby,
        "tools/poc/poc_extreme_campaign.rb",
        "--registry",
        str(args.registry),
        "--output",
        str(output),
        "--ruby",
        args.ruby,
        "--turns",
        str(args.turns),
        "--duration",
        str(args.duration),
        "--long-duration",
        str(args.long_duration),
        "--timeout-slack",
        str(args.timeout_slack),
        "--only",
        target,
    ]
    if args.exclude_confirmed:
        cmd.append("--exclude-confirmed")
    if args.no_long_followups:
        cmd.append("--no-long-followups")

    env = os.environ.copy()
    result = subprocess.run(cmd, cwd=args.repo_root, env=env, text=True, capture_output=True)
    stdout_log.write_text(result.stdout)
    stderr_log.write_text(result.stderr)
    return target, result.returncode


def merge_parts(part_dir: Path, output: Path) -> int:
    headers: list[str] | None = None
    rows: list[dict[str, str]] = []
    for path in sorted(part_dir.glob("*.csv")):
        with path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                continue
            if headers is None:
                headers = list(reader.fieldnames)
            elif headers != list(reader.fieldnames):
                raise RuntimeError(f"CSV header mismatch in {path}")
            rows.extend(reader)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        if headers is None:
            return 0
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ruby", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--host-ruby", default="ruby")
    parser.add_argument("--turns", type=int, default=5)
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--long-duration", type=int, default=600)
    parser.add_argument("--timeout-slack", type=int, default=15)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--only")
    parser.add_argument("--exclude-confirmed", action="store_true")
    parser.add_argument("--no-long-followups", action="store_true")
    args = parser.parse_args()

    args.registry = args.registry.resolve()
    args.output = args.output.resolve()
    args.repo_root = args.repo_root.resolve()
    only = set(item.strip() for item in args.only.split(",") if item.strip()) if args.only else None
    targets = read_targets(args.registry, not args.exclude_confirmed, only)
    if not targets:
        print("no runnable targets", file=sys.stderr)
        return 1

    part_dir = args.output.with_suffix(args.output.suffix + ".parts")
    part_dir.mkdir(parents=True, exist_ok=True)
    for old in part_dir.glob("*"):
        if old.is_file():
            old.unlink()

    print(f"running {len(targets)} targets with {args.workers} workers", flush=True)
    failures: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=max(args.workers, 1)) as pool:
        futures = {
            pool.submit(run_target, args, target, index, part_dir): target
            for index, target in enumerate(targets, start=1)
        }
        for future in as_completed(futures):
            target = futures[future]
            try:
                finished, code = future.result()
            except Exception as exc:  # pragma: no cover - operational wrapper
                print(f"ERROR {target}: {exc}", flush=True)
                failures.append((target, 1))
                continue
            status = "OK" if code == 0 else f"EXIT{code}"
            print(f"{status} {finished}", flush=True)
            if code != 0:
                failures.append((finished, code))

    row_count = merge_parts(part_dir, args.output)
    print(f"merged {row_count} rows into {args.output}", flush=True)
    if failures:
        for target, code in failures:
            print(f"failed target {target}: {code}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
