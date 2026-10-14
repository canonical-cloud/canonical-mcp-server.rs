#!/usr/bin/env python3
"""Repeatable, non-gating wall-time benchmark for the existing LLVM frontend.

Measures fresh compiler processes on the same source. This is NOT an
incremental-compilation benchmark: the LLVM frontend does not yet implement
module interfaces or an incremental object cache.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time


def percentile_nearest_rank(values, percentile):
    if not values:
        raise ValueError("empty sample")
    values = sorted(values)
    return values[math.ceil(len(values) * percentile / 100) - 1]


def measure(compiler, arguments, source, warmups, samples, timeout):
    if warmups < 0 or samples < 1 or timeout <= 0:
        raise ValueError("warmups >= 0, samples >= 1 and timeout > 0 are required")
    times_ms = []
    expected_digest = None
    command = [str(compiler), *arguments, str(source)]
    for index in range(warmups + samples):
        started = time.perf_counter_ns()
        try:
            completed = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"LLVM compiler timed out after {timeout}s") from exc
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        if completed.returncode != 0:
            snippet = completed.stderr.decode("utf-8", errors="replace")[:2000]
            raise RuntimeError(f"LLVM compiler exit {completed.returncode}: {snippet}")
        if not completed.stdout:
            raise RuntimeError("LLVM compiler emitted no IR")
        digest = hashlib.sha256(completed.stdout).hexdigest()
        if expected_digest is None:
            expected_digest = digest
        elif digest != expected_digest:
            raise RuntimeError("non-deterministic IR output across identical invocations")
        if index >= warmups:
            times_ms.append(elapsed_ms)
    return {
        "median_ms": statistics.median(times_ms),
        "p95_ms": percentile_nearest_rank(times_ms, 95),
        "min_ms": min(times_ms),
        "max_ms": max(times_ms),
        "samples_ms": times_ms,
        "ir_sha256": expected_digest,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True, type=Path)
    parser.add_argument("--compiler-arg", action="append", default=[],
                        help="repeatable compiler argument, placed before the source")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    if not args.source.is_file():
        parser.error("source file does not exist")
    if not args.compiler.is_file() or not os.access(args.compiler, os.X_OK):
        parser.error("compiler must be an executable file")
    try:
        stats = measure(args.compiler, args.compiler_arg, args.source,
                        args.warmups, args.samples, args.timeout)
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, f"benchmark error: {exc}\n")

    report = {
        "schema": "oreslang-llvm-compile-benchmark.v1",
        "mode": "fresh-subprocess-source-to-verified-ir",
        "source": str(args.source.resolve()),
        "source_sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(),
        "compiler": str(args.compiler.resolve()),
        "compiler_arguments": args.compiler_arg,
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "warmups": args.warmups,
        "samples": args.samples,
        **stats,
    }
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(payload, encoding="utf-8")
    sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
