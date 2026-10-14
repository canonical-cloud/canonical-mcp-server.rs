#!/usr/bin/env python3
"""Bounded, repeatable wall-time benchmark for the existing LLVM frontend.

Each sample launches a fresh compiler process: this is NOT an incremental
compilation benchmark, nor evidence of native multi-module support.
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
import tempfile
import time


MAX_SAMPLES = 1000
MAX_WARMUPS = 100
DEFAULT_OUTPUT_LIMIT = 64 * 1024 * 1024
MAX_OUTPUT_LIMIT = 512 * 1024 * 1024


def child_file_size_limit(max_output_bytes):
    """Apply a kernel file-size quota for compiler stdout/stderr on POSIX.

    subprocess stdout/stderr use distinct temporary regular files. A compiler
    must not write arbitrarily much output before the parent inspects it.
    This standalone benchmark is intentionally single-threaded; preexec_fn
    must never be transplanted into a multi-threaded build service.
    """
    if os.name != "posix":
        return None
    import resource

    def apply_limit():
        _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        limit = max_output_bytes if hard == resource.RLIM_INFINITY else min(hard, max_output_bytes)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, hard))

    return apply_limit


def percentile_nearest_rank(values, percentile):
    if not values or not 0 < percentile <= 100:
        raise ValueError("nonempty samples and 0 < percentile <= 100 required")
    values = sorted(values)
    return values[math.ceil(len(values) * percentile / 100) - 1]


def digest_file(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def measure(compiler, arguments, source, warmups, samples, timeout,
            max_output_bytes=DEFAULT_OUTPUT_LIMIT):
    if (not isinstance(warmups, int) or not isinstance(samples, int)
            or not 0 <= warmups <= MAX_WARMUPS
            or not 1 <= samples <= MAX_SAMPLES
            or not math.isfinite(timeout) or timeout <= 0
            or not isinstance(max_output_bytes, int)
            or not 1 <= max_output_bytes <= MAX_OUTPUT_LIMIT):
        raise ValueError("invalid sample, timeout or output budget")
    # Resolve paths before launching child processes. A relative source path
    # must not accidentally be reinterpreted by a child in another directory.
    compiler = Path(compiler).resolve(strict=True)
    source = Path(source).resolve(strict=True)
    source_digest = digest_file(source)
    compiler_digest = digest_file(compiler)
    times_ms = []
    expected_digest = None
    expected_size = None
    command = [str(compiler), *arguments, str(source)]

    for index in range(warmups + samples):
        # Verify tracked inputs *before and after every sample*. The timing
        # intentionally excludes hashing and report I/O.
        if digest_file(source) != source_digest or digest_file(compiler) != compiler_digest:
            raise RuntimeError("benchmark inputs changed before sample")
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            started = time.perf_counter_ns()
            try:
                completed = subprocess.run(
                    command, stdin=subprocess.DEVNULL, stdout=output,
                    stderr=errors, timeout=timeout, check=False,
                    preexec_fn=child_file_size_limit(max_output_bytes))
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"LLVM compiler timed out after {timeout}s") from exc
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            if digest_file(source) != source_digest or digest_file(compiler) != compiler_digest:
                raise RuntimeError("benchmark inputs changed during sample")
            output_size = output.seek(0, os.SEEK_END)
            error_size = errors.seek(0, os.SEEK_END)
            if output_size >= max_output_bytes or error_size >= max_output_bytes:
                raise RuntimeError("compiler output exceeded output budget")
            if completed.returncode != 0:
                if (os.name == "posix"
                        and completed.returncode == -getattr(__import__("signal"), "SIGXFSZ", 25)):
                    raise RuntimeError("compiler output exceeded output budget")
                errors.seek(0)
                snippet = errors.read(2000).decode("utf-8", errors="replace")
                raise RuntimeError(f"LLVM compiler exit {completed.returncode}: {snippet}")
            if output_size == 0:
                raise RuntimeError("LLVM compiler emitted no IR")
            output.seek(0)
            hasher = hashlib.sha256()
            for block in iter(lambda: output.read(1024 * 1024), b""):
                hasher.update(block)
            digest = hasher.hexdigest()
            if expected_digest is None:
                expected_digest, expected_size = digest, output_size
            elif digest != expected_digest or output_size != expected_size:
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
        "ir_bytes": expected_size,
        "source_sha256": source_digest,
        "compiler_sha256": compiler_digest,
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
    parser.add_argument("--max-output-bytes", type=int, default=DEFAULT_OUTPUT_LIMIT)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    if not args.source.is_file():
        parser.error("source file does not exist")
    if not args.compiler.is_file() or not os.access(args.compiler, os.X_OK):
        parser.error("compiler must be an executable file")
    try:
        stats = measure(args.compiler, args.compiler_arg, args.source,
                        args.warmups, args.samples, args.timeout, args.max_output_bytes)
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, f"benchmark error: {exc}\n")

    report = {
        "schema": "oreslang-llvm-compile-benchmark.v2",
        "mode": "fresh-subprocess-source-to-verified-ir",
        "source": str(args.source.resolve()),
        "compiler": str(args.compiler.resolve()),
        "compiler_arguments": args.compiler_arg,
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "warmups": args.warmups,
        "samples": args.samples,
        "max_output_bytes": args.max_output_bytes,
        **stats,
    }
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.write_text(payload, encoding="utf-8")
    sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
