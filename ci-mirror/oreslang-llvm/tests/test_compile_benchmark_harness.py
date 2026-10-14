"""Self-tests for the compiler timing harness. No LLVM installation needed."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "benchmark_compile", ROOT / "scripts" / "benchmark_compile.py")
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class CompileBenchmarkHarnessTest(unittest.TestCase):
    def test_nearest_rank_small_samples(self):
        self.assertEqual(9, BENCH.percentile_nearest_rank([1, 3, 9], 95))
        self.assertEqual(3, BENCH.percentile_nearest_rank([9, 3, 1], 50))
        with self.assertRaises(ValueError):
            BENCH.percentile_nearest_rank([], 95)

    def test_success_reports_ir_digest_and_all_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "test.ores"
            source.write_text("fnc main(): int { return 1; }", encoding="utf-8")
            fake = directory / "fake.py"
            fake.write_text(
                "import pathlib,sys\n"
                "assert pathlib.Path(sys.argv[1]).read_text().startswith('fnc')\n"
                "print('; verified IR fixture')\n", encoding="utf-8")
            result = BENCH.measure(
                Path(sys.executable), [str(fake)], source, 1, 3, 5)
            self.assertEqual(3, len(result["samples_ms"]))
            self.assertEqual(64, len(result["ir_sha256"]))
            self.assertGreaterEqual(result["p95_ms"], result["median_ms"])

    def test_rejects_nondeterminism_failures_and_invalid_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "test.ores"
            source.write_text("ok", encoding="utf-8")
            changing = directory / "changing.py"
            changing.write_text(
                "import os\nprint(os.getpid())\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "non-deterministic"):
                BENCH.measure(Path(sys.executable), [str(changing)], source, 0, 3, 5)

            failing = directory / "failing.py"
            failing.write_text("raise SystemExit(3)\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "exit 3"):
                BENCH.measure(Path(sys.executable), [str(failing)], source, 0, 1, 5)

            with self.assertRaises(ValueError):
                BENCH.measure(Path(sys.executable), [], source, 0, 0, 5)


if __name__ == "__main__":
    unittest.main()
