from datetime import datetime

from .models import FileTestResult, BatchTestResult
from .logger import logger
from .bandit_analyzer import analyze as bandit_analyze
from .codeql_analyzer import analyze as codeql_analyze
from .atheris_fuzzer import fuzz as atheris_fuzz
from .radon_analyzer import analyze as radon_analyze
from .code_metrics import count_lines, get_file_info, find_all_original_files


class FuzzerOrchestrator:
    def __init__(self):
        self.logger = logger

    def test_single_file(self, target_path, atheris_time=10):
        file_info = get_file_info(target_path)

        self.logger.write(f"\n{'='*80}", console=False)
        self.logger.write(f"Testing file ID: {file_info['id']}", console=False)
        self.logger.write(f"Path: {target_path}", console=False)
        self.logger.write(f"{'='*80}", console=False)

        result = FileTestResult(
            file_id=file_info['id'],
            file_path=target_path
        )

        result.code_metrics = count_lines(target_path)
        self.logger.write(f"Lines: {result.code_metrics.total_lines} (code: {result.code_metrics.code_lines}, comment: {result.code_metrics.comment_lines}, blank: {result.code_metrics.blank_lines})", console=False)

        self.logger.write("\n[1/4] Running Bandit (shallow security)...", console=False)
        result.bandit = bandit_analyze(target_path)

        if result.bandit.high > 0:
            self.logger.write(f"  HIGH: {result.bandit.high}", console=False)
        if result.bandit.medium > 0:
            self.logger.write(f"  MEDIUM: {result.bandit.medium}", console=False)
        if result.bandit.low > 0:
            self.logger.write(f"  LOW: {result.bandit.low}", console=False)

        self.logger.write("\n[2/4] Running CodeQL (deep security)...", console=False)
        result.codeql = codeql_analyze(target_path)

        if result.codeql.errors:
            self.logger.write(f"  CodeQL error: {result.codeql.errors[0][:50]}", console=False)
        else:
            self.logger.write(f"  HIGH: {result.codeql.high}, WARNING: {result.codeql.warnings}, NOTE: {result.codeql.low}", console=False)

        self.logger.write("\n[3/4] Running Radon (complexity/attack surface)...", console=False)
        result.radon = radon_analyze(target_path)

        if result.radon:
            self.logger.write(f"  Complexity: {result.radon.complexity}", console=False)
            self.logger.write(f"  Maintainability: {result.radon.maintainability_index:.2f}", console=False)
            self.logger.write(f"  Halstead Volume: {result.radon.halstead_volume:.2f}", console=False)

        self.logger.write("\n[4/4] Running Atheris fuzzing (dynamic)...", console=False)
        result.atheris = atheris_fuzz(target_path, time_limit=atheris_time)

        if result.atheris.error:
            self.logger.write(f"  Atheris error: {result.atheris.error}", console=False)
        else:
            self.logger.write(f"  Total runs: {result.atheris.total_runs:,}", console=False)
            self.logger.write(f"  Unique crashes: {result.atheris.unique_crashes}", console=False)
            if result.atheris.crash_types:
                self.logger.write(f"  Crash types: {result.atheris.crash_types}", console=False)

        self.logger.write(f"\nCompleted {file_info['id']} - HIGH vulns: {result.high_vulnerabilities}, Runtime crashes: {result.total_runtime_crashes}", console=False)

        return result

    def batch_test(self, base_path, atheris_time=10, limit=None):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = f"fuzz_batch_summary_{timestamp}.log"

        self.logger.write("=" * 80, console=False)
        self.logger.write("BATCH TEST REPORT", console=False)
        self.logger.write("=" * 80, console=False)
        self.logger.write(f"Start Time: {datetime.now().isoformat()}", console=False)
        self.logger.write(f"Scan Path: {base_path}", console=False)
        self.logger.write(f"Atheris Time Limit: {atheris_time}s", console=False)
        self.logger.write("=" * 80, console=False)

        files = find_all_original_files(base_path)
        if limit:
            files = files[:limit]

        self.logger.write(f"\nFound {len(files)} files to test\n", console=False)

        batch_result = BatchTestResult(
            timestamp=datetime.now().isoformat(),
            base_path=base_path,
            atheris_time=atheris_time
        )

        for i, file_info in enumerate(files, 1):
            self.logger.write(f"\n[{i}/{len(files)}] {'='*60}", console=False)

            try:
                result = self.test_single_file(file_info['path'], atheris_time)
                batch_result.add_result(result)
            except Exception as e:
                self.logger.write(f"FAILED: {str(e)}", console=False)

        self._print_batch_summary(batch_result, summary_file)

        return batch_result

    def _print_batch_summary(self, batch_result, summary_file):
        self.logger.write("\n" + "=" * 80, console=False)
        self.logger.write("BATCH SUMMARY", console=False)
        self.logger.write("=" * 80, console=False)
        self.logger.write(f"Total files: {batch_result.total_files}", console=False)
        self.logger.write(f"Total HIGH vulns (Bandit+CodeQL): {batch_result.total_high_vulns}", console=False)
        self.logger.write(f"Total runtime crashes (Atheris): {batch_result.total_crashes}", console=False)
        self.logger.write("=" * 80, console=False)

        self.logger.write("\n" + "=" * 80, console=False)
        self.logger.write("DETAILED RESULTS", console=False)
        self.logger.write("=" * 80, console=False)
        self.logger.write(f"{'ID':<8} {'Lines':<8} {'B-HIGH':<8} {'B-MED':<8} {'B-LOW':<8} {'Q-HIGH':<8} {'Q-WARN':<8} {'Q-NOTE':<8} {'CC':<8} {'MI':<8} {'Crashes'}", console=False)
        self.logger.write("-" * 100, console=False)

        for result in batch_result.results:
            b_high = result.bandit.high if result.bandit else 0
            b_med = result.bandit.medium if result.bandit else 0
            b_low = result.bandit.low if result.bandit else 0
            q_high = result.codeql.high if result.codeql else 0
            q_warn = result.codeql.warnings if result.codeql else 0
            q_note = result.codeql.low if result.codeql else 0
            cc = result.radon.complexity if result.radon else 0
            mi = f"{result.radon.maintainability_index:.1f}" if result.radon and result.radon.maintainability_index > 0 else "N/A"
            crashes = result.total_runtime_crashes

            self.logger.write(
                f"{result.file_id:<8} {result.code_metrics.total_lines:<8} "
                f"{b_high:<8} {b_med:<8} {b_low:<8} "
                f"{q_high:<8} {q_warn:<8} {q_note:<8} "
                f"{cc:<8} {mi:<8} {crashes}",
                console=False
            )

        self.logger.write("=" * 100, console=False)
        self.logger.write(f"End Time: {datetime.now().isoformat()}", console=False)

        self._write_summary_file(batch_result, summary_file)

        print(f"\n{'='*80}")
        print(f"Batch testing completed!")
        print(f"Total files: {batch_result.total_files}")
        print(f"Total HIGH vulns: {batch_result.total_high_vulns}")
        print(f"Total runtime crashes: {batch_result.total_crashes}")
        print(f"Summary log: {summary_file}")
        print(f"{'='*80}")

    def _write_summary_file(self, batch_result, summary_file):
        content = []
        content.append("=" * 100)
        content.append("BATCH TEST SUMMARY REPORT")
        content.append("=" * 100)
        content.append(f"Scan Path: {batch_result.base_path}")
        content.append(f"Test Time: {batch_result.timestamp}")
        content.append(f"Atheris Time Limit: {batch_result.atheris_time}s")
        content.append("=" * 100)
        content.append("")
        content.append("Tool Categories:")
        content.append("  - Bandit: Shallow security analysis")
        content.append("  - CodeQL: Deep security analysis")
        content.append("  - Radon: Complexity/Attack Surface (CC=Cyclomatic Complexity, MI=Maintainability Index)")
        content.append("  - Atheris: Dynamic fuzzing (runtime crashes)")
        content.append("")
        content.append(f"Total files: {batch_result.total_files}")
        content.append(f"Total HIGH vulns: {batch_result.total_high_vulns}")
        content.append(f"Total runtime crashes: {batch_result.total_crashes}")
        content.append("")
        content.append("Detailed Results:")
        content.append("-" * 100)
        content.append(f"{'ID':<8} {'Lines':<8} {'B-HIGH':<8} {'B-MED':<8} {'B-LOW':<8} {'Q-HIGH':<8} {'Q-WARN':<8} {'Q-NOTE':<8} {'CC':<8} {'MI':<8} {'Crashes'}")
        content.append("-" * 100)

        for result in batch_result.results:
            b_high = result.bandit.high if result.bandit else 0
            b_med = result.bandit.medium if result.bandit else 0
            b_low = result.bandit.low if result.bandit else 0
            q_high = result.codeql.high if result.codeql else 0
            q_warn = result.codeql.warnings if result.codeql else 0
            q_note = result.codeql.low if result.codeql else 0
            cc = result.radon.complexity if result.radon else 0
            mi = f"{result.radon.maintainability_index:.1f}" if result.radon and result.radon.maintainability_index > 0 else "N/A"
            crashes = result.total_runtime_crashes

            content.append(
                f"{result.file_id:<8} {result.code_metrics.total_lines:<8} "
                f"{b_high:<8} {b_med:<8} {b_low:<8} "
                f"{q_high:<8} {q_warn:<8} {q_note:<8} "
                f"{cc:<8} {mi:<8} {crashes}"
            )

        content.append("=" * 100)

        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(content))


orchestrator = FuzzerOrchestrator()