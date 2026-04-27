import os
from datetime import datetime
from typing import Dict, List, Optional

from .models import (
    EnergyMetrics,
    PairedSampleResult,
    BatchEvaluationResult,
    FileTestResult,
    load_config
)
from .bandit_analyzer import analyze as bandit_analyze
from .codeql_analyzer import analyze as codeql_analyze
from .atheris_fuzzer import fuzz as atheris_fuzz
from .radon_analyzer import analyze as radon_analyze
from .code_metrics import count_lines


class EvaluationEngine:
    def __init__(self, config_path: str = None):
        self.config = load_config(config_path)
        self.alpha = self.config.get('alpha', 0.5)
        self.atheris_time = self.config.get('atheris_time', 10)
        self.b_small = self.config.get('b_small', 0)
        self.b_large = self.config.get('b_large', 1000000)
        self.severity_weights = self.config.get('severity_weights', {
            'HIGH': 3.0, 'MEDIUM': 2.0, 'LOW': 1.0, 'WARNING': 2.5, 'NOTE': 0.5
        })

    def analyze_single_file(self, file_path: str) -> FileTestResult:
        file_id = os.path.basename(os.path.dirname(file_path))
        result = FileTestResult(file_id=file_id, file_path=file_path)

        result.code_metrics = count_lines(file_path)

        bandit_result = bandit_analyze(file_path)
        result.bandit = bandit_result

        codeql_result = codeql_analyze(file_path)
        result.codeql = codeql_result

        radon_result = radon_analyze(file_path)
        result.radon = radon_result

        atheris_result = atheris_fuzz(file_path, time_limit=self.atheris_time)
        result.atheris = atheris_result

        return result

    def compute_energy_metrics(self, test_result: FileTestResult) -> EnergyMetrics:
        metrics = EnergyMetrics(alpha=self.alpha, b_small=self.b_small, b_large=self.b_large)

        static_counts = {}
        if test_result.bandit:
            for vuln_type, count in test_result.bandit.vulnerability_types.items():
                static_counts[vuln_type] = count

        if test_result.codeql:
            for vuln_type, count in test_result.codeql.vulnerability_types.items():
                static_counts[vuln_type] = static_counts.get(vuln_type, 0) + count

        dynamic_counts = {}
        if test_result.atheris and not test_result.atheris.error:
            for crash_type, count in test_result.atheris.crash_types.items():
                dynamic_counts[crash_type] = count

        logical_lines = test_result.code_metrics.code_lines if test_result.code_metrics else 0

        metrics.compute_energies(static_counts, dynamic_counts, logical_lines)
        metrics.code_metrics = test_result.code_metrics

        return metrics

    def evaluate_pair(self, original_path: str, modified_path: str, sample_id: str) -> PairedSampleResult:
        result = PairedSampleResult(
            sample_id=sample_id,
            original_path=original_path,
            modified_path=modified_path
        )

        if os.path.exists(original_path):
            original_test = self.analyze_single_file(original_path)
            result.original_metrics = self.compute_energy_metrics(original_test)

        if os.path.exists(modified_path):
            modified_test = self.analyze_single_file(modified_path)
            result.modified_metrics = self.compute_energy_metrics(modified_test)

        result.compute_delta()

        return result

    def evaluate_batch(self, folder_path: str, limit: Optional[int] = None) -> BatchEvaluationResult:
        folder_name = os.path.basename(folder_path)
        batch_result = BatchEvaluationResult(
            timestamp=datetime.now().isoformat(),
            folder_name=folder_name
        )

        sample_dirs = []
        if os.path.exists(folder_path):
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isdir(item_path) and item.isdigit():
                    original_path = os.path.join(item_path, 'code.py')
                    modified_path = os.path.join(item_path, 'answer.py')
                    sample_dirs.append((item, original_path, modified_path))

        sample_dirs.sort(key=lambda x: int(x[0]))

        if limit:
            sample_dirs = sample_dirs[:limit]

        for sample_id, original_path, modified_path in sample_dirs:
            paired_result = self.evaluate_pair(original_path, modified_path, sample_id)
            batch_result.results.append(paired_result)

        batch_result.total_samples = len(batch_result.results)
        epsilon_complete = self.config.get('epsilon_complete', 1e-6)
        batch_result.compute_batch_metrics(epsilon_complete=epsilon_complete)

        return batch_result