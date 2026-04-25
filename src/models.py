from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import math
import json
import os



def load_config(config_path: str = None) -> Dict:
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), '..', 'conf.json')
    config_path = os.path.abspath(config_path)

    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    return DEFAULT_CONFIG.copy()


@dataclass
class Vulnerability:
    severity: str
    test_id: str
    filename: str
    line: int
    issue_text: str


@dataclass
class CrashInfo:
    exception_type: str
    count: int = 0


@dataclass
class CodeMetrics:
    total_lines: int = 0
    code_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0


@dataclass
class BanditResult:
    high: int = 0
    medium: int = 0
    low: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class CodeQLResult:
    high: int = 0
    medium: int = 0
    low: int = 0
    warnings: int = 0
    errors: List[str] = field(default_factory=list)


@dataclass
class AtherisResult:
    total_runs: int = 0
    total_crashes: int = 0
    unique_crashes: int = 0
    crash_types: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class RadonResult:
    complexity: int = 0
    raw_metrics: Dict[str, int] = field(default_factory=dict)
    maintainability_index: float = 0.0
    halstead_volume: float = 0.0


@dataclass
class VulnerabilityDensity:
    severity_weights: Dict[str, float] = field(default_factory=lambda: DEFAULT_CONFIG['severity_weights'])

    def compute_density(self, counts: Dict[str, int], logical_lines: int) -> float:
        if logical_lines <= 0:
            return 0.0
        total = 0.0
        for severity, count in counts.items():
            weight = self.severity_weights.get(severity, 1.0)
            total += weight * count
        return total / math.sqrt(logical_lines)


@dataclass
class EnergyMetrics:
    alpha: float = 0.5
    epsilon: float = 1e-6
    b_small: float = 0.0
    b_large: float = 1000000.0

    static_density: float = 0.0
    dynamic_density: float = 0.0

    E0_static: float = 0.0
    E0_dynamic: float = 0.0
    E0_total: float = 0.0

    Einf_static: float = 0.0
    Einf_dynamic: float = 0.0
    Einf_total: float = 0.0

    kl_divergence: float = 0.0
    total_variation: float = 0.0

    code_metrics: Optional[CodeMetrics] = None

    def compute_energies(self, static_counts: Dict[str, int], dynamic_counts: Dict[str, int], logical_lines: int):
        if logical_lines <= 0:
            return

        vd = VulnerabilityDensity()

        self.static_density = vd.compute_density(static_counts, logical_lines)
        self.dynamic_density = vd.compute_density(dynamic_counts, logical_lines)

        self.E0_static = self._log_sum_exp([self.static_density], self.b_small) / self.b_small if self.b_small > 0 else self.static_density
        self.E0_dynamic = self._log_sum_exp([self.dynamic_density], self.b_small) / self.b_small if self.b_small > 0 else self.dynamic_density
        self.E0_total = self.alpha * self.E0_static + (1 - self.alpha) * self.E0_dynamic

        self.Einf_static = self._log_sum_exp([self.static_density], self.b_large) / self.b_large if self.b_large > 0 else self.static_density
        self.Einf_dynamic = self._log_sum_exp([self.dynamic_density], self.b_large) / self.b_large if self.b_large > 0 else self.dynamic_density
        self.Einf_total = self.alpha * self.Einf_static + (1 - self.alpha) * self.Einf_dynamic

        self._compute_total_variation(static_counts, dynamic_counts, logical_lines)

    def _log_sum_exp(self, values: List[float], b: float) -> float:
        if not values:
            return 0.0
        if b < 1e-4:
            return sum(values)
        if b > 1e6:
            return max(values)
        max_val = max(values)
        return max_val + (1.0 / b) * math.log(sum(math.exp(b * (v - max_val)) for v in values))

    def _compute_total_variation(self, static_counts: Dict[str, int], dynamic_counts: Dict[str, int], logical_lines: int):
        vd = VulnerabilityDensity()

        p_values = []
        q_values = []
        all_keys = set(static_counts.keys()) | set(dynamic_counts.keys())

        for key in all_keys:
            p_i = vd.severity_weights.get(key, 1.0) * static_counts.get(key, 0) / math.sqrt(logical_lines) if logical_lines > 0 else 0
            q_i = vd.severity_weights.get(key, 1.0) * dynamic_counts.get(key, 0) / math.sqrt(logical_lines) if logical_lines > 0 else 0
            p_values.append(p_i)
            q_values.append(q_i)

        sum_p = sum(p_values)
        sum_q = sum(q_values)

        if sum_p <= 0 or sum_q <= 0:
            self.total_variation = 0.0
            return

        p_normalized = [p / sum_p for p in p_values]
        q_normalized = [q / sum_q for q in q_values]

        tv = 0.5 * sum(abs(p - q) for p, q in zip(p_normalized, q_normalized))
        self.total_variation = tv


@dataclass
class PairedSampleResult:
    sample_id: str
    original_path: str
    modified_path: str

    original_metrics: Optional[EnergyMetrics] = None
    modified_metrics: Optional[EnergyMetrics] = None

    delta_E0: float = 0.0
    delta_Einf: float = 0.0
    total_variation: float = 0.0

    def compute_delta(self):
        if self.original_metrics and self.modified_metrics:
            self.delta_E0 = self.modified_metrics.E0_total - self.original_metrics.E0_total
            self.delta_Einf = self.modified_metrics.Einf_total - self.original_metrics.Einf_total
            self.total_variation = self.original_metrics.total_variation


@dataclass
class BatchEvaluationResult:
    timestamp: str
    folder_name: str
    total_samples: int = 0

    mean_delta_E0: float = 0.0
    mean_delta_Einf: float = 0.0

    mu_tv: float = 0.0
    sigma_tv: float = 0.0

    R_infinity: float = 0.0
    R_0: float = 0.0
    R_complete: float = 0.0

    results: List[PairedSampleResult] = field(default_factory=list)

    def compute_batch_metrics(self, epsilon_complete: float = 1e-6):
        if not self.results:
            return

        delta_E0_list = [r.delta_E0 for r in self.results]
        delta_Einf_list = [r.delta_Einf for r in self.results]
        tv_list = [r.total_variation for r in self.results]

        self.mean_delta_E0 = sum(delta_E0_list) / len(delta_E0_list)
        self.mean_delta_Einf = sum(delta_Einf_list) / len(delta_Einf_list)

        self.mu_tv = sum(tv_list) / len(tv_list) if tv_list else 0.0

        variance_tv = sum((t - self.mu_tv) ** 2 for t in tv_list) / len(tv_list) if tv_list else 0.0
        self.sigma_tv = math.sqrt(variance_tv)

        self.R_infinity = sum(1 for d in delta_Einf_list if d < 0) / len(delta_Einf_list)
        self.R_0 = sum(1 for d in delta_E0_list if d < 0) / len(delta_E0_list)

        self.R_complete = sum(
            1 for r in self.results
            if r.modified_metrics and (r.modified_metrics.Einf_total + r.modified_metrics.E0_total <= epsilon_complete)
        ) / len(self.results)


@dataclass
class FileTestResult:
    file_id: str
    file_path: str
    code_metrics: CodeMetrics = field(default_factory=CodeMetrics)
    bandit: Optional[BanditResult] = None
    codeql: Optional[CodeQLResult] = None
    atheris: Optional[AtherisResult] = None
    radon: Optional[RadonResult] = None

    @property
    def high_vulnerabilities(self) -> int:
        high = 0
        if self.bandit:
            high += self.bandit.high
        if self.codeql:
            high += self.codeql.high
        return high

    @property
    def medium_vulnerabilities(self) -> int:
        med = 0
        if self.bandit:
            med += self.bandit.medium
        if self.codeql:
            med += self.codeql.warnings
        return med

    @property
    def total_runtime_crashes(self) -> int:
        if self.atheris:
            return self.atheris.unique_crashes
        return 0

    @property
    def crash_types_summary(self) -> Dict[str, int]:
        if self.atheris:
            return dict(self.atheris.crash_types)
        return {}


@dataclass
class BatchTestResult:
    timestamp: str
    base_path: str
    atheris_time: int
    total_files: int = 0
    total_high_vulns: int = 0
    total_crashes: int = 0
    results: List[FileTestResult] = field(default_factory=list)

    def add_result(self, result: FileTestResult):
        self.results.append(result)
        self.total_high_vulns += result.high_vulnerabilities
        self.total_crashes += result.total_runtime_crashes
        self.total_files = len(self.results)