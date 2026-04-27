from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import math
import json
import os


DEFAULT_CONFIG = {
    'severity_weights': {
        'HIGH': 10.0,
        'MEDIUM': 2.0,
        'LOW': 0.5,
        'WARNING': 2.5,
        'NOTE': 0.2
    },
    'alpha': 0.5,
    'b_small': 1e-3,
    'b_large': 1000,
    'epsilon_complete': 1e-3,
    'atheris_time': 10
}


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
    vulnerability_types: Dict[str, int] = field(default_factory=dict)


@dataclass
class CodeQLResult:
    high: int = 0
    medium: int = 0
    low: int = 0
    warnings: int = 0
    errors: List[str] = field(default_factory=list)
    vulnerability_types: Dict[str, int] = field(default_factory=dict)


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

    def _extract_severity(self, vuln_type: str) -> str:
        for sev in ['HIGH', 'MEDIUM', 'LOW', 'WARNING', 'NOTE']:
            if vuln_type.startswith(sev):
                return sev
        return 'UNKNOWN'

    def compute_density_vector(self, counts: Dict[str, int], logical_lines: int) -> Dict[str, float]:
        if logical_lines <= 0:
            return {}
        sqrt_L = math.sqrt(logical_lines)
        density_vec = {}
        for vuln_type, count in counts.items():
            severity = self._extract_severity(vuln_type)
            weight = self.severity_weights.get(severity, 1.0)
            density_vec[vuln_type] = weight * count / sqrt_L
        return density_vec

    def compute_total_density(self, density_vec: Dict[str, float]) -> float:
        return sum(density_vec.values()) if density_vec else 0.0


@dataclass
class EnergyMetrics:
    alpha: float = 0.5
    epsilon: float = 1e-6
    b_small: float = 0.0
    b_large: float = 1000000.0

    static_density_vec: Dict[str, float] = field(default_factory=dict)
    dynamic_density_vec: Dict[str, float] = field(default_factory=dict)

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

        self.static_density_vec = vd.compute_density_vector(static_counts, logical_lines)
        self.dynamic_density_vec = vd.compute_density_vector(dynamic_counts, logical_lines)

        static_density_values = list(self.static_density_vec.values())
        dynamic_density_values = list(self.dynamic_density_vec.values())

        self.E0_static = self._log_sum_exp(static_density_values, self.b_small)
        self.E0_dynamic = self._log_sum_exp(dynamic_density_values, self.b_small)
        self.E0_total = self.alpha * self.E0_static + (1 - self.alpha) * self.E0_dynamic

        self.Einf_static = self._log_sum_exp(static_density_values, self.b_large)
        self.Einf_dynamic = self._log_sum_exp(dynamic_density_values, self.b_large)
        self.Einf_total = self.alpha * self.Einf_static + (1 - self.alpha) * self.Einf_dynamic

    def _log_sum_exp(self, values: List[float], b: float) -> float:
        if not values:
            return 0.0
        if abs(b) < 1e-2:
            return sum(values)
        if abs(b) > 100:
            return max(values)
        max_val = max(values)
        return max_val + (1.0 / b) * math.log(sum(math.exp(b * (v - max_val)) for v in values))

    def _compute_density_dict(self, counts: Dict[str, int], logical_lines: int) -> Dict[str, float]:
        vd = VulnerabilityDensity()
        return vd.compute_density_vector(counts, logical_lines)


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
            self.total_variation = self._compute_tv_distance(
                self.original_metrics,
                self.modified_metrics
            )

    def _compute_tv_distance(self, orig: EnergyMetrics, mod: EnergyMetrics) -> float:
        orig_static = orig.static_density_vec
        orig_dynamic = orig.dynamic_density_vec
        mod_static = mod.static_density_vec
        mod_dynamic = mod.dynamic_density_vec

        all_keys = set(orig_static.keys()) | set(orig_dynamic.keys()) | set(mod_static.keys()) | set(mod_dynamic.keys())

        p_orig = []
        p_mod = []
        for key in all_keys:
            d_orig = orig_static.get(key, 0.0) + orig_dynamic.get(key, 0.0)
            d_mod = mod_static.get(key, 0.0) + mod_dynamic.get(key, 0.0)
            p_orig.append(d_orig)
            p_mod.append(d_mod)

        sum_orig = sum(p_orig)
        sum_mod = sum(p_mod)

        if sum_orig <= 0 or sum_mod <= 0:
            return 0.0

        p_orig_norm = [p / sum_orig for p in p_orig]
        p_mod_norm = [p / sum_mod for p in p_mod]

        tv = 0.5 * sum(abs(p - q) for p, q in zip(p_orig_norm, p_mod_norm))
        return tv


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