import os
from datetime import datetime

from .models import BatchEvaluationResult


class ReportGenerator:
    def __init__(self, log_dir: str = "."):
        self.log_dir = log_dir

    def generate_report(self, result: BatchEvaluationResult) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.log_dir, f"eval_{result.folder_name}_{timestamp}.log")

        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY ASSESSMENT REPORT")
        lines.append("=" * 80)
        lines.append(f"Folder: {result.folder_name}")
        lines.append(f"Timestamp: {result.timestamp}")
        lines.append(f"Total Samples: {result.total_samples}")
        lines.append("=" * 80)
        lines.append("")

        lines.append("-" * 80)
        lines.append("BATCH-LEVEL METRICS (LLM-level evaluation)")
        lines.append("-" * 80)
        lines.append(f"Mean Delta E0:  {result.mean_delta_E0:.6f}")
        lines.append(f"Mean Delta Einf: {result.mean_delta_Einf:.6f}")
        lines.append(f"Mu KL:           {result.mu_kl:.6f}")
        lines.append(f"Sigma KL:        {result.sigma_kl:.6f}")
        lines.append(f"R_infinity:      {result.R_infinity:.4f}")
        lines.append(f"R_0:             {result.R_0:.4f}")
        lines.append(f"R_complete:       {result.R_complete:.4f}")
        lines.append("")

        lines.append("-" * 80)
        lines.append("SAMPLE-LEVEL RESULTS")
        lines.append("-" * 80)
        lines.append(f"{'ID':<8} {'L_orig':<10} {'L_mod':<10} {'E0_orig':<12} {'E0_mod':<12} {'dE0':<12} {'dEinf':<12} {'KL':<10}")
        lines.append("-" * 80)

        for r in result.results:
            L_orig = r.original_metrics.code_metrics.code_lines if r.original_metrics else 0
            L_mod = r.modified_metrics.code_metrics.code_lines if r.modified_metrics else 0
            E0_orig = r.original_metrics.E0_total if r.original_metrics else 0
            E0_mod = r.modified_metrics.E0_total if r.modified_metrics else 0

            lines.append(
                f"{r.sample_id:<8} "
                f"{L_orig:<10} "
                f"{L_mod:<10} "
                f"{E0_orig:<12.6f} "
                f"{E0_mod:<12.6f} "
                f"{r.delta_E0:<12.6f} "
                f"{r.delta_Einf:<12.6f} "
                f"{r.kl_divergence:<10.6f}"
            )

        lines.append("=" * 80)

        with open(log_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

        return log_file

    def print_summary(self, result: BatchEvaluationResult):
        print("=" * 80)
        print("VULNERABILITY ASSESSMENT SUMMARY")
        print("=" * 80)
        print(f"Folder: {result.folder_name}")
        print(f"Samples: {result.total_samples}")
        print("-" * 80)
        print(f"Mean Delta E0:  {result.mean_delta_E0:.6f}")
        print(f"Mean Delta Einf: {result.mean_delta_Einf:.6f}")
        print(f"Mu KL:          {result.mu_kl:.6f}")
        print(f"Sigma KL:       {result.sigma_kl:.6f}")
        print(f"R_infinity:     {result.R_infinity:.4f}")
        print(f"R_0:            {result.R_0:.4f}")
        print(f"R_complete:      {result.R_complete:.4f}")
        print("=" * 80)