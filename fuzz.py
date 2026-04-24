import sys
import os

from src import EvaluationEngine, ReportGenerator, logger


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python fuzz.py <folder_name> [limit]")
        print("  Example: python fuzz.py add 100")
        sys.exit(1)

    folder_name = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 100

    base_path = os.path.join('./dataset', folder_name)

    if not os.path.exists(base_path):
        print(f"Folder does not exist: {base_path}")
        sys.exit(1)

    logger.setup()

    engine = EvaluationEngine()
    reporter = ReportGenerator()

    print(f"[*] Evaluating folder: {folder_name}")
    print(f"[*] Processing up to {limit} samples...")

    result = engine.evaluate_batch(base_path, limit=limit)

    log_file = reporter.generate_report(result)
    reporter.print_summary(result)

    print(f"\n[*] Detailed report saved to: {log_file}")


if __name__ == "__main__":
    main()