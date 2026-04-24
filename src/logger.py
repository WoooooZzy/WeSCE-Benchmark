import os
from datetime import datetime


class Logger:
    def __init__(self):
        self.log_file = None
        self.summary_file = None

    def setup(self, target_path=None):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if target_path:
            target_name = os.path.basename(target_path).replace('.py', '')
            self.log_file = f"fuzz_{target_name}_{timestamp}.log"
        else:
            self.log_file = f"fuzz_batch_{timestamp}.log"

        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("FUZZING TEST REPORT\n")
            f.write("=" * 80 + "\n")
            if target_path:
                f.write(f"Target: {target_path}\n")
            f.write(f"Start Time: {datetime.now().isoformat()}\n")
            f.write(f"Log File: {self.log_file}\n")
            f.write("=" * 80 + "\n\n")

        print(f"[*] Log file: {self.log_file}")
        return self.log_file

    def write(self, message, console=True):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"

        if self.log_file:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")

        if console:
            print(message)

    def write_summary(self, content):
        if self.summary_file:
            with open(self.summary_file, 'w', encoding='utf-8') as f:
                f.write(content)


logger = Logger()