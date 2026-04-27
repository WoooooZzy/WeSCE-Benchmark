import subprocess
import json
import os

from .models import BanditResult, Vulnerability


def analyze(target_path):
    result = BanditResult()

    try:
        cmd = ['bandit', '-r', target_path, '-f', 'json']
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if proc.stdout:
            output = json.loads(proc.stdout)
            results = output.get('results', [])

            for issue in results:
                vuln = Vulnerability(
                    severity=issue.get('issue_severity', 'UNKNOWN'),
                    test_id=issue.get('test_id', ''),
                    filename=os.path.basename(issue.get('filename', '')),
                    line=issue.get('line', 0),
                    issue_text=issue.get('issue_text', '')[:100]
                )
                result.vulnerabilities.append(vuln)

                if issue.get('issue_severity') == 'HIGH':
                    result.high += 1
                elif issue.get('issue_severity') == 'MEDIUM':
                    result.medium += 1
                elif issue.get('issue_severity') == 'LOW':
                    result.low += 1

                test_id = issue.get('test_id', 'unknown')
                if test_id and test_id != 'unknown':
                    severity = issue.get('issue_severity', 'UNKNOWN')
                    vuln_type = f"{severity}_{test_id}"
                    result.vulnerability_types[vuln_type] = result.vulnerability_types.get(vuln_type, 0) + 1

    except Exception as e:
        pass

    return result