import subprocess
import json
import os
from datetime import datetime

from .models import CodeQLResult


def analyze(target_path):
    result = CodeQLResult()

    target_dir = os.path.dirname(os.path.abspath(target_path))
    db_name = f"codeql_db_{os.path.basename(target_path).replace('.py', '')}_{datetime.now().strftime('%H%M%S')}"

    try:
        create_cmd = [
            'codeql', 'database', 'create',
            '--language=python',
            '--source-root=' + target_dir,
            db_name
        ]
        create_proc = subprocess.run(create_cmd, capture_output=True, text=True, timeout=120)

        if create_proc.returncode != 0:
            result.errors.append(f"Database creation failed: {create_proc.stderr[:200]}")
            return result

        analyze_cmd = [
            'codeql', 'database', 'analyze',
            db_name,
            'security-and-quality',
            '--format=sarif-latest',
            '--output=temp_codeql_results.sarif',
            '-v'
        ]
        analyze_proc = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=300)

        if os.path.exists('temp_codeql_results.sarif'):
            with open('temp_codeql_results.sarif', 'r') as f:
                sarif_data = json.load(f)

            if 'runs' in sarif_data and len(sarif_data['runs']) > 0:
                results = sarif_data['runs'][0].get('results', [])
                for r in results:
                    level = r.get('level', '')
                    rule_id = r.get('ruleId', 'unknown')
                    if level == 'error':
                        result.high += 1
                    elif level == 'warning':
                        result.warnings += 1
                    elif level == 'note':
                        result.low += 1

                    if rule_id and rule_id != 'unknown':
                        if level == 'error':
                            vuln_type = f"HIGH_{rule_id}"
                        elif level == 'warning':
                            vuln_type = f"WARNING_{rule_id}"
                        else:
                            vuln_type = f"NOTE_{rule_id}"
                        result.vulnerability_types[vuln_type] = result.vulnerability_types.get(vuln_type, 0) + 1

            os.remove('temp_codeql_results.sarif')

        subprocess.run(['rm', '-rf', db_name], timeout=10, capture_output=True)

    except Exception as e:
        result.errors.append(str(e)[:200])

        try:
            subprocess.run(['rm', '-rf', db_name], timeout=10, capture_output=True)
        except:
            pass

    return result