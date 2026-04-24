import subprocess
import json

from .models import RadonResult


def analyze(target_path):
    result = RadonResult()

    result.complexity = get_cyclomatic_complexity(target_path)
    result.raw_metrics = get_raw_metrics(target_path)
    result.maintainability_index = get_maintainability_index(target_path)
    result.halstead_volume = get_halstead_volume(target_path)

    return result


def get_cyclomatic_complexity(target_path):
    try:
        cmd = ['radon', 'cc', '-a', '-j', target_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if proc.returncode == 0 and proc.stdout:
            data = json.loads(proc.stdout)
            total_cc = 0
            if isinstance(data, dict):
                for file_data in data.values():
                    if isinstance(file_data, list):
                        for item in file_data:
                            if isinstance(item, dict) and 'complexity' in item:
                                total_cc += item['complexity']
            return total_cc
    except Exception as e:
        pass
    return 0


def get_raw_metrics(target_path):
    metrics = {
        'loc': 0,
        'lloc': 0,
        'sloc': 0,
        'comments': 0,
        'single_comments': 0,
        'blank_lines': 0
    }

    try:
        cmd = ['radon', 'raw', '-j', target_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if proc.returncode == 0 and proc.stdout:
            data = json.loads(proc.stdout)
            if isinstance(data, list) and len(data) > 0:
                item = data[0]
                metrics['loc'] = item.get('loc', 0)
                metrics['lloc'] = item.get('lloc', 0)
                metrics['sloc'] = item.get('sloc', 0)
                metrics['comments'] = item.get('comments', 0)
                metrics['single_comments'] = item.get('single_comments', 0)
                metrics['blank_lines'] = item.get('blank', 0)
    except Exception as e:
        pass

    return metrics


def get_maintainability_index(target_path):
    try:
        cmd = ['radon', 'mi', '-j', target_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if proc.returncode == 0 and proc.stdout:
            data = json.loads(proc.stdout)
            if isinstance(data, dict):
                for file_data in data.values():
                    if isinstance(file_data, dict) and 'mi' in file_data:
                        return float(file_data['mi'])
    except Exception as e:
        pass
    return 0.0


def get_halstead_volume(target_path):
    try:
        cmd = ['radon', 'hal', '-j', target_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if proc.returncode == 0 and proc.stdout:
            data = json.loads(proc.stdout)
            if isinstance(data, list) and len(data) > 0:
                item = data[0]
                if isinstance(item, dict) and 'volume' in item:
                    return float(item['volume'])
    except Exception as e:
        pass
    return 0.0