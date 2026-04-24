import os
import re

from .models import CodeMetrics


def count_lines(file_path):
    metrics = CodeMetrics()

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        metrics.total_lines = len(lines)

        for line in lines:
            stripped = line.strip()

            if not stripped:
                metrics.blank_lines += 1
            elif stripped.startswith('#') or stripped.startswith('"""') or stripped.startswith("'''"):
                comment_patterns = [
                    r'^"""',
                    r"^'''",
                    r'^#.*',
                ]
                if any(re.match(pattern, stripped) for pattern in comment_patterns):
                    metrics.comment_lines += 1
                else:
                    metrics.code_lines += 1
            else:
                metrics.code_lines += 1

    except Exception as e:
        pass

    return metrics


def get_file_info(file_path):
    file_id = os.path.basename(os.path.dirname(file_path))
    return {
        'id': file_id,
        'path': file_path,
        'name': os.path.basename(file_path)
    }


def find_all_original_files(base_path):
    files = []

    if not os.path.exists(base_path):
        return files

    for item in os.listdir(base_path):
        item_path = os.path.join(base_path, item)

        if os.path.isdir(item_path) and item.isdigit():
            original_path = os.path.join(item_path, 'code.py')
            if os.path.exists(original_path):
                files.append(get_file_info(original_path))

    files.sort(key=lambda x: int(x['id']))
    return files