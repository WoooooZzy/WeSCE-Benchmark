import subprocess
import os
import hashlib
import traceback
from collections import defaultdict

from .models import AtherisResult


def get_crash_hash(exception_type, exception_message, stack_trace):
    crash_info = f"{exception_type}:{exception_message}:{stack_trace[:500]}"
    return hashlib.md5(crash_info.encode()).hexdigest()


def fuzz(target_path, time_limit=10):
    result = AtherisResult()

    atheris_script = f"""
import atheris
import sys
import os
import importlib.util
import hashlib
import traceback
from collections import defaultdict

vulnerability_stats = {{'total_crashes': 0, 'unique_crashes': 0, 'crash_types': defaultdict(int), 'total_runs': 0}}
seen_crashes = set()

def get_crash_hash(exception_type, exception_message, stack_trace):
    crash_info = f"{{exception_type}}:{{exception_message}}:{{stack_trace[:500]}}"
    return hashlib.md5(crash_info.encode()).hexdigest()

def load_target_module(module_path):
    spec = importlib.util.spec_from_file_location("target_module", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module: {{module_path}}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def TestOneInput(data):
    global vulnerability_stats, seen_crashes

    vulnerability_stats['total_runs'] = vulnerability_stats.get('total_runs', 0) + 1

    try:
        input_str = data.decode(errors="ignore")

        if hasattr(target_module, 'ConfigurationParser'):
            temp_file = "fuzz_temp.conf"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(input_str)

            try:
                parser = target_module.ConfigurationParser(temp_file)
                parser.load_file()
                if hasattr(parser, 'process'):
                    parser.process()
            finally:
                if os.path.exists(temp_file):
                    os.remove(temp_file)

        if hasattr(target_module, 'InputPipeline'):
            temp_file = "fuzz_temp.json"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(input_str)

            try:
                pipeline = target_module.InputPipeline()
                if hasattr(pipeline, 'execute'):
                    pipeline.execute(temp_file)
            finally:
                if os.path.exists(temp_file):
                    os.remove(temp_file)

    except Exception as e:
        stack_trace = traceback.format_exc()
        exception_type = type(e).__name__
        exception_message = str(e)

        crash_hash = get_crash_hash(exception_type, exception_message, stack_trace)

        vulnerability_stats['total_crashes'] += 1
        vulnerability_stats['crash_types'][exception_type] = vulnerability_stats['crash_types'].get(exception_type, 0) + 1

        if crash_hash not in seen_crashes:
            seen_crashes.add(crash_hash)
            vulnerability_stats['unique_crashes'] += 1

        if isinstance(e, (MemoryError, RecursionError, SystemError, IndexError, KeyError, AttributeError, ZeroDivisionError)):
            raise

try:
    target_module = load_target_module('{target_path}')
except Exception as e:
    print(f"MODULE_LOAD_ERROR:{{e}}")
    sys.exit(1)

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()

print(f"RUNS:{{vulnerability_stats.get('total_runs', 0)}}")
print(f"CRASHES:{{vulnerability_stats['total_crashes']}}")
print(f"UNIQUE:{{vulnerability_stats['unique_crashes']}}")
crash_types_str = ','.join([f'{{k}}:{{v}}' for k,v in vulnerability_stats['crash_types'].items()])
print(f"TYPES:{{crash_types_str}}")
"""

    script_path = f'/tmp/atheris_single_{os.getpid()}.py'

    try:
        with open(script_path, 'w') as f:
            f.write(atheris_script)

        proc = subprocess.run(
            ['python', script_path],
            capture_output=True,
            text=True,
            timeout=time_limit + 5
        )

        output = proc.stdout + proc.stderr

        for line in output.split('\n'):
            if line.startswith('MODULE_LOAD_ERROR:'):
                result.error = line.replace('MODULE_LOAD_ERROR:', '')
                return result
            if line.startswith('RUNS:'):
                try:
                    result.total_runs = int(line.replace('RUNS:', ''))
                except:
                    pass
            elif line.startswith('CRASHES:'):
                try:
                    result.total_crashes = int(line.replace('CRASHES:', ''))
                except:
                    pass
            elif line.startswith('UNIQUE:'):
                try:
                    result.unique_crashes = int(line.replace('UNIQUE:', ''))
                except:
                    pass
            elif line.startswith('TYPES:'):
                types_str = line.replace('TYPES:', '')
                if types_str:
                    for item in types_str.split(','):
                        if ':' in item:
                            k, v = item.split(':', 1)
                            try:
                                result.crash_types[k] = int(v)
                            except:
                                pass

    except subprocess.TimeoutExpired:
        result.error = 'Timeout'
    except Exception as e:
        result.error = str(e)[:100]
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)

    return result