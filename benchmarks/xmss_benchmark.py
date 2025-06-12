import os
import time
import csv
import argparse
import tempfile
import subprocess


XMSS_SCRIPT = "..\\src\\xmss.py"
KEY_FILES = ["private_key.json", "public_key.json"]

SIZES = [
    1,
    1024,
    1024 ** 2,
    32 * 1024 ** 2,
    64 * 1024 ** 2,
    128 * 1024 ** 2,
    256 * 1024 ** 2,
    512 * 1024 ** 2,
    1024 ** 3,
]

HEIGHTS = [4, 6, 8, 10]  # умеренно, иначе дерево очень большое
WS = [4, 8, 16, 32]


def test_memory_vs_param(output_csv):
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        filepath = tmpfile.name
    generate_file(filepath, 1024 * 1024)  # 1 MB

    results = []
    for height in HEIGHTS:
        for w in WS:
            print(f"[MEMORY TEST] height={height}, w={w}")
            cleanup_keys()

            try:
                sign_cmd = [
                    "python", XMSS_SCRIPT,
                    "--action", "sign",
                    "--file", filepath,
                    "--height", str(height),
                    "--w", str(w)
                ]
                _, max_mem = measure_mem_and_time(sign_cmd)
                results.append([height, w, round(max_mem, 2)])
            finally:
                cleanup_keys()

    os.remove(filepath)
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Height", "W", "MaxMemoryMB"])
        writer.writerows(results)


def measure_mem_and_time(cmd):
    start = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = psutil.Process(proc.pid)
    max_rss = 0
    try:
        while proc.poll() is None:
            mem = p.memory_info().rss
            if mem > max_rss:
                max_rss = mem
            time.sleep(0.01)
        mem = p.memory_info().rss
        if mem > max_rss:
            max_rss = mem
    except psutil.NoSuchProcess:
        pass
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{stderr.decode()}")
    end = time.time()
    elapsed = end - start
    return elapsed, max_rss / (1024 * 1024)  # время, память в MB


def cleanup_keys():
    for f in KEY_FILES:
        if os.path.exists(f):
            os.remove(f)


def generate_file(path: str, size: int) -> None:
    """
    Generate a random binary file of given size.
    :param path: File path to write.
    :param size: Size in bytes.
    :return: None.
    """
    with open(path, "wb") as f:
        f.write(os.urandom(size))


def run_command(cmd: list) -> float:
    """
    Run a subprocess command and measure its execution time.
    :param cmd: List of command arguments.
    :return: Elapsed time in seconds.
    :raises RuntimeError: If the command fails.
    """
    start = time.time()
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    end = time.time()
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr.decode()}")
    return end - start


def test_time_vs_size(output_csv):
    results = []
    for size in SIZES:
        print(f"[SIZE TEST] File size: {size} bytes")
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            filepath = tmpfile.name
        sigpath = filepath + ".sig"
        generate_file(filepath, size)
        cleanup_keys()

        try:
            sign_cmd = [
                "python", XMSS_SCRIPT,
                "--action", "sign",
                "--file", filepath
            ]
            sign_time = run_command(sign_cmd)

            verify_cmd = [
                "python", XMSS_SCRIPT,
                "--action", "verify",
                "--file", filepath,
                "--sig", sigpath
            ]
            verify_time = run_command(verify_cmd)

            results.append([size, round(sign_time, 6), round(verify_time, 6)])
        finally:
            for f in [filepath, sigpath]:
                if os.path.exists(f):
                    os.remove(f)
            cleanup_keys()

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["FileSizeBytes", "SignTimeSeconds", "VerifyTimeSeconds"])
        writer.writerows(results)


def test_time_vs_param(output_csv):
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        filepath = tmpfile.name
    generate_file(filepath, 1024 * 1024)  # фиксированный 1 МБ

    results = []
    for height in HEIGHTS:
        for w in WS:
            print(f"[PARAM TEST] height={height}, w={w}")
            sigpath = filepath + ".sig"
            cleanup_keys()

            try:
                sign_cmd = [
                    "python", XMSS_SCRIPT,
                    "--action", "sign",
                    "--file", filepath,
                    "--height", str(height),
                    "--w", str(w)
                ]
                sign_time = run_command(sign_cmd)

                verify_cmd = [
                    "python", XMSS_SCRIPT,
                    "--action", "verify",
                    "--file", filepath,
                    "--sig", sigpath,
                    "--height", str(height),
                    "--w", str(w)
                ]
                verify_time = run_command(verify_cmd)

                results.append([height, w, round(sign_time, 6), round(verify_time, 6)])
            finally:
                if os.path.exists(sigpath):
                    os.remove(sigpath)
                cleanup_keys()

    os.remove(filepath)
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Height", "W", "SignTimeSeconds", "VerifyTimeSeconds"])
        writer.writerows(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark XMSS Signature")
    parser.add_argument("--time_vs_size", action="store_true", help="Benchmark vs file size")
    parser.add_argument("--time_vs_param", action="store_true", help="Benchmark vs height/w")
    parser.add_argument("--memory_vs_param", action="store_true", help="Benchmark memory usage vs height/w")
    args = parser.parse_args()

    if args.time_vs_size:
        test_time_vs_size("..\\results\\xmss_size_depend.csv")
    if args.time_vs_param:
        test_time_vs_param("..\\results\\xmss_param_depend.csv")
    if args.memory_vs_param:
        try:
            import psutil
        except ImportError:
            print("psutil не установлен! Установите через: pip install psutil")
            exit(1)

        test_memory_vs_param("..\\results\\xmss_memory_depend.csv")
