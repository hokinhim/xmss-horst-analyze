"""
Benchmarking and plotting tools for HORST signature scheme.
Provides time and memory measurements across file sizes and HORST parameters.
"""
import os
import csv
import time
import argparse
import tempfile
import subprocess


HORST_SCRIPT = "..\\src\\horst.py"

# Predefined test parameters
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
HEIGHTS = [10, 12, 14, 16]
KS = [8, 16, 32, 64, 128]


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


def measure_mem_and_time(cmd: list) -> tuple:
    """
    Run a command and measure both execution time and peak memory usage.
    :param cmd: Command and arguments.
    :return: Tuple of (elapsed_seconds, max_rss_mb).
    :raises RuntimeError: On command failure.
    """
    start = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = psutil.Process(proc.pid)
    max_rss = 0
    try:
        while proc.poll() is None:
            rss = p.memory_info().rss
            max_rss = max(max_rss, rss)
            time.sleep(0.01)
        rss = p.memory_info().rss
        max_rss = max(max_rss, rss)
    except psutil.NoSuchProcess:
        pass
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{stderr.decode()}")
    elapsed = time.time() - start
    return elapsed, max_rss / (1024 * 1024)


def test_time_vs_size(output_csv: str) -> None:
    """
    Benchmark signing and verifying time for varying file sizes.
    :param output_csv: CSV path to write results.
    :return: None.
    """
    results = []
    for size in SIZES:
        print(f"Testing file size: {size} bytes")
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            filepath = tmp.name
        bundlepath = f"{filepath}_signed.pkl"
        generate_file(filepath, size)
        try:
            sign_time = run_command(["python", HORST_SCRIPT, "sign", filepath, "--out", bundlepath])
            verify_time = run_command(["python", HORST_SCRIPT, "verify", filepath, bundlepath])
            results.append([size, round(sign_time, 6), round(verify_time, 6)])
        finally:
            os.remove(filepath)
            if os.path.exists(bundlepath):
                os.remove(bundlepath)
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["FileSizeBytes", "SignTimeSeconds", "VerifyTimeSeconds"])
        writer.writerows(results)


def test_time_vs_param(output_csv: str) -> None:
    """
    Benchmark signing and verifying time across HORST tree parameters (height, k).
    :param output_csv: CSV path to write results.
    :return: None.
    """
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        filepath = tmp.name
    generate_file(filepath, 1024 * 1024)  # 1 MB
    results = []
    for height in HEIGHTS:
        for k in KS:
            if k > (1 << height):
                continue
            print(f"Testing height={height}, k={k}")
            bundlepath = f"{filepath}_h{height}_k{k}.pkl"
            try:
                sign_time = run_command([
                    "python", HORST_SCRIPT, "sign", filepath,
                    "--height", str(height), "--k", str(k), "--out", bundlepath
                ])
                verify_time = run_command([
                    "python", HORST_SCRIPT, "verify", filepath, bundlepath,
                    "--height", str(height), "--k", str(k)
                ])
                results.append([height, k, round(sign_time, 6), round(verify_time, 6)])
            finally:
                if os.path.exists(bundlepath):
                    os.remove(bundlepath)
    os.remove(filepath)
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Height", "K", "SignTimeSeconds", "VerifyTimeSeconds"])
        writer.writerows(results)


def test_memory_vs_param(output_csv: str) -> None:
    """
    Benchmark peak memory usage for signing across HORST parameters.
    :param output_csv: CSV path to write results.
    :return: None.
    """
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        filepath = tmp.name
    generate_file(filepath, 1024 * 1024)  # 1 MB
    results = []
    for height in HEIGHTS:
        for k in KS:
            if k > (1 << height):
                continue
            print(f"Testing memory height={height}, k={k}")
            _, mem_max = measure_mem_and_time([
                "python", HORST_SCRIPT, "sign", filepath,
                "--height", str(height), "--k", str(k)
            ])
            results.append([height, k, round(mem_max, 3)])
    os.remove(filepath)
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Height", "K", "MaxMemoryMB"])
        writer.writerows(results)


def test_signature_size_vs_param(output_csv):
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        filepath = tmpfile.name
    generate_file(filepath, 1024 * 1024)  # 1 MB

    results = []
    for height in HEIGHTS:
        for k in KS:
            if k > (1 << height):
                continue
            print(f"[SIGNATURE SIZE] height={height}, k={k}")
            bundlepath = f"{filepath}_h{height}_k{k}.pkl"
            try:
                sign_cmd = [
                    "python", HORST_SCRIPT, "sign", filepath,
                    "--height", str(height),
                    "--k", str(k),
                    "--out", bundlepath
                ]
                run_command(sign_cmd)
                sig_size = os.path.getsize(bundlepath)
                results.append([height, k, sig_size])
            finally:
                if os.path.exists(bundlepath):
                    os.remove(bundlepath)
    os.remove(filepath)

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Height", "K", "SignatureSizeBytes"])
        writer.writerows(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark HORST Signature with memory monitoring")
    parser.add_argument("--time_vs_size", action="store_true", help="Benchmark time vs file size")
    parser.add_argument("--time_vs_param", action="store_true", help="Benchmark time vs HORST params")
    parser.add_argument("--memory_vs_param", action="store_true", help="Benchmark memory vs HORST params")
    parser.add_argument("--signature_size_vs_param", action="store_true", help="Measure signature size vs HORST parameters")

    args = parser.parse_args()

    if args.time_vs_size:
        test_time_vs_size("..\\results\\horst_size_depend.csv")
    if args.time_vs_param:
        test_time_vs_param("..\\results\\horst_param_depend.csv")
    if args.memory_vs_param:
        try:
            import psutil
        except ImportError:
            print("psutil не установлен! Установите его: pip install psutil")
            exit(1)

        test_memory_vs_param("..\\results\\horst_memory_depend.csv")
    if args.signature_size_vs_param:
        test_signature_size_vs_param("..\\results\\horst_signature_size_depend.csv")
