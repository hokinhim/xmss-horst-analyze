import os
import time
import csv
import argparse
import tempfile
import subprocess
import matplotlib.pyplot as plt
from collections import defaultdict
import psutil  # Для мониторинга памяти

HORST_SCRIPT = "..\\src\\horst.py"

SIZES = [
    1,
    1024,
    1024 ** 2,
    32 * 1024 ** 2,
    512 * 1024 ** 2,
    1024 ** 3,
    5 * 1024 ** 3
]

HEIGHTS = [10, 12, 14, 16]
KS = [8, 16, 32, 64, 128]

def generate_file(path, size):
    with open(path, "wb") as f:
        f.write(os.urandom(size))

def run_command(cmd):
    start = time.time()
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    end = time.time()
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr.decode()}")
    return end - start

def run_command_with_mem_monitor(cmd):
    """
    Запускает команду cmd и замеряет максимальное потребление памяти (RSS) процесса (в мегабайтах).
    Возвращает (время выполнения, max_rss_mb).
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = psutil.Process(proc.pid)
    max_rss = 0
    try:
        while proc.poll() is None:
            mem = p.memory_info().rss
            if mem > max_rss:
                max_rss = mem
            time.sleep(0.01)
        # Проверим память ещё раз в конце
        mem = p.memory_info().rss
        if mem > max_rss:
            max_rss = mem
    except psutil.NoSuchProcess:
        pass
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{stderr.decode()}")
    elapsed = proc.returncode  # Мы уже замерили время по loop, лучше замерить отдельно
    # Можно замерить точное время так:
    # Но проще повторим измерение времени отдельно:
    # Или, для простоты, запускаем обычный замер времени вокруг Popen:
    return max_rss / (1024 * 1024)  # в мегабайтах

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
    return elapsed, max_rss / (1024 * 1024)

# ========== Тестирование ==========

def test_time_vs_size(output_csv):
    results = []
    for size in SIZES:
        print(f"Testing file size: {size} bytes")
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            filepath = tmpfile.name
        bundlepath = f"{filepath}_signed.pkl"
        generate_file(filepath, size)

        try:
            sign_cmd = ["python", HORST_SCRIPT, "sign", filepath, "--out", bundlepath]
            sign_time = run_command(sign_cmd)

            verify_cmd = ["python", HORST_SCRIPT, "verify", filepath, bundlepath]
            verify_time = run_command(verify_cmd)

            results.append([size, round(sign_time, 6), round(verify_time, 6)])
        finally:
            os.remove(filepath)
            if os.path.exists(bundlepath):
                os.remove(bundlepath)

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["FileSizeBytes", "SignTimeSeconds", "VerifyTimeSeconds"])
        writer.writerows(results)

def test_time_vs_param(output_csv):
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        filepath = tmpfile.name
    generate_file(filepath, 1024 * 1024)  # 1 MB

    results = []
    for height in HEIGHTS:
        for k in KS:
            if k > (1 << height):
                continue
            print(f"Testing height={height}, k={k}")
            bundlepath = f"{filepath}_h{height}_k{k}.pkl"
            try:
                sign_cmd = ["python", HORST_SCRIPT, "sign", filepath,
                            "--height", str(height), "--k", str(k),
                            "--out", bundlepath]
                sign_time = run_command(sign_cmd)

                verify_cmd = ["python", HORST_SCRIPT, "verify", filepath, bundlepath,
                              "--height", str(height), "--k", str(k)]
                verify_time = run_command(verify_cmd)

                results.append([height, k, round(sign_time, 6), round(verify_time, 6)])
            finally:
                if os.path.exists(bundlepath):
                    os.remove(bundlepath)
    os.remove(filepath)

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Height", "K", "SignTimeSeconds", "VerifyTimeSeconds"])
        writer.writerows(results)

def test_memory_vs_param(output_csv):
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        filepath = tmpfile.name
    generate_file(filepath, 1024 * 1024)  # 1 MB

    results = []
    for height in HEIGHTS:
        for k in KS:
            if k > (1 << height):
                continue
            print(f"Testing memory height={height}, k={k}")
            sign_cmd = ["python", HORST_SCRIPT, "sign", filepath,
                        "--height", str(height), "--k", str(k)]
            mem_time, mem_max = measure_mem_and_time(sign_cmd)
            results.append([height, k, round(mem_max, 3)])
            print(f"Memory max: {mem_max:.2f} MB")

    os.remove(filepath)

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Height", "K", "MaxMemoryMB"])
        writer.writerows(results)

# ========== Визуализация ==========

def plot_time_vs_size(csv_file):
    import matplotlib.pyplot as plt
    sizes, sign_times, verify_times = [], [], []
    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            sizes.append(int(row["FileSizeBytes"]) / (1024 * 1024))
            sign_times.append(float(row["SignTimeSeconds"]))
            verify_times.append(float(row["VerifyTimeSeconds"]))

    plt.figure(figsize=(10, 6))
    plt.plot(sizes, sign_times, marker='o', label="Sign Time (s)")
    plt.plot(sizes, verify_times, marker='x', label="Verify Time (s)")
    plt.xlabel("File Size (MB)")
    plt.ylabel("Time (s)")
    plt.title("Time vs File Size")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig("time_vs_size.png")
    print("📊 Saved plot: time_vs_size.png")

def plot_time_vs_param(csv_file):
    import matplotlib.pyplot as plt
    from collections import defaultdict
    data = defaultdict(list)
    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            h = int(row["Height"])
            k = int(row["K"])
            s = float(row["SignTimeSeconds"])
            v = float(row["VerifyTimeSeconds"])
            data[h].append((k, s, v))

    plt.figure(figsize=(10, 6))
    for h in sorted(data):
        sorted_rows = sorted(data[h], key=lambda x: x[0])
        ks = [x[0] for x in sorted_rows]
        sign = [x[1] for x in sorted_rows]
        verify = [x[2] for x in sorted_rows]
        plt.plot(ks, sign, marker='o', label=f"Sign (h={h})")
        plt.plot(ks, verify, marker='x', linestyle='--', label=f"Verify (h={h})")

    plt.xlabel("k (Revealed Leaves)")
    plt.ylabel("Time (s)")
    plt.title("Time vs k for Different Heights")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig("time_vs_param.png")
    print("📊 Saved plot: time_vs_param.png")

def plot_memory_vs_param(csv_file):
    import matplotlib.pyplot as plt
    from collections import defaultdict
    data = defaultdict(list)
    with open(csv_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            h = int(row["Height"])
            k = int(row["K"])
            m = float(row["MaxMemoryMB"])
            data[h].append((k, m))

    plt.figure(figsize=(10, 6))
    for h in sorted(data):
        sorted_rows = sorted(data[h], key=lambda x: x[0])
        ks = [x[0] for x in sorted_rows]
        mems = [x[1] for x in sorted_rows]
        plt.plot(ks, mems, marker='o', label=f"Memory (h={h})")

    plt.xlabel("k (Revealed Leaves)")
    plt.ylabel("Max Memory Usage (MB)")
    plt.title("Memory Usage vs k for Different Heights")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig("memory_vs_param.png")
    print("📊 Saved plot: memory_vs_param.png")

# ========== Аргументы командной строки ==========

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark HORST Signature with memory monitoring")
    parser.add_argument("--time_vs_size", action="store_true", help="Benchmark time vs file size")
    parser.add_argument("--time_vs_param", action="store_true", help="Benchmark time vs HORST params")
    parser.add_argument("--memory_vs_param", action="store_true", help="Benchmark memory vs HORST params")
    parser.add_argument("--plot", action="store_true", help="Build plot after measurement")
    args = parser.parse_args()

    if args.time_vs_size:
        test_time_vs_size("..\\results\\size_depend.csv")
        if args.plot:
            plot_time_vs_size("..\\results\\size_depend.csv")

    if args.time_vs_param:
        test_time_vs_param("..\\results\\param_depend.csv")
        if args.plot:
            plot_time_vs_param("..\\results\\param_depend.csv")

    if args.memory_vs_param:
        try:
            import psutil
        except ImportError:
            print("psutil не установлен! Установите его: pip install psutil")
            exit(1)

        test_memory_vs_param("..\\results\\memory_depend.csv")
        if args.plot:
            plot_memory_vs_param("..\\results\\memory_depend.csv")
