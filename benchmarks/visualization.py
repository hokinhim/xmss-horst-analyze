import csv
import matplotlib.pyplot as plt
from collections import defaultdict
import os

# === Вспомогательная функция ===
def read_csv_rows(filename):
    with open(filename, newline='') as f:
        return list(csv.DictReader(f))

# === 1. График: Sign Time vs File Size (HORST vs XMSS) ===
def plot_sign_vs_size_dual():
    horst_data = read_csv_rows("..\\results\\size_depend.csv")
    xmss_data = read_csv_rows("..\\results\\xmss_size_depend.csv")

    def extract(data, key):
        return [int(row["FileSizeBytes"]) / (1024 * 1024) for row in data], [float(row[key]) for row in data]

    horst_x, horst_y = extract(horst_data, "SignTimeSeconds")
    xmss_x, xmss_y = extract(xmss_data, "SignTimeSeconds")

    plt.figure(figsize=(10, 6))
    plt.plot(horst_x, horst_y, marker='o', label="Подпись HORST")
    plt.plot(xmss_x, xmss_y, marker='x', label="Подпись XMSS")
    plt.xlabel("Размер файла (Мб)")
    plt.ylabel("Время подписи (сек)")
    plt.title("Зависимость времени создания подписи от размера файла (HORST vs XMSS)")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig("..\\results\\plots\\sign_time_vs_file_size.png")
    print("Saved: sign_time_vs_file_size.png")

# === 2. График: Verify Time vs File Size (HORST vs XMSS) ===
def plot_verify_vs_size_dual():
    horst_data = read_csv_rows("..\\results\\size_depend.csv")
    xmss_data = read_csv_rows("..\\results\\xmss_size_depend.csv")

    def extract(data, key):
        return [int(row["FileSizeBytes"]) / (1024 * 1024) for row in data], [float(row[key]) for row in data]

    horst_x, horst_y = extract(horst_data, "VerifyTimeSeconds")
    xmss_x, xmss_y = extract(xmss_data, "VerifyTimeSeconds")

    plt.figure(figsize=(10, 6))
    plt.plot(horst_x, horst_y, marker='o', label="Подпись HORST")
    plt.plot(xmss_x, xmss_y, marker='x', label="Подпись XMSS")
    plt.xlabel("Размер файла (Мб)")
    plt.ylabel("Время подписи (сек)")
    plt.title("Зависимость времени проверки подписи от размера файла (HORST vs XMSS)")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig("..\\results\\plots\\verify_time_vs_file_size.png")
    print("Saved: verify_time_vs_file_size.png")

# === 3. Время от параметров (horst or xmss) ===
def plot_param_depend(csv_file, label_prefix, output_name):
    data = defaultdict(list)
    with open(csv_file, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            p1 = int(row["Height"]) if "Height" in row else int(row["H"])
            p2 = int(row.get("K") or row.get("W"))
            s = float(row["SignTimeSeconds"])
            v = float(row["VerifyTimeSeconds"])
            data[p1].append((p2, s, v))

    plt.figure(figsize=(10, 6))
    for h in sorted(data):
        sorted_rows = sorted(data[h], key=lambda x: x[0])
        p2s = [x[0] for x in sorted_rows]
        sign = [x[1] for x in sorted_rows]
        verify = [x[2] for x in sorted_rows]
        plt.plot(p2s, sign, marker='o', label=f"{label_prefix} Подпись (h={h})")
        plt.plot(p2s, verify, marker='x', linestyle='--', label=f"{label_prefix} Проверка (h={h})")

    if label_prefix == "HORST":
        plt.xlabel("K (Раскрытые листья)")
    elif label_prefix == "XMSS":
        plt.xlabel("W (Параметр Винтерница)")
    else:
        plt.xlabel("Параметр")

    plt.ylabel("Время (сек)")
    plt.title(f"{label_prefix} Время vs Параметры")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_name)
    print(f"Saved: {output_name}")

# === 4. Память от параметров ===
def plot_memory_depend(csv_file, label_prefix, output_name):
    data = defaultdict(list)
    with open(csv_file, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            h = int(row["Height"])
            p = int(row.get("K") or row.get("W"))
            m = float(row["MaxMemoryMB"])
            data[h].append((p, m))

    plt.figure(figsize=(10, 6))
    for h in sorted(data):
        sorted_rows = sorted(data[h], key=lambda x: x[0])
        ps = [x[0] for x in sorted_rows]
        mems = [x[1] for x in sorted_rows]
        plt.plot(ps, mems, marker='o', label=f"{label_prefix} h={h}")

    if label_prefix == "HORST":
        plt.xlabel("K (Раскрытые листья)")
    elif label_prefix == "XMSS":
        plt.xlabel("W (Параметр Винтерница)")
    else:
        plt.xlabel("Параметр")

    plt.ylabel("Использование памяти (Мб)")
    plt.title(f"{label_prefix} Использование памяти vs Параметры")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_name)
    print(f"Saved: {output_name}")

def plot_csv(csv_file, label_prefix, output_file):
        from collections import defaultdict
        data = defaultdict(list)
        with open(csv_file, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                h = int(row["Height"])
                p = int(row.get("K") or row.get("W"))
                s = int(row["SignatureSizeBytes"])
                data[h].append((p, s))

        plt.figure(figsize=(10, 6))
        for h in sorted(data):
            sorted_rows = sorted(data[h], key=lambda x: x[0])
            ps = [x[0] for x in sorted_rows]
            sizes = [x[1] for x in sorted_rows]
            plt.plot(ps, sizes, marker='o', label=f"{label_prefix} h={h}")

        if label_prefix == "HORST":
            plt.xlabel("K (Revealed Leaves)")
        elif label_prefix == "XMSS":
            plt.xlabel("W (Winternitz Parameter)")
        else:
            plt.xlabel("Parameter")

        plt.ylabel("Signature Size (bytes)")
        plt.title(f"{label_prefix} Signature Size vs Parameter")
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        plt.savefig(output_file)
        print(f"Saved: {output_file}")

# === Запуск ===
if __name__ == "__main__":
    # Сравнение по размеру файла
    if os.path.exists("..\\results\\size_depend.csv") and os.path.exists("..\\results\\xmss_size_depend.csv"):
        plot_sign_vs_size_dual()
        plot_verify_vs_size_dual()

    # HORST отдельно
    if os.path.exists("..\\results\\param_depend.csv"):
        plot_param_depend("..\\results\\param_depend.csv", "HORST", "..\\results\\plots\\horst_time_vs_param.png")
    if os.path.exists("..\\results\\memory_depend.csv"):
        plot_memory_depend("..\\results\\memory_depend.csv", "HORST", "..\\results\\plots\\horst_memory_vs_param.png")
    if os.path.exists("..\\results\\horst_signature_size_depend.csv"):
        plot_csv("..\\results\\horst_signature_size_depend.csv", "HORST", "..\\results\\plots\\horst_signature_size_depend.png")

    # XMSS отдельно
    if os.path.exists("..\\results\\xmss_param_depend.csv"):
        plot_param_depend("..\\results\\xmss_param_depend.csv", "XMSS", "..\\results\\plots\\xmss_time_vs_param.png")
    if os.path.exists("..\\results\\xmss_memory_depend.csv"):
        plot_memory_depend("..\\results\\xmss_memory_depend.csv", "XMSS", "..\\results\\plots\\xmss_memory_vs_param.png")
    if os.path.exists("..\\results\\xmss_signature_size_depend.csv"):
        plot_csv("..\\results\\xmss_signature_size_depend.csv", "XMSS", "..\\results\\plots\\xmss_signature_size_depend.png")