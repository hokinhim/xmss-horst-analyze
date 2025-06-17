"""
Графический интерфейс для сравнения результатов тестов подписей HORST и XMSS.
"""
import os
import csv
import threading
import subprocess
import tkinter as tk
import matplotlib.pyplot as plt
from collections import defaultdict
from tkinter import ttk, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# Пути до скриптов
BENCH_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'benchmarks'))
RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'results'))
HORST_SCRIPT = os.path.join(BENCH_DIR, 'horst_benchmark.py')
XMSS_SCRIPT = os.path.join(BENCH_DIR, 'xmss_benchmark.py')


class BenchmarkGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Сравнение подписей: XMSS vs HORST")
        self.geometry("900x600")

        # Полноэкранный режим
        self.fullscreen = False
        self.attributes("-fullscreen", self.fullscreen)
        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<Escape>", self.end_fullscreen)

        self.notebook = None
        self.tabs = None
        self.status_var = None
        self.status_bar = None
        self.canvas_size = None
        self.canvas_xmss = None
        self.canvas_horst = None
        self.fig_size = None
        self.fig_xmss = None
        self.fig_horst = None
        self.ax_horst_sig = None
        self.canvas_horst_sig = None

        self.ax_xmss_sig = None
        self.canvas_xmss_sig = None

        self.ax_size = None
        self.create_widgets()

        self.current_thread = None
        self.benchmark_active = False

    def toggle_fullscreen(self):
        """
        Переключение полноэкранного режима по F11
        """
        self.fullscreen = not self.fullscreen
        self.attributes("-fullscreen", self.fullscreen)
        return "break"

    def end_fullscreen(self):
        """
        Выход из полноэкранного режима по Esc
        """
        self.fullscreen = False
        self.attributes("-fullscreen", False)
        return "break"

    def create_widgets(self):
        """
        Создание виджетов
        """
        # Создание рабочей области
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Создание вкладок
        self.tabs = {
            "size_comparison": ttk.Frame(self.notebook),
            "horst_params": ttk.Frame(self.notebook),
            "xmss_params": ttk.Frame(self.notebook),
            "horst_sigsize": ttk.Frame(self.notebook),
            "xmss_sigsize": ttk.Frame(self.notebook)
        }

        for name, tab in self.tabs.items():
            self.notebook.add(tab, text=self.get_tab_name(name))
            self.create_tab_content(name, tab)

        # Создание статус бара
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    @staticmethod
    def get_tab_name(tab_id):
        """
        Получение названий вкладок
        """
        names = {
            "size_comparison": "Зависимость от размеров файлов",
            "horst_params": "Зависимость скорости работы и использования памяти подписи HORST от параметров",
            "xmss_params": "Зависимость скорости работы и использования памяти подписи XMSS от параметров",
            "horst_sigsize": "Зависимость размера подписи HORST от параметров",
            "xmss_sigsize": "Зависимость размера подписи XMSS от параметров"
        }
        return names.get(tab_id, tab_id)

    def plot_signature_size(self, scheme):
        try:
            if scheme == 'horst':
                csv_file = os.path.join(RESULTS_DIR, 'horst_signature_size_depend.csv')
                fig = self.fig_horst_sig
                ax = self.ax_horst_sig
                canvas = self.canvas_horst_sig
                param_label = 'K (Раскрытые листья)'
                label = 'HORST'
            else:
                csv_file = os.path.join(RESULTS_DIR, 'xmss_signature_size_depend.csv')
                fig = self.fig_xmss_sig
                ax = self.ax_xmss_sig
                canvas = self.canvas_xmss_sig
                param_label = 'W (Параметр Винтерница)'
                label = 'XMSS'

            data = defaultdict(list)
            with open(csv_file, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    h = int(row["Height"])
                    p = int(row.get("K") or row.get("W"))
                    s = int(row["SignatureSizeBytes"])
                    data[h].append((p, s))

            ax.clear()
            for h in sorted(data):
                sorted_rows = sorted(data[h], key=lambda x: x[0])
                ps = [x[0] for x in sorted_rows]
                sizes = [x[1] for x in sorted_rows]
                ax.plot(ps, sizes, marker='o', label=f"h={h}")

            ax.set_xlabel(param_label)
            ax.set_ylabel("Размер подписи, Байт")
            ax.set_title(f"Сравнение размера подписи {label} от параметров")
            ax.legend()
            ax.grid(True)
            fig.tight_layout()
            canvas.draw()
            self.status_var.set(f"График {label} построен успешно")

        except Exception as e:
            self.status_var.set(f"Ошибка построения графика {scheme.upper()}: {str(e)}")

    def create_tab_content(self, tab_id, parent):
        """
        Создание рабочих областей внутри вкладки
        """
        def save_current_plots():
            """
            Сохранение построенных графиков
            """
            os.makedirs(os.path.join(RESULTS_DIR, "plots"), exist_ok=True)
            if tab_id == "size_comparison" and self.fig_size:
                self.fig_size.savefig(os.path.join(RESULTS_DIR, "plots", "size_comparison.png"))
            elif tab_id == "horst_params" and self.fig_horst:
                self.fig_horst.savefig(os.path.join(RESULTS_DIR, "plots", "horst_params.png"))
            elif tab_id == "xmss_params" and self.fig_xmss:
                self.fig_xmss.savefig(os.path.join(RESULTS_DIR, "plots", "xmss_params.png"))
            elif tab_id == "horst_sigsize" and self.fig_horst_sig:
                self.fig_horst_sig.savefig(os.path.join(RESULTS_DIR, "plots", "horst_signature_size_depend.png"))
            elif tab_id == "xmss_sigsize" and self.fig_xmss_sig:
                self.fig_xmss_sig.savefig(os.path.join(RESULTS_DIR, "plots", "xmss_signature_size_depend.png"))
            self.status_var.set("Графики сохранены в results/plots")

        # Создание управляющего блока
        ctrl_frame = ttk.LabelFrame(parent, text="Функции", padding=10)
        ctrl_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        # Создание блока графиков
        plot_frame = ttk.Frame(parent)
        plot_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Создание управляющего блока внутри вкладок
        if tab_id == "size_comparison":
            ttk.Button(ctrl_frame, text="Запуск тестирования HORST",
                       command=lambda: self.start_benchmark('horst')).pack(fill='x', pady=5)
            ttk.Button(ctrl_frame, text="Запуск тестирования XMSS",
                       command=lambda: self.start_benchmark('xmss')).pack(fill='x', pady=5)
            ttk.Button(ctrl_frame, text="Обновить графики",
                       command=self.plot_comparison).pack(fill='x', pady=5)
            ttk.Button(ctrl_frame, text="Сохранить графики",
                       command=save_current_plots).pack(fill='x', pady=5)

            self.fig_size, self.ax_size = plt.subplots(2, 1, figsize=(8, 8))
            self.canvas_size = FigureCanvasTkAgg(self.fig_size, master=plot_frame)
            self.canvas_size.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        elif tab_id == "horst_params":
            ttk.Button(ctrl_frame, text="Запуск тестирования HORST",
                       command=lambda: self.start_benchmark('horst_params')).pack(fill='x', pady=5)
            ttk.Button(ctrl_frame, text="Обновить графики",
                       command=lambda: self.plot_scheme('horst')).pack(fill='x', pady=5)
            ttk.Button(ctrl_frame, text="Сохранить графики",
                       command=save_current_plots).pack(fill='x', pady=5)

            self.fig_horst, (self.ax_horst_time, self.ax_horst_mem) = plt.subplots(1, 2, figsize=(10, 4))
            self.canvas_horst = FigureCanvasTkAgg(self.fig_horst, master=plot_frame)
            self.canvas_horst.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        elif tab_id == "xmss_params":
            ttk.Button(ctrl_frame, text="Запуск тестирования XMSS",
                       command=lambda: self.start_benchmark('xmss_params')).pack(fill='x', pady=5)
            ttk.Button(ctrl_frame, text="Обновить графики",
                       command=lambda: self.plot_scheme('xmss')).pack(fill='x', pady=5)
            ttk.Button(ctrl_frame, text="Сохранить графики",
                       command=save_current_plots).pack(fill='x', pady=5)

            self.fig_xmss, (self.ax_xmss_time, self.ax_xmss_mem) = plt.subplots(1, 2, figsize=(10, 4))
            self.canvas_xmss = FigureCanvasTkAgg(self.fig_xmss, master=plot_frame)
            self.canvas_xmss.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        elif tab_id == "horst_sigsize":
            ttk.Button(ctrl_frame, text="Обновить график",
                       command=lambda: self.plot_signature_size('horst')).pack(fill='x', pady=5)
            ttk.Button(ctrl_frame, text="Сохранить график",
                       command=save_current_plots).pack(fill='x', pady=5)

            self.fig_horst_sig, self.ax_horst_sig = plt.subplots(figsize=(8, 5))
            self.canvas_horst_sig = FigureCanvasTkAgg(self.fig_horst_sig, master=plot_frame)
            self.canvas_horst_sig.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        elif tab_id == "xmss_sigsize":
            ttk.Button(ctrl_frame, text="Построить график",
                       command=lambda: self.plot_signature_size('xmss')).pack(fill='x', pady=5)
            ttk.Button(ctrl_frame, text="Сохранить график",
                       command=save_current_plots).pack(fill='x', pady=5)

            self.fig_xmss_sig, self.ax_xmss_sig = plt.subplots(figsize=(8, 5))
            self.canvas_xmss_sig = FigureCanvasTkAgg(self.fig_xmss_sig, master=plot_frame)
            self.canvas_xmss_sig.get_tk_widget().pack(fill=tk.BOTH, expand=True)




    def start_benchmark(self, benchmark_type):
        """
        Запуск бенчмарков в другом потоке
        """
        if self.benchmark_active:
            messagebox.showwarning("Тестирование запущено", "Другое тестирование уже запущено.")
            return

        self.benchmark_active = True
        self.status_var.set(f"Запущено тестирование {benchmark_type}...")

        if benchmark_type == 'horst':
            cmd = ['python', HORST_SCRIPT, '--time_vs_size']
        elif benchmark_type == 'xmss':
            cmd = ['python', XMSS_SCRIPT, '--time_vs_size']
        elif benchmark_type == 'horst_params':
            cmd = ['python', HORST_SCRIPT, '--time_vs_param', '--memory_vs_param']
        elif benchmark_type == 'xmss_params':
            cmd = ['python', XMSS_SCRIPT, '--time_vs_param', '--memory_vs_param']
        else:
            self.benchmark_active = False
            return

        # Запуск в другом потоке
        self.current_thread = threading.Thread(
            target=self.run_benchmark_thread,
            args=(cmd, benchmark_type)
        )
        self.current_thread.start()

    def run_benchmark_thread(self, cmd, benchmark_type):
        """
        Выполнение теста в другом потоке
        """
        try:
            process = subprocess.Popen(
                cmd,
                cwd=BENCH_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            out, err = process.communicate()

            if process.returncode != 0:
                self.status_var.set(f"Тест завершился с ошибкой {process.returncode}")
                raise RuntimeError(err.decode())
            else:
                self.status_var.set(f"{benchmark_type} тест завершен успешно")

                # Update plots after benchmark completes
                if benchmark_type in ['horst', 'xmss', 'both']:
                    self.plot_comparison()
                elif benchmark_type == 'horst_params':
                    self.plot_scheme('horst')
                elif benchmark_type == 'xmss_params':
                    self.plot_scheme('xmss')

        except Exception as e:
            self.status_var.set(f"Ошибка: {str(e)}")
        finally:
            self.benchmark_active = False

    def plot_comparison(self):
        """
        Построение графиков сравнения XMSS vs HORST
        """
        try:
            # Чтение данных из CSV
            horst_data = self.read_csv(os.path.join(RESULTS_DIR, 'horst_size_depend.csv'))
            xmss_data = self.read_csv(os.path.join(RESULTS_DIR, 'xmss_size_depend.csv'))

            # Очищение предыдущих графиков
            for ax in self.ax_size:
                ax.clear()

            # Отрисовка графика по формированию подписи
            self.plot_size_comparison(
                self.ax_size[0],
                horst_data, xmss_data,
                'SignTimeSeconds',
                'Сравнение времени формирования подписи XMSS vs HORST'
            )

            # Отрисовка графика по валидации подписи
            self.plot_size_comparison(
                self.ax_size[1],
                horst_data, xmss_data,
                'VerifyTimeSeconds',
                'Сравнение времени проверки подписи XMSS vs HORST'
            )

            self.fig_size.tight_layout()
            self.canvas_size.draw()
            self.status_var.set("Графики обновлены")

        except Exception as e:
            self.status_var.set(f"Ошибка построения графиков: {str(e)}")

    @staticmethod
    def plot_size_comparison(ax, horst_data, xmss_data, metric, title):
        """
        Построение графиков сравнения XMSS vs HORST в зависимости от размера файла
        """
        # Извлечение данных
        sizes = [int(row['FileSizeBytes']) / (1024 * 1024) for row in horst_data]
        horst_times = [float(row[metric]) for row in horst_data]
        xmss_times = [float(row[metric]) for row in xmss_data]

        # Графики
        ax.plot(sizes, horst_times, 'o-', label='HORST')
        ax.plot(sizes, xmss_times, 's--', label='XMSS')
        ax.set_xlabel('Размер файла, МБайт')
        ax.set_ylabel('Время, с')
        ax.set_title(title)
        ax.legend()
        ax.grid(True)

    def plot_scheme(self, scheme):
        """
        Схема графиков
        """
        try:
            if scheme == 'horst':
                time_csv = os.path.join(RESULTS_DIR, 'horst_param_depend.csv')
                mem_csv = os.path.join(RESULTS_DIR, 'horst_memory_depend.csv')
                ax_time = self.ax_horst_time
                ax_mem = self.ax_horst_mem
                canvas = self.canvas_horst
            else:
                time_csv = os.path.join(RESULTS_DIR, 'xmss_param_depend.csv')
                mem_csv = os.path.join(RESULTS_DIR, 'xmss_memory_depend.csv')
                ax_time = self.ax_xmss_time
                ax_mem = self.ax_xmss_mem
                canvas = self.canvas_xmss

            # Очищение предыдущих графиков
            ax_time.clear()
            ax_mem.clear()

            # График зависимости времени от параметров
            self.plot_time_params(ax_time, time_csv, scheme)

            # График зависимости памяти от параметров
            self.plot_memory_params(ax_mem, mem_csv, scheme)

            canvas.draw()
            self.status_var.set(f"{scheme} графики загружены")

        except Exception as e:
            self.status_var.set(f"Ошибка графика: {str(e)}")

    @staticmethod
    def plot_time_params(ax, csv_file, scheme):
        """
        Сравнение времени формирования/проверки подписей от параметров
        """
        data = defaultdict(list)
        with open(csv_file) as f:
            reader = csv.DictReader(f)
            for row in reader:
                param = int(row['Height'])
                k = int(row.get('K') or row.get('W'))
                sign_time = float(row['SignTimeSeconds'])
                verify_time = float(row['VerifyTimeSeconds'])
                data[param].append((k, sign_time, verify_time))

        for param, values in sorted(data.items()):
            values.sort(key=lambda x: x[0])
            k_vals = [v[0] for v in values]
            sign_times = [v[1] for v in values]
            verify_times = [v[2] for v in values]

            ax.plot(k_vals, sign_times, 'o-', label=f'Формирование подписи (h={param})')
            ax.plot(k_vals, verify_times, 's--', label=f'Проверка подписи (h={param})')

        ax.set_xlabel('K (Раскрытые листья)' if scheme == 'horst' else 'W (Параметр Винтерница)')
        ax.set_ylabel('Время, с')
        ax.set_title(f'Сравнение времени формирования/проверки подписи {scheme.upper()} от параметров')
        ax.legend()
        ax.grid(True)

    @staticmethod
    def plot_memory_params(ax, csv_file, scheme):
        """
        Сравнение использования памяти подписей от параметров
        """
        data = defaultdict(list)
        with open(csv_file) as f:
            reader = csv.DictReader(f)
            for row in reader:
                param = int(row['Height'])
                k = int(row.get('K') or row.get('W'))
                memory = float(row['MaxMemoryMB'])
                data[param].append((k, memory))

        for param, values in sorted(data.items()):
            values.sort(key=lambda x: x[0])
            k_vals = [v[0] for v in values]
            mem_vals = [v[1] for v in values]

            ax.plot(k_vals, mem_vals, 'o-', label=f'h={param}')

        ax.set_xlabel('K (Раскрытые Листья)' if scheme == 'horst' else 'W (Параметр Винтерница)')
        ax.set_ylabel('Память, МБайт')
        ax.set_title(f'Сравнение использования памяти подписью {scheme.upper()} от параметров')
        ax.legend()
        ax.grid(True)

    @staticmethod
    def read_csv(file_path):
        """
        Чтение CSV
        """
        data = []
        with open(file_path, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                data.append(row)
        return data


if __name__ == '__main__':
    app = BenchmarkGUI()
    app.mainloop()
