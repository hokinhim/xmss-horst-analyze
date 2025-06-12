# Сравнение эффективности постквантовых схем ЭЦП: XMSS vs HORST

[![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Курсовой проект по исследованию и сравнительному анализу эффективности двух постквантовых алгоритмов электронной цифровой подписи:
- **XMSS** (eXtended Merkle Signature Scheme)
- **HORST** (компонент схемы SPHINCS)

## 🔍 Научные цели
1. Практическая реализация алгоритмов без использования готовых модулей.
2. Экспериментальная оценка скорости работы алгоритмов:
   - Зависимость времени формирования/проверки подписи XMSS от размера файла;
   - Зависимость времени формирования/проверки подписи HORST от размера файла; 
   - Зависимость времени формирования/проверки подписи XMSS от параметра K;
   - Зависимость времени формирования/проверки подписи HORST от параметра W.
3. Экспериментальная оценка потребления памяти алгоритмов:
   - Зависимость потребления памяти подписи XMSS от параметра K;
   - Зависимость потребления памяти подписи HORST от параметра W.

## 🛠 Технологический стек
- **Язык**: Python 3.7
- **Криптография**: `hashlib`, `hmac`, `secrets`, `pickle`
- **Тестирование**: `argparse` 
- **Визуализация**: `matplotlib`, `psutil`
- **Документация**: `Docstring`

## 👥 Команда разработки
- [@lesstray](https://github.com/lesstray) | Реализация XMSS
- [@sposhekhonov](https://github.com/sposhekhonov) | Реализация HORST
- [@tsibbbba](https://github.com/tsibbbba) | Тестирование, визуализация
- [@hokinhim](https://github.com/hokinhim) | Архитектура, GUI, анализ

## 🚀 Быстрый старт

### Установка
```bash
git clone https://github.com/hokinhim/xmss-horst-analyze.git
cd xmss-horst-analyze
pip install -r requirements.txt
```

### Запуск
```bash
python cli/main.py
```