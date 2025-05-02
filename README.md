# Сравнение эффективности постквантовых схем ЭЦП: XMSS vs HORST

[![Python 3.8](https://img.shields.io/badge/python-3.8-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Курсовой проект по исследованию и сравнительному анализу эффективности двух постквантовых алгоритмов электронной цифровой подписи:
- **XMSS** (eXtended Merkle Signature Scheme)
- **HORST** (компонент схемы SPHINCS)

## 🔍 Научные цели
1. Экспериментальная оценка скорости работы алгоритмов
2. Анализ зависимости размера подписи от параметров
3. Сравнение потребления памяти

## 🛠 Технологический стек
- **Язык**: Python 3.8
- **Криптография**: ???
- **Тестирование**: `argparse` 
- **Визуализация**: `matplotlib`
- **Документация**: `Docstring`

## 👥 Команда разработки
- [@lesstray](https://github.com/lesstray) | XMSS-реализация
- [@sposhekhonov](https://github.com/sposhekhonov) | HORST-реализация
- [@tsibbbba](https://github.com/tsibbbba) | Тестирование
- [@hokinhim](https://github.com/hokinhim) | Архитектура и анализ

## 🚀 Быстрый старт

### Установка
```bash
git clone https://github.com/hokinhim/xmss-horst-analyze.git
cd xmss-horst-analyze
pip install -r requirements.txt
