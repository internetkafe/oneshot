# OneShot‑pin (форк internetkafe)

Оригинал: [rofl0r/OneShot](https://github.com/rofl0r/OneShot)  
Модификации: drygdryg  
Улучшения PixieWPS: kimocoder  
Форк: **internetkafe** (добавлены русские комментарии, fallback‑wcwidth, пакетный режим `--bssid-list`)

## Что умеет

- **Pixie Dust** — офлайн‑вычисление PIN через уязвимость в WPS (требуется `pixiewps`).
- **Онлайн‑брутфорс** — «умный» перебор половинок PIN с сохранением прогресса.
- **Генератор PIN** — десятки алгоритмов для разных производителей (D‑Link, ASUS, Broadcom, Realtek и др.).
- **WPS Push Button** — подключение к точке доступа с активированным WPS‑PBC.
- **Сканер сетей** — цветная таблица с сортировкой по сигналу, пометками уязвимых и сохранённых сетей.
- **Сохранение результатов** — в `.txt` и `.csv`.
- **Пакетная атака** — можно скормить файл со списком BSSID (`--bssid-list bssids.txt`).

## Требования

- Python **3.6+**
- Права **root** (нужен доступ к сетевым интерфейсам)
- `wpa_supplicant` **с поддержкой WPS** (CONFIG_WPS=y)
- `pixiewps` — опционально, для Pixie Dust атаки
- `iw` — для сканирования

*Библиотека `wcwidth` не обязательна – если её нет, форматирование таблицы чуть упрощается, но всё работает «из коробки».*

## Установка

```bash
git clone https://github.com/internetkafe/oneshot.git
cd oneshot 
chmod +x oneshot-fork.py
# При желании: pip install wcwidth (для идеального выравнивания CJK‑символов)
