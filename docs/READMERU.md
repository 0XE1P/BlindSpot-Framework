<div align="center">

# ◈ BlindSpot

**Modular crypter/packer for security research**

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

*Упаковщик PE-файлов с reflective loading, API hashing и полным стеком anti-analysis.*

[Возможности](#-возможности) • [Результаты](#-результаты) • [Установка](#-установка) • [Использование](#-использование) • [Архитектура](#-архитектура) • [FAQ](#-faq)

</div>

---

> ⚠️ **DISCLAIMER**
>
> BlindSpot — **образовательный инструмент** для security-исследований.
> Использование **только** на собственных системах или в рамках
> **авторизованного** пентеста. Автор не несёт ответственности за misuse.
>
> См. [DISCLAIMER.md](DISCLAIMER.md).

---

## 📖 Что такое BlindSpot

**BlindSpot** — это **криптер/упаковщик** для Windows PE-файлов (`.exe`).

Он берёт **готовый исполняемый файл** (reverse shell, полезную нагрузку,
тестовый бинарник) и превращает его в **обфусцированный контейнер**,
который:

- **Шифрует** исходный payload (XOR)
- **Скрывает** его в памяти через reflective PE loading
- **Уменьшает** количество детектов у антивирусов
- **Сохраняет** функциональность исходного файла

**Ключевое отличие от готовых криптеров:** BlindSpot — **открытый**,
**модульный** и **полностью бесплатный**. Каждый компонент можно изучить,
изменить и улучшить.

---

## 🎯 Результаты

### Сводная таблица

| Payload | До BlindSpot | После BlindSpot | Снижение |
|---------|:------------:|:---------------:|:--------:|
| **Самописный reverse shell** | 22/70 | **8/75** | **−64%** |
| **Metasploit Meterpreter** | 44/71 | **16/69** | **−64%** |
| **Тестовый маркер** | — | 7/71 | — |

### Что обходится

✅ **Kaspersky** (top-1 в РФ/Европе)
✅ **ESET** (top-3 в мире)
✅ **BitDefender** (top-1 по детекту)
✅ **Dr.Web**
✅ **Avast / AVG / Avira**
✅ **Trend Micro / Sophos / Malwarebytes**
✅ **Avira, F-Secure, Emsisoft, eScan, GData**
✅ **67 из 75 AV** не детектят упакованный `rev.exe`

### Что остаётся

⚠️ **Microsoft Defender** (`Trojan:Win32/Wacatac`) — ML-детект, только подпись
⚠️ **CrowdStrike Falcon** (`Win/malicious_confidence_70-90%`) — behavior, direct syscalls
⚠️ **Symantec** (`ML.Attribute.HighConfidence`) — ML, только подпись
⚠️ **Elastic** (`Malicious (high Confidence)`) — behavior

**Это enterprise/ML-детекты.** Обходятся только **подписью сертификатом**
($200-500/год) или **direct syscalls** (недели работы).

---

## ✨ Возможности

### 🔐 Криптография

| Техника | Реализация |
|---------|-----------|
| **Шифрование payload** | XOR с 16-байтным случайным ключом |
| **Шифрование строк** | XOR с ключом на каждую строку |
| **PE-обфускация** | Рандомизация timestamp, section names |
| **Полиморфизм** | Рандомизация имён функций при каждой сборке |

### 🛡️ Anti-Analysis

- **Anti-VM** — CPUID vendor checks (`VMwareVMware`, `VBoxVBoxVBox`, `KVMKVMKVM`, `XenVMMXenVMM`)
- **Anti-Debug** — `PEB->BeingDebugged`, `IsDebuggerPresent`
- **Anti-Sandbox** — RAM, CPU, disk, uptime, username checks
- **Комбинированный score-подход** — не срабатывает на реальной машине

### ⚙️ Reflective Loader

- **Ноль импортов** — `loader.exe` не имеет Import Table
- **Ноль CRT** — компиляция с `-nostdlib`
- **PEB walking** — поиск модулей без `GetModuleHandle`
- **API hashing** — MurmurHash для имён функций
- **Forwarder resolution** — `kernel32 → kernelbase`
- **Manual PE mapping** — секции, IAT, релокации
- **Per-section protection** — `.text` → RX, `.data` → RW

### 💻 GUI

- Тёмная / светлая тема
- Drag-and-drop payload
- Чекбоксы опций (Polymorphism, PE Patcher, String Encryption)
- **Встроенная VT-проверка** с отображением отчёта
- Прогресс-бар с процентами
- Цветной лог (info / ok / error / warn)
- Сохранение настроек между запусками
- Портативный `.exe` (PyInstaller)

---

## 🚀 Установка

### Требования

| Компонент | Версия | Обязательно |
|-----------|--------|:-----------:|
| **Windows** | 10/11 x64 | ✅ |
| **Python** | 3.9+ | ✅ для CLI/GUI |
| **MinGW-w64 (gcc)** | 13.0+ | ✅ для компиляции loader'а |
| **Git** | любая | опционально |

### Шаг 1. Клонировать репозиторий

```bash
git clone https://github.com/yourname/BlindSpot.git
cd BlindSpot
```

### Шаг 2. Установить Python-зависимости

```bash
pip install -r requirements.txt
```

### Шаг 3. Установить MinGW-w64

**Windows (MSYS2):**
1. Скачай [MSYS2](https://www.msys2.org/) и установи в `C:\msys64\`
2. Открой **MSYS2 UCRT64** и выполни:
   ```bash
   pacman -S mingw-w64-ucrt-x86_64-gcc
   ```
3. Добавь `C:\msys64\ucrt64\bin` в `PATH` Windows

**Linux / Kali:**
```bash
sudo apt update
sudo apt install mingw-w64
```

### Шаг 4. Проверить установку

```bash
gcc --version
python --version
```

---

## 💡 Использование

### CLI

```bash
# Упаковать payload
python core/builder.py path/to/payload.exe

# Результат
# → build/loader.exe
```

### GUI

```bash
python blindspot_gui.py
```

**Или** запусти готовый `.exe`:

```bash
dist/BlindSpot_v1.0/BlindSpotGUI.exe
```

### Сборка GUI в `.exe`

```bash
build_exe.bat
```

**Результат:** `dist/BlindSpot_v1.0/BlindSpotGUI.exe`

---

## 🏗️ Архитектура

### Структура проекта

```
BlindSpot/
│
├── blindspot_gui.py              ← GUI (CustomTkinter)
├── build.bat                     ← сборка loader'а
├── build_exe.bat                 ← сборка GUI в .exe
├── requirements.txt
├── README.md
├── DISCLAIMER.md
├── LICENSE
│
├── core/                         ← Python (мозг)
│   ├── builder.py                ← главный сборщик
│   ├── crypter.py                ← шифрование payload
│   ├── pe_patcher.py             ← правка PE-заголовков
│   ├── polymorph.py              ← полиморфизм исходников
│   └── string_crypt.py           ← шифрование строк
│
├── src/                          ← C (loader)
│   ├── antianalysis/             ← Anti-VM / Anti-Debug
│   ├── common/                   ← типы, memory, hashes
│   ├── loader/                   ← reflective loader
│   │   ├── main.c                ← entry point
│   │   ├── pe_parser.c/h         ← парсинг PE
│   │   ├── api_resolver.c/h      ← PEB walking + hashing
│   │   ├── reflective.c/h        ← reflective mapping
│   │   └── decrypt.c/h           ← XOR расшифровка
│   ├── payload_test/             ← тестовый payload
│   └── telemetry/                ← AMSI/ETW patches
│
├── config/                       ← JSON-конфиги
│   ├── default.json
│   ├── fast.json
│   └── stealth.json
│
├── payloads/
│   ├── input/                    ← входные .exe
│   └── output/                   ← промежуточные .bin
│
└── build/                        ← результаты сборки
```

### Поток данных

```
┌─────────────────────────────────────────────────┐
│  ВХОД: payload.exe (любой PE32+ x64)            │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
         ┌─────────────────────┐
         │  converter.py       │  (опционально)
         │  PE → shellcode     │
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  crypter.py         │
         │  XOR шифрование     │  → payload_data.c
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  string_crypt.py    │
         │  XOR строк          │  → strings.h
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  polymorph.py       │
         │  Рандомизация имён  │  → build/poly_src/
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  gcc компиляция     │
         │  loader.c → exe     │
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  pe_patcher.py      │
         │  Timestamp, sections│
         └──────────┬──────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  ВЫХОД: loader.exe (упакованный payload)        │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼ (при запуске на цели)
┌─────────────────────────────────────────────────┐
│  1. Anti-VM / Anti-Debug / Anti-Sandbox         │
│  2. VirtualAlloc (RW)                           │
│  3. XOR-расшифровка payload в памяти            │
│  4. Reflective load:                            │
│     - Map headers                               │
│     - Map sections                              │
│     - Resolve imports (PEB walking)             │
│     - Apply relocations                         │
│     - Set per-section protection                │
│  5. Jump to entry point                         │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
         ┌─────────────────────┐
         │  Payload работает   │
         │  (reverse shell,    │
         │   marker, etc.)     │
         └─────────────────────┘
```

---

## 🔬 Технические детали

### Reflective PE Loader

Классический **reflective loader** работает так:

1. **Парсинг PE** — читаем DOS + NT заголовки
2. **VirtualAlloc** — выделяем память под образ
3. **Копирование секций** — из raw в memory
4. **Разрешение импортов** — вручную через PEB walking + API hashing
5. **Применение релокаций** — если загружено не по `preferred_base`
6. **VirtualProtect** — права по секциям (`.text` → RX, `.data` → RW)
7. **Entry point** — передаём управление

**Ключевое:** payload **никогда не касается диска** в открытом виде.
Windows loader не участвует. `LoadLibrary` не вызывается.

### API Hashing

**Проблема:** в Import Table видны `WSAConnect`, `CreateProcessA` — сигнатура reverse shell.

**Решение:** загружаем функции **по хешу имени**:

```c
u32 api_hash(const char* name) {
    u32 h = API_HASH_SEED;
    while (*name) {
        h = (h * 0x5BD1E995u) + (u8)*name;
        h ^= (h >> 13);
        h *= 0x85EBCA6Bu;
        name++;
    }
    h ^= (h >> 16);
    return h;
}
```

`resolve_api_by_hash` идёт по export table модуля и ищет функцию с нужным хешем.

**Результат:** в бинарнике **нет строк** `"WSAConnect"`, `"CreateProcessA"` и т.д.

### Forwarder Resolution

**Проблема:** в `kernel32.dll` многие функции — **форвардеры** в `kernelbase.dll`.
`HeapAlloc`, `GetProcessHeap`, `CreateFileA` — все форвардятся.

**Без обработки:** `resolve_api_by_hash` возвращает адрес **строки** `"KERNELBASE.HeapAlloc"`, а не функции. Вызов падает.

**Решение:** в `resolve_api_by_hash` проверяем, попадает ли RVA функции в диапазон `Export Directory`. Если да — это форвардер. Читаем строку, рекурсивно резолвим в целевой DLL.

### Anti-Analysis

**Score-based подход.** Не выходим при первом признаке — накапливаем:

| Проверка | Вес |
|----------|:---:|
| `PEB->BeingDebugged` | 2 |
| `NtGlobalFlag` | 2 |
| CPUID vendor (VMware/VBox) | 3 |
| RAM < 2 GB | 1 |
| CPU < 2 ядер | 1 |
| Uptime < 10 мин | 1 |
| Username в чёрном списке | 2 |
| Disk < 60 GB | 1 |

**Выход только при score >= 3.** Это снижает false positives на реальной машине с VBS/Hyper-V.

---

## ❓ FAQ

### BlindSpot работает на 32-битных Windows?

**Нет.** Только **x64**. Loader компилируется под AMD64.

### Payload должен быть 32-битным?

**Нет.** Только **PE32+ x64**. 32-битные payload'ы не загрузятся.

### Можно ли использовать на реальной машине?

**Только на своей.** См. [DISCLAIMER.md](DISCLAIMER.md).
На чужих системах — уголовная ответственность.

### Почему Microsoft Defender всё равно детектит?

**ML-детект** (`Trojan:Win32/Wacatac`). Microsoft обучает модель на миллиардах
образцов. Бесплатно обойти — невозможно. Только **подпись сертификатом**
($200-500/год).

### Почему Metasploit Meterpreter даёт 16/69, а самописный shell — 8/75?

**Meterpreter — самый известный payload в мире.** AV имеют его сигнатуры
на уровне **памяти**, а не только файла. BlindSpot убирает статику,
но AV эмулируют выполнение и находят Meterpreter после расшифровки.

**Самописный shell** — AV не имеют его сигнатур, поэтому 8/75.

### Можно ли обойти CrowdStrike?

**Частично.** CrowdStrike — enterprise EDR с kernel-mode компонентом.
Бесплатно — только **direct syscalls + unhooking**, но и они не гарантируют 100%.

### Что лучше — CLI или GUI?

**GUI** — удобнее, есть VT-интеграция.
**CLI** — быстрее, для скриптов.

Оба используют **один и тот же `builder.py`**.

### Можно ли коммерчески использовать?

**MIT License** разрешает. Но **использование на чужих системах — незаконно**.
Лицензия покрывает код, а не действия.

---

## 🛠️ Разработка

### Установка для разработки

```bash
git clone https://github.com/yourname/BlindSpot.git
cd BlindSpot
pip install -r requirements.txt
```

### Запуск GUI в режиме разработки

```bash
python blindspot_gui.py
```

### Тестирование

```bash
# Тестовый payload
python core/builder.py src/payload_test/payload_test.exe

# Проверка маркера
build/loader.exe
dir marker_from_final_loader.txt
```

### Сборка `.exe`

```bash
build_exe.bat
```

---

## 🤝 Вклад

Pull requests приветствуются.

**Что можно улучшить:**

- [ ] **Direct syscalls** (Hell's Gate) — обход user-mode хуков EDR
- [ ] **Sleep obfuscation** — payload зашифрован в памяти во время сна
- [ ] **Module Stomping** — инжект в `.text` легитимного модуля
- [ ] **AES/ChaCha20** — вместо XOR
- [ ] **Фейковые импорты** в PE — для обхода ML-детекта
- [ ] **Поддержка shellcode** — вместо PE
- [ ] **Автоматическая VT-проверка** через API
- [ ] **Пресеты** (Stealth / Balanced / Fast)

---

## 📜 Лицензия

**MIT License.** См. [LICENSE](LICENSE).

---

## ⚠️ Ответственность

BlindSpot — **educational project**.

**Не поддерживает:**
- Распространение малвари
- Атаки на инфраструктуру
- Любое действие против закона

**Используй только:**
- ✅ На своих системах
- ✅ В CTF (HackTheBox, TryHackMe)
- ✅ В авторизованном пентесте

Подробнее: [DISCLAIMER.md](DISCLAIMER.md).

---

<div align="center">

**BlindSpot** — сделан с нуля. За 2 дня. В 16 лет.

*Если проект помог — поставь ⭐ на GitHub.*

</div>