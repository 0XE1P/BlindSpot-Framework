<div align="center">

# ◈ BlindSpot

**Modular crypter/packer for security research**

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

*A PE packer with reflective loading, API hashing, and a full anti-analysis stack.*

[Features](#-features) • [Results](#-results) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#%EF%B8%8F-architecture) • [FAQ](#-faq)

</div>

---

> ⚠️ **DISCLAIMER**
>
> BlindSpot is an **educational tool** for security research.
> Use it **only** on systems you own or during **authorized** penetration tests.
> The author is not responsible for any misuse.
>
> See [DISCLAIMER.md](DISCLAIMER.md).

---

## 📖 What is BlindSpot

**BlindSpot** is a **crypter/packer** for Windows PE files (`.exe`).

It takes an **existing executable** (a reverse shell, a payload, a test binary)
and wraps it into an **obfuscated container** that:

- **Encrypts** the original payload (XOR)
- **Hides** it in memory via reflective PE loading
- **Reduces** the number of AV detections
- **Preserves** the functionality of the original file

**What sets it apart from off-the-shelf crypters:** BlindSpot is **open**,
**modular**, and **completely free**. Every component can be studied,
modified, and improved.

---

## 🎯 Results

### Summary

| Payload | Before BlindSpot | After BlindSpot | Reduction |
|---------|:----------------:|:---------------:|:---------:|
| **Custom reverse shell** | 22/70 | **8/75** | **−64%** |
| **Metasploit Meterpreter** | 44/71 | **16/69** | **−64%** |
| **Test marker** | — | 7/71 | — |

### What it bypasses

✅ **Kaspersky** (top-1 in Russia/Europe)
✅ **ESET** (top-3 worldwide)
✅ **BitDefender** (top-1 by detection rate)
✅ **Dr.Web**
✅ **Avast / AVG / Avira**
✅ **Trend Micro / Sophos / Malwarebytes**
✅ **Avira, F-Secure, Emsisoft, eScan, GData**
✅ **67 out of 75 AVs** do not detect the packed `rev.exe`

### What still detects

⚠️ **Microsoft Defender** (`Trojan:Win32/Wacatac`) — ML detection, signature only
⚠️ **CrowdStrike Falcon** (`Win/malicious_confidence_70-90%`) — behavior, direct syscalls
⚠️ **Symantec** (`ML.Attribute.HighConfidence`) — ML, signature only
⚠️ **Elastic** (`Malicious (high Confidence)`) — behavior

**These are enterprise/ML detections.** They can only be bypassed with a
**code signing certificate** ($200-500/year) or **direct syscalls** (weeks of work).

---

## ✨ Features

### 🔐 Cryptography

| Technique | Implementation |
|-----------|----------------|
| **Payload encryption** | XOR with a random 16-byte key |
| **String encryption** | XOR with a per-string key |
| **PE obfuscation** | Timestamp randomization, section renaming |
| **Polymorphism** | Function name randomization on every build |

### 🛡️ Anti-Analysis

- **Anti-VM** — CPUID vendor checks (`VMwareVMware`, `VBoxVBoxVBox`, `KVMKVMKVM`, `XenVMMXenVMM`)
- **Anti-Debug** — `PEB->BeingDebugged`, `IsDebuggerPresent`
- **Anti-Sandbox** — RAM, CPU, disk, uptime, username checks
- **Score-based approach** — does not trigger on real machines

### ⚙️ Reflective Loader

- **Zero imports** — `loader.exe` has no Import Table
- **Zero CRT** — compiled with `-nostdlib`
- **PEB walking** — module lookup without `GetModuleHandle`
- **API hashing** — MurmurHash for function names
- **Forwarder resolution** — `kernel32 → kernelbase`
- **Manual PE mapping** — sections, IAT, relocations
- **Per-section protection** — `.text` → RX, `.data` → RW

### 💻 GUI

- Dark / light theme
- Drag-and-drop payload
- Option checkboxes (Polymorphism, PE Patcher, String Encryption)
- **Built-in VT check** with report viewer
- Progress bar with percentages
- Colored log (info / ok / error / warn)
- Settings persistence between runs
- Portable `.exe` (PyInstaller)

---

## 🚀 Installation

### Requirements

| Component | Version | Required |
|-----------|---------|:--------:|
| **Windows** | 10/11 x64 | ✅ |
| **Python** | 3.9+ | ✅ for CLI/GUI |
| **MinGW-w64 (gcc)** | 13.0+ | ✅ for compiling the loader |
| **Git** | any | optional |

### Step 1. Clone the repository

```bash
git clone https://github.com/yourname/BlindSpot.git
cd BlindSpot
```

### Step 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 3. Install MinGW-w64

**Windows (MSYS2):**
1. Download [MSYS2](https://www.msys2.org/) and install to `C:\msys64\`
2. Open **MSYS2 UCRT64** and run:
   ```bash
   pacman -S mingw-w64-ucrt-x86_64-gcc
   ```
3. Add `C:\msys64\ucrt64\bin` to Windows `PATH`

**Linux / Kali:**
```bash
sudo apt update
sudo apt install mingw-w64
```

### Step 4. Verify installation

```bash
gcc --version
python --version
```

---

## 💡 Usage

### CLI

```bash
# Pack a payload
python core/builder.py path/to/payload.exe

# Output:
# → build/loader.exe
```

### GUI

```bash
python blindspot_gui.py
```

**Or** launch the prebuilt `.exe`:

```bash
dist/BlindSpot_v1.0/BlindSpotGUI.exe
```

### Build the GUI as `.exe`

```bash
build_exe.bat
```

**Output:** `dist/BlindSpot_v1.0/BlindSpotGUI.exe`

---

## 🏗️ Architecture

### Project structure

```
BlindSpot/
│
├── blindspot_gui.py              ← GUI (CustomTkinter)
├── build.bat                     ← loader build script
├── build_exe.bat                 ← GUI → .exe build script
├── requirements.txt
├── README.md
├── DISCLAIMER.md
├── LICENSE
│
├── core/                         ← Python (the brain)
│   ├── builder.py                ← main build orchestrator
│   ├── crypter.py                ← payload encryption
│   ├── pe_patcher.py             ← PE header patching
│   ├── polymorph.py              ← source polymorphism
│   └── string_crypt.py           ← string encryption
│
├── src/                          ← C (the loader)
│   ├── antianalysis/             ← Anti-VM / Anti-Debug
│   ├── common/                   ← types, memory, hashes
│   ├── loader/                   ← reflective loader
│   │   ├── main.c                ← entry point
│   │   ├── pe_parser.c/h         ← PE parsing
│   │   ├── api_resolver.c/h      ← PEB walking + hashing
│   │   ├── reflective.c/h        ← reflective mapping
│   │   └── decrypt.c/h           ← XOR decryption
│   ├── payload_test/             ← test payload
│   └── telemetry/                ← AMSI/ETW patches
│
├── config/                       ← JSON configs
│   ├── default.json
│   ├── fast.json
│   └── stealth.json
│
├── payloads/
│   ├── input/                    ← input .exe files
│   └── output/                   ← intermediate .bin files
│
└── build/                        ← build artifacts
```

### Data flow

```
┌─────────────────────────────────────────────────┐
│  INPUT: payload.exe (any PE32+ x64)             │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
         ┌─────────────────────┐
         │  converter.py       │  (optional)
         │  PE → shellcode     │
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  crypter.py         │
         │  XOR encryption     │  → payload_data.c
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  string_crypt.py    │
         │  String XOR         │  → strings.h
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  polymorph.py       │
         │  Name randomization │  → build/poly_src/
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  gcc compilation    │
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
│  OUTPUT: loader.exe (packed payload)            │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼ (on execution at target)
┌─────────────────────────────────────────────────┐
│  1. Anti-VM / Anti-Debug / Anti-Sandbox         │
│  2. VirtualAlloc (RW)                           │
│  3. XOR decryption of payload in memory         │
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
         │  Payload executes   │
         │  (reverse shell,    │
         │   marker, etc.)     │
         └─────────────────────┘
```

---

## 🔬 Technical details

### Reflective PE Loader

A classic **reflective loader** works like this:

1. **Parse PE** — read DOS + NT headers
2. **VirtualAlloc** — allocate memory for the image
3. **Copy sections** — from raw to memory
4. **Resolve imports** — manually via PEB walking + API hashing
5. **Apply relocations** — if not loaded at `preferred_base`
6. **VirtualProtect** — per-section protection (`.text` → RX, `.data` → RW)
7. **Entry point** — transfer control

**Key point:** the payload **never touches disk** in plaintext form.
The Windows loader is not involved. `LoadLibrary` is never called.

### API Hashing

**Problem:** the Import Table exposes `WSAConnect`, `CreateProcessA` — a reverse shell signature.

**Solution:** load functions **by name hash**:

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

`resolve_api_by_hash` walks the export table and matches the hash.

**Result:** the binary contains **no strings** like `"WSAConnect"` or `"CreateProcessA"`.

### Forwarder Resolution

**Problem:** in `kernel32.dll`, many functions are **forwarders** to `kernelbase.dll`.
`HeapAlloc`, `GetProcessHeap`, `CreateFileA` — all forwarded.

**Without handling:** `resolve_api_by_hash` returns the address of the string
`"KERNELBASE.HeapAlloc"` instead of the function. The call crashes.

**Solution:** inside `resolve_api_by_hash`, check whether the function RVA falls
into the `Export Directory` range. If so, it's a forwarder. Read the string and
recursively resolve it in the target DLL.

### Anti-Analysis

**Score-based approach.** We don't exit on the first signal — we accumulate:

| Check | Weight |
|-------|:------:|
| `PEB->BeingDebugged` | 2 |
| `NtGlobalFlag` | 2 |
| CPUID vendor (VMware/VBox) | 3 |
| RAM < 2 GB | 1 |
| CPU < 2 cores | 1 |
| Uptime < 10 min | 1 |
| Username in blacklist | 2 |
| Disk < 60 GB | 1 |

**Exit only when score >= 3.** This reduces false positives on real machines
with VBS/Hyper-V enabled.

---

## ❓ FAQ

### Does BlindSpot work on 32-bit Windows?

**No.** Only **x64**. The loader compiles for AMD64.

### Does the payload have to be 32-bit?

**No.** Only **PE32+ x64**. 32-bit payloads won't load.

### Can I use it on a real machine?

**Only on your own.** See [DISCLAIMER.md](DISCLAIMER.md).
On other people's systems — criminal liability.

### Why does Microsoft Defender still detect it?

**ML detection** (`Trojan:Win32/Wacatac`). Microsoft trains its model on
billions of samples. Bypassing it for free is impossible. Only a
**code signing certificate** ($200-500/year) will help.

### Why does Metasploit Meterpreter give 16/69, while a custom shell gives 8/75?

**Meterpreter is the most well-known payload in the world.** AVs have
signatures for it at the **memory** level, not just on disk. BlindSpot strips
the static signatures, but AVs emulate execution and find Meterpreter after
decryption.

**Custom shells** have no known signatures, hence 8/75.

### Can I bypass CrowdStrike?

**Partially.** CrowdStrike is an enterprise EDR with a kernel-mode component.
For free — only **direct syscalls + unhooking**, and even those don't guarantee 100%.

### CLI or GUI — which is better?

**GUI** — more convenient, includes VT integration.
**CLI** — faster, script-friendly.

Both use the **same `builder.py`**.

### Can I use it commercially?

The **MIT License** allows it. But **using it on someone else's systems is illegal**.
The license covers the code, not the actions.

---

## 🛠️ Development

### Setup for development

```bash
git clone https://github.com/yourname/BlindSpot.git
cd BlindSpot
pip install -r requirements.txt
```

### Run the GUI in dev mode

```bash
python blindspot_gui.py
```

### Testing

```bash
# Build a test payload
python core/builder.py src/payload_test/payload_test.exe

# Check the marker
build/loader.exe
dir marker_from_final_loader.txt
```

### Build `.exe`

```bash
build_exe.bat
```

---

## 🤝 Contributing

Pull requests are welcome.

**Ideas for improvement:**

- [ ] **Direct syscalls** (Hell's Gate) — bypass user-mode EDR hooks
- [ ] **Sleep obfuscation** — payload encrypted in memory during sleep
- [ ] **Module Stomping** — inject into a legitimate module's `.text`
- [ ] **AES/ChaCha20** — instead of XOR
- [ ] **Fake imports** in the PE — to bypass ML detection
- [ ] **Shellcode support** — instead of PE
- [ ] **Automated VT check** via API
- [ ] **Presets** (Stealth / Balanced / Fast)

---

## 📜 License

**MIT License.** See [LICENSE](LICENSE).

---

## ⚠️ Responsibility

BlindSpot is an **educational project**.

**It does not support:**
- Distribution of malware
- Attacks on infrastructure
- Any illegal activity

**Use it only:**
- ✅ On your own systems
- ✅ In CTFs (HackTheBox, TryHackMe)
- ✅ In authorized penetration tests

More details: [DISCLAIMER.md](DISCLAIMER.md).

---

<div align="center">

**BlindSpot**

*If this project helped you — leave a ⭐ on GitHub.*

</div>
