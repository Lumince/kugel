# toolconf.py — Windows tool paths (repo-local first, then PATH)
import os, shutil

HERE = os.path.dirname(os.path.abspath(__file__))

def _pick(*cands):
    for c in cands:
        if not c: continue
        if os.path.isabs(c) and os.path.exists(c): return c
        w = shutil.which(c)
        if w: return w
    return cands[-1]   # fall through so the use-site failure is obvious

# --- AOSP clang (same toolchain dfrag uses) ---
_CLANG_BIN = r"C:\android-ndk\toolchains\llvm\prebuilt\windows-x86_64\bin"
READELF = _pick(os.path.join(_CLANG_BIN, "llvm-readelf.exe"), "llvm-readelf")
NM      = _pick(os.path.join(_CLANG_BIN, "llvm-nm.exe"),      "llvm-nm")
OBJDUMP = _pick(os.path.join(_CLANG_BIN, "llvm-objdump.exe"), "llvm-objdump")   # NEW

# --- payload-dumper-go: repo root, or repo\ntools\, or an absolute install ---
PDG = _pick(
    os.path.join(HERE, "payload-dumper-go.exe"),
    os.path.join(HERE, "payload-dumper-go.EXE"),
    os.path.join(HERE, "tools", "payload-dumper-go.exe"),
    os.path.join(HERE, "tools", "payload-dumper-go.EXE"),
    "payload-dumper-go",
)

# --- e2fsprogs (Cygwin build): repo\tools\debugfs.exe + its DLLs live alongside ---
DEBUGFS = _pick(
    os.path.join(HERE, "tools", "debugfs.exe"),
    r"C:\tools\e2fsprogs\bin\debugfs.exe",
    "debugfs",
)

# --- vmlinux-to-elf: pip console script ---
VMLINUX_TO_ELF = _pick(
    os.path.join(HERE, "tools", "vmlinux-to-elf.exe"),
    r"C:\Users\user\AppData\Local\Programs\Python\Python313\Scripts\vmlinux-to-elf.exe",
    "vmlinux-to-elf",
)