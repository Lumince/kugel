#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-IonStack-Proprietary
# Copyright (C) 2026 darknight1050
# Copyright (C) 2026 Liem Eldert. All rights reserved.
#
# derive_target_q2.py — derive kugel offsets for a Quest 2 / Quest Pro build
# (4.19 msm kernels) from its OTA boot image.
#
# Pulls ONLY boot.img from an OTA zip (~64 MB), runs vmlinux-to-elf, resolves
# kugel.map against nm, disassembles kgsl_drawobj_destroy_object to pick the
# epilogue ret, disassembles worker_thread (and fallbacks) to pick the tracefs
# sched_blocked_reason caller offset, reads cap_last_cap from .rodata, writes
# targets/<name>.json.
#
# All offsets are (symbol - _text), i.e. text-relative. kugel does
# `kbase + OFF_*`, where kbase is the runtime _text, so KASLR cancels.
#
# OFF_TRACE_WCHAN: fixed offset from _text of the kernel address the
# sched_blocked_reason tracepoint records in its `caller` field on this build.
#
# Mechanism: the tracepoint stores caller = get_wchan(prev), which walks the
# blocked task's stack to the return address of the function that called
# schedule(). For an idle kworker blocking directly at `bl schedule` inside
# worker_thread, that return address is worker_thread+N — and that is the
# value the tracefs leak reads from trace_pipe_raw, then subtracts _text to
# recover the KASLR base.
#
# Resolution priority (each stage stops at the first hit):
#   1. bl <schedule> in worker_thread idle path   ("bl-schedule-in-worker")
#      — canonical. The idle path releases the pool lock, calls schedule()
#        directly, and re-acquires the lock on wakeup. Verified against
#        QPro 51483620027600340 where the value is worker_thread+0x98
#        (0x63a84 from _text).
#   2. bl <sched_blocked_reason-target> in __schedule      ("bl-to-trace")
#      — legacy fallback for builds where the tracepoint records the
#        callsite of the trace function rather than the wchan return
#        address. Rare on msm 4.19.
#   3. blr inside __schedule                               ("blr")
#      — for indirect tracepoint invocation.
#   4. bl schedule/__schedule in __rt_mutex_slowlock*      ("bl-rtmutex")
#      — legacy fallback for the rt_mutex slowpath.
#   5. --trace-wchan-manual <value>                        ("manual")
#      — explicit override.
#
# If validation fails, iterate over trace_wchan_candidates with
# KUGEL_KASLR_SOURCE=verify, or force a value via --trace-wchan-manual.
#
# Note on CONFIG_KALLSYMS_ALL:
#   A build without it exports only function symbols to kallsyms. Data
#   symbols (root_user, init_user_ns, init_groups, selinux_state, modedb)
#   are missing and this tool CANNOT recover them. That is a hard limit of
#   vmlinux-to-elf. Affects the Android 12 Q2 line (4.19.157+); the A14
#   builds have KALLSYMS_ALL=y and resolve normally.
#
# usage:
#   derive_target_q2.py --zip q2_<build>.zip --ident
#   derive_target_q2.py --zip q2_<build>.zip --name q2_<build>
#   derive_target_q2.py --boot boot.img --name q2_<build>
#   derive_target_q2.py --elf vmlinux.elf --name q2_<build>
#   derive_target_q2.py --import-targets
#
# Exit codes: 0 ok; 1 unresolved mandatory symbol; 2 usage / tool error.

import argparse
import atexit
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from toolconf import NM, OBJDUMP, PDG, READELF, VMLINUX_TO_ELF

DEFAULT_MAP = os.path.join(HERE, "kugel.map")
DEFAULT_TARGETS = os.path.join(HERE, "targets")
DEFAULT_REGISTRY = os.path.join(HERE, "targets.tsv")
NO_VALUE = "-"
SPECIAL_MACROS = {"OFF_RET", "OFF_TRACE_WCHAN"}
REGISTRY_MACROS = ("OFF_COMMIT_CREDS", "OFF_ROOT_USER", "OFF_INIT_USER_NS",
                   "OFF_INIT_GROUPS", "OFF_SELINUX_STATE", "OFF_SECBLOB",
                   "OFF_RET", "OFF_TRACE_WCHAN",
                   "OFF_FIND_VPID", "OFF_PID_TASK", "OFF_SSUSE")
REGISTRY_COLUMNS = ("incremental", "name", "vermagic", "text_base",
                    *REGISTRY_MACROS, "cap_last_cap", "status")
STATUS_RANK = {"": 0, "unverified": 1, "derived": 2, "booted": 3}


def die(msg, code=2):
    sys.stderr.write("ERROR: %s\n" % msg)
    sys.exit(code)


# ------------------------------------------------------------- extraction --

def extract_boot_from_zip(zippath, workdir):
    try:
        with zipfile.ZipFile(zippath) as z:
            z.extract("payload.bin", workdir)
    except (KeyError, zipfile.BadZipFile) as e:
        die("%s: no readable payload.bin (%s)" % (zippath, e))
    r = subprocess.run([PDG, "-p", "boot", "-o", workdir,
                        os.path.join(workdir, "payload.bin")],
                       capture_output=True, text=True)
    boot = os.path.join(workdir, "boot.img")
    if not os.path.exists(boot) or os.path.getsize(boot) == 0:
        die("payload-dumper-go produced no boot.img (exit %d)\n"
            "stdout: %s\nstderr: %s"
            % (r.returncode,
               (r.stdout or "").strip()[-500:],
               (r.stderr or "").strip()[-500:]))
    print("[*] boot.img: %d bytes" % os.path.getsize(boot))
    return boot


def elf_from_boot(boot, workdir):
    out = os.path.join(workdir, "vmlinux.elf")
    r = subprocess.run([VMLINUX_TO_ELF, boot, out],
                       capture_output=True, text=True)
    if not os.path.exists(out) or os.path.getsize(out) == 0:
        die("vmlinux-to-elf produced no output from %s (exit %d)\n"
            "stdout: %s\nstderr: %s"
            % (boot, r.returncode,
               (r.stdout or "").strip()[-1000:],
               (r.stderr or "").strip()[-1000:]))
    size = os.path.getsize(out)
    print("[*] vmlinux.elf: %d bytes" % size)
    if r.returncode != 0:
        sys.stderr.write(
            "[!] vmlinux-to-elf exited %d but produced a file; check:\n%s\n"
            % (r.returncode, (r.stderr or "").strip()[-500:]))
    elif (r.stderr or "").strip():
        for line in (r.stderr or "").strip().splitlines()[:6]:
            print("    v2e: %s" % line)
    return out


def kernel_banner(elf):
    data = open(elf, "rb").read()
    m = re.search(rb"Linux version "
                  rb"([0-9]+\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9.\-]+)?\+?)", data)
    return m.group(1).decode() if m else None


def infer_incremental(name_or_zip):
    m = re.search(r"(\d{6,})", os.path.basename(name_or_zip or ""))
    return m.group(1) if m else None


# ------------------------------------------------------------- symbols ----

def read_symbols(elf):
    r = subprocess.run([NM, "-n", elf], capture_output=True, text=True)
    if r.returncode != 0:
        die("nm failed on %s: %s" % (elf, (r.stderr or "").strip()))
    syms = {}
    ordered = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        if len(parts) >= 4 and parts[3].startswith("["):
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        syms.setdefault(parts[2], addr)
        ordered.append(addr)
    ordered.sort()
    return syms, ordered


def pick_text_symbol(syms, elf):
    if "_text" in syms:
        if "_stext" in syms and syms["_stext"] != syms["_text"]:
            sys.stderr.write(
                "note: _text=%#x and _stext=%#x differ; using _text\n"
                % (syms["_text"], syms["_stext"]))
        return "_text", syms["_text"], "direct"

    if "_stext" not in syms:
        if not syms:
            die("no symbols at all in %s\n"
                "  vmlinux-to-elf produced an ELF but with an empty .symtab.\n"
                "  Most likely the boot.img does not contain a compressible\n"
                "  kernel (corrupt zip, or wrong partition extracted).\n"
                "  Check that payload.bin in the zip is intact." % elf)
        sample = [n for n, _ in sorted(syms.items(), key=lambda kv: kv[1])[:20]]
        die("no _text or _stext in %s (total symbols: %d)\n"
            "  First 20 symbols present:\n    %s\n"
            "  If the list looks like user-space symbols or section names,\n"
            "  the ELF is not a vmlinux -- vmlinux-to-elf may have failed to\n"
            "  find the kernel inside this specific boot.img."
            % (elf, len(syms), ", ".join(sample)))

    inferred = syms["_stext"] - 0x1000
    sys.stderr.write(
        "warning: no _text symbol; inferring _text = _stext - 0x1000 = %#x\n"
        "  _stext=%#x. This assumes the standard arm64 layout where\n"
        "  .head.text is one 4 KiB page. If a build ever uses a different\n"
        "  head.text size, the inferred _text will be wrong and every\n"
        "  offset shifted by that delta. Verify against a kallsyms dump\n"
        "  if the derived offsets don't work on device.\n"
        % (inferred, syms["_stext"]))
    return "_text_inferred_from_stext", inferred, "inferred"


def resolve(entry, syms):
    delta = 0
    if "+" in entry:
        sym, off = entry.split("+", 1)
        try:
            delta = int(off, 16)
        except ValueError:
            return None
    else:
        sym = entry
    if sym not in syms:
        return None
    return syms[sym] + delta


def load_map(path):
    rows = []
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            die("bad map line in %s: %r" % (path, line))
        macro, entry = parts[0], parts[1]
        optional = macro.startswith("?")
        if optional:
            macro = macro[1:]
        rows.append((macro, entry, optional))
    return rows


# ------------------------------------------------------------- OFF_RET ----

def find_rets(elf, start, end):
    r = subprocess.run([OBJDUMP, "-d", elf,
                        "--start-address=0x%x" % start,
                        "--stop-address=0x%x" % end],
                       capture_output=True, text=True)
    rets = []
    for line in r.stdout.splitlines():
        m = re.match(r"\s*([0-9a-fA-F]+):\s+\S+\s+ret\b", line)
        if m:
            rets.append(int(m.group(1), 16))
    return rets


# FIX: accept max_span; when the symbol table has a gap after `start`,
# `next symbol` can be far away and previously caused the "inside __schedule"
# candidate list to include functions that are not actually in __schedule.
def _end_of(sym_name, start, ordered, max_span=0x8000):
    nxt = next((a for a in ordered if a > start), start + max_span)
    if nxt - start > max_span:
        nxt = start + max_span
    return nxt


def resolve_off_ret(syms, ordered, elf, map_entry, do_disasm, text_base):
    if "+" in map_entry:
        func, hint_hex = map_entry.split("+", 1)
        hint = int(hint_hex, 16)
    else:
        func, hint = map_entry, None

    if func not in syms:
        return None, "symbol %r not found" % func, []
    start = syms[func]

    if do_disasm:
        # FIX: cap the range so we don't disassemble into the next function.
        end = _end_of(func, start, ordered, max_span=0x2000)
        rets = find_rets(elf, start, end)
        if rets:
            epilogue = rets[-1]
            if hint is not None and start + hint != epilogue:
                sys.stderr.write(
                    "note: kugel.map says %s+0x%x, disasm says +0x%x; "
                    "using disasm\n" % (func, hint, epilogue - start))
            return epilogue - text_base, None, [r - text_base for r in rets]
        if hint is None:
            return None, "no ret found in %s" % func, []

    if hint is None:
        return None, "no hint in map and disasm unavailable", []
    return (start + hint) - text_base, None, []


# ----------------------------------------------------- OFF_TRACE_WCHAN ----
#
# The sched_blocked_reason tracepoint records caller = get_wchan(prev),
# which walks the blocked task's stack to the return address of the
# function that called schedule(). For an idle kworker blocking directly
# at `bl schedule` inside worker_thread, that return address is
# worker_thread+N — the value the tracefs leak reads from trace_pipe_raw
# and then subtracts _text to recover the KASLR base.
#
# Resolution priority (each stage stops at the first hit):
#
#   1. bl <schedule> in worker_thread idle path   ("bl-schedule-in-worker")
#      -> canonical. The idle kworker releases the pool lock, calls
#         schedule() directly, and re-acquires the lock on wakeup.
#
#   2. bl <sched_blocked_reason-related symbol> inside __schedule
#      ("bl-to-trace")
#      -> legacy fallback: for builds where the tracepoint records the
#         callsite of the trace function rather than the wchan return
#         address. Rare on msm 4.19.
#
#   3. blr inside __schedule                      ("blr")
#      -> for builds where the tracepoint is invoked indirectly.
#
#   4. bl schedule / __schedule inside __rt_mutex_slowlock*
#      ("bl-rtmutex")
#      -> legacy fallback for the rt_mutex slowpath.
#
# Without disasm, we cannot disambiguate; the script reports the map hint
# (if any) and asks the user to test with KUGEL_KASLR_SOURCE=verify.
#

BL_PAT = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+\S+\s+bl\s+[0-9a-fA-F]+\s+<([^>+]+)(?:\+[^>]*)?>")
BLR_PAT = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+\S+\s+blr\s+\S+")
INSN_PAT = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]+)\s+(\S+)\s*(.*)$")
_MOV_X0_RE = re.compile(r"^x0,\s*x\d+")


def disasm(elf, start, end):
    r = subprocess.run([OBJDUMP, "-d", elf,
                        "--start-address=0x%x" % start,
                        "--stop-address=0x%x" % end],
                       capture_output=True, text=True)
    return r.stdout


def find_bl_to(elf, start, end, targets):
    text = disasm(elf, start, end)
    hits = []
    for line in text.splitlines():
        m = BL_PAT.match(line)
        if not m:
            continue
        if m.group(2) in targets:
            hits.append((int(m.group(1), 16), m.group(2)))
    return hits


def find_blr_in(elf, start, end):
    text = disasm(elf, start, end)
    hits = []
    for line in text.splitlines():
        m = BLR_PAT.match(line)
        if m:
            hits.append(int(m.group(1), 16))
    return hits


def _parse_insns(text):
    insns = []
    for line in text.splitlines():
        m = INSN_PAT.match(line)
        if not m:
            continue
        insns.append({
            "addr": int(m.group(1), 16),
            "mnem": m.group(3),
            "op": m.group(4).split(";")[0].strip(),
        })
    return insns


def find_worker_idle_schedule(elf, syms, ordered, text_base):
    """Find `bl <schedule>` inside worker_thread on the idle path.

    Idle kworkers that have nothing to do release the pool lock, call
    schedule() directly, and re-acquire the pool lock on wakeup. The
    compiler emits:

        bl  _raw_spin_unlock_irq
        ...
        bl  schedule
        mov x0, pool          ; reload pool, clobbered by the call
        bl  _raw_spin_lock_irq

    The return address after `bl schedule` is what get_wchan() reports
    for this task, and it is what the tracefs leak consumes.

    Scoring is used so that if worker_thread contains more than one
    `bl schedule`, the idle-path one (unlock -> schedule -> lock,
    with a pool reload in between) wins. Non-idle schedules don't
    have that shape.
    """
    if "worker_thread" not in syms:
        return []
    start = syms["worker_thread"]
    end = _end_of("worker_thread", start, ordered, max_span=0x1000)
    insns = _parse_insns(disasm(elf, start, end))

    hits = []
    for i, insn in enumerate(insns):
        if insn["mnem"] != "bl" or "<schedule>" not in insn["op"]:
            continue
        if i + 1 >= len(insns):
            continue
        ret = insns[i + 1]["addr"]
        score, reasons = 0, []

        # Preceding window: pool lock release.
        for k in range(max(0, i - 8), i):
            if insns[k]["mnem"] == "bl" and "unlock" in insns[k]["op"]:
                score += 100
                reasons.append("preceded by unlock")
                break

        # Following window: pool lock re-acquire (exclude unlock).
        for k in range(i + 1, min(i + 5, len(insns))):
            if (insns[k]["mnem"] == "bl"
                    and "lock" in insns[k]["op"]
                    and "unlock" not in insns[k]["op"]):
                score += 50
                reasons.append("followed by lock")
                break

        # Immediately after: reload of the pool register into x0.
        nxt = insns[i + 1]
        if nxt["mnem"] == "mov" and _MOV_X0_RE.match(nxt["op"]):
            score += 25
            reasons.append("pool reload")

        hits.append({
            "offset": ret - text_base,
            "site": "bl schedule in worker_thread @%#x" % insn["addr"],
            "addr": ret,
            "score": score,
            "reason": "; ".join(reasons) or "no context match",
        })

    hits.sort(key=lambda h: h["score"], reverse=True)
    return hits


# FIX: rewritten with priority order and capped ranges, plus a "source"
# string so the JSON records how the value was obtained.
def resolve_off_trace_wchan(syms, ordered, elf, text_base, do_disasm):
    """Return (offset_or_None, source, candidates)."""
    cand = []

    if not do_disasm:
        return None, "no-disasm", []

    # Priority 1: bl <schedule> in worker_thread idle path.
    # Canonical mechanism: get_wchan(prev) returns the return address from
    # `bl schedule` on the blocked worker's stack.
    hits = find_worker_idle_schedule(elf, syms, ordered, text_base)
    if hits:
        return hits[0]["offset"], "bl-schedule-in-worker", hits

    # Priority 2: bl <sched_blocked_reason target> inside __schedule.
    if "__schedule" in syms:
        start = syms["__schedule"]
        end = _end_of("__schedule", start, ordered, max_span=0x8000)
        trace_targets = {n for n in syms if "sched_blocked_reason" in n}
        trace_targets |= {
            "__traceiter_sched_blocked_reason",
            "__trace_sched_blocked_reason",
            "trace_event_raw_event_sched_blocked_reason",
            "trace_event_raw_event_sched_blocked_reason_",
        }
        for addr, target in find_bl_to(elf, start, end, trace_targets):
            cand.append({
                "offset": addr + 4 - text_base,
                "site": "bl %s in __schedule @%#x" % (target, addr),
                "addr": addr + 4,
                "score": 0,
                "reason": "",
            })
        if cand:
            return cand[0]["offset"], "bl-to-trace", cand

    # Priority 3: blr inside __schedule (indirect tracepoint invocation).
    if "__schedule" in syms:
        start = syms["__schedule"]
        end = _end_of("__schedule", start, ordered, max_span=0x8000)
        for addr in find_blr_in(elf, start, end):
            cand.append({
                "offset": addr + 4 - text_base,
                "site": "blr inside __schedule @%#x" % addr,
                "addr": addr + 4,
                "score": 0,
                "reason": "",
            })
        if cand:
            return cand[0]["offset"], "blr", cand

    # Priority 4: bl schedule/__schedule inside rt_mutex slowpath.
    for fn in ("__rt_mutex_slowlock_locked", "rt_mutex_slowlock_locked",
               "__rt_mutex_slowlock", "rt_mutex_slowlock"):
        if fn not in syms:
            continue
        start = syms[fn]
        end = _end_of(fn, start, ordered, max_span=0x2000)
        for addr, target in find_bl_to(elf, start, end,
                                       {"schedule", "__schedule"}):
            cand.append({
                "offset": addr + 4 - text_base,
                "site": "bl %s in %s @%#x" % (target, fn, addr),
                "addr": addr + 4,
                "score": 0,
                "reason": "",
            })
        if cand:
            return cand[0]["offset"], "bl-rtmutex", cand

    return None, "not-found", []


# ----------------------------------------------------- cap_last_cap -------

def find_file_offset(elf, vaddr):
    r = subprocess.run([READELF, "-lW", elf], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        m = re.match(r"\s*LOAD\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+"
                     r"0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+0x[0-9a-fA-F]+", line)
        if not m:
            continue
        foff, vstart, filesz = int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16)
        if vstart <= vaddr < vstart + filesz:
            return foff + (vaddr - vstart)
    return None


def read_cap_last_cap(elf, syms):
    if "cap_last_cap" not in syms:
        return None, "cap_last_cap not in symbol table"
    foff = find_file_offset(elf, syms["cap_last_cap"])
    if foff is None:
        return None, "cap_last_cap in BSS; read /proc/sys/kernel/cap_last_cap"
    with open(elf, "rb") as fh:
        fh.seek(foff)
        raw = fh.read(4)
    if len(raw) < 4:
        return None, "cap_last_cap past EOF"
    v = struct.unpack("<I", raw)[0]
    if v == 0:
        return None, "cap_last_cap is 0 in file; read /proc at runtime"
    return v, None


# ------------------------------------------------------------- registry ---

def read_registry(path):
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw.strip():
                entries.append(("blank", raw, None))
            elif raw.lstrip().startswith("#"):
                entries.append(("comment", raw, None))
            else:
                cols = raw.split("\t")
                if len(cols) != len(REGISTRY_COLUMNS):
                    entries.append(("comment", raw, None))
                else:
                    entries.append(("row", raw, cols))
    return entries


def write_registry(path, entries, dry_run):
    text = "".join(("\t".join(c) if kind == "row" else raw) + "\n"
                   for kind, raw, c in entries)
    if dry_run:
        return
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                               prefix=".targets.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        try:
            os.chmod(tmp, os.stat(path).st_mode & 0o7777)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def insert_row(entries, cols):
    prefix = cols[1].split("_", 1)[0]
    same = [i for i, e in enumerate(entries)
            if e[0] == "row" and e[2][1].split("_", 1)[0] == prefix]
    if not same:
        if entries and entries[-1][0] != "blank":
            entries.append(("blank", "", None))
        entries.append(("row", None, cols))
        return len(entries) - 1
    for i in same:
        if entries[i][2][0] > cols[0]:
            entries.insert(i, ("row", None, cols))
            return i
    entries.insert(same[-1] + 1, ("row", None, cols))
    return same[-1] + 1


def update_registry(args, name, incremental, vermagic, text_base, offsets, cap):
    entries = read_registry(args.registry)
    ds = [("0x%x" % offsets[m]) if offsets.get(m) is not None else NO_VALUE
          for m in REGISTRY_MACROS]
    cols = [incremental or NO_VALUE, name, vermagic or NO_VALUE,
            "0x%x" % text_base, *ds,
            str(cap) if cap is not None else NO_VALUE, "derived"]

    existing = next((e for e in entries
                     if e[0] == "row" and e[2][0] == cols[0]), None)
    if existing is None:
        insert_row(entries, cols)
        print("targets.tsv: ADD  %s" % cols[0])
    else:
        before = list(existing[2])
        existing[2][:] = cols[:len(cols) - 1] + [existing[2][-1]]
        if before == existing[2]:
            print("targets.tsv: OK   %s already correct" % cols[0])
        else:
            print("targets.tsv: EDIT %s" % cols[0])
            for i, key in enumerate(REGISTRY_COLUMNS):
                if before[i] != existing[2][i]:
                    print("  %-14s %r -> %r"
                          % (key, before[i], existing[2][i]))
    write_registry(args.registry, entries, args.dry_run)
    if args.dry_run:
        print("(--dry-run: nothing written)")


# --------------------------------------------------------------- main -----

def load_elf(args, workdir):
    if args.elf:
        if not os.path.exists(args.elf) or os.path.getsize(args.elf) == 0:
            die("--elf %s is missing or empty" % args.elf)
        return args.elf
    if args.boot:
        return elf_from_boot(args.boot, workdir)
    if args.zip:
        return elf_from_boot(extract_boot_from_zip(args.zip, workdir), workdir)
    die("need --zip, --boot, or --elf")


def derive(args, workdir):
    elf = load_elf(args, workdir)
    syms, ordered = read_symbols(elf)
    text_sym, text, text_kind = pick_text_symbol(syms, elf)

    release = kernel_banner(elf)
    vermagic = args.vermagic or release

    name = args.name
    if not name and args.zip:
        name = os.path.splitext(os.path.basename(args.zip))[0]
    incremental = args.incremental or infer_incremental(name)

    if args.ident:
        print("kernel_release=%s" % release)
        print("vermagic=%s" % vermagic)
        print("build_incremental=%s" % (incremental or "UNKNOWN"))
        print("text_symbol=%s (%s)" % (text_sym, text_kind))
        print("text_base=0x%x" % text)
        print("symbol_count=%d" % len(syms))
        return 0

    if not name:
        die("--name is required (could not infer from a zip basename)")

    rows = load_map(args.map)
    offsets = {}
    missing, opt_missing = [], []
    for macro, entry, optional in rows:
        if macro in SPECIAL_MACROS:
            continue
        v = resolve(entry, syms)
        if v is None:
            (opt_missing if optional else missing).append(
                "%s(%s)" % (macro, entry))
            offsets[macro] = None
        else:
            offsets[macro] = v - text

    ret_off, ret_why, ret_candidates = None, None, []
    map_ret = next((e for m, e, _o in rows if m == "OFF_RET"), None)
    if map_ret is None:
        missing.append("OFF_RET(no map entry)")
    else:
        ret_off, ret_why, ret_candidates = resolve_off_ret(
            syms, ordered, elf, map_ret,
            do_disasm=not args.no_disasm, text_base=text)
    if ret_off is None and map_ret is not None:
        if args.no_disasm or not ret_candidates:
            missing.append("OFF_RET(%s)" % (ret_why or "no hint"))
    offsets["OFF_RET"] = ret_off

    # FIX: --trace-wchan-manual bypasses derivation entirely.
    tw_off, tw_src, tw_why, tw_candidates = None, None, None, []
    if args.trace_wchan_manual is not None:
        tw_off = int(args.trace_wchan_manual, 0)
        tw_src = "manual"
        sys.stderr.write(
            "note: OFF_TRACE_WCHAN forced to 0x%x via --trace-wchan-manual\n"
            % tw_off)
    else:
        tw_off, tw_src, tw_candidates = resolve_off_trace_wchan(
            syms, ordered, elf, text, do_disasm=not args.no_disasm)
        if tw_off is None and tw_src == "not-found":
            tw_why = "no bl/blr candidates in worker_thread/__schedule/rtmutex"
    offsets["OFF_TRACE_WCHAN"] = tw_off

    if opt_missing:
        for m in opt_missing:
            print("note: optional %s missing (ok)" % m)
    if missing and not args.force_partial:
        data_missing = [m for m in missing
                        if any(m.startswith(x + "(") for x in
                               ("OFF_ROOT_USER", "OFF_INIT_USER_NS",
                                "OFF_INIT_GROUPS", "OFF_SELINUX_STATE",
                                "OFF_SECBLOB"))]
        msg = "\nERROR: unresolved mandatory: " + ", ".join(missing) + "\n\n"
        if data_missing:
            msg += (
                "  %d of the unresolved symbols are DATA (not functions).\n"
                "  vmlinux-to-elf can only recover symbols that are in\n"
                "  kallsyms. Kernels built without CONFIG_KALLSYMS_ALL\n"
                "  export only functions, so data symbols cannot be\n"
                "  recovered from the boot.img alone.\n"
                "\n"
                "  This affects the Android 12 Quest 2 line (4.19.157+)\n"
                "  and any other older build without KALLSYMS_ALL. The\n"
                "  A14 builds do have it and derive normally.\n"
                "\n"
                "  Options for a build in this state:\n"
                "    * skip it -- kugel is a 5.10/A14-era chain\n"
                "    * obtain a rooted /proc/kallsyms dump for this\n"
                "      exact build and read the data addresses directly\n"
                "    * derive the data symbols by disassembly analysis\n"
                "      (much more work; not automated here)\n"
                "\n"
                "  --force-partial does NOT help: the missing data\n"
                "  symbols are load-bearing, and any offsets this tool\n"
                "  would write for them are wrong.\n"
            ) % len(data_missing)
        sys.stderr.write(msg)
        sys.exit(1)

    cap, cap_why = read_cap_last_cap(elf, syms)
    cap_full = (1 << (cap + 1)) - 1 if cap is not None else None

    target = {
        "name": name,
        "description": "build %s, kernel %s"
                       % (incremental or "unknown", vermagic or "unknown"),
        "device": {
            "build_incremental": incremental,
            "vermagic": vermagic,
        },
        "kernel": {
            "text_symbol": text_sym,
            "text_kind": text_kind,
            "text_base": "0x%x" % text,
            "offsets": {k: (("0x%x" % v) if v is not None else None)
                        for k, v in offsets.items()},
            "ret_candidates": ["0x%x" % r for r in ret_candidates],
            "trace_wchan_source": tw_src,
            "trace_wchan_candidates": [
                {"offset": "0x%x" % c["offset"],
                 "site": c["site"],
                 "addr": "0x%x" % c["addr"]}
                for c in tw_candidates
            ],
            "cap_last_cap": cap,
            "cap_full": ("0x%x" % cap_full) if cap_full is not None else None,
            # Struct layout constants for the adbd cred-patch path.
            # These are NOT kernel symbols; they are fixed for the 4.19 msm
            # kernel family (Quest 2 / Quest Pro). KUGEL checks find_vpid != 0
            # to decide between the cred-patch path and the legacy SIGKILL path.
            "cred_off":          "0x7e8",   # offsetof(task_struct, cred), 4.19 msm
            "enforcing_off":     1,          # offsetof(selinux_state, enforcing), 4.19
            "cred_security_off": "0x78",    # offsetof(struct cred, security), all msm
        },
    }
    if cap_why:
        target["kernel"]["cap_note"] = cap_why
    if text_kind == "inferred":
        target["kernel"]["text_inferred"] = True
    if missing:
        target["partial"] = True
        target["unresolved"] = missing

    os.makedirs(args.targets, exist_ok=True)
    out = os.path.join(args.targets, name + ".json")
    if args.dry_run:
        print(json.dumps(target, indent=2))
    else:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(target, fh, indent=2)
        print("wrote %s" % out)

    update_registry(args, name, incremental, vermagic, text, offsets, cap)
    if cap_why:
        sys.stderr.write("note: %s\n" % cap_why)
    if ret_candidates and len(ret_candidates) > 1:
        sys.stderr.write(
            "note: %d rets in kgsl_drawobj_destroy_object at +%s; "
            "using the last (epilogue)\n"
            % (len(ret_candidates),
               ", +0x".join("%x" % r for r in ret_candidates)))
    if tw_off is not None:
        sys.stderr.write(
            "note: OFF_TRACE_WCHAN = 0x%x (source=%s)\n" % (tw_off, tw_src))
    if tw_candidates and tw_src != "manual":
        sys.stderr.write(
            "       %d candidate(s); picked %s. If the tracefs leak\n"
            "       produces a base that is not 2 MB aligned, test the\n"
            "       others from trace_wchan_candidates with\n"
            "       KUGEL_KASLR_SOURCE=verify, or force the correct\n"
            "       value with --trace-wchan-manual.\n"
            % (len(tw_candidates), tw_candidates[0]["site"]))
        for c in tw_candidates:
            reason = c.get("reason") or ""
            suffix = ("  [%s]" % reason) if reason else ""
            sys.stderr.write("       +0x%-8x %s%s\n"
                             % (c["offset"], c["site"], suffix))
    return 0


def import_targets(args):
    if not os.path.isdir(args.targets):
        die("targets dir %s does not exist" % args.targets)
    entries = read_registry(args.registry)
    known = {e[2][0] for e in entries if e[0] == "row"}
    added = 0
    for fn in sorted(os.listdir(args.targets)):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(args.targets, fn)
        try:
            j = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        name = os.path.splitext(fn)[0]
        k = j.get("kernel") or {}
        inc = (j.get("device") or {}).get("build_incremental") or name
        if inc in known:
            continue
        offs = k.get("offsets") or {}
        ds = [str(offs.get(m)) if offs.get(m) is not None else NO_VALUE
              for m in REGISTRY_MACROS]
        cols = [inc, name,
                (j.get("device") or {}).get("vermagic") or NO_VALUE,
                k.get("text_base") or NO_VALUE, *ds,
                str(k.get("cap_last_cap")) if k.get("cap_last_cap") is not None
                else NO_VALUE,
                "derived"]
        insert_row(entries, cols)
        known.add(inc)
        added += 1
    print("import: %d added" % added)
    if added:
        write_registry(args.registry, entries, args.dry_run)
        if args.dry_run:
            print("(--dry-run: nothing written)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_argument_group("kernel source (one of)")
    src.add_argument("--zip", help="OTA zip; pulls ONLY boot.img")
    src.add_argument("--boot", help="boot.img directly")
    src.add_argument("--elf", help="pre-extracted vmlinux.elf")

    ap.add_argument("--map", default=DEFAULT_MAP)
    ap.add_argument("--name", help="target name (default: zip basename)")
    ap.add_argument("--incremental", help="ro.build.version.incremental")
    ap.add_argument("--vermagic", help="override the banner")
    ap.add_argument("--targets", default=DEFAULT_TARGETS)
    ap.add_argument("--registry", default=DEFAULT_REGISTRY)
    ap.add_argument("--no-disasm", action="store_true",
                    help="skip ret/bl scan; fall back to kugel.map's +offset")
    ap.add_argument("--force-partial", action="store_true",
                    help="write a target even with unresolved mandatory symbols")
    # FIX: allow forcing OFF_TRACE_WCHAN once empirically validated
    ap.add_argument("--trace-wchan-manual", default=None,
                    help="force OFF_TRACE_WCHAN (hex/dec); useful when the\n"
                         "auto-derivation cannot identify the site")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--ident", action="store_true")
    ap.add_argument("--import-targets", action="store_true")

    a = ap.parse_args()

    if a.import_targets:
        return import_targets(a)

    scratch = os.path.join(HERE, "build")
    os.makedirs(scratch, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix="derive_", dir=scratch)
    atexit.register(lambda: shutil.rmtree(workdir, ignore_errors=True))

    return derive(a, workdir)


if __name__ == "__main__":
    sys.exit(main())
