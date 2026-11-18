# kugel

Root exploit for Meta Quest 2 and Quest Pro via KGSL drawobj use-after-free on Android 4.19/5.10 msm kernels.

---

## What it does

kugel exploits a dangling drawobj use-after-free in the Qualcomm GPU kernel driver (`/dev/kgsl-3d0`). After submitting a GPU command whose underlying draw object is concurrently destroyed and then overwritten by a racing sendmsg payload carrying a crafted fake credential struct, the process inherits uid=0, full capabilities, and SELinux is flipped to permissive. It then spawns a persistent root shell server on `127.0.0.1:4444` that accepts line-delimited shell commands and returns their output over TCP.

The exploit process never exits — the fake cred lands inside a socket control buffer held alive by a blocked `sendmsg`, and freeing the slab would corrupt kernel memory. Everything that needs root runs through the shell server instead.

---

## Supported hardware

| Device         | Codename            |
|----------------|---------------------|
| Meta Quest 2   | hollywood           |
| Meta Quest Pro | seacliff            |

---

## Firmware coverage

You can view the /targets/ folder to see what firmwares/incrementals are currently covered. As of Nov 18th 2026, Kugel is patched. Expect any new releases above the following max supported incrementals to be patched.

**Quest 2: 52371960014100150** \
**Quest Pro: 51583910014400340**

---

## How it works

### The race

1. A GPU command is queued via `IOCTL_GPU_COMMAND`, which allocates an in-kernel `kgsl_drawobj`. The ioctl intentionally fails validation, leaving the drawobj allocated but orphaned — with no active reference on the KGSL side.

2. Sixteen sender threads each hold a blocked `sendmsg` on a socket filled with crafted ancillary data. The ancillary data is a serialized fake `cred` struct with uid/gid=0, all capability bits set, and pointers into the kernel text segment for `commit_creds`, `init_user_ns`, and `init_groups`.

3. A destroy thread triggers `kgsl_drawobj_destroy_object` on the orphaned drawobj, freeing its slab back to the kernel allocator.

4. When the slab is returned to the pool and immediately reclaimed by the kernel's socket layer to service one of the blocked `sendmsg` calls, the ancillary data overwrites the former drawobj memory, placing the fake cred at the right offset.

5. The main thread unblocks. The kernel follows the now-redirected cred pointer for the calling process, `commit_creds` runs with the fake cred, and the process emerges as uid=0 with full capabilities.

### SELinux

After gaining uid=0 and full capabilities, kugel locates `selinux_state.enforcing` via the per-firmware `OFF_SELINUX_STATE` offset and writes 0 to flip the kernel to permissive mode. The `secblob` gadget (`modedb+0x430` on Q2/QPro) is used as an aliased write path to reach the enforcing field without a direct kernel write primitive.

---

## Build prerequisites

- **Android NDK** at `C:\android-ndk` — toolchain at `toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android30-clang.cmd`
- **Python 3** — for `gen_strings.py`, `embed_targets.py`, and the derive scripts
- **payload-dumper-go** — for extracting `boot.img` from OTA zips (see `toolconf.py` for path)
- **vmlinux-to-elf** — for symbol/offset extraction from compressed kernel images
- **PowerShell** — for `derive-all-q2.ps1`

---

## Building

### 1. Derive targets (only needed when adding new firmwares)

```powershell
# Quest Pro targets
.\derive-all-q2.ps1 -Families qpro

# Quest 2 targets
.\derive-all-q2.ps1 -Families q2
```

### 2. Regenerate headers

From the repo root:

```powershell
cd L:\Github\kugel


# Target table 
python .\embed_targets.py --out targets_gen.h
```

### 3. Build binary

```powershell
& "C:\android-ndk\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android30-clang.cmd" `
    -O2 -g -Wall -o kugel_q2_debug kugel_q2_debug.c
```
---

## Usage

```powershell
# Push and run build
adb push kugel_q2_debug /data/local/tmp/
adb shell chmod +x /data/local/tmp/kugel_q2_debug
adb shell /data/local/tmp/kugel_q2_debug
```

The exploit runs, identifies the firmware from `ro.build.version.incremental`, leaks KASLR, triggers the race, and spawns the root shell server. The process blocks indefinitely in a heartbeat loop — this is expected. The root shell is accessible on `127.0.0.1:4444` immediately after the `[sh] root shell ready` log line.

---

## Root shell protocol

After a successful exploit, kugel listens on `127.0.0.1:4444`. The protocol is intentionally minimal:

- Connect via TCP to `127.0.0.1:4444`
- Send shell commands, one per line (`\n`-terminated)
- Receive the full stdout of each command before sending the next
- Empty lines are ignored
- The connection stays open until closed by the client
- Each connection forks an isolated child: `setgroups(0, NULL)` → `setresgid(0, 0, 0)` → `setresuid(0, 0, 0)` → SELinux exec transition to `u:r:shell:s0`

No framing, no authentication, loopback only. Each command runs via `popen()` and all stdout output is flushed back over the socket before the next command is read.

**Example (via netcat):**
```sh
adb forward tcp:4444 tcp:4444
echo "id" | nc 127.0.0.1 4444
# uid=0(root) gid=0(root) context=u:r:shell:s0
```

---

## Adding new targets

1. Obtain the OTA zip for the target firmware.
2. Place it in the input directory expected by `derive-all-q2.ps1` (see `toolconf.py` for path config).
3. Run:
   ```powershell
   .\derive-all-q2.ps1 -Families q2   # or qpro
   ```
4. Verify the new `.json` appears under `targets/` with all required offsets (`OFF_COMMIT_CREDS`, `OFF_SELINUX_STATE`, `OFF_RET`).
5. Regenerate headers and rebuild both binaries.

---

## Credit
Lumince - Batch targeting firmwares, Kernel panic crash fixes, Potential softboot/brick mitigation, Root shell additions (no adbd patching),  \
Thunda - Exploit findings, POC. initial adbd patches to confirm root