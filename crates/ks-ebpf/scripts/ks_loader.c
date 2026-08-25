
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <gelf.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

#define LOG_BUF_SIZE (2 * 1024 * 1024)
#define MAX_MAPS 32
#define MAX_PROGS 32
#define MAX_CPUS 256
#define PERF_DATA_PAGES 64
#define MAX_PERF_MAPS 8
#define HEARTBEAT_INTERVAL_SEC 30
#define VERIFIER_LOG_TAIL 4096
#define POLL_TIMEOUT_MS 1000

static char log_buf[LOG_BUF_SIZE];
static volatile sig_atomic_t stop = 0;

struct map_entry {
    char name[64];
    int fd;
    int sec_idx;
    Elf64_Addr offset;
    size_t size;
};

static struct map_entry maps[MAX_MAPS];
static int nmaps = 0;

static int prog_fds[MAX_PROGS];
static int nprog_fds = 0;
static char prog_sec_names[MAX_PROGS][128];
#define MAX_ATTACH_FDS (MAX_PROGS * MAX_CPUS)
static int attach_fds[MAX_ATTACH_FDS];
static int nattach_fds = 0;

struct perf_cpu_buf {
    int fd;
    void *base;
    size_t size;
};

struct perf_map_buf {
    int map_fd;
    int ncpus;
    struct perf_cpu_buf bufs[MAX_CPUS];
};

static struct perf_map_buf perf_maps[MAX_PERF_MAPS];
static int nperf_maps = 0;

static int bpf_syscall(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

static int perf_event_open_syscall(struct perf_event_attr *attr, pid_t pid,
                                   int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

struct known_map {
    const char *name;
    int map_type;
    int key_size;
    int value_size;
    int max_entries;
};

static const struct known_map known_maps[] = {
    {"events",            BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4, 4, 0},
    {"tree_events",       BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4, 4, 0},
    {"freq_events",       BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4, 4, 0},
    {"flow_events",       BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4, 4, 0},
    {"filter_events",     BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4, 4, 0},
    {"risk_scores",       BPF_MAP_TYPE_HASH, 4, 4, 4096},
    {"block_decisions",   BPF_MAP_TYPE_HASH, 8, 16, 4096},
    {"protected_pids",   BPF_MAP_TYPE_HASH, 4, 1, 256},
    {"protected_comms",  BPF_MAP_TYPE_HASH, 16, 1, 64},
    {"ip_whitelist",      BPF_MAP_TYPE_HASH, 4, 1, 256},
    {"net_conn_history",  BPF_MAP_TYPE_HASH, 12, 8, 8192},
    {"freq_counters",     BPF_MAP_TYPE_HASH, 4, 48, 4096},
    {"process_tree",      BPF_MAP_TYPE_HASH, 4, 312, 65536},
    {"net_flows",         BPF_MAP_TYPE_HASH, 20, 48, 8192},
    {"port_scan_map",     BPF_MAP_TYPE_HASH, 4, 24, 4096},
    {"process_whitelist", BPF_MAP_TYPE_HASH, 4, 1, 256},
    {"syscall_ctxs",      BPF_MAP_TYPE_HASH, 8, 64, 10240},
    {"anomaly_relations", BPF_MAP_TYPE_HASH, 32, 2, 64},
    {"safe_patterns",     BPF_MAP_TYPE_HASH, 48, 1, 128},
    {"ks_scratch",        BPF_MAP_TYPE_ARRAY, 4, 1024, 256},
    {"pt_scratch_map",    BPF_MAP_TYPE_ARRAY, 4, 936, 256},
    {"filter_stats_map",  BPF_MAP_TYPE_ARRAY, 4, 24, 256},
    {"syscount_map",      BPF_MAP_TYPE_ARRAY, 4, 24, 256},
    {"infer_config",      BPF_MAP_TYPE_ARRAY, 4, 4, 32},
    {"freq_thresholds",   BPF_MAP_TYPE_ARRAY, 4, 4, 16},
    {"filter_config",     BPF_MAP_TYPE_ARRAY, 4, 4, 8},
    {NULL, 0, 0, 0, 0}
};

static int get_map_type(const char *name) {
    for (int i = 0; known_maps[i].name; i++) {
        if (strcmp(known_maps[i].name, name) == 0) return known_maps[i].map_type;
    }
    return -1;
}

static int create_map_for(const char *name) {
    const struct known_map *km = NULL;
    for (int i = 0; known_maps[i].name; i++) {
        if (strcmp(known_maps[i].name, name) == 0) {
            km = &known_maps[i];
            break;
        }
    }
    if (!km) {
        fprintf(stderr, "  [!] unknown map: %s\n", name);
        return -1;
    }

    int max_entries = km->max_entries;
    if (km->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
        max_entries = sysconf(_SC_NPROCESSORS_ONLN);
    }

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = km->map_type;
    attr.key_size = km->key_size;
    attr.value_size = km->value_size;
    attr.max_entries = max_entries;
    attr.map_flags = 0;

    int fd = bpf_syscall(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        fprintf(stderr, "  [!] map_create '%s' (type=%d key=%d val=%d max=%d) failed: %s\n",
                name, km->map_type, km->key_size, km->value_size, max_entries,
                strerror(errno));
    } else {
        fprintf(stderr, "  [+] map_create '%s' (type=%d key=%d val=%d max=%d) = fd %d\n",
                name, km->map_type, km->key_size, km->value_size, max_entries, fd);
    }
    return fd;
}

static int find_maps(Elf *e) {
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    int maps_sec_idx = -1;
    int symtab_idx = -1;
    size_t strtab_idx = 0;

    while ((scn = elf_nextscn(e, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) == NULL) continue;
        size_t shstrndx;
        if (elf_getshdrstrndx(e, &shstrndx) != 0) continue;
        const char *name = elf_strptr(e, shstrndx, shdr.sh_name);
        if (name && strcmp(name, ".maps") == 0) {
            maps_sec_idx = elf_ndxscn(scn);
            break;
        }
    }
    if (maps_sec_idx < 0) {
        fprintf(stderr, "[!] .maps section not found\n");
        return -1;
    }

    scn = NULL;
    while ((scn = elf_nextscn(e, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) == NULL) continue;
        if (shdr.sh_type == SHT_SYMTAB) {
            symtab_idx = elf_ndxscn(scn);
            strtab_idx = shdr.sh_link;
            break;
        }
    }
    if (symtab_idx < 0) {
        fprintf(stderr, "[!] .symtab not found\n");
        return -1;
    }

    Elf_Data *symtab = elf_getdata(elf_getscn(e, symtab_idx), NULL);
    if (!symtab) return -1;
    int nsyms = symtab->d_size / sizeof(GElf_Sym);

    for (int i = 0; i < nsyms && nmaps < MAX_MAPS; i++) {
        GElf_Sym sym;
        if (gelf_getsym(symtab, i, &sym) == NULL) continue;
        if (GELF_ST_TYPE(sym.st_info) != STT_OBJECT) continue;
        if (sym.st_shndx != maps_sec_idx) continue;
        const char *name = elf_strptr(e, strtab_idx, sym.st_name);
        if (!name || !*name) continue;

        strncpy(maps[nmaps].name, name, sizeof(maps[nmaps].name) - 1);
        maps[nmaps].sec_idx = maps_sec_idx;
        maps[nmaps].offset = sym.st_value;
        maps[nmaps].size = sym.st_size;

        maps[nmaps].fd = create_map_for(name);
        if (maps[nmaps].fd < 0) {
            return -1;
        }
        nmaps++;
    }

    fprintf(stderr, "[*] Created %d maps\n", nmaps);
    return 0;
}

static int find_map_fd(const char *name) {
    for (int i = 0; i < nmaps; i++) {
        if (strcmp(maps[i].name, name) == 0) return maps[i].fd;
    }
    return -1;
}

static void dump_verifier_log_tail(void) {
    size_t total = strlen(log_buf);
    size_t tail_len = (total > VERIFIER_LOG_TAIL) ? VERIFIER_LOG_TAIL : total;
    const char *start = log_buf + (total - tail_len);
    fprintf(stderr, "  === verifier log (tail %zu bytes) ===\n", tail_len);
    fwrite(start, 1, tail_len, stderr);
    fprintf(stderr, "\n  === end verifier log ===\n");
}

static int load_prog(Elf *e, int sec_idx, const char *sec_name) {
    Elf_Scn *scn = elf_getscn(e, sec_idx);
    if (!scn) return -1;
    GElf_Shdr shdr;
    if (gelf_getshdr(scn, &shdr) == NULL) return -1;

    Elf_Data *data = elf_getdata(scn, NULL);
    if (!data || data->d_size == 0) {
        fprintf(stderr, "  [-] %s: empty, skip\n", sec_name);
        return -1;
    }

    int prog_type = BPF_PROG_TYPE_KPROBE;
    if (strncmp(sec_name, "tracepoint/", 11) == 0) {
        prog_type = BPF_PROG_TYPE_TRACEPOINT;
    } else if (strncmp(sec_name, "kprobe/", 7) == 0) {
        prog_type = BPF_PROG_TYPE_KPROBE;
    } else if (strncmp(sec_name, "kretprobe/", 10) == 0) {
        prog_type = BPF_PROG_TYPE_KPROBE;
    }

    size_t insn_cnt = data->d_size / sizeof(struct bpf_insn);
    struct bpf_insn *insns = malloc(data->d_size);
    if (!insns) return -1;
    memcpy(insns, data->d_buf, data->d_size);

    Elf_Scn *rel_scn = NULL;
    scn = NULL;
    while ((scn = elf_nextscn(e, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) == NULL) continue;
        if (shdr.sh_type == SHT_REL && (int)shdr.sh_info == sec_idx) {
            rel_scn = scn;
            break;
        }
    }

    if (rel_scn) {
        Elf_Data *reltab = elf_getdata(rel_scn, NULL);
        if (reltab) {
            int nrels = reltab->d_size / sizeof(GElf_Rel);
            GElf_Shdr rel_shdr;
            gelf_getshdr(rel_scn, &rel_shdr);
            Elf_Data *symtab = elf_getdata(elf_getscn(e, rel_shdr.sh_link), NULL);
            GElf_Shdr sym_shdr;
            gelf_getshdr(elf_getscn(e, rel_shdr.sh_link), &sym_shdr);

            for (int i = 0; i < nrels; i++) {
                GElf_Rel rel;
                if (gelf_getrel(reltab, i, &rel) == NULL) continue;
                int sym_idx = GELF_R_SYM(rel.r_info);
                int rel_type = GELF_R_TYPE(rel.r_info);
                GElf_Sym sym;
                if (gelf_getsym(symtab, sym_idx, &sym) == NULL) continue;
                const char *sym_name = elf_strptr(e, sym_shdr.sh_link, sym.st_name);
                if (!sym_name) continue;

                int insn_idx = rel.r_offset / sizeof(struct bpf_insn);
                if (insn_idx + 1 >= (int)insn_cnt) continue;

                if (rel_type == 1) {
                    int map_fd = find_map_fd(sym_name);
                    if (map_fd < 0) {
                        fprintf(stderr, "  [!] cannot find map '%s' for relocation\n", sym_name);
                        free(insns);
                        return -1;
                    }
                    insns[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;
                    insns[insn_idx].imm = map_fd;
                    insns[insn_idx + 1].imm = 0;
                }
            }
        }
    }

    unsigned int kern_version = 0;
    FILE *fv = fopen("/proc/version", "r");
    if (fv) {
        char vbuf[256];
        if (fgets(vbuf, sizeof(vbuf), fv)) {
            char *hash = strchr(vbuf, '#');
            if (hash) {
                char *p = hash + 1;
                for (; *p; p++) {
                    unsigned int a = 0, b = 0, c = 0;
                    int matched = sscanf(p, "%u.%u.%u", &a, &b, &c);
                    if (matched >= 2 && a >= 2 && a <= 9 && b < 100) {
                        if (matched == 2) c = 0;
                        kern_version = KERNEL_VERSION(a, b, c);
                        break;
                    }
                }
            }
        }
        fclose(fv);
    }
    if (kern_version == 0) {
        struct utsname uts;
        if (uname(&uts) == 0) {
            unsigned int a = 0, b = 0, c = 0;
            int matched = sscanf(uts.release, "%u.%u.%u", &a, &b, &c);
            if (matched >= 2) {
                if (matched == 2) c = 0;
                kern_version = KERNEL_VERSION(a, b, c);
            }
        }
    }

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = prog_type;
    attr.insns = (unsigned long)insns;
    attr.insn_cnt = insn_cnt;
    attr.license = (unsigned long)"GPL";
    attr.kern_version = kern_version;
    attr.log_level = 1;
    attr.log_buf = (unsigned long)log_buf;
    attr.log_size = LOG_BUF_SIZE;

    fprintf(stderr, "\n[+] Loading program '%s' (type=%d, insns=%zu, kern_version=0x%x)...\n",
            sec_name, prog_type, insn_cnt, kern_version);

    log_buf[0] = '\0';

    size_t attr_size = offsetof(union bpf_attr, kern_version) + sizeof(unsigned int);
    int fd = bpf_syscall(BPF_PROG_LOAD, &attr, attr_size);
    if (fd < 0) {
        fprintf(stderr, "[FAIL] program=%s errno=%d msg=%s\n", sec_name, errno, strerror(errno));
        dump_verifier_log_tail();
        free(insns);
        return -1;
    }

    fprintf(stderr, "  [+] loaded fd=%d\n", fd);
    free(insns);
    return fd;
}

static void write_frame(const void *data, __u32 len) {
    fwrite(&len, sizeof(len), 1, stdout);
    if (len > 0 && data != NULL) {
        fwrite(data, 1, len, stdout);
    }
    fflush(stdout);
}

static void send_heartbeat(void) {
    __u32 zero = 0;
    fwrite(&zero, sizeof(zero), 1, stdout);
    fflush(stdout);
}

static int setup_perfbuf_for_map(int map_fd, struct perf_map_buf *pb) {
    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    long page_size_l = sysconf(_SC_PAGE_SIZE);
    if (page_size_l < 0) page_size_l = 4096;
    size_t page_size = (size_t)page_size_l;
    size_t mmap_size = page_size * (1 + PERF_DATA_PAGES);

    pb->map_fd = map_fd;
    pb->ncpus = ncpus;

    for (int cpu = 0; cpu < ncpus && cpu < MAX_CPUS; cpu++) {
        struct perf_event_attr pe;
        memset(&pe, 0, sizeof(pe));
        pe.type = PERF_TYPE_SOFTWARE;
        pe.config = PERF_COUNT_SW_BPF_OUTPUT;
        pe.sample_type = PERF_SAMPLE_RAW;
        pe.wakeup_events = 1;

        int perf_fd = perf_event_open_syscall(&pe, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (perf_fd < 0) {
            fprintf(stderr, "[!] perf_event_open cpu=%d failed: %s\n", cpu, strerror(errno));
            return -1;
        }

        void *base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
        if (base == MAP_FAILED) {
            fprintf(stderr, "[!] mmap cpu=%d failed: %s\n", cpu, strerror(errno));
            close(perf_fd);
            return -1;
        }

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.map_fd = map_fd;
        attr.key = (unsigned long)&cpu;
        attr.value = (unsigned long)&perf_fd;
        attr.flags = BPF_ANY;
        if (bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
            fprintf(stderr, "[!] map_update_elem perf cpu=%d failed: %s\n", cpu, strerror(errno));
            munmap(base, mmap_size);
            close(perf_fd);
            return -1;
        }

        pb->bufs[cpu].fd = perf_fd;
        pb->bufs[cpu].base = base;
        pb->bufs[cpu].size = mmap_size;
    }

    fprintf(stderr, "[*] perfbuf setup map_fd=%d ncpus=%d\n", map_fd, ncpus);
    return 0;
}

static void cleanup_perfbufs(void) {
    for (int m = 0; m < nperf_maps; m++) {
        for (int c = 0; c < perf_maps[m].ncpus; c++) {
            if (perf_maps[m].bufs[c].base && perf_maps[m].bufs[c].base != MAP_FAILED) {
                munmap(perf_maps[m].bufs[c].base, perf_maps[m].bufs[c].size);
                perf_maps[m].bufs[c].base = NULL;
            }
            if (perf_maps[m].bufs[c].fd > 0) {
                close(perf_maps[m].bufs[c].fd);
                perf_maps[m].bufs[c].fd = -1;
            }
        }
    }
}

static __u8 wrap_buf[65536];

static void process_cpu_buffer(struct perf_cpu_buf *pcb, int cpu) {
    long page_size_l = sysconf(_SC_PAGE_SIZE);
    if (page_size_l < 0) page_size_l = 4096;
    size_t page_size = (size_t)page_size_l;
    size_t data_size = pcb->size - page_size;
    char *data_start = (char *)pcb->base + page_size;

    struct perf_event_mmap_page *header = (struct perf_event_mmap_page *)pcb->base;
    __u64 data_head = header->data_head;
    __u64 data_tail = header->data_tail;
    __sync_synchronize();

    if (data_head - data_tail > data_size) {
        __u64 lost = (data_head - data_tail) - data_size;
        fprintf(stderr, "[lost] cpu=%d count=%llu (ring overflow)\n",
                cpu, (unsigned long long)lost);
        data_tail = data_head - data_size;
    }

    while (data_tail < data_head) {
        __u64 offset = data_tail % data_size;
        struct perf_event_header *eh = (struct perf_event_header *)(data_start + offset);

        if (offset + sizeof(*eh) > data_size) {
            size_t first = data_size - offset;
            memcpy(wrap_buf, data_start + offset, first);
            memcpy(wrap_buf + first, data_start, sizeof(*eh) - first);
            eh = (struct perf_event_header *)wrap_buf;
        }

        __u16 raw_size_field = eh->size;
        size_t event_size = raw_size_field;
        if (event_size == 0) break;

        if (offset + event_size > data_size) {
            size_t first = data_size - offset;
            if (event_size > sizeof(wrap_buf)) {
                data_tail += event_size;
                continue;
            }
            memcpy(wrap_buf, data_start + offset, first);
            memcpy(wrap_buf + first, data_start, event_size - first);
            eh = (struct perf_event_header *)wrap_buf;
        }

        __u32 hdr_type = eh->type;

        if (hdr_type == PERF_RECORD_SAMPLE) {
            const __u8 *sample = (const __u8 *)eh + sizeof(struct perf_event_header);
            __u32 raw_size = *(__u32 *)sample;
            const void *raw_data = sample + sizeof(__u32);
            write_frame(raw_data, raw_size);
        } else if (hdr_type == PERF_RECORD_LOST) {
            const __u64 *lost = (const __u64 *)((const __u8 *)eh + sizeof(struct perf_event_header));
            fprintf(stderr, "[lost] cpu=%d count=%llu\n",
                    cpu, (unsigned long long)lost[1]);
        }

        data_tail += event_size;
    }

    __sync_synchronize();
    header->data_tail = data_tail;
}

static int poll_perfbufs(void) {
    struct pollfd pfds[MAX_PERF_MAPS * MAX_CPUS];
    int nfds = 0;
    for (int m = 0; m < nperf_maps; m++) {
        for (int c = 0; c < perf_maps[m].ncpus; c++) {
            if (nfds >= (int)(sizeof(pfds) / sizeof(pfds[0]))) break;
            pfds[nfds].fd = perf_maps[m].bufs[c].fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }
    }

    int ret = poll(pfds, nfds, POLL_TIMEOUT_MS);
    if (ret < 0) {
        if (errno == EINTR) return 0;
        fprintf(stderr, "[!] poll failed: %s\n", strerror(errno));
        return -1;
    }
    if (ret == 0) return 0;

    for (int m = 0; m < nperf_maps; m++) {
        for (int c = 0; c < perf_maps[m].ncpus; c++) {
            process_cpu_buffer(&perf_maps[m].bufs[c], c);
        }
    }
    return 0;
}

static void sig_handler(int sig) {
    (void)sig;
    stop = 1;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--stream | --load-only] <object.o>\n"
        "\n"
        "  --load-only  (default) Load all programs and exit.\n"
        "  --stream      Load, then poll perfbuf and stream events to stdout\n"
        "                in frame format: [u32 LE length][u8[length] payload].\n"
        "                length=0 is a heartbeat (every %d s).\n"
        "                Logs/errors go to stderr; event data to stdout.\n",
        prog, HEARTBEAT_INTERVAL_SEC);
}

static int attach_program(int prog_fd, const char *sec_name) {
    char id_path[256];
    const char *tracing = "/sys/kernel/debug/tracing";

    if (strncmp(sec_name, "tracepoint/", 11) == 0) {
        const char *rest = sec_name + 11;
        snprintf(id_path, sizeof(id_path), "%s/events/%s/id", tracing, rest);
    } else if (strncmp(sec_name, "kprobe/", 7) == 0) {
        const char *func = sec_name + 7;
        char tag[80];
        snprintf(tag, sizeof(tag), "ks_%s", func);
        int kf = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY);
        if (kf < 0) {
            fprintf(stderr, "  [!] attach %s: open kprobe_events: %s\n", sec_name, strerror(errno));
            return -1;
        }
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "p:%s %s\n", tag, func);
        if (write(kf, cmd, strlen(cmd)) < 0) {
        }
        close(kf);
        snprintf(id_path, sizeof(id_path), "%s/events/kprobes/%s/id", tracing, tag);
    } else {
        fprintf(stderr, "  [-] skip attach (section %s)\n", sec_name);
        return 0;
    }

    int idf = open(id_path, O_RDONLY);
    if (idf < 0) {
        fprintf(stderr, "  [!] attach %s: open %s: %s\n", sec_name, id_path, strerror(errno));
        return -1;
    }
    char idbuf[32];
    ssize_t n = read(idf, idbuf, sizeof(idbuf) - 1);
    close(idf);
    if (n <= 0) {
        fprintf(stderr, "  [!] attach %s: read id failed\n", sec_name);
        return -1;
    }
    idbuf[n] = 0;
    unsigned long long event_id = strtoull(idbuf, NULL, 10);

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_TRACEPOINT;
    pe.config = event_id;
    pe.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME;
    pe.sample_period = 1;
    pe.wakeup_events = 1;

    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 1) ncpus = 1;
    int attached = 0;
    for (int cpu = 0; cpu < ncpus; cpu++) {
        int perf_fd = perf_event_open_syscall(&pe, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (perf_fd < 0) continue;
        if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
            fprintf(stderr, "  [!] attach %s cpu=%d: SET_BPF: %s\n", sec_name, cpu, strerror(errno));
            close(perf_fd);
            continue;
        }
        if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
            fprintf(stderr, "  [!] attach %s cpu=%d: ENABLE: %s\n", sec_name, cpu, strerror(errno));
            close(perf_fd);
            continue;
        }
        if (nattach_fds < MAX_ATTACH_FDS) {
            attach_fds[nattach_fds++] = perf_fd;
        } else {
            close(perf_fd);
        }
        attached++;
    }
    if (attached > 0) {
        fprintf(stderr, "  [+] attached %s on %d/%d CPUs (event_id=%llu)\n", sec_name, attached, ncpus, event_id);
        return 0;
    }
    fprintf(stderr, "  [!] attach %s: 全部CPU失败\n", sec_name);
    return -1;
}

int main(int argc, char **argv) {
    int stream_mode = 0;
    const char *obj_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--stream") == 0) {
            stream_mode = 1;
        } else if (strcmp(argv[i], "--load-only") == 0) {
            stream_mode = 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        } else {
            if (!obj_path) {
                obj_path = argv[i];
            } else {
                fprintf(stderr, "unexpected argument: %s\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
    }

    if (!obj_path) {
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rl);

    union bpf_attr test_attr;
    memset(&test_attr, 0, sizeof(test_attr));
    test_attr.map_type = BPF_MAP_TYPE_ARRAY;
    test_attr.key_size = 4;
    test_attr.value_size = 4;
    test_attr.max_entries = 1;
    int test_fd = bpf_syscall(BPF_MAP_CREATE, &test_attr, sizeof(test_attr));
    if (test_fd < 0) {
        fprintf(stderr, "[!] bpf() syscall test failed: %s\n", strerror(errno));
        return 1;
    }
    close(test_fd);
    fprintf(stderr, "[*] bpf() syscall OK\n");

    int fd = open(obj_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[!] open %s: %s\n", obj_path, strerror(errno));
        return 1;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "[!] libelf init failed\n");
        close(fd);
        return 1;
    }

    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e) {
        fprintf(stderr, "[!] elf_begin failed\n");
        close(fd);
        return 1;
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(e, &shstrndx) != 0) {
        fprintf(stderr, "[!] elf_getshdrstrndx failed\n");
        elf_end(e);
        close(fd);
        return 1;
    }

    fprintf(stderr, "\n=== Step 1: Create maps ===\n");
    if (find_maps(e) < 0) {
        fprintf(stderr, "[!] map creation failed\n");
        elf_end(e);
        close(fd);
        return 1;
    }

    fprintf(stderr, "\n=== Step 2: Load programs ===\n");
    Elf_Scn *scn = NULL;
    int loaded = 0, failed = 0;
    while ((scn = elf_nextscn(e, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == NULL) continue;
        if (shdr.sh_type != SHT_PROGBITS) continue;
        const char *sec_name = elf_strptr(e, shstrndx, shdr.sh_name);
        if (!sec_name) continue;
        if (!(shdr.sh_flags & SHF_EXECINSTR)) continue;
        if (shdr.sh_size == 0) continue;
        if (strcmp(sec_name, ".text") == 0) continue;

        int prog_fd = load_prog(e, elf_ndxscn(scn), sec_name);
        if (prog_fd >= 0) {
            loaded++;
            if (stream_mode) {
                if (nprog_fds < MAX_PROGS) {
                    strncpy(prog_sec_names[nprog_fds], sec_name, 127);
                    prog_sec_names[nprog_fds][127] = 0;
                    prog_fds[nprog_fds++] = prog_fd;
                } else {
                    close(prog_fd);
                }
            } else {
                close(prog_fd);
            }
        } else {
            failed++;
            goto cleanup_fail;
        }
    }

    fprintf(stderr, "\n=== Summary: %d loaded, %d failed ===\n", loaded, failed);

    if (stream_mode) {
        fprintf(stderr, "\n=== Step 3: Setup perfbuf ===\n");
        for (int i = 0; i < nmaps && nperf_maps < MAX_PERF_MAPS; i++) {
            int mt = get_map_type(maps[i].name);
            if (mt == BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
                fprintf(stderr, "[*] perfbuf for map '%s' (fd=%d)\n",
                        maps[i].name, maps[i].fd);
                if (setup_perfbuf_for_map(maps[i].fd, &perf_maps[nperf_maps]) < 0) {
                    fprintf(stderr, "[!] perfbuf setup failed for map '%s'\n",
                            maps[i].name);
                    goto cleanup_fail;
                }
                nperf_maps++;
            }
        }
        if (nperf_maps == 0) {
            fprintf(stderr, "[!] no PERF_EVENT_ARRAY maps found, nothing to poll\n");
        }

        fprintf(stderr, "\n=== Step 3.5: Attach programs (per-CPU) ===\n");
        for (int i = 0; i < nprog_fds; i++) {
            attach_program(prog_fds[i], prog_sec_names[i]);
        }

        fprintf(stderr, "\n=== Step 4: Polling perfbuf (stream mode) ===\n");
        struct timespec last_hb;
        clock_gettime(CLOCK_MONOTONIC, &last_hb);

        while (!stop) {
            if (poll_perfbufs() < 0) break;

            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - last_hb.tv_sec >= HEARTBEAT_INTERVAL_SEC) {
                send_heartbeat();
                last_hb = now;
            }
        }

        fprintf(stderr, "\n[*] exiting stream mode (stop=%d)\n", (int)stop);
        cleanup_perfbufs();
    }

    for (int i = 0; i < nattach_fds; i++) {
        if (attach_fds[i] > 0) close(attach_fds[i]);
    }
    for (int i = 0; i < nprog_fds; i++) {
        if (prog_fds[i] > 0) close(prog_fds[i]);
    }
    for (int i = 0; i < nmaps; i++) {
        if (maps[i].fd >= 0) close(maps[i].fd);
    }
    elf_end(e);
    close(fd);
    return failed > 0 ? 1 : 0;

cleanup_fail:
    cleanup_perfbufs();
    for (int i = 0; i < nprog_fds; i++) {
        if (prog_fds[i] > 0) close(prog_fds[i]);
    }
    for (int i = 0; i < nmaps; i++) {
        if (maps[i].fd >= 0) close(maps[i].fd);
    }
    elf_end(e);
    close(fd);
    return 1;
}
