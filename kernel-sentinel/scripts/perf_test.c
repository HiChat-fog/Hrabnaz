/* P0-D 诊断：3.10上perf_event_open(PERF_TYPE_TRACEPOINT)可行的attr配置。
 * 用法：gcc -O2 -o perf_test perf_test.c && ./perf_test（需root）；fd>=0即可用。 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 298
#endif
#ifndef PERF_ATTR_SIZE_VER0
#define PERF_ATTR_SIZE_VER0 64
#endif

static int perf_open(struct perf_event_attr *pe) {
    /* 3.10 要求 cpu=具体核(0/1/...)，cpu=-1 对tracepoint返EINVAL；6.17接受-1所以没暴露 */
    return (int)syscall(__NR_perf_event_open, pe, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
}

int main(void) {
    unsigned long long id = 81; /* raw_syscalls/sys_enter（实测）*/
    int fd;

    /* A: size=0, sample_period=1, RAW|TIME, enabled（当前ks_loader配置）*/
    struct perf_event_attr a; memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_TRACEPOINT; a.config = id;
    a.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME; a.sample_period = 1; a.wakeup_events = 1;
    fd = perf_open(&a);
    printf("A size=0  per=1 RAW|TIME enabled: fd=%d %s\n", fd, fd<0?strerror(errno):"OK");
    if (fd>=0) close(fd);

    /* B: size=PERF_ATTR_SIZE_VER0(64) */
    struct perf_event_attr b = a; b.size = PERF_ATTR_SIZE_VER0;
    fd = perf_open(&b);
    printf("B size=64 per=1 RAW|TIME enabled: fd=%d %s\n", fd, fd<0?strerror(errno):"OK");
    if (fd>=0) close(fd);

    /* C: size=sizeof(struct perf_event_attr)（构建机可能>3.10内核max → E2BIG）*/
    struct perf_event_attr c = a; c.size = sizeof(struct perf_event_attr);
    fd = perf_open(&c);
    printf("C size=sz per=1 RAW|TIME enabled: fd=%d %s\n", fd, fd<0?strerror(errno):"OK");
    if (fd>=0) close(fd);

    /* D: size=64, disabled=1（open disabled, ENABLE after SET_BPF）*/
    struct perf_event_attr d = b; d.disabled = 1;
    fd = perf_open(&d);
    printf("D size=64 per=1 RAW|TIME disabled: fd=%d %s\n", fd, fd<0?strerror(errno):"OK");
    if (fd>=0) close(fd);

    /* E: size=64, sample_period=0 */
    struct perf_event_attr e = b; e.sample_period = 0;
    fd = perf_open(&e);
    printf("E size=64 per=0 RAW|TIME enabled: fd=%d %s\n", fd, fd<0?strerror(errno):"OK");
    if (fd>=0) close(fd);

    /* F: size=64, sample_type=RAW only */
    struct perf_event_attr f = b; f.sample_type = PERF_SAMPLE_RAW;
    fd = perf_open(&f);
    printf("F size=64 per=1 RAW enabled: fd=%d %s\n", fd, fd<0?strerror(errno):"OK");
    if (fd>=0) close(fd);

    /* G: PERF_TYPE_HARDWARE CPU_CYCLES（确认perf_event_open对非tracepoint可用）*/
    struct perf_event_attr g; memset(&g, 0, sizeof(g));
    g.size = PERF_ATTR_SIZE_VER0; g.type = PERF_TYPE_HARDWARE; g.config = PERF_COUNT_HW_CPU_CYCLES;
    g.sample_period = 1000000; g.wakeup_events = 1;
    fd = perf_open(&g);
    printf("G HARDWARE CPU_CYCLES: fd=%d %s\n", fd, fd<0?strerror(errno):"OK");
    if (fd>=0) close(fd);

    /* H: PERF_TYPE_TRACEPOINT config=320 (sched_process_fork，另一个tracepoint) */
    struct perf_event_attr h = b; h.config = 320;
    fd = perf_open(&h);
    printf("H TRACEPOINT config=320 (sched_fork): fd=%d %s\n", fd, fd<0?strerror(errno):"OK");
    if (fd>=0) close(fd);

    /* I: 最简—size=64, sample_type=0(纯触发/计数,不采样), sample_period=0, wakeup=0 */
    {
        struct perf_event_attr attr_i;
        memset(&attr_i, 0, sizeof(attr_i));
        attr_i.size = PERF_ATTR_SIZE_VER0;
        attr_i.type = PERF_TYPE_TRACEPOINT;
        attr_i.config = id;
        fd = perf_open(&attr_i);
        printf("I size=64 sample_type=0 per=0 wakeup=0: fd=%d %s\n", fd, fd<0?strerror(errno):"OK");
        if (fd>=0) close(fd);
    }

    return 0;
}
