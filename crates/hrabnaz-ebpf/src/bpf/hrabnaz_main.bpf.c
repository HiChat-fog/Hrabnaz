
#include "common.h"

HRABNAZ_EVENT_MAP(events, 16 * 1024 * 1024);

#include "hrabnaz_probes_freq.h"
#include "hrabnaz_probes_netflow.h"
#include "hrabnaz_probes_smart_filter.h"
#include "hrabnaz_probes_lkm.h"
#include "hrabnaz_probes_syscall.h"
#include "hrabnaz_probes_vfs.h"
#include "hrabnaz_probes_net.h"
#include "hrabnaz_probes_process_tree.h"
#include "hrabnaz_probes_container.h"
#include "hrabnaz_probes_self_protect.h"

char LICENSE[] SEC("license") = "GPL";
