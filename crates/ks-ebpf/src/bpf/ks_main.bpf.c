
#include "common.h"

KS_EVENT_MAP(events, 16 * 1024 * 1024);

#include "ks_probes_freq.h"
#include "ks_probes_netflow.h"
#include "ks_probes_smart_filter.h"
#include "ks_probes_lkm.h"
#include "ks_probes_syscall.h"
#include "ks_probes_vfs.h"
#include "ks_probes_net.h"
#include "ks_probes_process_tree.h"
#include "ks_probes_container.h"
#include "ks_probes_self_protect.h"

char LICENSE[] SEC("license") = "GPL";
