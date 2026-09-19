#ifndef KS_PROBES_PROCESS_TREE_H
#define KS_PROBES_PROCESS_TREE_H

#define EVENT_TREE_FORK    40
#define EVENT_TREE_EXEC    41
#define EVENT_TREE_EXIT    42
#define EVENT_TREE_ANOMALY 43


#define PROC_FLAG_ROOT      (1 << 0)
#define PROC_FLAG_CONTAINER (1 << 1)
#define PROC_FLAG_ORPHAN    (1 << 2)
#define PROC_FLAG_ANOMALOUS (1 << 3)

struct process_tree_event {
    struct ks_event header;
    u32 pid, ppid;
    u8  comm[16], exe_path[KS_EXE_PATH_LEN];
    u64 create_time, exit_time;
    u32 flags, risk_score;
    u8  parent_comm[16];
    u16 parent_risk, anomaly_type;
    u32 _pad_tree1, _pad_tree2;
};

KS_EVENT_MAP(tree_events, 1024 * 1024);

struct anomaly_relation_key {
    u8 parent_comm[16], child_comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct anomaly_relation_key);
    __type(value, u16);
    __uint(max_entries, 64);
} anomaly_relations SEC(".maps");

struct pt_scratch {
    struct process_node parent_info;
    struct process_node child_node;
    struct process_node updated;
};

KS_PERCPU_ARRAY_MAP(pt_scratch_map, struct pt_scratch);

static __always_inline struct pt_scratch *pt_scratch_get(void) {
    u32 key = KS_PERCPU_KEY();
    return bpf_map_lookup_elem(&pt_scratch_map, &key);
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_fork(KS_TP_SCHED_FORK *ctx) {
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid  = ctx->child_pid;
    if (parent_pid == 0 || child_pid == 0) return 0;

    u64 now = bpf_ktime_get_ns();

    struct pt_scratch *s = pt_scratch_get();
    if (!s) return 0;
    struct process_node *parent_info = &s->parent_info;
    struct process_node *child_node   = &s->child_node;

    __builtin_memset(parent_info, 0, sizeof(*parent_info));
    __builtin_memset(child_node,   0, sizeof(*child_node));

    struct process_node *existing_parent = bpf_map_lookup_elem(&process_tree, &parent_pid);
    if (existing_parent)
        __builtin_memcpy(parent_info, existing_parent, sizeof(*parent_info));
    else {
        bpf_get_current_comm(&parent_info->comm, sizeof(parent_info->comm));
        parent_info->pid = parent_pid;
        parent_info->create_time = now;
        parent_info->risk_score = 0;
    }

    child_node->pid = child_pid;
    child_node->ppid = parent_pid;
    child_node->create_time = now;
    child_node->risk_score = parent_info->risk_score;
    bpf_get_current_comm(&child_node->comm, sizeof(child_node->comm));
    __builtin_memcpy(child_node->exe_path, parent_info->exe_path, sizeof(child_node->exe_path));

    u64 uid_gid = bpf_get_current_uid_gid();
    if ((u32)uid_gid == 0) child_node->flags |= PROC_FLAG_ROOT;

    bpf_map_update_elem(&process_tree, &child_pid, child_node, BPF_ANY);

    struct anomaly_relation_key rel_key = {};
    __builtin_memcpy(rel_key.parent_comm, parent_info->comm, 16);
    __builtin_memcpy(rel_key.child_comm,  child_node->comm,  16);
    u16 *anomaly_type = bpf_map_lookup_elem(&anomaly_relations, &rel_key);
    u16 detected_anomaly = 0;
    if (anomaly_type) {
        detected_anomaly = *anomaly_type;
        child_node->flags |= PROC_FLAG_ANOMALOUS;
    }
    if (parent_info->risk_score >= 40) {
        child_node->flags |= PROC_FLAG_ANOMALOUS;
        if (detected_anomaly == 0) detected_anomaly = 1;
    }
    bpf_map_update_elem(&process_tree, &child_pid, child_node, BPF_ANY);

    if (detected_anomaly > 0 || parent_info->risk_score >= 40) {
        struct process_tree_event *evt = KS_RESERVE(tree_events, struct process_tree_event);
        if (!evt) return 0;
        fill_header(&evt->header, EVENT_TREE_FORK);
        evt->pid = child_pid;  evt->ppid = parent_pid;
        __builtin_memcpy(evt->comm, child_node->comm, 16);
        __builtin_memcpy(evt->exe_path, child_node->exe_path, sizeof(evt->exe_path));
        evt->create_time = now;  evt->exit_time = 0;
        evt->flags = child_node->flags;  evt->risk_score = child_node->risk_score;
        __builtin_memcpy(evt->parent_comm, parent_info->comm, 16);
        evt->parent_risk = (u16)parent_info->risk_score;
        evt->anomaly_type = detected_anomaly;
        evt->_pad_tree1 = 0;  evt->_pad_tree2 = 0;
        KS_SUBMIT(ctx, tree_events, evt);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_exec_tree(KS_TP_SCHED_EXEC *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) return 0;

    u64 now = bpf_ktime_get_ns();

    struct pt_scratch *s = pt_scratch_get();
    if (!s) return 0;
    struct process_node *updated = &s->updated;
    __builtin_memset(updated, 0, sizeof(*updated));

    struct process_node *node = bpf_map_lookup_elem(&process_tree, &pid);
    if (node) __builtin_memcpy(updated, node, sizeof(*updated));
    else {
        updated->pid = pid;  updated->ppid = 0;
        updated->create_time = now;  updated->risk_score = 0;
        updated->flags = 0;
    }

    bpf_get_current_comm(&updated->comm, sizeof(updated->comm));
    u16 filename_off = ctx->__data_loc_filename & 0xFFFF;
    const char *filename = (const void *)ctx + filename_off;
    bpf_probe_read_kernel_str(updated->exe_path, sizeof(updated->exe_path), filename);
    updated->exit_time = 0;

    u32 *risk = bpf_map_lookup_elem(&risk_scores, &pid);
    if (risk) updated->risk_score = *risk;
    bpf_map_update_elem(&process_tree, &pid, updated, BPF_ANY);

    struct process_tree_event *evt = KS_RESERVE(tree_events, struct process_tree_event);
    if (!evt) return 0;
    fill_header(&evt->header, EVENT_TREE_EXEC);
    evt->pid = pid;  evt->ppid = updated->ppid;
    __builtin_memcpy(evt->comm, updated->comm, 16);
    __builtin_memcpy(evt->exe_path, updated->exe_path, sizeof(evt->exe_path));
    evt->create_time = updated->create_time;  evt->exit_time = 0;
    evt->flags = updated->flags;  evt->risk_score = updated->risk_score;

    struct process_node *parent = bpf_map_lookup_elem(&process_tree, &updated->ppid);
    if (parent) {
        __builtin_memcpy(evt->parent_comm, parent->comm, 16);
        evt->parent_risk = (u16)parent->risk_score;
    } else {
        __builtin_memset(evt->parent_comm, 0, 16);
        evt->parent_risk = 0;
    }
    evt->anomaly_type = 0;  evt->_pad_tree1 = 0;  evt->_pad_tree2 = 0;
    KS_SUBMIT(ctx, tree_events, evt);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit_tree(KS_TP_SCHED_EXIT *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) return 0;

    u64 now = bpf_ktime_get_ns();
    struct process_node *node = bpf_map_lookup_elem(&process_tree, &pid);
    if (!node) return 0;

    node->exit_time = now;

    struct process_tree_event *evt = KS_RESERVE(tree_events, struct process_tree_event);
    if (!evt) return 0;
    fill_header(&evt->header, EVENT_TREE_EXIT);
    evt->pid = pid;  evt->ppid = node->ppid;
    __builtin_memcpy(evt->comm, node->comm, 16);
    __builtin_memcpy(evt->exe_path, node->exe_path, sizeof(evt->exe_path));
    evt->create_time = node->create_time;  evt->exit_time = now;
    evt->flags = node->flags;  evt->risk_score = node->risk_score;
    __builtin_memset(evt->parent_comm, 0, 16);
    evt->parent_risk = 0;  evt->anomaly_type = 0;
    evt->_pad_tree1 = 0;  evt->_pad_tree2 = 0;
    KS_SUBMIT(ctx, tree_events, evt);

    bpf_map_delete_elem(&process_tree, &pid);
    return 0;
}

#endif
