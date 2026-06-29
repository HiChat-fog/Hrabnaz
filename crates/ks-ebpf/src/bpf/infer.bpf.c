// 内核推理 — 敏感文件/可疑网络/C2检测/进程注入
// 所有推理函数已移至 common.h 作为 static __always_inline
// 此文件仅保留独立编译入口（暂留空，各探针自带推理逻辑）
#include "common.h"

char LICENSE[] SEC("license") = "GPL";