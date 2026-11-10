//! 探针注册表的单一来源：从编译产物 `.o` 的 SEC 段自动枚举探针。
//!
//! 为什么从 SEC 段枚举：探针的 SEC 注解（`SEC("kprobe/vfs_open")` 等）已经是
//! 编译器强制存在的注册信息——新增探针只写探针函数与 SEC 注解，构建期自动进入
//! 注册表；loader 按注册表 attach、status 按注册表报表，不再有人工清单，漏注册
//! 在编译期就暴露（本解析器对未知 SEC 前缀直接报错）。
//!
//! 本模块同时被 `build.rs`（构建期枚举）与库内单元测试（对嵌入的 `.o` 复核）
//! 使用，因此**不依赖任何 crate**，只做最小 ELF64 解析。

/// 构建期解析出的一条探针元数据（未排序、带 String，便于诊断输出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProbe {
    /// 程序名（SEC 段内的函数符号名，与 aya `program_mut(name)` 一致）
    pub name: String,
    /// "tracepoint" | "kprobe" | "kretprobe"
    pub kind: &'static str,
    /// tracepoint 的 category（如 raw_syscalls / sched）；kprobe 为 None
    pub category: Option<String>,
    /// tracepoint 的 event 名，或 kprobe/kretprobe 的目标内核符号
    pub target: String,
}

const SHF_EXECINSTR: u64 = 0x4;
const SHT_SYMTAB: u32 = 2;
const STT_FUNC: u8 = 2;

struct Section {
    name: String,
    typ: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: usize,
}

fn rd_u16(b: &[u8], off: usize) -> Result<u16, String> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| format!("ELF 越界读取 u16 @{off}"))
}

fn rd_u32(b: &[u8], off: usize) -> Result<u32, String> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| format!("ELF 越界读取 u32 @{off}"))
}

fn rd_u64(b: &[u8], off: usize) -> Result<u64, String> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| format!("ELF 越界读取 u64 @{off}"))
}

fn cstr_at(b: &[u8], off: usize) -> Result<String, String> {
    let tail = b.get(off..).ok_or_else(|| format!("字符串越界 @{off}"))?;
    let end = tail.iter().position(|&c| c == 0).unwrap_or(tail.len());
    String::from_utf8(tail[..end].to_vec()).map_err(|e| format!("节名非 UTF-8: {e}"))
}

/// 解析 ELF64 节表（内部复用：探针枚举 + 指令数预算检查）。
fn parse_sections(bytes: &[u8]) -> Result<Vec<Section>, String> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return Err("不是 ELF 文件".into());
    }
    let shoff = rd_u64(bytes, 0x28)? as usize;
    let shentsize = rd_u16(bytes, 0x3A)? as usize;
    let shnum = rd_u16(bytes, 0x3C)? as usize;
    let shstrndx = rd_u16(bytes, 0x3E)? as usize;
    if shentsize < 64 {
        return Err(format!("节头尺寸异常: {shentsize}"));
    }
    if shnum == 0 || shstrndx >= shnum {
        return Err("节表为空或 shstrndx 越界".into());
    }
    let raw_section = |i: usize| -> Result<(u32, u32, u64, usize, usize, usize), String> {
        let base = shoff
            .checked_add(i.checked_mul(shentsize).ok_or("节表偏移溢出")?)
            .ok_or("节表偏移溢出")?;
        Ok((
            rd_u32(bytes, base)?,
            rd_u32(bytes, base + 4)?,
            rd_u64(bytes, base + 8)?,
            rd_u64(bytes, base + 24)? as usize,
            rd_u64(bytes, base + 32)? as usize,
            rd_u32(bytes, base + 40)? as usize,
        ))
    };
    let (_, _, _, shstr_off, shstr_size, _) = raw_section(shstrndx)?;
    let shstrtab = bytes
        .get(shstr_off..shstr_off + shstr_size)
        .ok_or("shstrtab 越界")?;
    let mut sections = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let (name_off, typ, flags, offset, size, link) = raw_section(i)?;
        let name = cstr_at(shstrtab, name_off as usize)?;
        sections.push(Section {
            name,
            typ,
            flags,
            offset,
            size,
            link,
        });
    }
    Ok(sections)
}

/// 各探针程序段的指令数（段大小 ÷ 8），供构建期守老内核指令上限。
///
/// 为什么必须守：老内核验证器 BPF_MAXINSNS=4096（<5.2 的 privileged 上限）。
/// 程序超限时 BPF_PROG_LOAD 返回 E2BIG，运行时回退 mock——而部署的旧二进制
/// 可能仍小于上限，本地一切正常，直到某次发布才在 3.10 上静默哑火（QEMU 实测
/// trace_sys_exit 曾膨胀到 7483 条）。故在构建期直接失败。
pub fn program_sizes(bytes: &[u8]) -> Result<Vec<(String, u64)>, String> {
    let sections = parse_sections(bytes)?;
    // 一个 SEC 段可含多个程序函数（如 sys_exit 拆 proc/file/net）：按符号表逐函数
    // 统计 st_size/8；找不到函数符号时回退整段大小。
    let mut symtab: Option<(usize, usize, usize)> = None; // (off, size, link)
    for sec in &sections {
        if sec.typ == SHT_SYMTAB {
            symtab = Some((sec.offset, sec.size, sec.link));
            break;
        }
    }
    let mut out = Vec::new();
    for (idx, sec) in sections.iter().enumerate() {
        if sec.flags & SHF_EXECINSTR == 0 || sec.name == ".text" {
            continue;
        }
        if !(sec.name.starts_with("tracepoint/")
            || sec.name.starts_with("kprobe/")
            || sec.name.starts_with("kretprobe/"))
        {
            continue;
        }
        let mut found = false;
        if let Some((off, size, link)) = symtab {
            if let Some(strtab) = sections.get(link) {
                let str_off = strtab.offset;
                let str_end = strtab.offset + strtab.size;
                let mut i = 0usize;
                while i + 24 <= size {
                    let base = off + i;
                    let name_off = rd_u32(bytes, base)? as usize;
                    let info = *bytes.get(base + 4).ok_or("符号表越界")?;
                    let shndx = rd_u16(bytes, base + 6)? as usize;
                    let st_size = rd_u64(bytes, base + 16)?;
                    if info & 0xf == STT_FUNC && shndx == idx && st_size > 0 {
                        if let Some(name_bytes) = bytes.get(str_off + name_off..str_end) {
                            let end = name_bytes
                                .iter()
                                .position(|&c| c == 0)
                                .unwrap_or(name_bytes.len());
                            if let Ok(name) = String::from_utf8(name_bytes[..end].to_vec()) {
                                out.push((name, st_size / 8));
                                found = true;
                            }
                        }
                    }
                    i += 24;
                }
            }
        }
        if !found {
            out.push((sec.name.clone(), (sec.size / 8) as u64));
        }
    }
    Ok(out)
}

/// 解析 `.o`，枚举全部探针 SEC 段。
///
/// 约束（违反即构建失败，防"新增探针静默未注册"）：
/// - 只接受 `kprobe/`、`kretprobe/`、`tracepoint/` 三类可执行段；
/// - 每个探针段必须恰好含一个函数符号（程序名）；
/// - tracepoint 段名必须是 `tracepoint/<category>/<event>`，事件名内不得再有 `/`。
pub fn parse_probe_sections(bytes: &[u8]) -> Result<Vec<RawProbe>, String> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return Err("不是 ELF 文件".into());
    }
    if bytes[4] != 2 {
        return Err("仅支持 ELF64".into());
    }
    if bytes[5] != 1 {
        return Err("仅支持小端 ELF".into());
    }

    let sections = parse_sections(bytes)?;

    let mut probes = Vec::new();
    for (idx, sec) in sections.iter().enumerate() {
        if sec.flags & SHF_EXECINSTR == 0 || sec.name == ".text" {
            continue;
        }
        let (kind, rest) = if let Some(rest) = sec.name.strip_prefix("tracepoint/") {
            ("tracepoint", rest)
        } else if let Some(rest) = sec.name.strip_prefix("kretprobe/") {
            ("kretprobe", rest)
        } else if let Some(rest) = sec.name.strip_prefix("kprobe/") {
            ("kprobe", rest)
        } else {
            return Err(format!(
                "未知 SEC 段 '{}'：探针只支持 tracepoint/、kprobe/、kretprobe/（如需新类型，请显式扩展注册表解析）",
                sec.name
            ));
        };

        let (category, target) = if kind == "tracepoint" {
            let (cat, evt) = rest.split_once('/').ok_or_else(|| {
                format!(
                    "tracepoint 段名格式应为 tracepoint/<category>/<event>: '{}'",
                    sec.name
                )
            })?;
            if cat.is_empty() || evt.is_empty() || evt.contains('/') {
                return Err(format!("tracepoint 段名不合法: '{}'", sec.name));
            }
            (Some(cat.to_string()), evt.to_string())
        } else {
            if rest.is_empty() || rest.contains('/') {
                return Err(format!("kprobe 目标符号不合法: '{}'", sec.name));
            }
            (None, rest.to_string())
        };

        // 程序名 = 该段内唯一的函数符号（.text 之外的辅助函数不会出现在探针段）
        let mut funcs: Vec<String> = Vec::new();
        for symtab in sections.iter().filter(|s| s.typ == SHT_SYMTAB) {
            let strtab = sections
                .get(symtab.link)
                .ok_or_else(|| format!("符号表链接的 strtab 越界: '{}'", sec.name))?;
            let strtab_bytes = bytes
                .get(strtab.offset..strtab.offset + strtab.size)
                .ok_or("符号 strtab 越界")?;
            const SYM_ENTSIZE: usize = 24; // Elf64_Sym
            let count = symtab.size / SYM_ENTSIZE;
            for s in 0..count {
                let base = symtab.offset + s * SYM_ENTSIZE;
                let st_name = rd_u32(bytes, base)? as usize;
                let st_info = *bytes
                    .get(base + 4)
                    .ok_or_else(|| format!("符号表越界 @{base}"))?;
                let st_shndx = rd_u16(bytes, base + 6)? as usize;
                let sym_type = st_info & 0xf;
                // 只认 FUNC：BPF 函数体里的 LBB0_* 局部标签是 NOTYPE，
                // 不能当作程序名（一个 SEC 段只有一个程序函数）
                if st_shndx != idx || sym_type != STT_FUNC {
                    continue;
                }
                if let Ok(name) = cstr_at(strtab_bytes, st_name) {
                    if !name.is_empty() {
                        funcs.push(name);
                    }
                }
            }
        }
        funcs.sort();
        funcs.dedup();
        match funcs.as_slice() {
            [] => {
                return Err(format!(
                    "探针段 '{}' 内没有函数符号（SEC 注解必须挂在探针函数上）",
                    sec.name
                ))
            }
            [one] => probes.push(RawProbe {
                name: one.clone(),
                kind,
                category,
                target,
            }),
            many => {
                // 一个 SEC 段可挂多个程序（同一 tracepoint/kprobe 允许多个 BPF 程序）：
                // 用于把超长程序拆小以守住老内核 4096 指令上限（raw_syscalls/sys_exit
                // 拆成 proc/file/net 三个）。每个函数符号独立注册为一条探针。
                for one in many {
                    probes.push(RawProbe {
                        name: one.clone(),
                        kind,
                        category: category.clone(),
                        target: target.clone(),
                    });
                }
            }
        }
    }

    probes.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(probes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(parse_probe_sections(b"not an elf").is_err());
    }

    #[test]
    fn rejects_truncated_elf() {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        // e_shoff 指向文件外
        b[0x28..0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        assert!(parse_probe_sections(&b).is_err());
    }
}
