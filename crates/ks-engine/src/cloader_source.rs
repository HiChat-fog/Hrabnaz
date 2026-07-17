//! CLoaderSource — 通过 fork+exec `ks_loader --stream` 子进程从 stdout 管道读取事件。
//!
//! 用于 3.10 stock 内核（无 BTF，aya 无法加载），ks_loader C loader 加载 eBPF 程序
//! 并把 perfbuf 事件按帧格式 `[u32 LE length][u8[length] payload]` 写 stdout。
//! Rust 父进程从 stdout 异步读帧，解码为事件字节。
//!
//! 注：`tokio::process` 在所有 unix 平台可用，故此模块不做
//! `cfg(target_os = "linux")` 限制；但实际只在 Linux 上有意义
//! （非 Linux 平台 spawn `ks_loader` 会立即失败返回 Err）。

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::event_source::{EventSource, SourceKind};

/// stderr 环形缓冲保留的字节数（用于错误诊断时打印末尾 tail）。
const STDERR_TAIL_BYTES: usize = 512;

/// 后台 stderr 读取任务的单次 read 缓冲大小。
const STDERR_READ_CHUNK: usize = 256;

/// C loader sidecar 事件源。
///
/// 持有 `ks_loader --stream <obj>` 子进程，从其 stdout 异步读帧。
/// 子进程 stderr 由后台 tokio task 异步预读到环形缓冲，仅保留末尾
/// `STDERR_TAIL_BYTES` 字节，便于子进程异常退出时打印诊断信息。
///
/// 设计要点：
/// - `child` / `stdout` 各自独立 `Mutex` 包装：未来若需并行访问（如 kill child）
///   不会与 `next_bytes` 的 `&mut self` 冲突；当前 trait 仅 `&mut self` 调用，
///   Mutex 不会引入锁竞争。
/// - `stderr_buf` 用 `Arc<Mutex<Vec<u8>>>`：后台 task 与本结构共享所有权。
/// - `read_exact` 在 EOF 时返回 `Err(UnexpectedEof)`，由 [`read_frame`] 统一处理为
///   `Ok(None)` 表示优雅 EOF；payload 中途 EOF 视为错误（子进程崩溃/管道断裂）。
pub struct CLoaderSource {
    child: Mutex<Child>,
    stdout: Mutex<BufReader<ChildStdout>>,
    /// stderr 末尾 `STDERR_TAIL_BYTES` 字节（用于错误诊断）。
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    loader_path: String,
}

impl CLoaderSource {
    /// 启动 `ks_loader --stream <object_path>` 子进程。
    ///
    /// - `loader_path`: `ks_loader` 二进制路径
    /// - `object_path`: `.o` 文件路径
    ///
    /// stdin/stdout/stderr 全部重定向：stdin 关闭（null），stdout/stderr piped。
    /// stderr 由后台 task 异步预读，保留末尾 512 字节用于诊断。
    pub fn spawn(loader_path: &str, object_path: &str) -> Result<Self> {
        let mut child = Command::new(loader_path)
            .arg("--stream")
            .arg(object_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("启动 ks_loader 失败: {} (path={})", e, loader_path))?;

        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let stderr_buf = Arc::new(Mutex::new(Vec::with_capacity(STDERR_TAIL_BYTES)));

        // 后台预读 stderr：维护末尾 STDERR_TAIL_BYTES 字节用于错误诊断。
        // 若不预读，stderr 管道写满（默认 64KB）会阻塞子进程，导致 stdout 也停止。
        let stderr_buf_clone = Arc::clone(&stderr_buf);
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut chunk = [0u8; STDERR_READ_CHUNK];
            loop {
                match reader.read(&mut chunk).await {
                    Ok(0) => break, // EOF — 子进程关闭 stderr
                    Ok(n) => {
                        let mut buf = stderr_buf_clone.lock().await;
                        buf.extend_from_slice(&chunk[..n]);
                        // 仅保留末尾 STDERR_TAIL_BYTES 字节
                        if buf.len() > STDERR_TAIL_BYTES {
                            let drop_n = buf.len() - STDERR_TAIL_BYTES;
                            buf.drain(..drop_n);
                        }
                    }
                    Err(_) => break, // 读错误 — 子进程已退出或管道断裂
                }
            }
        });

        Ok(Self {
            child: Mutex::new(child),
            stdout: Mutex::new(BufReader::new(stdout)),
            stderr_buf,
            loader_path: loader_path.to_string(),
        })
    }

    /// `ks_loader` 二进制路径（用于诊断/日志）。
    pub fn loader_path(&self) -> &str {
        &self.loader_path
    }

    /// 取 stderr 末尾的字符串（用于错误诊断）。
    pub async fn stderr_tail(&self) -> String {
        let buf = self.stderr_buf.lock().await;
        String::from_utf8_lossy(&buf[..]).to_string()
    }
}

/// 从异步 reader 读一帧。
///
/// 帧格式：`[u32 LE length][u8[length] payload]`
/// - `length == 0`：心跳帧，跳过并继续读下一帧（用 loop 改写避免无限递归）。
/// - 优雅 EOF（读完前一帧后再次 read_exact 返回 UnexpectedEof）：返回 `Ok(None)`。
/// - payload 中途 EOF（length 声明 N 字节但实际读到 < N）：返回 `Err`，
///   视为子进程崩溃/管道断裂（与优雅 EOF 区分）。
/// - 正常帧：返回 `Ok(Some(payload))`。
///
/// 提取为独立函数便于单元测试（用 `std::io::Cursor` 模拟 reader，
/// tokio 为 `std::io::Cursor` 实现了 `AsyncRead`）。
async fn read_frame<R>(r: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncReadExt + Unpin,
{
    loop {
        let mut len_buf = [0u8; 4];
        // tokio AsyncReadExt::read_exact 返回 io::Result<usize>（成功时为 buf.len()）。
        // 用 Ok(_) 匹配，忽略返回的字节数（成功即等于 4 / length）。
        match r.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let length = u32::from_le_bytes(len_buf) as usize;
        if length == 0 {
            // 心跳帧 — 跳过继续读下一帧
            continue;
        }
        let mut payload = vec![0u8; length];
        match r.read_exact(&mut payload).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(anyhow!(
                    "ks_loader stdout 在 payload 中途 EOF (期望 {} 字节)",
                    length
                ));
            }
            Err(e) => return Err(e.into()),
        }
        return Ok(Some(payload));
    }
}

#[async_trait]
impl EventSource for CLoaderSource {
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        // 心跳帧 (length=0) 已由 read_frame 内部 loop 跳过，此处无需外层 loop。
        let mut stdout = self.stdout.lock().await;
        // &mut *stdout 解引用 MutexGuard 得到 &mut BufReader<ChildStdout>，
        // BufReader<ChildStdout> 实现 AsyncReadExt + Unpin。
        match read_frame(&mut *stdout).await? {
            Some(payload) => Ok(Some(payload)),
            None => {
                // stdout EOF — 子进程已退出，检查退出状态
                drop(stdout); // 释放 stdout 锁，避免与 child 锁竞争
                let mut child = self.child.lock().await;
                let exit = child.wait().await?;
                if exit.success() {
                    Ok(None) // 优雅退出
                } else {
                    let tail = self.stderr_tail().await;
                    Err(anyhow!(
                        "ks_loader 退出 code={:?} stderr_tail={}",
                        exit.code(),
                        tail
                    ))
                }
            }
        }
    }

    fn kind(&self) -> SourceKind {
        SourceKind::EbpfAncientNoBtf
    }

    fn description(&self) -> &str {
        "eBPF Ancient tier (NOBTF, C loader sidecar)"
    }

    fn is_mock(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_source_kind_ancient_nobtf_str() {
        assert_eq!(
            SourceKind::EbpfAncientNoBtf.as_str(),
            "eBPF-Ancient (NOBTF, C loader sidecar)"
        );
    }

    #[tokio::test]
    async fn test_read_frame_simple() {
        // 帧：length=4, payload=[0x01,0x02,0x03,0x04]
        let data: Vec<u8> = vec![0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[tokio::test]
    async fn test_read_frame_heartbeat_skipped() {
        // 帧 1: length=0 (心跳)
        // 帧 2: length=4, payload=[0x01,0x02,0x03,0x04]
        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[tokio::test]
    async fn test_read_frame_multiple_heartbeats_then_payload() {
        // 多个心跳帧后跟真实帧（验证 loop 改写无递归栈风险）
        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(
            frame,
            Some(vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00])
        );
    }

    #[tokio::test]
    async fn test_read_frame_eof_empty_input() {
        // 空输入 → 立即 EOF
        let data: Vec<u8> = vec![];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, None);
    }

    #[tokio::test]
    async fn test_read_frame_eof_after_one_frame() {
        // 一帧后再读 → EOF（优雅退出）
        let data: Vec<u8> = vec![0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut cursor = Cursor::new(data);
        let frame1 = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame1, Some(vec![0x01, 0x02, 0x03, 0x04]));
        let frame2 = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame2, None);
    }

    #[tokio::test]
    async fn test_read_frame_payload_eof_midway_is_error() {
        // length=8 但只提供 4 字节 payload → 错误（不是优雅 EOF）
        // 这模拟子进程在写 payload 中途崩溃的场景
        let data: Vec<u8> = vec![0x08, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut cursor = Cursor::new(data);
        let result = read_frame(&mut cursor).await;
        assert!(result.is_err(), "应在 payload 中途 EOF 时返回错误");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("payload 中途 EOF"),
            "错误信息应说明 payload 中途 EOF，实际：{}",
            err
        );
    }

    #[tokio::test]
    async fn test_read_frame_large_length() {
        // 大 length 帧测试（1024 字节 = 0x400）
        let mut data: Vec<u8> = vec![0x00, 0x04, 0x00, 0x00];
        data.extend(std::iter::repeat_n(0xAB, 1024));
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(frame.len(), 1024);
        assert!(frame.iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn test_read_frame_sequential_multiple() {
        // 连续多帧（含心跳）— 验证 read_frame 可被反复调用
        let mut data: Vec<u8> = Vec::new();
        // 帧 1: length=2 payload=[0xAA,0xBB]
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB]);
        // 帧 2: length=0 心跳
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // 帧 3: length=3 payload=[0x01,0x02,0x03]
        data.extend_from_slice(&[0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03]);
        let mut cursor = Cursor::new(data);
        assert_eq!(
            read_frame(&mut cursor).await.unwrap(),
            Some(vec![0xAA, 0xBB])
        );
        assert_eq!(
            read_frame(&mut cursor).await.unwrap(),
            Some(vec![0x01, 0x02, 0x03])
        );
        assert_eq!(read_frame(&mut cursor).await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_read_frame_length_uses_little_endian() {
        // 验证 length 字段按 LE 解码：0x01000000 LE = 1
        // payload 为单字节 0x42
        let data: Vec<u8> = vec![0x01, 0x00, 0x00, 0x00, 0x42];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Some(vec![0x42]));
    }

    #[tokio::test]
    async fn test_read_frame_two_bytes_length_field() {
        // length = 0x00000200 LE = 512 字节
        let mut data: Vec<u8> = vec![0x00, 0x02, 0x00, 0x00];
        data.extend(std::iter::repeat_n(0x7F, 512));
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(frame.len(), 512);
        assert!(frame.iter().all(|&b| b == 0x7F));
    }

    #[tokio::test]
    async fn test_stderr_tail_initial_empty() {
        // stderr_buf 初始为空（不实际 spawn 子进程，仅验证结构行为）
        let stderr_buf = Arc::new(Mutex::new(Vec::with_capacity(STDERR_TAIL_BYTES)));
        let tail = {
            let buf = stderr_buf.lock().await;
            String::from_utf8_lossy(&buf[..]).to_string()
        };
        assert_eq!(tail, "");
    }

    #[tokio::test]
    async fn test_stderr_ring_buffer_keeps_tail_only() {
        // 模拟后台 stderr 任务写入超过 STDERR_TAIL_BYTES 字节的行为
        let stderr_buf: Arc<Mutex<Vec<u8>>> =
            Arc::new(Mutex::new(Vec::with_capacity(STDERR_TAIL_BYTES)));

        // 写入 700 字节 'A'，应只保留末尾 512 字节
        {
            let mut buf = stderr_buf.lock().await;
            buf.extend(std::iter::repeat_n(b'A', 700));
            if buf.len() > STDERR_TAIL_BYTES {
                let drop_n = buf.len() - STDERR_TAIL_BYTES;
                buf.drain(..drop_n);
            }
        }

        let buf = stderr_buf.lock().await;
        assert_eq!(buf.len(), STDERR_TAIL_BYTES);
        assert!(buf.iter().all(|&b| b == b'A'));
    }
}
