//! CLoaderSource通过fork+exec启动ks_loader --stream子进程,从其stdout管道读事件。
//!
//! 用于3.10 stock内核(无BTF,aya无法加载):ks_loader这个C loader加载eBPF程序,把perfbuf事件按帧格式[u32 LE length][u8[length] payload]写到stdout,Rust父进程异步读帧后解码为事件字节。
//!
//! tokio::process在所有unix平台可用,所以这个模块不做cfg(target_os="linux")限制,但只在Linux上有意义(非Linux平台spawn ks_loader会立即失败返回Err)。

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::event_source::{EventSource, SourceKind};

/// stderr环形缓冲保留的字节数,错误诊断时打印末尾tail。
const STDERR_TAIL_BYTES: usize = 512;

/// 后台stderr读取任务的单次read缓冲大小。
const STDERR_READ_CHUNK: usize = 256;

/// C loader sidecar事件源。
///
/// 持有ks_loader --stream <obj>子进程,从其stdout异步读帧。子进程stderr由后台tokio task异步预读到环形缓冲,只保留末尾STDERR_TAIL_BYTES字节,子进程异常退出时方便打印诊断信息。
///
/// 设计要点:child和stdout各自独立Mutex包装,未来若要并行访问(比如kill child)不会跟next_bytes的&mut self冲突,当前trait只用&mut self调用,Mutex不会引入锁竞争;stderr_buf用Arc<Mutex<Vec<u8>>>,后台task与本结构共享所有权;read_exact在EOF时返回Err(UnexpectedEof),由read_frame统一处理成Ok(None)表示优雅EOF,payload中途EOF视为错误(子进程崩溃或管道断裂)。
pub struct CLoaderSource {
    child: Mutex<Child>,
    stdout: Mutex<BufReader<ChildStdout>>,
    /// stderr末尾STDERR_TAIL_BYTES字节,用于错误诊断。
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    loader_path: String,
}

impl CLoaderSource {
    /// 启动ks_loader --stream <object_path>子进程。
    ///
    /// loader_path是ks_loader二进制路径,object_path是.o文件路径。stdin/stdout/stderr全部重定向:stdin关闭(null),stdout/stderr piped。stderr由后台task异步预读,保留末尾512字节用于诊断。
    pub fn spawn(loader_path: &str, object_path: &str) -> Result<Self> {
        let mut child = Command::new(loader_path)
            .arg("--stream")
            .arg(object_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("启动ks_loader失败: {} (path={})", e, loader_path))?;

        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        let stderr_buf = Arc::new(Mutex::new(Vec::with_capacity(STDERR_TAIL_BYTES)));

        // 后台预读stderr,维护末尾STDERR_TAIL_BYTES字节用于错误诊断。
        // 不预读的话stderr管道写满(默认64KB)会阻塞子进程,导致stdout也停止。
        let stderr_buf_clone = Arc::clone(&stderr_buf);
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut chunk = [0u8; STDERR_READ_CHUNK];
            loop {
                match reader.read(&mut chunk).await {
                    Ok(0) => break, // EOF,子进程关闭stderr
                    Ok(n) => {
                        let mut buf = stderr_buf_clone.lock().await;
                        buf.extend_from_slice(&chunk[..n]);
                        // 只保留末尾STDERR_TAIL_BYTES字节
                        if buf.len() > STDERR_TAIL_BYTES {
                            let drop_n = buf.len() - STDERR_TAIL_BYTES;
                            buf.drain(..drop_n);
                        }
                    }
                    Err(_) => break, // 读错误,子进程已退出或管道断裂
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

    /// ks_loader二进制路径,用于诊断和日志。
    pub fn loader_path(&self) -> &str {
        &self.loader_path
    }

    /// 取stderr末尾的字符串,用于错误诊断。
    pub async fn stderr_tail(&self) -> String {
        let buf = self.stderr_buf.lock().await;
        String::from_utf8_lossy(&buf[..]).to_string()
    }
}

/// 从异步reader读一帧。
///
/// 帧格式是[u32 LE length][u8[length] payload]。length为0是心跳帧,跳过继续读下一帧(用loop改写避免无限递归);读完前一帧后再次read_exact返回UnexpectedEof属于优雅EOF,返回Ok(None);length声明N字节但实际读到不足N属于payload中途EOF,返回Err,视为子进程崩溃或管道断裂,跟优雅EOF区分开;正常帧返回Ok(Some(payload))。
///
/// 提取为独立函数方便单测,用std::io::Cursor模拟reader,tokio为std::io::Cursor实现了AsyncRead。
async fn read_frame<R>(r: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncReadExt + Unpin,
{
    loop {
        let mut len_buf = [0u8; 4];
        // tokio AsyncReadExt::read_exact返回io::Result<usize>,成功时为buf长度。
        // 这里用Ok(_)匹配,忽略返回的字节数(成功即等于4或length)。
        match r.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let length = u32::from_le_bytes(len_buf) as usize;
        if length == 0 {
            // 心跳帧,跳过继续读下一帧
            continue;
        }
        let mut payload = vec![0u8; length];
        match r.read_exact(&mut payload).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(anyhow!(
                    "ks_loader stdout在payload中途EOF(期望{}字节)",
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
        // 心跳帧(length=0)已由read_frame内部loop跳过,这里不需要外层loop。
        let mut stdout = self.stdout.lock().await;
        // &mut *stdout解引用MutexGuard得到&mut BufReader<ChildStdout>,
        // BufReader<ChildStdout>实现AsyncReadExt + Unpin。
        match read_frame(&mut *stdout).await? {
            Some(payload) => Ok(Some(payload)),
            None => {
                // stdout EOF,子进程已退出,检查退出状态
                drop(stdout); // 释放stdout锁,避免跟child锁竞争
                let mut child = self.child.lock().await;
                let exit = child.wait().await?;
                if exit.success() {
                    Ok(None) // 优雅退出
                } else {
                    let tail = self.stderr_tail().await;
                    Err(anyhow!(
                        "ks_loader退出code={:?} stderr_tail={}",
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
        // 帧:length=4,payload=[0x01,0x02,0x03,0x04]
        let data: Vec<u8> = vec![0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[tokio::test]
    async fn test_read_frame_heartbeat_skipped() {
        // 帧1:length=0(心跳)
        // 帧2:length=4,payload=[0x01,0x02,0x03,0x04]
        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[tokio::test]
    async fn test_read_frame_multiple_heartbeats_then_payload() {
        // 多个心跳帧后跟真实帧,验证loop改写没有递归栈风险
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
        // 空输入立即EOF
        let data: Vec<u8> = vec![];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, None);
    }

    #[tokio::test]
    async fn test_read_frame_eof_after_one_frame() {
        // 一帧后再读为EOF,属于优雅退出
        let data: Vec<u8> = vec![0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut cursor = Cursor::new(data);
        let frame1 = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame1, Some(vec![0x01, 0x02, 0x03, 0x04]));
        let frame2 = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame2, None);
    }

    #[tokio::test]
    async fn test_read_frame_payload_eof_midway_is_error() {
        // length=8但只提供4字节payload,返回错误,不是优雅EOF
        // 模拟子进程在写payload中途崩溃的场景
        let data: Vec<u8> = vec![0x08, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut cursor = Cursor::new(data);
        let result = read_frame(&mut cursor).await;
        assert!(result.is_err(), "应在payload中途EOF时返回错误");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("payload中途EOF"),
            "错误信息应说明payload中途EOF,实际:{}",
            err
        );
    }

    #[tokio::test]
    async fn test_read_frame_large_length() {
        // 大length帧测试,1024字节即0x400
        let mut data: Vec<u8> = vec![0x00, 0x04, 0x00, 0x00];
        data.extend(std::iter::repeat_n(0xAB, 1024));
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(frame.len(), 1024);
        assert!(frame.iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn test_read_frame_sequential_multiple() {
        // 连续多帧含心跳,验证read_frame可被反复调用
        let mut data: Vec<u8> = Vec::new();
        // 帧1:length=2 payload=[0xAA,0xBB]
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB]);
        // 帧2:length=0 心跳
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // 帧3:length=3 payload=[0x01,0x02,0x03]
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
        // 验证length字段按LE解码,0x01000000 LE=1
        // payload为单字节0x42
        let data: Vec<u8> = vec![0x01, 0x00, 0x00, 0x00, 0x42];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Some(vec![0x42]));
    }

    #[tokio::test]
    async fn test_read_frame_two_bytes_length_field() {
        // length=0x00000200 LE=512字节
        let mut data: Vec<u8> = vec![0x00, 0x02, 0x00, 0x00];
        data.extend(std::iter::repeat_n(0x7F, 512));
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(frame.len(), 512);
        assert!(frame.iter().all(|&b| b == 0x7F));
    }

    #[tokio::test]
    async fn test_stderr_tail_initial_empty() {
        // stderr_buf初始为空,不实际spawn子进程,只验证结构行为
        let stderr_buf = Arc::new(Mutex::new(Vec::with_capacity(STDERR_TAIL_BYTES)));
        let tail = {
            let buf = stderr_buf.lock().await;
            String::from_utf8_lossy(&buf[..]).to_string()
        };
        assert_eq!(tail, "");
    }

    #[tokio::test]
    async fn test_stderr_ring_buffer_keeps_tail_only() {
        // 模拟后台stderr任务写入超过STDERR_TAIL_BYTES字节的行为
        let stderr_buf: Arc<Mutex<Vec<u8>>> =
            Arc::new(Mutex::new(Vec::with_capacity(STDERR_TAIL_BYTES)));

        // 写入700字节A,应只保留末尾512字节
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
