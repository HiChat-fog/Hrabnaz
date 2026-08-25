use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::event_source::{EventSource, SourceKind};

const STDERR_TAIL_BYTES: usize = 512;

const STDERR_READ_CHUNK: usize = 256;

pub struct CLoaderSource {
    child: Mutex<Child>,
    stdout: Mutex<BufReader<ChildStdout>>,
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    loader_path: String,
}

impl CLoaderSource {
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

        let stderr_buf_clone = Arc::clone(&stderr_buf);
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut chunk = [0u8; STDERR_READ_CHUNK];
            loop {
                match reader.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut buf = stderr_buf_clone.lock().await;
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.len() > STDERR_TAIL_BYTES {
                            let drop_n = buf.len() - STDERR_TAIL_BYTES;
                            buf.drain(..drop_n);
                        }
                    }
                    Err(_) => break,
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

    pub fn loader_path(&self) -> &str {
        &self.loader_path
    }

    pub async fn stderr_tail(&self) -> String {
        let buf = self.stderr_buf.lock().await;
        String::from_utf8_lossy(&buf[..]).to_string()
    }
}

async fn read_frame<R>(r: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncReadExt + Unpin,
{
    loop {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let length = u32::from_le_bytes(len_buf) as usize;
        if length == 0 {
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
        let mut stdout = self.stdout.lock().await;
        match read_frame(&mut *stdout).await? {
            Some(payload) => Ok(Some(payload)),
            None => {
                drop(stdout);
                let mut child = self.child.lock().await;
                let exit = child.wait().await?;
                if exit.success() {
                    Ok(None)
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
        let data: Vec<u8> = vec![0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[tokio::test]
    async fn test_read_frame_heartbeat_skipped() {
        let data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Some(vec![0x01, 0x02, 0x03, 0x04]));
    }

    #[tokio::test]
    async fn test_read_frame_multiple_heartbeats_then_payload() {
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
        let data: Vec<u8> = vec![];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, None);
    }

    #[tokio::test]
    async fn test_read_frame_eof_after_one_frame() {
        let data: Vec<u8> = vec![0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let mut cursor = Cursor::new(data);
        let frame1 = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame1, Some(vec![0x01, 0x02, 0x03, 0x04]));
        let frame2 = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame2, None);
    }

    #[tokio::test]
    async fn test_read_frame_payload_eof_midway_is_error() {
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
        let mut data: Vec<u8> = vec![0x00, 0x04, 0x00, 0x00];
        data.extend(std::iter::repeat_n(0xAB, 1024));
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(frame.len(), 1024);
        assert!(frame.iter().all(|&b| b == 0xAB));
    }

    #[tokio::test]
    async fn test_read_frame_sequential_multiple() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
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
        let data: Vec<u8> = vec![0x01, 0x00, 0x00, 0x00, 0x42];
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap();
        assert_eq!(frame, Some(vec![0x42]));
    }

    #[tokio::test]
    async fn test_read_frame_two_bytes_length_field() {
        let mut data: Vec<u8> = vec![0x00, 0x02, 0x00, 0x00];
        data.extend(std::iter::repeat_n(0x7F, 512));
        let mut cursor = Cursor::new(data);
        let frame = read_frame(&mut cursor).await.unwrap().unwrap();
        assert_eq!(frame.len(), 512);
        assert!(frame.iter().all(|&b| b == 0x7F));
    }

    #[tokio::test]
    async fn test_stderr_tail_initial_empty() {
        let stderr_buf = Arc::new(Mutex::new(Vec::with_capacity(STDERR_TAIL_BYTES)));
        let tail = {
            let buf = stderr_buf.lock().await;
            String::from_utf8_lossy(&buf[..]).to_string()
        };
        assert_eq!(tail, "");
    }

    #[tokio::test]
    async fn test_stderr_ring_buffer_keeps_tail_only() {
        let stderr_buf: Arc<Mutex<Vec<u8>>> =
            Arc::new(Mutex::new(Vec::with_capacity(STDERR_TAIL_BYTES)));

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
