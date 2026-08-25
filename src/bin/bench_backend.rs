//! 极简压测后端：单文件、零业务逻辑，返回 `ok`（2 字节）。
//!
//! 用途：在本机压测 `RustGate` 时充当受保护后端，避免 `Python` 等慢后端
//! 成为吞吐瓶颈。只监听 `127.0.0.1`，不对外服务。
//!
//! 运行：
//! ```bash
//! cargo build --release --bin bench_backend
//! ./target/release/bench_backend
//! ```

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:18080")
        .await
        .expect("压测后端绑定 127.0.0.1:18080 失败");
    eprintln!("bench_backend 监听 127.0.0.1:18080");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept 失败: {e}");
                continue;
            }
        };

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(|_req: Request<Incoming>| async move {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("连接错误: {e}");
            }
        });
    }
}
