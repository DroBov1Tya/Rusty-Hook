//! `rusty-hook healthcheck`: tiny HTTP probe for Docker (image has no curl).

use std::{io, net::SocketAddr, process::ExitCode, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const TIMEOUT: Duration = Duration::from_secs(3);

pub async fn probe() -> ExitCode {
    let port = std::env::var("APP_BIND").ok().and_then(|b| b.parse::<SocketAddr>().ok()).map_or(8080, |a| a.port());
    let status = timeout(TIMEOUT, get_status(SocketAddr::from(([127, 0, 0, 1], port)))).await;
    match status {
        Ok(Ok(200)) => ExitCode::SUCCESS,
        Ok(Ok(code)) => {
            eprintln!("healthz: {code}");
            ExitCode::FAILURE
        }
        Ok(Err(err)) => {
            eprintln!("healthz: {err}");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("healthz: timed out");
            ExitCode::FAILURE
        }
    }
}

async fn get_status(addr: SocketAddr) -> io::Result<u16> {
    let mut conn = TcpStream::connect(addr).await?;
    conn.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await?;
    let mut head = [0u8; 12];
    conn.read_exact(&mut head).await?;
    // "HTTP/1.1 200"
    std::str::from_utf8(&head[9..12])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("bad status line"))
}
