//! `rusty-hook healthcheck`: tiny HTTP probe for Docker (image has no curl).

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    process::ExitCode,
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_secs(3);

pub fn probe() -> ExitCode {
    let port = std::env::var("APP_BIND").ok().and_then(|b| b.parse::<SocketAddr>().ok()).map_or(8080, |a| a.port());
    match get_status(SocketAddr::from(([127, 0, 0, 1], port))) {
        Ok(200) => ExitCode::SUCCESS,
        Ok(code) => {
            eprintln!("healthz: {code}");
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("healthz: {err}");
            ExitCode::FAILURE
        }
    }
}

fn get_status(addr: SocketAddr) -> std::io::Result<u16> {
    let mut conn = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    conn.set_read_timeout(Some(TIMEOUT))?;
    conn.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut head = [0u8; 12];
    conn.read_exact(&mut head)?;
    // "HTTP/1.1 200"
    std::str::from_utf8(&head[9..12])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::other("bad status line"))
}
