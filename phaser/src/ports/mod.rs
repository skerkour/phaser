use crate::report::{Host, Port, Protocol};
use futures::{stream, StreamExt};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;

mod common_ports;
use common_ports::MOST_COMMON_PORTS;

pub async fn scan_ports(concurrency: usize, mut host: Host) -> Host {
    let hostname = &host.domain.clone();

    host.ports = stream::iter(MOST_COMMON_PORTS.into_iter())
        .map(|port| scan_port(hostname, *port))
        .buffer_unordered(concurrency)
        .filter_map(|port| async { port })
        .collect()
        .await;

    host
}

async fn scan_port(hostname: &str, port: u16) -> Option<Port> {
    let timeout = Duration::from_secs(3);
    let socket_addresses: Vec<SocketAddr> = format!("{}:{}", hostname, port)
        .to_socket_addrs()
        .expect("port scanner: Creating socket address")
        .collect();

    if socket_addresses.len() == 0 {
        return None;
    }

    // TODO: detect protocol
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addresses[0])).await {
        Ok(_) => Some(Port {
            port: port,
            protocol: Protocol::Tcp,
            findings: Vec::new(),
        }),
        Err(_) => None,
    }
}
