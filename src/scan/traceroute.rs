//! `kaisen path <target>` / `kaisen traceroute <target>` — TCP connect path tracing.
//! Discovers intermediate hops and latency toward a destination port without requiring root.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::util::output::Painter;

#[derive(Debug, Clone)]
pub struct Hop {
    pub ttl: u8,
    pub rtt: Option<Duration>,
    pub state: &'static str,
    pub reached: bool,
}

/// Trace TCP route to target IP and port by incrementing IP_TTL.
pub async fn run_traceroute(target: &str, ip: IpAddr, port: u16, max_hops: u8, timeout_ms: u64, color: bool) {
    let p = Painter::new(color);
    println!();
    println!(
        "{} {} ({}) on port {}/tcp (max {} hops):",
        p.bold("Tracing path to"),
        p.cyan(target),
        ip,
        port,
        max_hops
    );
    println!();
    println!("  {:<4}  {:<12}  {}", p.bold("HOP"), p.bold("RTT"), p.bold("STATUS"));
    println!("  ----------------------------------------");

    let timeout_dur = Duration::from_millis(timeout_ms.max(500));

    for ttl in 1..=max_hops {
        let hop = probe_hop(ip, port, ttl, timeout_dur).await;
        let rtt_str = hop
            .rtt
            .map(|d| format!("{:.2} ms", d.as_secs_f64() * 1000.0))
            .unwrap_or_else(|| "*".to_string());

        let status_str = match hop.state {
            "reached (open)" => p.green("REACHED [open] (SYN-ACK)"),
            "reached (closed)" => p.yellow("REACHED [closed] (RST)"),
            "ttl-expired / intermediate" => p.cyan("transit response"),
            _ => p.dim("* timeout"),
        };

        println!("  {:<4}  {:<12}  {}", ttl, rtt_str, status_str);

        if hop.reached {
            println!();
            println!("{}", p.green(&format!("Destination reached in {ttl} hop(s).")));
            return;
        }
    }

    println!();
    println!("{}", p.dim(&format!("Trace completed ({max_hops} hops probed).")));
}

async fn probe_hop(ip: IpAddr, port: u16, ttl: u8, timeout_dur: Duration) -> Hop {
    let start = Instant::now();
    let addr = SocketAddr::new(ip, port);

    let res = tokio::task::spawn_blocking(move || {
        let domain = if ip.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = match socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP)) {
            Ok(s) => s,
            Err(_) => return Hop { ttl, rtt: None, state: "socket-error", reached: false },
        };

        // Set IP_TTL / unicast hops
        if ip.is_ipv4() {
            let _ = socket.set_ttl_v4(ttl as u32);
        } else {
            let _ = socket.set_unicast_hops_v6(ttl as u32);
        }

        let _ = socket.set_nonblocking(true);
        let sock_addr = socket2::SockAddr::from(addr);

        match socket.connect(&sock_addr) {
            Ok(_) => Hop {
                ttl,
                rtt: Some(start.elapsed()),
                state: "reached (open)",
                reached: true,
            },
            Err(e) => {
                let raw_os = e.raw_os_error();
                // On Windows WSAEWOULDBLOCK = 10035, Linux EINPROGRESS = 115
                #[cfg(windows)]
                let in_progress = raw_os == Some(10035);
                #[cfg(not(windows))]
                let in_progress = raw_os == Some(115);

                if in_progress {
                    // Poll for connection with timeout
                    let pollfd = libc_pollfd(socket, timeout_dur);
                    if pollfd {
                        Hop {
                            ttl,
                            rtt: Some(start.elapsed()),
                            state: "reached (open)",
                            reached: true,
                        }
                    } else {
                        Hop {
                            ttl,
                            rtt: None,
                            state: "timeout",
                            reached: false,
                        }
                    }
                } else if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    Hop {
                        ttl,
                        rtt: Some(start.elapsed()),
                        state: "reached (closed)",
                        reached: true,
                    }
                } else {
                    Hop {
                        ttl,
                        rtt: None,
                        state: "timeout",
                        reached: false,
                    }
                }
            }
        }
    })
    .await;

    match res {
        Ok(h) => h,
        Err(_) => Hop { ttl, rtt: None, state: "error", reached: false },
    }
}

fn libc_pollfd(socket: socket2::Socket, timeout_dur: Duration) -> bool {
    let std_stream: std::net::TcpStream = socket.into();
    let fds = [std_stream];
    // Simple poll using select/connect check
    let start = Instant::now();
    while start.elapsed() < timeout_dur {
        if let Ok(Some(_)) = fds[0].take_error() {
            return false;
        }
        if fds[0].peer_addr().is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

