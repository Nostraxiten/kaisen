//! Service & version detection via banner grabbing, protocol probes and TLS.
//! All unprivileged: it just talks to the open TCP port like any client would.
//!
//! Detection runs in three tiers, cheapest first:
//!   1. **Listen** — protocols that greet you (SSH, SMTP, FTP, IMAP, VNC…).
//!   2. **Probe** — a per-port plan that says the right thing to make a silent
//!      service identify itself: an HTTP request, a TLS ClientHello, or one of
//!      the binary handshakes in `probe.rs` (SMB, TDS, TNS, CQL, BSON…).
//!   3. **Fallback** — for ports with no plan and no greeting, try HTTP, then
//!      TLS, then a bare newline, because unusual ports are exactly where
//!      unexpected web and TLS services live.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::probe::{self, first_version};
use crate::tls;

#[derive(Debug, Clone, Default)]
pub struct ServiceInfo {
    pub name: String,        // e.g. "http", "ssh"
    pub product: String,     // e.g. "OpenSSH", "nginx"
    pub version: String,     // e.g. "8.2p1"
    pub extra: String,       // e.g. "Ubuntu 4ubuntu0.5"
    pub banner: String,      // raw banner (trimmed)
    pub os_hint: String,     // OS inferred from banner, if any
    pub tls_version: String, // negotiated TLS/SSL version, when the port speaks TLS
    pub cert_expired: bool,  // certificate notAfter is in the past
    pub self_signed: bool,   // certificate subject == issuer
    pub hostnames: Vec<String>, // names learned from the certificate (CN + SANs)
    /// True when the service returned *any* bytes during detection — even
    /// binary data we could not parse into a product string. A middlebox that
    /// accepts the TCP handshake but says nothing will leave this false, so it
    /// remains the best single signal that a real listener is present.
    pub got_data: bool,
}

impl ServiceInfo {
    /// Did anything actually answer on this port? `name` alone doesn't
    /// count — that starts life as a guess from the port number. A banner, a
    /// product, raw received bytes, or a completed TLS handshake is the
    /// service itself speaking — the difference between a real listener and a
    /// middlebox that merely completes handshakes.
    pub fn has_evidence(&self) -> bool {
        self.got_data
            || !self.banner.is_empty()
            || !self.product.is_empty()
            || !self.tls_version.is_empty()
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.product.is_empty() {
            parts.push(self.product.clone());
        }
        if !self.version.is_empty() {
            parts.push(self.version.clone());
        }
        if !self.extra.is_empty() {
            parts.push(format!("({})", self.extra));
        }
        parts.join(" ")
    }
}

/// What to say to a port to make it talk.
enum Plan {
    /// Say nothing: the server greets first.
    Listen,
    /// Send these bytes verbatim, then read.
    Text(&'static [u8]),
    /// Issue an HTTP GET for this path.
    Http(&'static str),
    /// Run a TLS handshake and read the certificate.
    Tls,
    /// Speak a binary protocol from `probe.rs`.
    Bin(Bin),
}

#[derive(Clone, Copy, PartialEq)]
enum Bin {
    Smb,
    Mssql,
    Mongo,
    Postgres,
    Mqtt,
    Amqp,
    Dns,
    Minecraft,
    Epmd,
    Cassandra,
    Kafka,
    Rdp,
    X11,
    Ldap,
    Oracle,
    Ajp,
    Socks,
    Git,
}

/// The per-port probe plan. Ports absent from this table fall through to the
/// listen-then-fallback path, which still finds HTTP and TLS services.
fn plan_for(port: u16) -> Plan {
    match port {
        // ── plain HTTP, and web UIs worth asking a specific path for ────────
        80 | 81 | 82 | 83 | 84 | 591 | 3000 | 3001 | 4200 | 5000 | 5001 | 7080 | 8000
        | 8001 | 8002 | 8003 | 8008 | 8010 | 8060 | 8069 | 8080 | 8081 | 8082 | 8083 | 8085
        | 8088 | 8090 | 8095 | 8096 | 8112 | 8123 | 8181 | 8291 | 8500 | 8600 | 8765 | 8787
        | 8880 | 8888 | 8889 | 9080 | 9090 | 9091 | 9100 | 9111 | 9200 | 9300 | 9981 | 10000
        | 32400 | 3128 | 5601 | 5800 | 55555 | 61208 => Plan::Http("/"),
        2375 | 2376 => Plan::Http("/version"),
        2379 | 2380 | 4001 => Plan::Http("/version"),
        8086 => Plan::Http("/ping"),
        15672 | 15692 => Plan::Http("/"),
        7474 | 7473 => Plan::Http("/"),
        9042 => Plan::Bin(Bin::Cassandra),
        8161 => Plan::Http("/"),
        4848 | 7001 | 7002 | 9990 => Plan::Http("/"),
        6800 | 6801 => Plan::Http("/"),

        // ── TLS-wrapped ports ───────────────────────────────────────────────
        443 | 444 | 448 | 465 | 563 | 585 | 614 | 636 | 853 | 989 | 990 | 992 | 993 | 994
        | 995 | 1311 | 2083 | 2087 | 2096 | 2484 | 3269 | 4443 | 5061 | 5986 | 6443 | 6697
        | 7443 | 8443 | 8834 | 8883 | 9001 | 9443 | 10250 | 10443 | 16443 | 18091 | 18092
        | 27019 | 32443 | 44300 | 47001 => Plan::Tls,

        // ── binary / handshake protocols ────────────────────────────────────
        139 | 445 => Plan::Bin(Bin::Smb),
        1433 | 1434 => Plan::Bin(Bin::Mssql),
        27017 | 27018 | 27020 | 28017 => Plan::Bin(Bin::Mongo),
        5432 | 5433 | 6432 | 26257 => Plan::Bin(Bin::Postgres),
        1883 => Plan::Bin(Bin::Mqtt),
        5672 | 5671 => Plan::Bin(Bin::Amqp),
        53 | 5353 | 5355 => Plan::Bin(Bin::Dns),
        25565 | 25575 | 19132 => Plan::Bin(Bin::Minecraft),
        4369 => Plan::Bin(Bin::Epmd),
        9092 | 9093 | 9094 => Plan::Bin(Bin::Kafka),
        3389 | 3388 => Plan::Bin(Bin::Rdp),
        6000..=6009 => Plan::Bin(Bin::X11),
        389 | 3268 => Plan::Bin(Bin::Ldap),
        1521 | 1522 | 1526 | 1630 | 2483 => Plan::Bin(Bin::Oracle),
        8009 | 8109 | 8209 => Plan::Bin(Bin::Ajp),
        1080 | 1085 | 9050 | 9150 => Plan::Bin(Bin::Socks),
        9418 => Plan::Bin(Bin::Git),

        // ── line protocols that want a nudge ────────────────────────────────
        6379 | 6380 | 16379 => Plan::Text(b"INFO\r\nPING\r\n"),
        11211 | 11212 => Plan::Text(b"version\r\nstats\r\n"),
        2181 | 2182 | 2888 | 3888 => Plan::Text(b"srvr"),
        554 | 8554 | 1935 | 7070 => Plan::Text(
            b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Kaisen\r\n\r\n",
        ),
        5060 | 5062 | 5080 => Plan::Text(
            b"OPTIONS sip:kaisen SIP/2.0\r\nVia: SIP/2.0/TCP kaisen;branch=z9hG4bKkaisen\r\n\
              From: <sip:kaisen@kaisen>;tag=1\r\nTo: <sip:kaisen>\r\nCall-ID: kaisen\r\n\
              CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
        ),
        194 | 6660..=6669 | 6679 | 7000 => Plan::Text(b"NICK kaisen\r\nUSER kaisen 0 * :kaisen\r\n"),
        70 => Plan::Text(b"\r\n"),
        79 => Plan::Text(b"root\r\n"),
        43 | 4321 => Plan::Text(b"kaisen\r\n"),
        119 | 433 => Plan::Text(b"HELP\r\n"),

        _ => Plan::Listen,
    }
}

/// Probe an open port for its service banner/version. `default_name` is the
/// nmap-services guess used when we cannot read anything useful; `host` is the
/// name the user asked for, used for TLS SNI and virtual-host aware requests.
pub async fn detect(addr: SocketAddr, default_name: &str, timeout_ms: u64, host: &str) -> ServiceInfo {
    let mut info = ServiceInfo {
        name: default_name.to_string(),
        ..Default::default()
    };

    let dur = Duration::from_millis(timeout_ms.max(500));
    let port = addr.port();
    let host_opt = if host.is_empty() { None } else { Some(host) };

    match plan_for(port) {
        Plan::Tls => {
            if let Some(t) = tls::probe(addr, host_opt, dur).await {
                apply_tls(port, &t, &mut info);
                // Many TLS ports are HTTPS; the certificate alone doesn't say
                // which web server sits behind it, but the ALPN does tell us
                // it's HTTP at all.
                return info;
            }
            // Not actually TLS: fall through to the generic path.
        }
        Plan::Bin(kind) => {
            if let Some(p) = run_binary(kind, addr, host, dur).await {
                apply_probed(&p, &mut info);
                return info;
            }
        }
        _ => {}
    }

    let probe_bytes: Option<Vec<u8>> = match plan_for(port) {
        Plan::Text(b) => Some(b.to_vec()),
        Plan::Http(path) => Some(http_request(path, host, port).into_bytes()),
        _ => None,
    };

    // Server-speaks-first protocols answer without prompting; give ports with
    // no active probe a longer window to say hello before we give up on them.
    // MySQL is why this scales with --timeout instead of being a fixed 900 ms:
    // a server with `skip-name-resolve` off reverse-resolves the client address
    // before it greets, and where that lookup has to time out first the
    // handshake arrives seconds late — which showed up as an open 3306 with an
    // empty VERSION column.
    let listen_ms = if probe_bytes.is_some() { 400 } else { (dur.as_millis() as u64).max(900) };

    let mut stream = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return info,
    };
    // RST on close so this probe doesn't leave a lingering conntrack entry.
    crate::netutil::reset_on_close(&stream);

    let mut data = read_for(&mut stream, Duration::from_millis(listen_ms), 8192).await;

    if data.is_empty() {
        if let Some(p) = &probe_bytes {
            let _ = timeout(dur, stream.write_all(p)).await;
            data = read_for(&mut stream, dur, 65536).await;
        }
    } else if matches!(plan_for(port), Plan::Text(_)) {
        // The greeting arrived first (Redis, memcached and friends), but our
        // command still adds the version lines we actually want.
        if let Some(p) = &probe_bytes {
            let _ = timeout(dur, stream.write_all(p)).await;
            let more = read_for(&mut stream, dur, 65536).await;
            data.extend_from_slice(&more);
        }
    }

    if !data.is_empty() {
        // Any bytes from the service — even binary data we cannot parse — are
        // evidence that a real listener is present (not just a middlebox).
        info.got_data = true;
        parse_banner(port, &data, &mut info);
        follow_up(&mut stream, port, dur, &mut info).await;
        if !info.product.is_empty() || !info.version.is_empty() {
            return info;
        }
    }

    drop(stream);

    // ── fallbacks: nothing identified the port yet ──────────────────────────
    if info.product.is_empty() {
        // An HTTP service on an unexpected port is by far the most common case.
        if !matches!(plan_for(port), Plan::Http(_)) {
            if let Ok(Ok(mut s)) = timeout(dur, TcpStream::connect(addr)).await {
                crate::netutil::reset_on_close(&s);
                let req = http_request("/", host, port);
                if timeout(dur, s.write_all(req.as_bytes())).await.is_ok() {
                    let body = read_for(&mut s, dur, 65536).await;
                    if !body.is_empty() {
                        info.got_data = true;
                        parse_banner(port, &body, &mut info);
                        if !info.product.is_empty() {
                            return info;
                        }
                    }
                }
            }
        }
        // Then TLS: management consoles and databases love odd TLS ports.
        if !matches!(plan_for(port), Plan::Tls) {
            if let Some(t) = tls::probe(addr, host_opt, dur).await {
                apply_tls(port, &t, &mut info);
                return info;
            }
        }
    }

    info
}

/// Like `detect`, but runs on an *already-connected* `TcpStream` instead of
/// opening a new one. This is the critical path when a middlebox accepts the
/// initial TCP handshake for every port and then blocks reconnects from the
/// same source — by reusing the socket we already have, we get real service
/// data before the rate-limit can hide it.
///
/// Protocol handling:
/// * **TLS** — sends a ClientHello directly on the stream (TLS 1.3 extensions
///   included), covering all modern servers in one shot.
/// * **Binary** (SMB, TDS, …) — need a fresh connection with the right framing;
///   the initial stream is dropped. This path may fail behind a rate-limit,
///   but it was already failing before this change.
/// * **Listen / Text / HTTP** — banner/probe exchange runs on the existing
///   stream, then falls back to HTTP and TLS on fresh connections if needed.
pub async fn detect_with_stream(
    mut stream: TcpStream,
    addr: SocketAddr,
    default_name: &str,
    timeout_ms: u64,
    host: &str,
) -> ServiceInfo {
    let mut info = ServiceInfo {
        name: default_name.to_string(),
        ..Default::default()
    };

    let dur = Duration::from_millis(timeout_ms.max(500));
    let port = addr.port();
    let host_opt = if host.is_empty() { None } else { Some(host) };

    // TLS ports: run handshake on the initial stream, both TLS 1.2 and 1.3.
    if matches!(plan_for(port), Plan::Tls) {
        if let Some(t) = tls::probe_stream(&mut stream, host_opt, dur, true).await {
            apply_tls(port, &t, &mut info);
            return info;
        }
        // Not actually TLS — drop corrupted stream and try fresh connection.
        drop(stream);
        return detect(addr, default_name, timeout_ms, host).await;
    }

    // Binary-protocol ports need their own framing from byte 0.
    if let Plan::Bin(kind) = plan_for(port) {
        drop(stream);
        if let Some(p) = run_binary(kind, addr, host, dur).await {
            apply_probed(&p, &mut info);
        }
        return info;
    }

    // Listen / Text / HTTP — use the existing stream.
    let probe_bytes: Option<Vec<u8>> = match plan_for(port) {
        Plan::Text(b) => Some(b.to_vec()),
        Plan::Http(path) => Some(http_request(path, host, port).into_bytes()),
        _ => None,
    };

    // MySQL is why this scales with --timeout instead of being a fixed 900 ms:
    // a server with `skip-name-resolve` off reverse-resolves the client address
    // before it greets, and where that lookup has to time out first the
    // handshake arrives seconds late — which showed up as an open 3306 with an
    // empty VERSION column.
    let listen_ms = if probe_bytes.is_some() { 400 } else { (dur.as_millis() as u64).max(900) };
    let mut data = read_for(&mut stream, Duration::from_millis(listen_ms), 8192).await;

    if data.is_empty() {
        if let Some(p) = &probe_bytes {
            let _ = timeout(dur, stream.write_all(p)).await;
            data = read_for(&mut stream, dur, 65536).await;
        }
    } else if matches!(plan_for(port), Plan::Text(_)) {
        if let Some(p) = &probe_bytes {
            let _ = timeout(dur, stream.write_all(p)).await;
            let more = read_for(&mut stream, dur, 65536).await;
            data.extend_from_slice(&more);
        }
    }

    if !data.is_empty() {
        info.got_data = true;
        parse_banner(port, &data, &mut info);
        follow_up(&mut stream, port, dur, &mut info).await;
        if !info.product.is_empty() || !info.version.is_empty() {
            return info;
        }
    }

    drop(stream);

    // Fallbacks on fresh connections (may be blocked by middlebox rate-limits).
    if info.product.is_empty() {
        if !matches!(plan_for(port), Plan::Http(_)) {
            if let Ok(Ok(mut s)) = timeout(dur, TcpStream::connect(addr)).await {
                crate::netutil::reset_on_close(&s);
                let req = http_request("/", host, port);
                if timeout(dur, s.write_all(req.as_bytes())).await.is_ok() {
                    let body = read_for(&mut s, dur, 65536).await;
                    if !body.is_empty() {
                        info.got_data = true;
                        parse_banner(port, &body, &mut info);
                    }
                }
            }
        }
        if !matches!(plan_for(port), Plan::Tls) {
            if let Some(t) = tls::probe(addr, host_opt, dur).await {
                apply_tls(port, &t, &mut info);
            }
        }
    }

    info
}

async fn run_binary(kind: Bin, addr: SocketAddr, host: &str, dur: Duration) -> Option<probe::Probed> {
    let mut s = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    crate::netutil::reset_on_close(&s);
    let host_opt = if host.is_empty() { None } else { Some(host) };
    match kind {
        Bin::Smb => probe::smb(&mut s, addr.port(), dur).await,
        Bin::Mssql => probe::mssql(&mut s, dur).await,
        Bin::Mongo => probe::mongodb(&mut s, dur).await,
        Bin::Postgres => probe::postgres(&mut s, dur).await,
        Bin::Mqtt => probe::mqtt(&mut s, dur).await,
        Bin::Amqp => probe::amqp(&mut s, dur).await,
        Bin::Dns => probe::dns_version(&mut s, dur).await,
        Bin::Minecraft => probe::minecraft(&mut s, host, addr.port(), dur).await,
        Bin::Epmd => probe::epmd(&mut s, dur).await,
        Bin::Cassandra => probe::cassandra(&mut s, dur).await,
        Bin::Kafka => probe::kafka(&mut s, dur).await,
        Bin::Rdp => probe::rdp(&mut s, host_opt, dur).await,
        Bin::X11 => probe::x11(&mut s, dur).await,
        Bin::Ldap => probe::ldap(&mut s, dur).await,
        Bin::Oracle => probe::oracle_tns(&mut s, dur).await,
        Bin::Ajp => probe::ajp(&mut s, dur).await,
        Bin::Socks => probe::socks(&mut s, dur).await,
        Bin::Git => probe::git_daemon(&mut s, dur).await,
    }
}

/// Build a `ServiceInfo` from a protocol probe's findings. Used by the UDP
/// scanner, where there is no banner-grab stage to fold the result into.
pub fn from_probed(p: &probe::Probed, default_name: &str) -> ServiceInfo {
    let mut info = ServiceInfo {
        name: default_name.to_string(),
        ..Default::default()
    };
    apply_probed(p, &mut info);
    info
}

fn apply_probed(p: &probe::Probed, info: &mut ServiceInfo) {
    if !p.name.is_empty() {
        info.name = p.name.to_string();
    }
    if !p.product.is_empty() {
        info.product = p.product.clone();
    }
    if !p.version.is_empty() {
        info.version = p.version.clone();
    }
    if !p.extra.is_empty() {
        info.extra = p.extra.clone();
    }
    if !p.banner.is_empty() {
        info.banner = p.banner.clone();
    }
    if !p.os_hint.is_empty() && info.os_hint.is_empty() {
        info.os_hint = p.os_hint.clone();
    }
    detect_os_from_text(&format!("{} {} {}", p.product, p.extra, p.banner), info);
}

fn apply_tls(port: u16, t: &tls::TlsInfo, info: &mut ServiceInfo) {
    info.tls_version = t.version.clone();
    info.cert_expired = t.expired;
    info.self_signed = t.self_signed;
    info.name = tls_service_name(port, &t.alpn).to_string();
    info.product = "TLS".into();
    info.version = t
        .version
        .trim_start_matches("TLS ")
        .trim_start_matches("SSL ")
        .to_string();
    info.extra = t.summary();
    info.banner = t.summary();
    if !t.subject_cn.is_empty() {
        info.hostnames.push(t.subject_cn.clone());
    }
    for s in &t.sans {
        if !info.hostnames.contains(s) {
            info.hostnames.push(s.clone());
        }
    }
    // Appliance certificates routinely name the product outright — in the CN,
    // the issuer, a SAN, or (for devices with a generic CN) the subject O.
    let hay = format!(
        "{} {} {} {}",
        t.subject_cn,
        t.subject_o,
        t.issuer_cn,
        t.sans.join(" ")
    );
    if let Some(prod) = match_app(&hay) {
        info.product = format!("TLS / {prod}");
    }
    detect_os_from_text(&hay, info);
}

fn tls_service_name(port: u16, alpn: &str) -> &'static str {
    if alpn.starts_with("h2") || alpn.starts_with("http") {
        return "https";
    }
    match port {
        465 | 587 => "smtps",
        993 => "imaps",
        995 => "pop3s",
        636 | 3269 => "ldaps",
        990 => "ftps",
        992 => "telnets",
        853 => "dns-over-tls",
        5061 => "sip-tls",
        6697 => "ircs",
        8883 => "mqtt-ssl",
        2484 => "oracle-db-ssl",
        5986 | 47001 => "wsmans",
        6443 | 10250 | 16443 => "kubernetes",
        _ => "https",
    }
}

/// Build an HTTP/1.1 request. Sending a real `Host` matters: virtual-hosted
/// servers answer a bare IP with a generic default page (or a 400) and hide
/// the product we're trying to identify.
fn http_request(path: &str, host: &str, port: u16) -> String {
    let host_header = if host.is_empty() {
        "kaisen".to_string()
    } else if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: Kaisen\r\n\
         Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    )
}

/// Read until the peer goes quiet or we hit `cap` bytes.
async fn read_for(stream: &mut TcpStream, dur: Duration, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
    for _ in 0..12 {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                out.extend_from_slice(&buf[..n]);
                if out.len() >= cap {
                    break;
                }
                // Headers plus a slice of the body is all we ever need; don't
                // sit here draining a large page.
                if out.len() > 2048 && out.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            _ => break,
        }
    }
    out
}

/// Protocol-specific second questions, asked only once we know what we're
/// talking to. These are where SMTP/IMAP/POP3/FTP hand over their real detail.
async fn follow_up(stream: &mut TcpStream, _port: u16, dur: Duration, info: &mut ServiceInfo) {
    let cmd: &[u8] = match info.name.as_str() {
        "ftp" => b"SYST\r\n",
        "smtp" | "submission" | "smtps" => b"EHLO kaisen\r\n",
        "imap" | "imaps" => b"a1 CAPABILITY\r\n",
        "pop3" | "pop3s" => b"CAPA\r\n",
        _ => return,
    };
    if timeout(dur, stream.write_all(cmd)).await.is_err() {
        return;
    }
    let resp = read_for(stream, Duration::from_millis(900), 8192).await;
    if resp.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(&resp);

    match info.name.as_str() {
        "ftp" => {
            // "215 UNIX Type: L8" / "215 Windows_NT" — a strong OS signal.
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("215 ").or_else(|| line.strip_prefix("215-")) {
                    if info.extra.is_empty() {
                        info.extra = rest.trim().to_string();
                    }
                    let up = rest.to_ascii_uppercase();
                    if up.contains("WINDOWS") || up.contains("WIN32") || up.contains("WIN_NT") {
                        info.os_hint = "Windows".into();
                    } else if (up.contains("UNIX") || up.contains("LINUX") || up.contains("L8"))
                        && info.os_hint.is_empty()
                    {
                        info.os_hint = "Unix / Linux-like".into();
                    }
                    detect_os_from_text(rest, info);
                    break;
                }
            }
        }
        _ => {
            // Capability lists name the product surprisingly often, and always
            // say whether the cleartext port offers an encrypted upgrade.
            let mut caps = Vec::new();
            if text.to_ascii_uppercase().contains("STARTTLS") {
                caps.push("STARTTLS".to_string());
            } else {
                caps.push("no STARTTLS".to_string());
            }
            let upper = text.to_ascii_uppercase();
            if upper.contains("AUTH=PLAIN") || upper.contains("AUTH PLAIN") {
                caps.push("cleartext AUTH offered".to_string());
            }
            if upper.contains("PIPELINING") {
                caps.push("PIPELINING".to_string());
            }
            if info.product.is_empty() {
                if let Some(prod) = match_mail_product(&text) {
                    info.product = prod.to_string();
                }
            }
            if info.version.is_empty() {
                let v = first_version(&text);
                if !v.is_empty() {
                    info.version = v;
                }
            }
            let joined = caps.join(", ");
            if info.extra.is_empty() {
                info.extra = joined;
            } else {
                info.extra = format!("{}; {}", info.extra, joined);
            }
            detect_os_from_text(&text, info);
        }
    }
}

// ── banner parsing ──────────────────────────────────────────────────────────

fn parse_banner(port: u16, data: &[u8], info: &mut ServiceInfo) {
    // MySQL/MariaDB greet in a binary frame, so try that before any text work.
    if parse_mysql(data, info) {
        return;
    }

    let text = String::from_utf8_lossy(data);
    let first = text.lines().next().unwrap_or("").trim();
    if info.banner.is_empty() {
        if let Some(clean) = readable(first) {
            info.banner = clean;
        }
    }

    // SSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    if first.starts_with("SSH-") {
        info.name = "ssh".into();
        if let Some(rest) = first.splitn(3, '-').nth(2) {
            let mut it = rest.splitn(2, ' ');
            let prodver = it.next().unwrap_or("");
            info.extra = it.next().unwrap_or("").to_string();
            if let Some((prod, ver)) = prodver.split_once('_') {
                info.product = prod.to_string();
                info.version = ver.to_string();
            } else if let Some((prod, ver)) = split_trailing_version(prodver) {
                info.product = prod;
                info.version = ver;
            } else {
                info.product = prodver.to_string();
            }
        }
        // Embedded and appliance SSH stacks are named right in the banner.
        let low = first.to_ascii_lowercase();
        if let Some((needle, label)) = SSH_SOFTWARE
            .iter()
            .filter(|(needle, _)| low.contains(needle))
            .max_by_key(|(needle, _)| needle.len())
        {
            info.product = (*label).to_string();
            if needle.contains("windows") {
                info.os_hint = "Windows".into();
            }
        }
        // The split above assumes "product_version". Plenty of stacks write
        // "Sun_SSH_1.1" or "OpenSSH_for_Windows_8.1", where that leaves a
        // version field holding words. Take the real one off the tail instead.
        if !info.version.is_empty() && !probe::looks_like_version(&info.version) {
            let tail = trailing_version(first.splitn(3, '-').nth(2).unwrap_or(""));
            info.version = tail;
        }
        detect_os_from_text(first, info);
        return;
    }

    // HTTP first among the text protocols: its response line is unambiguous.
    if text.starts_with("HTTP/") || text.contains("HTTP/1.") || text.contains("HTTP/0.9") {
        parse_http(port, &text, info);
        return;
    }
    if text.starts_with("RTSP/") {
        parse_http(port, &text, info);
        info.name = "rtsp".into();
        if info.product.is_empty() {
            info.product = "RTSP server".into();
        }
        return;
    }
    if text.starts_with("SIP/2.0") {
        parse_http(port, &text, info);
        info.name = "sip".into();
        if info.product.is_empty() {
            info.product = "SIP server".into();
        }
        return;
    }

    // FTP: "220 (vsFTPd 3.0.3)" / "220 ProFTPD 1.3.5 Server"
    if port == 21 || port == 990 || port == 2121 || first.starts_with("220 ") || first.starts_with("220-")
    {
        // 220 is also SMTP's greeting, so let the content decide.
        let is_smtp = first.contains("ESMTP")
            || first.contains("SMTP")
            || matches!(port, 25 | 465 | 587 | 2525 | 24);
        if !is_smtp {
            info.name = "ftp".into();
            info.product = extract_product(
                first,
                &[
                    "vsFTPd",
                    "ProFTPD",
                    "FileZilla",
                    "Pure-FTPd",
                    "Microsoft FTP Service",
                    "Serv-U",
                    "CrushFTP",
                    "Cerberus",
                    "wu-ftpd",
                    "bftpd",
                    "glFTPd",
                    "Titan FTP",
                    "WS_FTP",
                    "gene6",
                    "Xlight",
                    "PyFtpdLib",
                    // The daemons nmap's ftp set knows that announce their own
                    // name in the 220 greeting. Ordered specific-first like the
                    // rest of the list, and every one of them ahead of the bare
                    // "FTP" fallback, which only means "something said FTP".
                    "NcFTPd",
                    "GlobalSCAPE",
                    "Core FTP",
                    "CompleteFTP",
                    "FileCOPA",
                    "Fastream",
                    "WarFTPd",
                    "War-FTPd",
                    "BulletProof",
                    "BlackMoon",
                    "ArGoSoft",
                    "Wing FTP",
                    "WinGate",
                    "Rumpus",
                    "TYPSoft",
                    "Quick 'n Easy",
                    "Home FTP",
                    "Solar FTP",
                    "VicFTPS",
                    "SwiFTP",
                    "FreeFloat",
                    "Easy File Sharing",
                    "PCMan's FTP",
                    "Mollensoft",
                    "Sambar",
                    "Xitami",
                    "Xerver",
                    "zFTPServer",
                    "Raiden",
                    "Synchronet",
                    "NetPresenz",
                    "Hummingbird",
                    "Indy",
                    "gatling",
                    "OpenFTPD",
                    "lukemftpd",
                    "Inetutils",
                    "Ability Server",
                    "CommuniGate Pro",
                    "Merak",
                    "Oracle XML DB",
                    "Dreambox",
                    "JetDirect",
                    "VxWorks",
                    "OpenBSD ftpd",
                    "pyftpdlib",
                    "FTP",
                ],
            );
            info.version = extract_version(first);
            if first.contains("Microsoft FTP") {
                info.os_hint = "Windows".into();
            }
            detect_os_from_text(first, info);
            return;
        }
    }

    // SMTP: "220 mail.example.com ESMTP Postfix (Ubuntu)"
    if matches!(port, 25 | 587 | 465 | 2525 | 24 | 1025)
        || first.contains("ESMTP")
        || first.contains("SMTP")
    {
        info.name = if port == 587 { "submission" } else { "smtp" }.into();
        info.product = match_mail_product(first).map(|s| s.to_string()).unwrap_or_default();
        info.version = extract_version(first);
        if info.product.contains("Microsoft") || info.product.contains("Exchange") {
            info.os_hint = "Windows".into();
        }
        detect_os_from_text(first, info);
        return;
    }

    // POP3 / IMAP
    if first.starts_with("+OK") {
        info.name = "pop3".into();
        info.product = match_mail_product(first).map(|s| s.to_string()).unwrap_or_default();
        info.version = extract_version(first);
        detect_os_from_text(first, info);
        return;
    }
    if first.starts_with("* OK") || first.starts_with("* PREAUTH") || first.contains("IMAP4") {
        info.name = "imap".into();
        info.product = match_mail_product(first).map(|s| s.to_string()).unwrap_or_default();
        info.version = extract_version(first);
        detect_os_from_text(first, info);
        return;
    }

    // NNTP: "200 news.example.com InterNetNews NNRP server INN 2.6.3 ready"
    if first.starts_with("200 ") && (first.contains("NNTP") || first.contains("NNRP") || port == 119)
    {
        info.name = "nntp".into();
        info.product = extract_product(first, &["INN", "Diablo", "Cyclone", "leafnode", "NNTP"]);
        info.version = extract_version(first);
        return;
    }

    // VNC: "RFB 003.008"
    if first.starts_with("RFB ") {
        info.name = "vnc".into();
        info.product = "VNC (RFB)".into();
        info.version = first.trim_start_matches("RFB ").trim().to_string();
        // Some servers append their own name after the protocol version.
        if let Some(rest) = text.lines().nth(1) {
            if !rest.trim().is_empty() {
                info.extra = rest.trim().chars().take(60).collect();
            }
        }
        for (needle, label) in [
            ("realvnc", "RealVNC"),
            ("tightvnc", "TightVNC"),
            ("ultravnc", "UltraVNC"),
            ("tigervnc", "TigerVNC"),
            ("vino", "Vino (GNOME)"),
        ] {
            if text.to_ascii_lowercase().contains(needle) {
                info.product = label.into();
            }
        }
        return;
    }

    // rsync: "@RSYNCD: 31.0"
    if first.starts_with("@RSYNCD:") {
        info.name = "rsync".into();
        info.product = "rsync daemon".into();
        info.version = first.trim_start_matches("@RSYNCD:").trim().to_string();
        return;
    }

    // Subversion: "( success ( 2 2 ( ) ( edit-pipeline ... ) ) )". The two
    // numbers are the min/max wire protocol, not a release, so they belong in
    // the notes rather than in the VERSION column.
    if first.starts_with("( success ( ") {
        info.name = "svn".into();
        info.product = "Subversion (svnserve)".into();
        let nums: Vec<&str> = first
            .trim_start_matches("( success ( ")
            .split_whitespace()
            .take(2)
            .filter(|t| t.chars().all(|c| c.is_ascii_digit()))
            .collect();
        if !nums.is_empty() {
            info.extra = format!("protocol {}", nums.join("-"));
        }
        return;
    }

    // Redis: either the INFO dump, or an error that still identifies it.
    if text.contains("redis_version:") {
        info.name = "redis".into();
        info.product = "Redis".into();
        let mut bits = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("redis_version:") {
                info.version = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("redis_mode:") {
                bits.push(format!("mode {}", v.trim()));
            } else if let Some(v) = line.strip_prefix("os:") {
                detect_os_from_text(v, info);
                bits.push(v.trim().to_string());
            }
        }
        // INFO can arrive twice (greeting plus our own command); don't say
        // everything twice because of it.
        let mut seen = std::collections::HashSet::new();
        bits.retain(|b| !b.is_empty() && seen.insert(b.clone()));
        bits.push("UNAUTHENTICATED".into());
        info.extra = bits.join("; ");
        return;
    }
    if text.starts_with("-NOAUTH") || text.contains("NOAUTH Authentication required") {
        info.name = "redis".into();
        info.product = "Redis".into();
        info.extra = "authentication required".into();
        return;
    }
    if text.starts_with("-DENIED") {
        info.name = "redis".into();
        info.product = "Redis".into();
        info.extra = "protected mode enabled".into();
        return;
    }

    // Memcached
    if text.starts_with("VERSION ") {
        info.name = "memcached".into();
        info.product = "Memcached".into();
        info.version = text
            .trim_start_matches("VERSION ")
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        return;
    }

    // ZooKeeper four-letter-word output.
    if text.contains("Zookeeper version:") || text.contains("ZooKeeper version:") {
        info.name = "zookeeper".into();
        info.product = "Apache ZooKeeper".into();
        info.version = first_version(&text);
        return;
    }
    if text.contains("is not executed because it is not in the whitelist") {
        info.name = "zookeeper".into();
        info.product = "Apache ZooKeeper".into();
        info.extra = "4lw commands restricted".into();
        return;
    }

    // IRC: the 004 numeric names the daemon and its version.
    if text.contains(" 004 ") || text.starts_with(":") && text.contains("NOTICE AUTH") {
        info.name = "irc".into();
        for line in text.lines() {
            if let Some(pos) = line.find(" 004 ") {
                let rest = &line[pos + 5..];
                let mut it = rest.split_whitespace();
                let _target = it.next();
                let _server = it.next();
                if let Some(daemon) = it.next() {
                    if let Some((prod, ver)) = split_trailing_version(daemon) {
                        info.product = prod;
                        info.version = ver;
                    } else {
                        info.product = daemon.to_string();
                    }
                }
                break;
            }
        }
        if info.product.is_empty() {
            info.product = extract_product(
                &text,
                &["UnrealIRCd", "InspIRCd", "ngIRCd", "Charybdis", "Solanum", "ircd-hybrid", "IRC"],
            );
            info.version = extract_version(&text);
        }
        return;
    }

    // Telnet: strip the IAC negotiation, then read whatever login banner remains.
    if port == 23 || port == 2323 || data.first() == Some(&0xff) {
        info.name = "telnet".into();
        let visible = strip_telnet(data);
        let clean = visible.trim();
        if !clean.is_empty() {
            info.banner = clean.lines().next().unwrap_or("").chars().take(120).collect();
            info.product = match_app(clean)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Telnet service".to_string());
            info.version = extract_version(clean);
            detect_os_from_text(clean, info);
        } else {
            info.product = "Telnet service".into();
        }
        return;
    }

    // Gopher / finger / daytime and other tiny text services.
    if matches!(port, 13 | 37 | 70 | 79) && !first.is_empty() {
        info.product = first.chars().take(60).collect();
        return;
    }

    // A generic "identify it by keyword" pass before giving up.
    if let Some(prod) = match_app(&text) {
        info.product = prod.to_string();
        info.version = extract_version(&text);
        detect_os_from_text(&text, info);
        return;
    }

    // Fallback: keep whatever readable first line we captured, but only if it
    // really is readable — an unknown binary protocol gets left blank.
    if info.product.is_empty() {
        if let Some(clean) = readable(first) {
            info.product = clean;
        }
    }
}

/// MySQL/MariaDB initial handshake packet:
/// `[3-byte length][seq][protocol version 0x0a][NUL-terminated server version]`,
/// then connection id (4), salt part 1 (8), filler, capability flags low (2),
/// default collation (1), status flags (2), capability flags high (2), salt
/// length (1), 10 reserved bytes, salt part 2 and the auth plugin name.
///
/// Only the version string is dependable: proxies, forks and honeypots cut the
/// tail short, so every field after it is read defensively and simply left out
/// when the packet ends early.
fn parse_mysql(data: &[u8], info: &mut ServiceInfo) -> bool {
    if data.len() < 6 {
        return false;
    }
    // Error packet: the server rejected us but still identified itself.
    if data[3] == 0x00 && data[4] == 0xff {
        return parse_mysql_error(data, info);
    }
    // 10 is the handshake everything since 4.1 speaks; 9 is the pre-4.1 one,
    // still emitted by museum installs and by a few honeypots.
    if data[4] != 0x0a && data[4] != 0x09 {
        return false;
    }
    let end = match data[5..].iter().position(|&b| b == 0) {
        Some(p) => 5 + p,
        None => return false,
    };
    let raw = String::from_utf8_lossy(&data[5..end]).to_string();
    if raw.is_empty() || !raw.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return false;
    }

    info.name = "mysql".into();
    if info.banner.is_empty() {
        info.banner = raw.chars().take(120).collect();
    }

    // MariaDB fakes a "5.5.5-" prefix so pre-10.x clients keep working. Every
    // other fork signs the version string itself, which is why the flavour
    // lookup runs on that and never on the random salt bytes behind it.
    let reported = raw.strip_prefix("5.5.5-").unwrap_or(&raw).to_string();
    let low = reported.to_ascii_lowercase();
    let tail = String::from_utf8_lossy(&data[end..]).to_string();

    // Longest needle wins, exactly like SSH_SOFTWARE: "mariadb-maxscale" is a
    // proxy in front of a database, not a database, and "xtradb-cluster" is
    // Percona's Galera build rather than plain Percona Server.
    let flavor = MYSQL_FLAVORS
        .iter()
        .filter(|(needle, _, _)| low.contains(needle))
        .max_by_key(|(needle, _, _)| needle.len());

    // A fork that fronts a MySQL compatibility version reports its own after the
    // marker: "8.0.11-TiDB-v7.5.0" is TiDB 7.5.0, and calling it MySQL 8.0.11
    // would pin a decade of MySQL CVEs on an engine that never had them.
    let (product, version, matched, own_used) = match flavor {
        Some((needle, label, own)) => {
            let own_version = if own.is_empty() { None } else { version_after(&low, own) };
            let used = own_version.is_some();
            let version = own_version.unwrap_or_else(|| leading_version(&reported));
            ((*label).to_string(), version, *needle, used)
        }
        None => ("MySQL".to_string(), leading_version(&reported), "", false),
    };
    info.product = product;
    info.version = version;

    let mut extras: Vec<String> = Vec::new();
    if data[4] == 0x09 {
        push_unique(&mut extras, "pre-4.1 protocol");
    }
    // Which release series this is, and whether that series still gets fixes.
    if let Some(series) = mysql_series(&info.product, &info.version) {
        push_unique(&mut extras, series);
    }
    // Oracle's paid builds say so in the version string; nothing else does.
    if let Some((_, edition)) = MYSQL_EDITIONS.iter().find(|(needle, _)| low.contains(needle)) {
        push_unique(&mut extras, edition);
    }
    for (needle, label) in MYSQL_BUILD_FLAGS {
        if low.contains(needle) {
            push_unique(&mut extras, label);
        }
    }
    // "8.0.35-cluster" is MySQL NDB. "…-xtradb-cluster" is Percona's Galera
    // build, which the wsrep tag above already names.
    if low.contains("-cluster") && !low.contains("xtradb") {
        push_unique(&mut extras, "NDB Cluster");
    }
    // Whatever the packager wrote after the first dash — "0ubuntu0.22.04.1",
    // "1:10.11.6+maria~ubu2204", Percona's "-27". Kept only when it carries a
    // number, so a tail that is purely a tag named above isn't repeated.
    let build: String =
        reported.split_once('-').map(|x| x.1).unwrap_or("").chars().take(60).collect();
    // The flavour's own name in front of that tail is already the product name.
    let build = match !matched.is_empty() && build.to_ascii_lowercase().starts_with(matched) {
        true => build[matched.len()..].trim_start_matches(['-', '_', ' ']),
        false => &build,
    };
    // A fork whose own version we just read wrote nothing else here.
    if !own_used && build.chars().any(|c| c.is_ascii_digit()) {
        push_unique(&mut extras, build);
    }
    // The default auth plugin dates a server better than its build tail does.
    for plugin in MYSQL_AUTH_PLUGINS {
        if tail.contains(plugin) {
            push_unique(&mut extras, plugin);
            break;
        }
    }
    // The fixed part after the version. Capability flags carry the one
    // security-relevant bit a handshake hands out before anyone authenticates:
    // whether the server will accept TLS at all.
    if let Some(caps) = mysql_capabilities(data, end) {
        push_unique(
            &mut extras,
            if caps & MYSQL_CLIENT_SSL != 0 { "TLS supported" } else { "no TLS offered" },
        );
        if caps & MYSQL_CLIENT_COMPRESS != 0 {
            push_unique(&mut extras, "compression offered");
        }
    }
    // The default collation corroborates the branch: 255 is 8.0's
    // utf8mb4_0900_ai_ci, 8 is the latin1 default nothing past 5.7 ships.
    if let Some(collation) = mysql_collation(data, end) {
        push_unique(&mut extras, collation);
    }

    info.extra = extras.join("; ").chars().take(200).collect();
    detect_os_from_text(&raw, info);
    true
}

/// The other way a MySQL server introduces itself: it refuses the connection
/// and explains why. `[len][seq][0xff][code lo][code hi][message]`. The message
/// names the flavour ("… to this MariaDB server") and the code is worth
/// reporting on its own — 1130 and 1129 mean *this host* is blocked, not that
/// the database is shut to everyone.
fn parse_mysql_error(data: &[u8], info: &mut ServiceInfo) -> bool {
    let code = u16::from_le_bytes([*data.get(5).unwrap_or(&0), *data.get(6).unwrap_or(&0)]);
    let msg = String::from_utf8_lossy(&data[7.min(data.len())..data.len().min(200)]).to_string();
    let low = msg.to_ascii_lowercase();
    let known = MYSQL_ERRORS.iter().find(|(c, _)| *c == code).map(|(_, text)| *text);
    let flavor = MYSQL_FLAVORS
        .iter()
        .filter(|(needle, _, _)| low.contains(needle))
        .max_by_key(|(needle, _, _)| needle.len());
    // A leading 0xff is not exclusive to this protocol, so claim the port only
    // when the message names the product, or when a known MySQL error code
    // comes with text that actually reads like an error message.
    let texty = msg.len() >= 10 && msg.chars().all(|c| c.is_ascii_graphic() || c == ' ');
    if flavor.is_none() && !low.contains("mysql") && !(known.is_some() && texty) {
        return false;
    }

    info.name = "mysql".into();
    info.product = match flavor {
        Some((_, label, _)) => (*label).to_string(),
        None => "MySQL".to_string(),
    };
    if info.banner.is_empty() {
        if let Some(clean) = readable(msg.trim()) {
            info.banner = clean;
        }
    }
    let mut extras: Vec<String> = Vec::new();
    match known {
        Some(text) => push_unique(&mut extras, &format!("error {code}: {text}")),
        None if code != 0 => push_unique(&mut extras, &format!("error {code}")),
        None => {}
    }
    push_unique(&mut extras, msg.trim());
    info.extra = extras.join("; ").chars().take(200).collect();
    detect_os_from_text(&msg, info);
    true
}

/// Capability flags from the fixed part of the handshake: the low 16 bits sit
/// 14 bytes past the version string's NUL, the high 16 five bytes later.
/// `None` when the packet stops before them — proxies routinely truncate it.
fn mysql_capabilities(data: &[u8], end: usize) -> Option<u32> {
    let low = u16::from_le_bytes([*data.get(end + 14)?, *data.get(end + 15)?]) as u32;
    let high = match (data.get(end + 19), data.get(end + 20)) {
        (Some(a), Some(b)) => u16::from_le_bytes([*a, *b]) as u32,
        _ => 0,
    };
    Some(low | (high << 16))
}

/// The server's default collation, one byte past the low capability flags.
fn mysql_collation(data: &[u8], end: usize) -> Option<&'static str> {
    let id = *data.get(end + 16)?;
    MYSQL_COLLATIONS.iter().find(|(k, _)| *k == id).map(|(_, name)| *name)
}

/// Name the release series a version belongs to, and say whether that series
/// still gets security fixes. Forks and proxies keep their own calendars, so
/// they get nothing here rather than a confidently wrong date.
fn mysql_series(product: &str, version: &str) -> Option<&'static str> {
    let mut nums = version.split('.').map(|p| {
        p.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u32>()
            .ok()
    });
    let major = nums.next().flatten()?;
    let minor = nums.next().flatten().unwrap_or(0);
    let mariadb = product.contains("MariaDB");
    let table = match product {
        // These report a version they emulate, not one they are.
        p if p.contains("MaxScale") || p.contains("ProxySQL") || p.contains("Vitess") => {
            return None
        }
        _ if mariadb => MARIADB_BRANCHES,
        p if p.contains("MySQL") || p.contains("Percona") => MYSQL_BRANCHES,
        _ => return None,
    };
    if let Some((_, label)) = table.iter().find(|((ma, mi), _)| (*ma, *mi) == (major, minor)) {
        return Some(label);
    }
    // A series newer than this table: name the track rather than invent a date.
    // Oracle alternates LTS and Innovation releases; MariaDB ships rolling ones
    // between its LTS branches.
    match (mariadb, major) {
        (true, m) if m >= 11 => Some("rolling release"),
        (false, m) if m >= 8 => Some("Innovation release"),
        _ => None,
    }
}

/// The leading dotted number: "8.0.35-0ubuntu0.22.04.1" is version 8.0.35 and
/// everything past the first dash is the packager's business.
fn leading_version(s: &str) -> String {
    let head = s.split('-').next().unwrap_or("").trim();
    let num: String = head.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    // Aurora reports "5.6.10a", and that letter is part of the number. Anything
    // longer than one letter is a fork's name glued to it, as in
    // "8.0.mysql_aurora.3.04.0", and only the digits in front are the version.
    let rest = &head[num.len()..];
    if rest.len() == 1 && rest.chars().all(|c| c.is_ascii_alphabetic()) {
        head.to_string()
    } else {
        num.trim_end_matches('.').to_string()
    }
}

/// The number a fork writes right after its own name: "…-tidb-v7.5.0" → 7.5.0.
fn version_after(hay: &str, marker: &str) -> Option<String> {
    let rest = hay.split_once(marker)?.1;
    let v: String = rest
        .trim_start_matches(['-', '_', ' ', ':', '.', 'v'])
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let v = v.trim_end_matches('.').to_string();
    v.chars().next().filter(char::is_ascii_digit).map(|_| v)
}

fn push_unique(list: &mut Vec<String>, item: &str) {
    if !item.is_empty() && !list.iter().any(|e| e == item) {
        list.push(item.to_string());
    }
}

/// Everything that answers on 3306 while not being Oracle's MySQL: forks,
/// managed rebuilds, protocol-compatible engines and the proxies that sit in
/// front of all of them. Keyed on a lowercase needle in the version string,
/// longest needle first. The third field is the marker a fork writes its *own*
/// version after, empty when the leading number is already the real one.
///
/// Products keep "MySQL" or "MariaDB" in their name wherever the engine really
/// is one, because `vuln::assess` and `cve::correlate` match products by
/// substring — that is what keeps the EOL and exposure findings firing on a
/// managed rebuild. Engines that merely speak the protocol (TiDB, Doris,
/// SingleStore…) deliberately do not, since MySQL's CVEs are not theirs.
pub(crate) const MYSQL_FLAVORS: &[(&str, &str, &str)] = &[
    // ── the names the signature and CVE tables already key on ───────────
    ("mariadb", "MariaDB", ""),
    ("percona", "Percona Server", ""),
    ("xtradb-cluster", "Percona XtraDB Cluster", ""),
    // ── managed rebuilds: the operator owns the version, not the admin ──
    ("mysql_aurora", "Amazon Aurora MySQL", "mysql_aurora"),
    ("aurora", "Amazon Aurora MySQL", ""),
    ("azure", "Azure Database for MySQL", ""),
    ("google", "Google Cloud SQL for MySQL", ""),
    ("alisql", "AliSQL", ""),
    ("polardb", "PolarDB for MySQL", ""),
    ("rdsdb", "Amazon RDS for MySQL", ""),
    ("txsql", "Tencent TXSQL", ""),
    ("tdsql", "Tencent TDSQL", ""),
    ("gaussdb", "Huawei GaussDB for MySQL", ""),
    ("greatsql", "GreatSQL", ""),
    ("opensource-percona", "Percona Server", ""),
    // ── engines that speak the protocol but are not MySQL ───────────────
    ("tidb", "TiDB", "tidb"),
    ("oceanbase", "OceanBase", "oceanbase"),
    ("doris", "Apache Doris", ""),
    ("starrocks", "StarRocks", ""),
    ("singlestore", "SingleStore", ""),
    ("memsql", "SingleStore (MemSQL)", ""),
    ("dolt", "Dolt", ""),
    ("databend", "Databend", ""),
    ("clickhouse", "ClickHouse", ""),
    ("drizzle", "Drizzle", ""),
    ("radondb", "RadonDB", ""),
    ("manticore", "Manticore Search", ""),
    ("sphinx", "Sphinx SphinxQL", ""),
    // ── proxies and routers: what answers is not what stores ────────────
    ("proxysql", "ProxySQL", ""),
    ("maxscale", "MariaDB MaxScale", ""),
    ("planetscale", "PlanetScale (Vitess)", ""),
    ("vitess", "Vitess", "vitess"),
    ("mysqlrouter", "MySQL Router", ""),
    ("mysql router", "MySQL Router", ""),
    ("kingshard", "kingshard", ""),
    ("dbproxy", "DBProxy", ""),
];

/// Oracle's paid builds, which are the only ones that name an edition in the
/// handshake. Longest needle first: the advanced build says all three words.
const MYSQL_EDITIONS: &[(&str, &str)] = &[
    ("enterprise-commercial-advanced", "Enterprise Advanced"),
    ("enterprise-commercial", "Enterprise Commercial"),
    ("enterprise", "Enterprise Edition"),
    ("commercial", "commercial build"),
];

/// Build tags a server volunteers about how it was compiled or how it runs.
const MYSQL_BUILD_FLAGS: &[(&str, &str)] = &[
    ("-log", "binlog enabled"),
    ("ndb", "NDB Cluster"),
    ("wsrep", "Galera cluster node"),
    ("galera", "Galera cluster node"),
    ("debug", "debug build"),
    ("valgrind", "valgrind build"),
    ("asan", "ASan build"),
    ("embedded", "embedded build"),
];

/// Auth plugins, which date a server better than its build tail does:
/// `caching_sha2_password` is 8.0's default, `client_ed25519` and `parsec` are
/// MariaDB's, `mysql_old_password` is the pre-4.1 hash nothing should offer.
/// First match wins, so the specific names come before the generic ones.
const MYSQL_AUTH_PLUGINS: &[&str] = &[
    "caching_sha2_password",
    "mysql_native_password",
    "sha256_password",
    "authentication_kerberos_client",
    "authentication_ldap_sasl_client",
    "authentication_webauthn_client",
    "authentication_fido_client",
    "auth_gssapi_client",
    "client_ed25519",
    "mysql_old_password",
    "mysql_clear_password",
    "unix_socket",
    "auth_socket",
    "parsec",
    "dialog",
];

/// Connection refusals worth naming. A blocked host still proves a database is
/// there, and 3159 in particular says the server requires TLS.
const MYSQL_ERRORS: &[(u16, &str)] = &[
    (1040, "too many connections"),
    (1042, "cannot resolve client hostname"),
    (1043, "bad handshake"),
    (1045, "access denied"),
    (1129, "host blocked after too many connection errors"),
    (1130, "host not allowed to connect"),
    (1152, "connection aborted"),
    (1153, "packet larger than max_allowed_packet"),
    (1156, "packets out of order"),
    (1159, "read interrupted"),
    (1203, "too many connections for this user"),
    (1226, "user resource limit reached"),
    (1251, "client does not support the server's auth protocol"),
    (1698, "access denied (socket auth)"),
    (3159, "connections require TLS (require_secure_transport)"),
];

/// Default collations worth recognising, each a hint at the branch: 8 is the
/// latin1 default of 5.7 and older, 45/224 arrive with 5.5's utf8mb4, 255 is
/// 8.0's.
const MYSQL_COLLATIONS: &[(u8, &str)] = &[
    (8, "latin1_swedish_ci"),
    (33, "utf8_general_ci"),
    (45, "utf8mb4_general_ci"),
    (46, "utf8mb4_bin"),
    (63, "binary"),
    (83, "utf8_bin"),
    (192, "utf8_unicode_ci"),
    (224, "utf8mb4_unicode_ci"),
    (255, "utf8mb4_0900_ai_ci"),
];

/// MySQL release series → support status, keyed on `(major, minor)`. Reporting
/// "MySQL 5.7.44" is a fact; reporting that 5.7 stopped receiving security
/// fixes in October 2023 is the part someone can act on. Percona Server tracks
/// these branches, so it reads the same table.
const MYSQL_BRANCHES: &[((u32, u32), &str)] = &[
    ((3, 22), "3.22 EOL since 1999"),
    ((3, 23), "3.23 EOL since 2006"),
    ((4, 0), "4.0 EOL since 2008"),
    ((4, 1), "4.1 EOL since Dec 2009"),
    ((5, 0), "5.0 EOL since Jan 2012"),
    ((5, 1), "5.1 EOL since Dec 2013"),
    ((5, 5), "5.5 EOL since Dec 2018"),
    ((5, 6), "5.6 EOL since Feb 2021"),
    ((5, 7), "5.7 EOL since Oct 2023"),
    ((8, 0), "8.0 EOL since Apr 2026"),
    ((8, 1), "8.1 Innovation, superseded"),
    ((8, 2), "8.2 Innovation, superseded"),
    ((8, 3), "8.3 Innovation, superseded"),
    ((8, 4), "8.4 LTS, supported to Apr 2032"),
    ((9, 0), "9.0 Innovation, superseded"),
    ((9, 1), "9.1 Innovation, superseded"),
    ((9, 2), "9.2 Innovation, superseded"),
    ((9, 3), "9.3 Innovation, superseded"),
];

/// MariaDB's own calendar: LTS branches get five years, everything between
/// them is a rolling release that lasts about one.
const MARIADB_BRANCHES: &[((u32, u32), &str)] = &[
    ((5, 1), "5.1 EOL since Feb 2012"),
    ((5, 2), "5.2 EOL since Nov 2012"),
    ((5, 3), "5.3 EOL since Mar 2014"),
    ((5, 5), "5.5 EOL since Apr 2020"),
    ((10, 0), "10.0 EOL since Mar 2019"),
    ((10, 1), "10.1 EOL since Oct 2020"),
    ((10, 2), "10.2 EOL since May 2022"),
    ((10, 3), "10.3 EOL since May 2023"),
    ((10, 4), "10.4 EOL since Jun 2024"),
    ((10, 5), "10.5 EOL since Jun 2025"),
    ((10, 6), "10.6 LTS, supported to Jul 2026"),
    ((10, 7), "10.7 EOL since Feb 2023"),
    ((10, 8), "10.8 EOL since May 2023"),
    ((10, 9), "10.9 EOL since Aug 2023"),
    ((10, 10), "10.10 EOL since Nov 2023"),
    ((10, 11), "10.11 LTS, supported to Feb 2028"),
    ((11, 0), "11.0 EOL since Jun 2024"),
    ((11, 1), "11.1 EOL since Aug 2024"),
    ((11, 2), "11.2 EOL since Nov 2024"),
    ((11, 3), "11.3 EOL since Nov 2024"),
    ((11, 4), "11.4 LTS, supported to May 2029"),
    ((11, 5), "11.5 rolling release, superseded"),
    ((11, 6), "11.6 rolling release, superseded"),
    ((11, 7), "11.7 rolling release, superseded"),
    ((11, 8), "11.8 LTS, supported to Jun 2030"),
];

/// `CLIENT_SSL`: the server will negotiate TLS if the client asks.
const MYSQL_CLIENT_SSL: u32 = 0x0000_0800;
/// `CLIENT_COMPRESS`: the server will accept the compressed protocol.
const MYSQL_CLIENT_COMPRESS: u32 = 0x0000_0020;

/// Strip Telnet IAC negotiation sequences, leaving the human-readable banner.
fn strip_telnet(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == 0xff {
            match data.get(i + 1) {
                Some(0xfa) => {
                    // Subnegotiation: skip to IAC SE.
                    i += 2;
                    while i + 1 < data.len() && !(data[i] == 0xff && data[i + 1] == 0xf0) {
                        i += 1;
                    }
                    i += 2;
                }
                Some(0xff) => {
                    out.push(0xff);
                    i += 2;
                }
                Some(_) => i += 3,
                None => break,
            }
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r')
        .collect()
}

// ── HTTP ────────────────────────────────────────────────────────────────────

fn parse_http(port: u16, text: &str, info: &mut ServiceInfo) {
    info.name = if port == 443 || port == 8443 || port == 9443 {
        "https"
    } else {
        "http"
    }
    .into();

    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        None => (text, ""),
    };

    let status = text.lines().next().unwrap_or("").trim().to_string();
    let mut extras: Vec<String> = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let get = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    if let Some(server) = get("server") {
        info.banner = format!("Server: {server}");
        parse_server_header(&server, info);
        detect_os_from_text(&server, info);
    }

    // Framework/appliance headers, each of which carries its own version. The
    // `authoritative` flag marks headers that only one product ever sends: an
    // X-Jenkins header identifies the service far better than the Server header
    // of whatever servlet container Jenkins happens to be running on.
    for (header, label, authoritative) in [
        ("x-powered-by", "", false),
        ("x-aspnet-version", "ASP.NET", false),
        ("x-aspnetmvc-version", "ASP.NET MVC", false),
        ("x-jenkins", "Jenkins", true),
        ("x-influxdb-version", "InfluxDB", true),
        ("x-generator", "", false),
        ("x-drupal-cache", "Drupal", false),
        ("x-varnish", "Varnish", false),
        ("x-kong-upstream-latency", "Kong", false),
        ("x-sonarqube-version", "SonarQube", true),
        ("x-artifactory-id", "Artifactory", true),
        ("x-jfrog-version", "JFrog", true),
        ("x-oracle-dms-ecid", "Oracle Fusion Middleware", false),
        ("x-nextcloud-version", "Nextcloud", true),
        ("x-gitlab-feature-category", "GitLab", true),
        ("x-grafana-version", "Grafana", true),
        ("x-sabnzbd-version", "SABnzbd", true),
        // Exchange states its build here and nowhere else on an unauthenticated
        // request, which is what makes the ProxyShell-era checks possible at all.
        ("x-owa-version", "Microsoft Exchange", true),
        ("x-confluence-request-time", "Atlassian Confluence", true),
    ] {
        let Some(v) = get(header) else { continue };
        let product = if label.is_empty() {
            v.split('/').next().unwrap_or(&v).trim().to_string()
        } else {
            label.to_string()
        };
        let version = extract_version(&v);
        if info.product.is_empty() {
            info.product = product;
            info.version = version;
        } else if authoritative {
            // Demote what we had; the specific product takes the headline.
            let previous = if info.version.is_empty() {
                info.product.clone()
            } else {
                format!("{} {}", info.product, info.version)
            };
            extras.push(format!("on {previous}"));
            info.product = product;
            info.version = version;
        } else if !product.is_empty() {
            extras.push(if version.is_empty() {
                product
            } else {
                format!("{product} {version}")
            });
        }
    }

    // A 401 names the realm, which on embedded devices is the model number.
    if let Some(auth) = get("www-authenticate") {
        if let Some(realm) = auth.split("realm=").nth(1) {
            let realm = realm.trim().trim_matches('"').split('"').next().unwrap_or("");
            if !realm.is_empty() {
                extras.push(format!("realm \"{realm}\""));
                if info.product.is_empty() {
                    if let Some(p) = match_app(realm) {
                        info.product = p.to_string();
                    }
                }
            }
        }
        extras.push(
            auth.split_whitespace()
                .next()
                .unwrap_or("auth")
                .to_string(),
        );
    }

    if status.starts_with("HTTP/") {
        let code = status.split_whitespace().nth(1).unwrap_or("");
        if code.starts_with('3') {
            if let Some(loc) = get("location") {
                extras.push(format!("-> {loc}"));
            }
        } else if code == "401" || code == "403" {
            extras.push(format!("HTTP {code}"));
        }
    }

    // JSON APIs that hand out their version on the root path.
    parse_http_json(body, info, &mut extras);

    // <title> is the single best hint for an unfamiliar web UI.
    if let Some(title) = html_title(body) {
        if info.product.is_empty() {
            if let Some(app) = match_app(&title) {
                info.product = app.to_string();
            }
        }
        extras.push(format!("title \"{title}\""));
    }

    // Last resort: fingerprint the application from headers plus body markers.
    let hay = format!("{head}\n{}", &body[..body.len().min(4096)]);
    if let Some(app) = match_app(&hay) {
        if info.product.is_empty() {
            info.product = app.to_string();
        } else if !info.product.contains(app) {
            extras.push(app.to_string());
        }
    }
    detect_os_from_text(&hay, info);

    if !extras.is_empty() {
        let joined = extras.join("; ");
        info.extra = if info.extra.is_empty() {
            joined
        } else {
            format!("{}; {}", info.extra, joined)
        };
    }
    if info.product.is_empty() {
        info.product = "HTTP server".into();
    }
}

/// "nginx/1.18.0 (Ubuntu)", "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3",
/// "Microsoft-IIS/10.0", or a bare product name with no version at all.
fn parse_server_header(server: &str, info: &mut ServiceInfo) {
    let mut tokens = server.split_whitespace();
    let head = tokens.next().unwrap_or(server);
    if let Some((prod, rest)) = head.split_once('/') {
        info.product = prod.to_string();
        info.version = rest.to_string();
    } else if let Some((prod, rest)) = head.split_once('(') {
        // Jetty and a few others write "Jetty(10.0.18)" instead of "Jetty/…".
        let rest = rest.trim_end_matches(')');
        if probe::looks_like_version(rest) {
            info.product = prod.to_string();
            info.version = rest.to_string();
        } else {
            info.product = head.to_string();
        }
    } else {
        info.product = head.to_string();
    }
    // Everything after the first token is context: the distro in parentheses
    // plus co-installed modules, each of which is its own version fact.
    let rest: String = server[head.len()..].trim().to_string();
    if !rest.is_empty() {
        info.extra = rest.trim_matches(|c| c == '(' || c == ')').to_string();
    }
    if info.product.eq_ignore_ascii_case("Microsoft-IIS") {
        info.os_hint = "Windows".into();
    }
    // The head-token reading is right for "nginx/1.24.0" and wrong for a header
    // that leads with a connector, a codename or an OEM string. Rename after the
    // split, never before: the version was already taken from the header and
    // stays exactly as it was.
    if let Some(canonical) = match_server_alias(server) {
        info.product = canonical.to_string();
    }
    // "WWW File Share Pro 2.0", "Tomcat Web Server/9.0.85 ( Debian )": the
    // version is in the header but not attached to the leading token. Only ever
    // fills a gap — a version read from the head token is never overwritten.
    if info.version.is_empty() {
        info.version = extract_version(server);
        // "uc-httpd 1.0.0" put the version in both columns; the notes should
        // carry what the VERSION column does not already say.
        if info.extra.trim() == info.version {
            info.extra.clear();
        }
    }
}

fn parse_http_json(body: &str, info: &mut ServiceInfo, extras: &mut Vec<String>) {
    let trimmed = body.trim_start();
    if !trimmed.starts_with('{') {
        return;
    }
    // Elasticsearch / OpenSearch
    if trimmed.contains("\"lucene_version\"") || trimmed.contains("You Know, for Search") {
        let distro = if trimmed.contains("opensearch") {
            "OpenSearch"
        } else {
            "Elasticsearch"
        };
        info.product = distro.into();
        if let Some(v) = probe::json_str(trimmed, "number") {
            info.version = v;
        }
        if let Some(c) = probe::json_str(trimmed, "cluster_name") {
            extras.push(format!("cluster {c}"));
        }
        extras.push("UNAUTHENTICATED".into());
        return;
    }
    // etcd
    if trimmed.contains("\"etcdserver\"") {
        info.product = "etcd".into();
        if let Some(v) = probe::json_str(trimmed, "etcdserver") {
            info.version = v;
        }
        return;
    }
    // Docker Engine API
    if trimmed.contains("\"ApiVersion\"") || trimmed.contains("\"GoVersion\"") {
        info.product = "Docker Engine".into();
        if let Some(v) = probe::json_str(trimmed, "Version") {
            info.version = v;
        }
        if let Some(os) = probe::json_str(trimmed, "Os") {
            extras.push(os);
        }
        if let Some(k) = probe::json_str(trimmed, "KernelVersion") {
            detect_os_from_text(&k, info);
            extras.push(format!("kernel {k}"));
        }
        extras.push("UNAUTHENTICATED DOCKER API".into());
        return;
    }
    // Consul / Nomad / Vault style
    if trimmed.contains("\"Config\"") && trimmed.contains("\"Datacenter\"") {
        info.product = "HashiCorp Consul".into();
        if let Some(v) = probe::json_str(trimmed, "Version") {
            info.version = v;
        }
        return;
    }
    if trimmed.contains("\"sealed\"") && trimmed.contains("\"initialized\"") {
        info.product = "HashiCorp Vault".into();
        if let Some(v) = probe::json_str(trimmed, "version") {
            info.version = v;
        }
        return;
    }
    // Kibana status
    if trimmed.contains("\"kibana\"") || trimmed.contains("\"nodes\":") && trimmed.contains("kibana")
    {
        info.product = "Kibana".into();
        if let Some(v) = probe::json_str(trimmed, "number") {
            info.version = v;
        }
        return;
    }
    // Generic {"version": "x.y.z"} APIs.
    if info.product.is_empty() {
        if let Some(v) = probe::json_str(trimmed, "version") {
            if v.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                info.version = v;
                info.product = "JSON API".into();
            }
        }
    }
}

fn html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let open_end = lower[start..].find('>')? + start + 1;
    let end = lower[open_end..].find("</title>")? + open_end;
    let title: String = body[open_end..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let title = title.trim().chars().take(60).collect::<String>();
    if title.is_empty() {
        None
    } else {
        Some(title)
    }
}

// ── product fingerprint tables ──────────────────────────────────────────────

/// Canonical product names for `Server:` headers whose leading token is not the
/// product's own name. "Apache-Coyote/1.1" is Tomcat's HTTP connector,
/// "App-webs/" is a Hikvision camera, "Cougar/9.01" is Windows Media Services,
/// and "ADB Broadband embedded httpd" reads as the product "ADB" if you just
/// take the first token. Derived from nmap's service-probe database, and
/// deliberately restricted to the headers where the generic reading in
/// `parse_server_header` loses the product — nginx, Apache and IIS name
/// themselves correctly and are not in here.
///
/// Matched as a **prefix of the whole header value**, longest key winning. The
/// scope is the Server header alone and never the page body, which is what lets
/// this table be large without inventing products: a page that merely mentions
/// "Cougar" is untouched. Renaming does not disturb the version — the header
/// still supplies the number, and `parse_server_header` keeps it.
pub(crate) const SERVER_ALIASES: &[(&str, &str)] = &[
    ("2nas_light", "2NAS_LIGHT"),
    ("2wire gateway bdc", "AT&T 2wire Gateway router http admin"),
    ("2wire-gateway", "2Wire HomePortal router http config"),
    ("360wzws", "360 WangZhan httpd"),
    ("4d_webstar_s", "WebSTAR httpd"),
    ("ability server", "Code Crafters Ability httpd"),
    ("adaptiveserveranywhere", "Sybase Adaptive Server Anywhere httpd"),
    ("adh-web", "ADH-Web httpd"),
    ("agent-listenserver-httpsvr", "Network Associates ePO Agent"),
    ("agent-listenserver-httpsvr/1", "Network Associates ePolicy Orchestrator"),
    ("agranat-emweb/r", "Agranat-EmWeb"),
    ("airdroid-g", "AirDroid httpd"),
    ("alexandrie", "GBConcept Alexandrie httpd"),
    ("allegroserve", "Franz Allegroserve httpd"),
    ("alpha-webserver", "ALPHA-WebServer"),
    ("alpha_webserv", "D-Link DIR-100 http config"),
    ("alphanetworks,inc", "Western Digital WD TV Live media player http config"),
    ("alt-n securitygateway", "ALT-N SecurityGateway httpd"),
    ("alvarion-webs", "Alvarion-Webs"),
    ("and-httpd", "and-httpd"),
    ("android webcam server", "IP Webcam"),
    ("anti-web", "Anti-Web httpd"),
    ("anti-web httpd", "Anti-Web httpd"),
    ("anweb", "AN httpd"),
    ("aos http server", "A2 httpd"),
    ("ap http server", "Nortel Integrated Conference bridge http config"),
    ("apache coyote", "Apache Tomcat (Coyote connector)"),
    ("apache embedded server", "NewCS satellite card sharing system http config"),
    ("apache netfile", "Ricoh Aficio IS200e scanner http config"),
    ("apache tomcat", "Apache Tomcat"),
    ("apache traffic server", "Apache Traffic Server"),
    ("apache-coyote", "Apache Tomcat (Coyote connector)"),
    ("apache-traffic-server", "Apache Traffic Server"),
    ("app-webs", "Hikvision IP camera httpd"),
    ("aprisasr web server", "4RF Aprisa SR smart radio httpd"),
    ("apt-proxy", "Debian Apt-proxy"),
    ("aquacontroller", "Neptune Systems AquaController aquarium monitor httpd"),
    ("arenasrv", "ArenaNet ArenaSrv game server"),
    ("asterisk", "Digium Asterisk AJAM"),
    ("atcom-ip-phone", "ATCOM VoIP phone web ui"),
    ("aterm", "NEC Aterm admin httpd"),
    ("atvise", "Certec atvise SCADA control httpd"),
    ("av_receiver", "Yamaha AV receiver web ui"),
    ("avgadminserver", "AVG Administration Console httpd"),
    ("avgadminserver64", "AVG Administration Console httpd"),
    ("avigilononvifnvt", "Avigilon webcam ONVIF NVT"),
    ("avigilonserver", "Avigilon Control Center httpd"),
    ("awselb/2", "AWS Elastic Load Balancing"),
    ("axhttpd", "axTLS axhttpd"),
    ("axway-copilot", "Axway CFT http admin"),
    ("barracudaserver", "Barracuda Embedded Web Server"),
    ("baseswitch 801fm", "Transtec BaseSwitch 801FM http config"),
    ("bcreport", "Blue Coat Reporter httpd"),
    ("big-ip", "F5 BIG-IP"),
    ("bigfixhttpserver", "BigFix enterprise patch management httpd"),
    ("bigip", "F5 BIG-IP"),
    ("bisw_sdr", "Billion/TeleWell ADSL modem http config"),
    ("bitleaphttp", "Barracuda Backup 490 appliance http admin"),
    ("bluedragon server", "New Atlanta BlueDragon httpd"),
    ("blueiris-http", "BlueIris"),
    ("blueiris-http/1", "Blue Iris camera webserver"),
    ("bluexp connector", "NetApp BlueXP"),
    ("boss/1", "Funkwerk embedded httpd"),
    ("brazil", "Sun Labs Brazil httpd"),
    ("bws/1", "Corel Paradox relational database web interface"),
    ("cba8/", "LANDesk Management Agent"),
    ("cc-web", "Centova Cast httpd"),
    ("ccs/jigsaw", "Commerce One httpd"),
    ("cegid-web-access-server", "Cegid-WEB-Access-Server"),
    ("cgi-httpd", "shttpd cgi-httpd"),
    ("chapurasyncmgrserver", "Chapura SyncManager httpd"),
    ("chatspace", "Akiva ChatSpace httpd"),
    ("cisco-ios", "Cisco IOS http config"),
    ("cjserver/1", "WebCTRL building automation http ui"),
    ("cl-http", "CL-HTTPd"),
    ("cloud connector", "SAP Cloud Connector"),
    ("cloudfront", "Amazon CloudFront httpd"),
    ("cloudstack password server 4", "Apache CloudStack Password Server"),
    ("clxwifiserver", "DejaOffice Wi-Fi Sync"),
    ("cnix http server 1", "Siemens LOGO! 8 PLC httpd"),
    ("colib_async_http_server", "COLIB_ASYNC_HTTP_SERVER"),
    ("conexant-emweb/r", "Conexant-EmWeb"),
    ("configurationservice", "Avaya Scopia Pathfinder firewall traversal http config"),
    ("content gateway manager", "Websense Content Gateway Manager http config"),
    ("cosminexus http server", "Hitachi Cosminexus httpd"),
    ("cosminexuscomponentcontainer", "Cosminexus httpd"),
    ("cougar", "Microsoft Windows Media Services"),
    ("cpanel::httpd like apache", "cPanel WebDisk httpd"),
    ("cpaneld", "cPanel httpd"),
    ("cpsrvd", "cPanel httpd"),
    ("cpws/", "Check Point firewall SmartPortal"),
    ("cs-mars", "Cisco MARS firewall http config"),
    ("cyms-secs", "Citrix Cyms-SecS"),
    ("d-box network", "Dreambox streaming audio httpd"),
    ("data ontap", "NetApp http vFiler"),
    ("day-servlet-engine", "Day CRX httpd"),
    ("dc-mpserver", "DC-MPSERVER"),
    ("dclk-httpsvr", "DoubleClick advertising httpd"),
    ("desktop on-call httpd", "IBM Desktop On-Call httpd"),
    ("desktopauthority", "ScriptLogic DesktopAuthority httpd"),
    ("dhost", "Novell eDirectory DHOST httpd"),
    ("digiweb", "Digitronic Digiweb httpd"),
    ("distributed-net-proxy", "distributed.net personal key proxy httpd"),
    ("diva_httpd", "Eicon Diva ISDN card configuration server"),
    ("divawebconfig", "Dialogic Diva media board http config"),
    ("dnvrs-webs", "Hikvision Network Video Recorder http admin"),
    ("domino-go-webserver", "Lotus Domino Go httpd"),
    ("dot-tunes", "Dot.Tunes iTunes sharing httpd"),
    ("dph-140", "D-Link DPH-140 VoIP phone http config"),
    ("drwebav-deskserver", "Dr. Web AV-Desk httpd"),
    ("drwebserver/rel-1000", "Dr.Web Enterprise Security Suite httpd"),
    ("dt-umeshkal", "Seagull BarTender printer driver httpd"),
    ("dtv hmc-lite server", "DirecTV HMC-Lite"),
    ("dvrdvs-webs", "Hikvision DVR httpd"),
    ("dvss-httpserver", "DVSS Herculese DVR http config"),
    ("dwhttpd", "Sun AnswerBook2 httpd"),
    ("easy-web server/1", "EasyFTP Server httpd"),
    ("ecacc", "Edgecast CDN"),
    ("edicom-http", "Edicom AS2 proxy server http config"),
    ("egdlws", "GE Ethernet Global Data Configuration Server"),
    ("embeded_httpd", "Ambit DOCSIS router http config"),
    ("embedthis-appweb", "Embedthis Appweb"),
    ("embos/ip", "Segger embOS/IP httpd"),
    ("embperl", "Apache httpd"),
    ("eni-web/r", "ENI-Web httpd"),
    ("enp-psna-web", "Emerson Network Power PSNA Web/SNMP Agent"),
    ("entropychat", "cPanel EntropyChat httpd"),
    ("epson-http", "Epson printer httpd"),
    ("esp8266-httpd", "esphttpd"),
    ("esp8266-link", "esp-link ESP8266 firmware httpd"),
    ("ews-nic4/8", "Embedded Web Server httpd"),
    ("extensible upnp agent", "xupnpd http admin"),
    ("extremeware", "Exreme Networks switch admin httpd"),
    ("extremez-ip", "ExtremeZ-IP httpd"),
    ("eye-fi agent", "Eye-Fi Manager httpd"),
    ("fasthttp", "Vertamedia fasthttp"),
    ("fec/1", "Funkwerk embedded httpd"),
    ("fexsrv", "F*EX (Frams' Fast File EXchange) server"),
    ("firewall", "WatchGuard Firebox Soho Firewall http config"),
    ("fitnesse", "FitNesse httpd"),
    ("flumotion", "Fluendo Flumotion httpd"),
    ("fm web publishing", "FileMaker Web Publishing httpd"),
    ("footprint", "Sandpiper Footprint http load balancer"),
    ("forcelivetransfer", "ForceTech ForceLive Transfer"),
    ("fortiweb", "Fortinet FortiWifi 60 http config"),
    ("freebrowser", "FreeBox FreeBrowser http interface"),
    ("frontpage-pws32", "FrontPage Personal Webserver"),
    ("fsav4igw", "F-Secure Internet Gatekeeper httpd"),
    ("fspms", "F-Secure Policy Manager Server httpd"),
    ("ftgate", "Floosietek FTgate webmail httpd"),
    ("gateway web server/1", "Mirasys WebClient server"),
    ("gemtekbaltichttpd", "Gemtek Systems GemtekBalticHTTPD"),
    ("geohttpserver", "GeoVision GeoHttpServer for webcams"),
    ("gnat-box", "Global Technology Associates Gnat Box firewall http config"),
    ("gnump3d2", "GNUMP3d streaming server"),
    ("goahead-http", "GoAhead WebServer"),
    ("goodreader for ipad", "Good.iWare WebDAV Server"),
    ("google frontend", "GoAgent http proxy"),
    ("groove-relay", "Groove-Relay http service"),
    ("groupwise gwia", "Novell GroupWise GWIA httpd"),
    ("groupwise mta", "Novell GroupWise MTA httpd"),
    ("groupwise poa", "Novell GroupWise POA httpd"),
    ("gs-webs", "Huacam Cyclops IP camera http config"),
    ("gws-grfe", "Google httpd"),
    ("hasp lm", "Sentinel HASP License Manager httpd"),
    ("hasp server", "Aladdin HASP license manager"),
    ("hbhttp pogobasic", "Pogoplug HBHTTP"),
    ("hbhttp pogomvoffice", "Pogoplug Office NAS httpd"),
    ("hcw_dvb_epg_server", "Hauppauge DVB EPG http config"),
    ("hds hi-track server", "Hi-Track httpd"),
    ("hp-ux_apache-based_web_server", "HP Apache-based httpd"),
    ("hp-web-server", "HP Web Jetwebadmin"),
    ("hp_compact_server", "HP LaserJet printer http admin"),
    ("hpsmh", "HP System Management Homepage"),
    ("ht5xx ht", "Grandstream HT502 VoIP router http config"),
    ("hts/tvheadend", "Tvheadend http config"),
    ("http server/everfocus", "Everfocus webcam http config"),
    ("http::proxy", "Perl HTTP::Proxy"),
    ("http::server::psgi", "Plack HTTP::Server::PSGI httpd"),
    ("httpd-wasd", "WASD httpd"),
    ("httpd_gargoyle", "httpd_gargoyle"),
    ("httpinfo olsrd plugin", "olsrd http info plugin"),
    ("httpsrv", "Boa httpd"),
    ("httpsvr", "Commtech Messenger Service httpd"),
    ("httrack-small-server", "httrack offline browsing httpd"),
    ("ibm-http-server", "IBM httpd"),
    ("ibm-proxy-fw", "IBM-PROXY-FW http proxy"),
    ("ibm-proxy-wte", "IBM WebSphere Edge caching proxy"),
    ("ibm-proxy-wte-us", "IBM-PROXY-WTE-US web proxy"),
    ("ids-server", "IDS-Server httpd"),
    ("idsl mailgate", "MailGate web proxy"),
    ("iisguard", "Troxo IISGuard"),
    ("imail_monitor", "Ipswitch IMail Monitor web service"),
    ("indigowebserver", "Perceptive Automation Indigo http config"),
    ("inets/develop", "CouchDB REST httpd"),
    ("inkhttp", "Wirehog http transfer interface"),
    ("insight manager", "Compaq Insight Manager"),
    ("instart/nginx", "nginx"),
    ("integrity", "Hay Systems HSL 2.75G Femtocell http config"),
    ("intellipoolhttpd", "Intellipool Network Monitor http config"),
    ("interdialog", "Teckinfo InterDialog UCCS"),
    ("interlogix-webs", "Interlogix TruVision DVR web interface"),
    ("internet firewall", "3Com OfficeConnect Firewall http config"),
    ("intrinsyc deviceweb", "Intermec CK31 http config"),
    ("iostreams", "Cisco IOS http config"),
    ("ip speaker web interface", "Advanced Network Devices IP Speaker web interface"),
    ("ip_sharer web", "IP_SHARER WEB"),
    ("ipc@chip", "Beck IPC@CHIP embedded httpd"),
    ("ipcamera http/onvif/p2p/rtsp/vod multi-server", "DB Power IP Camera HTTP/ONVIF/P2P/RTSP/VOD multi-server"),
    ("ipcamera-web", "Tenvis IP camera admin httpd"),
    ("ipl t s2", "Extron IPL T S2 http config"),
    ("ipmonitor", "MediaHouse ipMonitor httpd"),
    ("ipoffice", "Avaya IP Office VoIP PBX httpd"),
    ("iprism-httpd/v3", "St. Bernard iPrism firewall http config"),
    ("iprism/v3", "St. Bernard iPrism firewall http config"),
    ("iroffer-dinoex", "iroffer-dinoex httpd"),
    ("isocor web500gw", "Eudora Worldmail http config"),
    ("iss-httpmod", "Intelligent Security Systems webcam httpd"),
    ("iss-pxserver", "ISS-PXServer httpd"),
    ("ituneslib", "Apple TV http config"),
    ("java cell server", "dCache httpd"),
    ("javaopserver", "JavaOp httpd"),
    ("javaweb/0", "AirDroid httpd"),
    ("jiffyserver", "Jiffy secure messaging httpd"),
    ("jigsaw", "Java Jigsaw httpd"),
    ("jrentserver/1", "Jinfonet JReport Enterprise Server"),
    ("jtoolkithttp", "jToolkit web framework httpd"),
    ("jtvchat", "justin.tv chat server httpd"),
    ("keil-eweb", "Keil Embedded Web Server"),
    ("kestrel", "Microsoft Kestrel httpd"),
    ("keyreporter", "Sassafras KeyReporter http interface"),
    ("km-mfp-http/v", "Kyocera MFP httpd"),
    ("km_http-server", "KM_HTTP-Server"),
    ("ks_http", "Canon Pixma printer http config"),
    ("kwiknet web server", "Kadak KwikNet httpd"),
    ("labview", "National Instruments LabVIEW integrated httpd"),
    ("lancam server", "American Dynamics EDVR security recorder"),
    ("lbaas", "OpenStack Neutron LBaaS load balancer"),
    ("libisc", "BIND stats httpd"),
    ("libwww-perl-daemon", "libwww-perl-daemon httpd"),
    ("libzapid-httpd", "libzapid-httpd"),
    ("linux, stunnel/1", "D-Link router admin httpd"),
    ("linux, webaccess", "D-Link SharePort web access"),
    ("listmanagerweb", "Lyris ListManagerWeb"),
    ("liteserve", "Perception LiteServe httpd"),
    ("livestats reporting server", "DeepMetrix LiveStats httpd"),
    ("llink-daemon", "llink media streamer httpd"),
    ("lpc http server/v", "Konica Minolta LPC httpd"),
    ("lseriesweb", "HP Tape Library Web Interface Software httpd"),
    ("lucid-httpd", "LuCId-HTTPd"),
    ("lwip", "lwIP embedded httpd"),
    ("m1 webserver", "Bachmann M1 PLC httpd"),
    ("macos_personal_websharing", "Mac OS X Personal Websharing httpd"),
    ("magic iradio", "AGK WiFi Internet radio http config"),
    ("majestic-12 webserver", "Majestic-12 httpd"),
    ("marimba-transmitter", "BMC/Marimba Transmitter"),
    ("marvell 8688wm", "3M Filtrete 3M-50 thermostat http config"),
    ("mbedthis-app", "Mbedthis-Appweb"),
    ("mbedthis-appweb", "Embedthis Appweb"),
    ("mcafee-agent-httpsvr", "McAfee Agent httpd"),
    ("mediabolicmweb", "Mediabolic http config"),
    ("mediamallserver", "PlayOn MediaMallServer httpd"),
    ("mediasite web server", "SonicFoundry MediaSite httpd"),
    ("messaging", "Sybase Unwired Server Synchronization httpd"),
    ("messenger-ma", "Novell Messenger httpd"),
    ("micro-http", "Tektronix printer httpd"),
    ("micro_httpd", "micro_httpd (embedded)"),
    ("micro_proxy", "acme.com micro_proxy http proxy"),
    ("microsoft-pws", "Microsoft Peer Web Services httpd"),
    ("microsoft-pws-95", "Microsoft Peer Web Services 95 httpd"),
    ("microsoft-wince/5", "Kesseltronics car wash tunnel http config"),
    ("mineloadhttpd", "Mineload Bukkit plugin"),
    ("miner web server", "Asicminer Block Eruptor Blade bitcoin miner httpd"),
    ("mini web server 1", "thttpd"),
    ("mini-http", "Kemp 2500 load balancer http config"),
    ("mini_httpd", "mini_httpd (embedded)"),
    ("minituner", "BMC/Marimba Management http config"),
    ("miniweb", "MediaCoder media converter http interface"),
    ("ml_www", "ml_www WinAmp control httpd"),
    ("mono-httpapi", "Mono-HTTPAPI"),
    ("mono-xsp server", "Mono-XSP .NET httpd"),
    ("mordac", "Bridgeworks iSCSI-to-SAS bridge http ui"),
    ("mortbay-jetty", "Jetty"),
    ("mpsconserver", "ZebraNet print server httpd"),
    ("mqx http - freescale embedded web server", "Freescale MQX embedded httpd"),
    ("mqx httpsrv", "Freescale MQX embedded httpd"),
    ("mrvl-r1_0", "HP LaserJet CP1205nw or P1606 http config"),
    ("mrvl-r2_0", "HP LaserJet Pro MFP config httpd"),
    ("ms-mfc-httpsvr", "Microsoft Foundation Class httpd"),
    ("msos/", "Patton mawebserver httpd"),
    ("multisync plugin", "SyncML PIM sync server for MultiSync"),
    ("mx4j-httpd", "MX4J"),
    ("mx4j-httpd/1", "MX4J HTTP Adaptor"),
    ("mystery webserver", "Espion Interceptor http proxy"),
    ("nae server", "Ingrian i3xx health monitor httpd"),
    ("nae01", "Johnson Metasys building management system http interface"),
    ("nano httpd library", "Ferhat Ayaz's Nano httpd"),
    ("netcache", "NetApp NetCache http proxy"),
    ("netcache appliance", "NetApp NetCache http proxy"),
    ("netid", "Optivity NetID httpd"),
    ("netlab", "Cisco NETLab http proxy"),
    ("netqcheck", "Visualware NetQCheck httpd"),
    ("netqos-httpd/1", "CA NetQoS ReporterAnalyzer"),
    ("netscape-administrator", "Netscape FastTrack Administrator"),
    ("netscape-commerce", "Netscape-Commerce httpd"),
    ("nettalk-webserver", "CapeSoft NetTalk WebServer"),
    ("netware http stack", "Novell NetWare HTTP Stack"),
    ("netware-enterprise-web-server", "Novell NetWare enterprise web server"),
    ("network camera with pan/tilt", "Vivotek Network Camera http config"),
    ("network_module/1", "Yamaha AV device httpd"),
    ("networkactiv-web-server", "NetworkActiv httpd"),
    ("nexg_httpd", "nexg_httpd"),
    ("ngams/v", "BaseHTTPServer"),
    ("ngconvert/6", "Exalead CloudView"),
    ("ngx_openresty", "OpenResty web app server"),
    ("ni service locator", "National Instruments LabVIEW service locator httpd"),
    ("noelios-restlet-engine", "Noelios Restlet Framework"),
    ("novell-agent", "Novell GroupWise Monitor"),
    ("nt-ware-embeddedtcpserver-httpdevice", "NT-ware uniFLOW/MOM httpd"),
    ("nu-os", "Nu-OS"),
    ("octowebsvr/com", "SLWebMail Supervisor http config"),
    ("odn webserver", "Cisco ODN set-top box httpd"),
    ("officescan client", "Trend Micro OfficeScan Antivirus http config"),
    ("openbmc", "OpenBMC baseboard controller httpd"),
    ("openlink-web-configurator", "OpenLink http config"),
    ("openvpn-as", "OpenVPN Access Server"),
    ("otdav", "Olive Toast WebDAVServer"),
    ("otherwebserver", "ESET Remote Administrator Web Console"),
    ("owhttpd", "OWFS httpd"),
    ("ownserver", "Anteco OwnServer"),
    ("ows/1", "Canon varioPRINT or imagePRESS http ui"),
    ("pager enterprise", "Avtech PageR Enterprise http interface"),
    ("panweb server", "Palo Alto PanWeb httpd"),
    ("pbps-sessionmanager", "BeyondTrust Password Safe session manager JSON API"),
    ("pcastd", "Buffalo Linkstation http config"),
    ("pdr-m800/1", "Sanyo M800 DVR http admin"),
    ("peerguardnf", "Phoenix Labs PeerGuardian httpd"),
    ("phionentegrahttp", "phion Entegra SSL VPN client"),
    ("phttp", "Termika OlimpOKS PHttpd"),
    ("picowebserver", "Newmad PicoWebServer"),
    ("plack::handler::starlet", "Plack Starlet"),
    ("play! framework;", "Play Framework"),
    ("pmsoftware-sws", "PMSoftware Simple Web Server"),
    ("polycom-gab", "Polycom CMA Global Address Book (GAB) httpd"),
    ("popchartserver", "PopChart Pro"),
    ("powered by highwinds-software", "Highwinds CDN httpd"),
    ("powerstudio", "Circutor PowerStudio"),
    ("ppr-httpd", "PPR print spooling daemon ppradmin"),
    ("print_server web", "PRINT_SERVER WEB"),
    ("procurve web server", "HP ProCurve httpd"),
    ("proxygen", "Facebook Proxygen httpd"),
    ("prtg/", "Indy httpd"),
    ("pulsarcoreembeddedplantserver/1", "ThinKnx web ui"),
    ("puremessage web server", "Sophos PureMessage spam filter http interface"),
    ("pve-api-daemon", "Proxmox Virtual Environment REST API"),
    ("rac_one_http", "Dell Embedded Remote Access card httpd"),
    ("radia integration server", "HP Radia Integration Server httpd"),
    ("radiamessagingservice", "HP SIM NVDKIT.exe http config"),
    ("radware-web-server", "Radware OnDemand switch http config"),
    ("raid httpserver", "Sun StorEdge 3511 http config"),
    ("realtimes desktop service", "RealPlayer RealTimes Desktop Service"),
    ("redback application server", "IBM RedBack Application Server SOAP"),
    ("redtitan-enterprisequeue", "RedTitan-eNterpriseQueue"),
    ("remote-potato", "Remote Potato media player"),
    ("resin", "Caucho Resin JSP engine"),
    ("restlet-framework/@major-number@", "Serviio media server http status"),
    ("roamabout switch manager services", "Enterasys RoamAbout Switch Manager http config"),
    ("salive", "Servers Alive network monitor"),
    ("sametime server", "IBM Lotus Sametime httpd"),
    ("sap-internet-sapdb-server", "SAP Internet DB httpd"),
    ("sawmill", "BlueCoat Sawmill http proxy config"),
    ("schneider-web/v", "Schneider-WEB"),
    ("securetransport", "Axway SecureTransport httpd"),
    ("security console", "Nexpose Security Console"),
    ("sentinelkeysserver", "SafeNet Sentinel Keys License Monitor httpd"),
    ("sentinelprotectionserver", "SafeNet Sentinel Protection Server"),
    ("serv-u", "Rhinosoft Serv-U httpd"),
    ("server: paws", "Paws"),
    ("servletexecas", "New Atlanta ServletExec"),
    ("servx", "Hilscher servX httpd"),
    ("sffe", "Google Web Server"),
    ("shingetsu", "Saku"),
    ("si3phx1", "Prolexic DDoS protected httpd"),
    ("simple, secure web server", "Symantec firewall http proxy"),
    ("simpleserver:www", "AnalogX SimpleServer httpd"),
    ("sims/", "Stalker Mail Server web config"),
    ("sinclair zx-81 spectrum", "Urchin Web Statistics httpd"),
    ("sitescope", "Mercury SiteScope Application Managment httpd"),
    ("siyou server", "D-LINK siyou httpd"),
    ("sks_www", "SKS OpenPGP Key Server httpd"),
    ("sky_router", "BSkyB router"),
    ("skyx https", "Packeteer SkyX Accellerator"),
    ("slinger", "Panasonic DVR slinger http config"),
    ("smc internet update manager", "Avira SMC Internet Update Manager"),
    ("smssmtphttp", "Symantec smtp mail security http config"),
    ("snare", "InterSect Alliance SNARE httpd"),
    ("snare/1", "InterSect Alliance SNARE http config"),
    ("spacemon", "IPWorx SpaceMon storage monitor httpd"),
    ("spinnaker", "Searchlight Software Spinnaker httpd"),
    ("sq-webcam", "dvr1614n web-cam httpd"),
    ("sqlanywhere", "Sybase SQLAnywhere httpd"),
    ("standard erp", "HansaWorld Standard ERP"),
    ("statistics server", "DeepMetrix Statistics Server"),
    ("stronghold", "Apache Stronghold httpd"),
    ("sun-ilom-web-server", "Sun Integrated Lights-Out httpd"),
    ("sun-java-system-web-proxy-server", "Sun Java System Web Proxy http admin"),
    ("sun-java-system-web-server", "Sun Java System httpd"),
    ("sun-java-system/web-services-pack-1", "Java Web Services Developer Pack"),
    ("sun_ray_admin_server", "SunRay http config"),
    ("svea_httpd", "svea_httpd"),
    ("sw-cp-server", "sw-cp-server httpd"),
    ("swift1", "Samsung Swift httpd"),
    ("targetweb", "Blunk Microsystems TargetWeb"),
    ("tcl-webserver", "Tcl-Webserver"),
    ("tcsjh-webserver", "TCS John Huxley Gaming Floor Live httpd"),
    ("texis-monitor", "Thunderstone Texis-monitor httpd"),
    ("the knopflerfish http server", "Knopflerfish httpd"),
    ("this is for prtg probes", "PRTG remote probes httpd"),
    ("threadedservers", "Pacserve package server for Arch Linux"),
    ("thttpd-alphanetworks", "thttpd-alphanetworks"),
    ("tivo-httpd-1:", "TiVo To Go httpd"),
    ("tksock", "Agfeo TK-Suite PBX httpd"),
    ("tomcat web server", "Apache Tomcat"),
    ("tp-link httpd/1", "TP-LINK embedded httpd"),
    ("tp-link smartplug", "TP-LINK Smart Plug fake_httpd"),
    ("tr069 client cli server", "Alcatel-Lucent I-240W-A WAP TR069"),
    ("tr069 http server", "TP-LINK TR-069 remote access"),
    ("traffic manager", "Apache Traffic Server"),
    ("trapeze-srv", "Trapeze-Srv"),
    ("twproxy", "ThunderWeb twproxy"),
    ("uc-httpd", "UC-HTTPd (Xiongmai/HiSilicon DVR)"),
    ("uclinux-httpd", "uClinux-httpd"),
    ("ui-webserver", "UI-View Automatic Packet Reporting System httpd"),
    ("undefined", "McAfee ePolicy Orchestrator http interface"),
    ("unknown http server", "thttpd"),
    ("unrealengine uweb web server build", "Unreal Tournament http admin"),
    ("user agent web server", "Cisco ODN set-top box httpd"),
    ("vb150", "Canon WebView VB150 http config"),
    ("venky", "Smartfren EVDO modem httpd"),
    ("viavideo-web", "Polycom ViewStation"),
    ("virata-emweb", "Agranat/Virata EmWeb (embedded)"),
    ("virata-emweb/r", "Virata-EmWeb"),
    ("virtual web", "ZyXEL Virtual Web httpd"),
    ("visibroker", "Borland VisiBroker CORBA httpd"),
    ("vistabox", "Convision Vistabox security camera http config"),
    ("vorlon sr", "Hummingbird Vorlon Servlet Runner"),
    ("vpl-jail-system", "Virtual Programming Lab for Moodle"),
    ("vyktor xml winamp server", "Snowcrash WinAmp http control plugin"),
    ("waitress", "Pylons Waitress WSGI server"),
    ("wanduck", "Asus wanduck WAN monitor httpd"),
    ("wasabi/1", "Equitrac Office EQCASService.exe"),
    ("wave world wide web server", "Brocade Wave httpd"),
    ("wdaemon", "World Client WDaemon httpd"),
    ("web transaction server for clearpath mcp", "Unisys ClearPath MCP http config"),
    ("webpidginz", "WebPidgin-Z instant messaging interface"),
    ("websitepro", "O'Reilly WebSite Pro"),
    ("websnmp server httpd", "Apache WebSnmp module"),
    ("webtob", "TmaxSoft WebtoB httpd"),
    ("webtopia", "Archetopia WebTopia httpd"),
    ("webzerver/v", "Axonix SuperCD http config"),
    ("wg_httpd", "wg_httpd"),
    ("wgt_http", "wgt_http"),
    ("whc chatroom", "Fifi chat server http interface"),
    ("wifi-security-server", "Apache Tomcat"),
    ("wireless network camera", "LevelOne WCS-2030 webcam http config"),
    ("wireless network camera with pan/tilt", "Vivotek Network Camera http config"),
    ("wso2 carbon server", "WS02 Carbon middleware"),
    ("wstl cpe", "Westell cable modem http config"),
    ("wstl cpe 1", "Westell broadband router TR-069"),
    ("www-kodeks", "Knowledge On Demand httpd"),
    ("xcc web server", "Lenovo XClarity Controller"),
    ("xcd webadmin", "Intermec EasyLAN print server http admin"),
    ("xes 8830 windweb", "WindWeb"),
    ("xes windweb", "WindWeb"),
    ("xmpp-share-server", "xmpp-share-server httpd"),
    ("xmsksvr", "Xensoft X-MSK httpd"),
    ("z-world rabbit", "Z-World Rabbit microcontroller httpd"),
    ("zenagent", "Novell ZENworks Configuration Management"),
    ("zibase", "Zodianet ZiBASE home automation httpd"),
    ("zworld rabbit", "Z-World Rabbit microcontroller httpd"),
];

/// SSH software strings, matched against the greeting (`SSH-2.0-<software>`).
/// Kaisen already derives "OpenSSH" and friends by splitting the string on `_`;
/// this table is for the stacks where that reading is wrong or uninformative —
/// an appliance that calls itself "ROSSSH", a "Sun_SSH_1.1" whose product is
/// two tokens, the dozens of vendor sshd builds nmap has collected. Longest
/// needle wins, so "openssh_for_windows" beats "openssh".
pub(crate) const SSH_SOFTWARE: &[(&str, &str)] = &[
    // Kaisen's own labels come first and are kept verbatim: signatures
    // and the CVE table key on these strings.
    ("dropbear", "Dropbear sshd"),
    ("rosssh", "MikroTik RouterOS sshd"),
    ("cisco", "Cisco SSH"),
    ("libssh", "libssh"),
    ("openssh_for_windows", "OpenSSH for Windows"),
    ("wolfssh", "wolfSSH"),
    ("mod_sftp", "ProFTPD mod_sftp"),
    ("gopenssh", "Go x/crypto/ssh"),
    ("paramiko", "Paramiko"),
    ("erlang", "Erlang SSH"),
    // The rest is nmap's ssh match set, keyed on the software string the
    // banner carries after "SSH-2.0-".
    ("adtran", "Adtran sshd"),
    ("akamai", "Akamai SSH"),
    ("akamai-i", "Akamai SSH"),
    ("aos_ssh", "AOS sshd"),
    ("arrayos", "Array Networks sshd"),
    ("asyncssh", "AsyncSSH sshd"),
    ("atissh", "Allied Telesis sshd"),
    ("audiocodes", "AudioCodes MP-124 SIP gateway sshd"),
    ("axway.gateway", "Axway API Gateway sshd"),
    ("bluearcssh", "BlueArc sshd"),
    ("boks_ssh", "FoxT BoKS sshd"),
    ("cerberusftpserver", "Cerberus FTP Server sshd"),
    ("cisco_wlc", "Cisco Wireless LAN Controller sshd"),
    ("ciscoios", "Cisco SSH"),
    ("completeftp", "CompleteFTP sftpd"),
    ("comware", "HP Comware switch sshd"),
    ("confd", "ConfD sshd"),
    ("coreftp", "CoreFTP sshd"),
    ("cps_ssh_id", "CyberPower sshd"),
    ("crushftpsshd", "CrushFTP sftpd"),
    ("crushftpsshd_5", "CrushFTP sftpd"),
    ("cryptlib", "APC AOS cryptlib sshd"),
    ("data ontap ssh", "NetApp Data ONTAP sshd"),
    ("derived_from_openssh", "RedLineNetworks sshd"),
    ("digissh", "Digi CM sshd"),
    ("dlink corp. ssh server", "D-Link sshd"),
    ("dopra", "Dopra Linux sshd"),
    ("dragonfly", "OpenSSH"),
    ("drayssh", "DrayTek Vigor ADSL router sshd"),
    ("dss f-secure ssh", "F-Secure sshd"),
    ("echosystem_server", "EchoSystem sshd"),
    ("elastic-sshd", "Elastic Hosts emergency SSH console"),
    ("f-secure ssh", "F-Secure sshd"),
    ("filecopa", "FileCOPA sftpd"),
    ("flowssh: bitvise ssh ser", "Bitvise WinSSHD"),
    ("flowssh: winsshd", "Bitvise WinSSHD"),
    ("fortissh", "FortiSSH"),
    ("foxit-wac-server", "Foxit WAC Server sshd"),
    ("freebsd localisations", "OpenSSH"),
    ("freebsd-openssh-gssapi", "OpenSSH"),
    ("freebsd-openssh-portable", "OpenSSH"),
    ("fressh", "FreSSH"),
    ("gerritcodereview", "Apache Mina sshd"),
    ("gitblit", "Apache Mina sshd"),
    ("goanywhere", "GoAnywhere MFT sshd"),
    ("huawei", "Huawei WAP sshd"),
    ("huawei-umg", "Huawei Unified Media Gateway sshd"),
    ("huawei-vrp", "Huawei VRP sshd"),
    ("ift ssh server build", "Sun StorEdge 3511 sshd"),
    ("ilom.2015-5600", "OpenSSH"),
    ("in desktopauthority", "DesktopAuthority OpenSSH"),
    ("in remotelyanywhere", "OpenSSH"),
    ("ingrian_ssh", "Ingrian SSH"),
    ("ipage ftp server ready", "iPage Hosting sftpd"),
    ("ipssh", "Cisco/3com IPSSHd"),
    ("lancom", "lancom sshd"),
    ("lsh - a free ssh", "lshd secure shell"),
    ("lsh - a gnu ssh", "lshd secure shell"),
    ("lxssh", "MRV LX sshd"),
    ("maverick_sshd", "Maverick sshd"),
    ("meow roototkt by rebel", "meow SSH ROOTKIT"),
    ("ncsa_gssapi", "OpenSSH"),
    ("ncsa_gssapi_20040818 krb5", "OpenSSH"),
    ("ncsa_gssapi_gpt", "OpenSSH"),
    ("netbsd_secure_shell", "OpenSSH"),
    ("neteyes-c-series", "Neteyes C Series load balancer sshd"),
    ("netscreen", "NetScreen sshd"),
    ("nortel", "Nortel SSH"),
    ("nos-ssh", "3Com WX2200 or WX4400 NOS sshd"),
    ("onessh", "OneAccess OneSSH"),
    ("openssh", "OpenSSH"),
    ("ovh-rescue", "OpenSSH"),
    ("plan9", "Plan 9 sshd"),
    ("pragma fortressssh", "Pragma Fortress SSH Server"),
    ("process software multinet", "WRQ Reflection for Secure IT sshd"),
    ("reflectionforsecureit", "WRQ Reflection for Secure IT sshd"),
    ("romclisecure", "Adtran Netvanta RomCliSecure sshd"),
    ("romsshell", "AllegroSoft RomSShell sshd"),
    ("sc123/sc143 chip-rtos", "Dropbear sshd"),
    ("securelink ssh ser", "SecureLink sshd"),
    ("serv-u", "Serv-U SSH Server"),
    ("server-vi", "Akamai SSH"),
    ("server-vii", "Akamai SSH"),
    ("sftp ser", "IBM Sterling B2B Integrator sftpd"),
    ("sftpfilecontrol", "OpenSSH"),
    ("silvershield", "SilverSHielD sshd"),
    ("solidfire element", "OpenSSH"),
    ("srtsshserver", "South River Titan sftpd"),
    ("ssh compatible ser", "SCS NetScreen sshd"),
    ("ssh server - sshd", "SSHelper sshd (com.arachnoid.sshelper)"),
    ("ssh-1.5-by-ice_4_all", "ICE_4_All backdoor sshd"),
    ("ssh-1.5-ssh.0.1", "Dell PowerConnect sshd"),
    ("ssh-1.99-interopsecshell", "InteropSystems SSH"),
    ("ssh-2.0-0.0", "VanDyke VShell sshd"),
    ("ssh-2.0-1.0 radware ssh", "Radware sshd"),
    ("ssh-2.0-apssh", "APSSHd"),
    ("ssh-2.0-cisco_wlc", "Cisco WLC sshd"),
    ("ssh-2.0-mpssh", "HP Integrated Lights-Out mpSSH"),
    ("ssh-2.0-pbps-sm-1.0.0", "BeyondTrust Password Safe session manager"),
    ("ssh-2.0-pgp", "PGP Universal sshd"),
    ("ssh-2.0-twisted", "Kojoney SSH honeypot"),
    ("ssh-2.0-unknown", "Allot Netenforcer OpenSSH"),
    ("ssh_0.2", "3com sshd"),
    ("ssh_2.0", "Digi PortServer TS MEI sshd"),
    ("sshd-core", "Apache Mina sshd"),
    ("sshd-unknown", "Apache Mina sshd"),
    ("sshlib:", "MoveIT DMZ sshd"),
    ("sshlib: edmzsshdaemon", "EdmzSshDaemon"),
    ("sshlib: globalscape", "GlobalScape CuteFTP sshd"),
    ("sshlib: sshlibsrsshser", "SrSshServer"),
    ("sshlib: winsshd", "Bitvise WinSSHD"),
    ("sshtroll", "SSHTroll ssh honeypot"),
    ("sun_ssh", "SunSSH"),
    ("syncplify.me", "Syncplify.me Server sftpd"),
    ("sysaxssh", "Sysax Multi Server sshd"),
    ("technicolor_sw", "Technicolor SA sshd"),
    ("teleport", "Gravitational Teleport sshd"),
    ("trisquel_gnu/linux", "OpenSSH"),
    ("truex compt 32/64", "FrSAR truex compt sshd"),
    ("usha ssh", "USHA SSH"),
    ("weonlydo", "WeOnlyDo sshd"),
    ("weonlydo-wingftp", "WingFTP sftpd"),
    ("wingftpser", "Wing FTP Server sftpd"),
    ("ws_ftp-ssh", "WS_FTP sshd"),
    ("xfb.gateway", "Axway File Broker (XFB) sshd"),
    ("xlightftpd_release", "Xlight FTP Server sshd"),
    ("xxxxxxx", "Fortinet VPN/firewall sshd"),
    ("zte_ssh", "ZTE router/switch sshd"),
    ("zyxel ssh ser", "ZyXEL ZyWALL sshd"),
];

/// The version at the tail of an SSH software string: "Sun_SSH_1.1" → "1.1",
/// "OpenSSH_for_Windows_8.1" → "8.1". Used only to repair a version field that
/// the `_` split left holding words instead of numbers.
fn trailing_version(s: &str) -> String {
    s.rsplit(['_', '-', ' '])
        .find(|tok| probe::looks_like_version(tok))
        .unwrap_or("")
        .to_string()
}

/// The longest alias that starts this header value. Longest-first matters:
/// "agent-listenserver-httpsvr/1" is a different product from
/// "agent-listenserver-httpsvr", and table order should not decide which wins.
fn match_server_alias(server: &str) -> Option<&'static str> {
    let low = server.trim().to_ascii_lowercase();
    SERVER_ALIASES
        .iter()
        .filter(|(key, _)| low.starts_with(key))
        .max_by_key(|(key, _)| key.len())
        .map(|(_, product)| *product)
}

/// Web apps, appliances and devices identifiable from a keyword anywhere in the
/// response (headers, cookies, body markers, certificate names, telnet banners).
/// Ordered most-specific-first so "GitLab" wins over a bare "nginx" cookie.
pub(crate) const APP_MARKERS: &[(&str, &str)] = &[
    // Session-cookie names, from nmap's http set. A cookie name is about the
    // most specific thing a web application ever emits — it survives rebranding,
    // a stripped Server header and a custom login page — so these lead the
    // table: when one of them is present it is a better answer than whatever
    // generic keyword appears further down the page.
    ("webvpn=", "Cisco ASA SSL VPN"),
    ("cprelogin=", "cPanel"),
    ("whostmgrrelogin=", "cPanel Web Host Manager"),
    ("webmailrelogin=", "cPanel Webmail"),
    ("crushauth=", "CrushFTP"),
    ("mainserverinstance=", "CrushFTP"),
    ("grafana_sess=", "Grafana"),
    ("_sonar_session=", "SonarQube"),
    ("_gorilla_csrf=", "Gophish phishing framework"),
    ("hpribsession=", "HP Integrated Lights-Out (iLO)"),
    ("sslx_sseshid=", "SSL Explorer VPN"),
    ("extraweb_referer=", "Aventail SSL VPN"),
    ("bcsi_mc=", "Blue Coat CacheFlow"),
    ("cspsessionid=", "InterSystems Caché"),
    ("ispmgrses5=", "ISPmanager"),
    ("coreses5=", "ISPsystem COREmanager"),
    ("prtg4session=", "PRTG Network Monitor"),
    ("dlilpc=", "Digital Loggers Web Power Switch"),
    ("wdcpsessionid=", "WDLinux Control Panel"),
    ("unite-session-id=", "Opera Unite"),
    ("_appwebsessionid_=", "Embedthis Appweb"),
    ("sessionid_r3=", "Huawei router http admin"),
    ("wbm_cookie_session_id=", "Vodafone Station"),
    // Authentication realms, same idea: the realm is what an embedded device
    // calls itself when it has nothing else to say.
    ("realm=\"kubernetes-master\"", "Kubernetes API"),
    ("realm=\"powerdns\"", "PowerDNS"),
    ("realm=\"opensearch security\"", "OpenSearch"),
    ("realm=\"ip webcam\"", "IP Webcam"),
    ("realm=\"ascotel domain\"", "Aastra Ascotel PBX"),
    ("realm=\"securityspy web server\"", "SecuritySpy video server"),
    ("realm=\"fhem: login required\"", "FHEM home automation"),
    ("realm=\"sapbc\"", "SAP Business Connector"),
    ("x-jenkins", "Jenkins"),
    ("jenkins", "Jenkins"),
    ("gitlab", "GitLab"),
    ("gitea", "Gitea"),
    ("forgejo", "Forgejo"),
    ("sonatype nexus", "Sonatype Nexus"),
    ("artifactory", "JFrog Artifactory"),
    ("sonarqube", "SonarQube"),
    ("screenconnect", "ScreenConnect"),
    ("teamcity", "TeamCity"),
    ("activemq", "ActiveMQ"),
    ("manageengine", "ManageEngine"),
    ("grafana", "Grafana"),
    ("kibana", "Kibana"),
    ("prometheus", "Prometheus"),
    ("alertmanager", "Prometheus Alertmanager"),
    ("node_exporter", "Prometheus node_exporter"),
    ("cadvisor", "cAdvisor"),
    ("portainer", "Portainer"),
    ("rancher", "Rancher"),
    ("kubernetes", "Kubernetes API"),
    ("traefik", "Traefik"),
    ("haproxy", "HAProxy"),
    ("varnish", "Varnish"),
    ("squid", "Squid proxy"),
    ("nextcloud", "Nextcloud"),
    ("owncloud", "ownCloud"),
    ("seafile", "Seafile"),
    // Before the WordPress markers on purpose: match_app takes the first hit,
    // and naming the vulnerable plugin is strictly more useful than naming the
    // CMS it is installed in (the label still says WordPress either way).
    ("cm-download-manager", "WordPress CM Download Manager"),
    ("wp-content", "WordPress"),
    ("wp-json", "WordPress"),
    ("wordpress", "WordPress"),
    ("drupal", "Drupal"),
    ("joomla", "Joomla"),
    ("typo3", "TYPO3"),
    ("magento", "Magento"),
    ("prestashop", "PrestaShop"),
    ("phpmyadmin", "phpMyAdmin"),
    ("adminer", "Adminer"),
    ("pgadmin", "pgAdmin"),
    ("roundcube", "Roundcube"),
    ("zimbra", "Zimbra"),
    ("horde", "Horde"),
    ("squirrelmail", "SquirrelMail"),
    ("mailcow", "mailcow"),
    // mj_wwwusr is Majordomo 2's CGI entry point — the path CVE-2011-0049 is
    // reached through, and often the only thing the list server publishes.
    ("mj_wwwusr", "Majordomo 2"),
    ("majordomo", "Majordomo 2"),
    // The Totals add-on is what CVE-2008-3922 is about, and it names itself in
    // the URL and in the page it renders; plain AWStats does not carry it.
    ("awstatstotals", "AWStats Totals"),
    ("zabbix", "Zabbix"),
    ("nagios", "Nagios"),
    ("icinga", "Icinga"),
    ("cacti", "Cacti"),
    ("librenms", "LibreNMS"),
    ("netbox", "NetBox"),
    ("observium", "Observium"),
    ("proxmox", "Proxmox VE"),
    ("pve-manager", "Proxmox VE"),
    // Specific before generic: match_app takes the *first* hit, so "vmware"
    // must not shadow the products that also say "VMware" on the same page.
    ("esxi", "VMware ESXi"),
    ("vcenter", "VMware vCenter"),
    ("vsphere", "VMware vSphere"),
    ("vmware", "VMware"),
    ("xenserver", "Citrix XenServer"),
    // IoT cameras/NVRs name themselves in the certificate Organization even
    // when the CN is generic (Ezviz ships CN=Device, O=Ezviz). Hikvision and
    // Ezviz share a lineage, so keep both.
    ("ezviz", "Ezviz"),
    ("hikvision", "Hikvision"),
    // Infineon signs TPM-attested certificates with its own CA name ("Infineon
    // OPTIGA(TM) TPM 2.0 RSA CA"), which is how a ROCA-era key announces the
    // library that generated it.
    ("infineon", "Infineon TPM"),
    ("cockpit", "Cockpit"),
    ("webmin", "Webmin"),
    ("cpanel", "cPanel"),
    ("plesk", "Plesk"),
    ("directadmin", "DirectAdmin"),
    ("ispconfig", "ISPConfig"),
    ("pfsense", "pfSense"),
    ("opnsense", "OPNsense"),
    ("mikrotik", "MikroTik RouterOS"),
    ("routeros", "MikroTik RouterOS"),
    ("openwrt", "OpenWrt"),
    ("dd-wrt", "DD-WRT"),
    ("tomato firmware", "Tomato firmware"),
    ("ubiquiti", "Ubiquiti"),
    ("unifi", "Ubiquiti UniFi"),
    ("tp-link", "TP-Link device"),
    ("netgear", "Netgear device"),
    ("d-link", "D-Link device"),
    ("linksys", "Linksys device"),
    ("asuswrt", "ASUS router"),
    ("huawei", "Huawei device"),
    ("zyxel", "Zyxel device"),
    ("fortigate", "Fortinet FortiGate"),
    ("fortiweb", "Fortinet FortiWeb"),
    ("fortimail", "Fortinet FortiMail"),
    ("fortios", "Fortinet FortiOS"),
    ("fortinet", "Fortinet"),
    ("pan-os", "Palo Alto PAN-OS"),
    ("globalprotect", "Palo Alto GlobalProtect"),
    ("sonicwall", "SonicWall"),
    ("sophos", "Sophos"),
    ("watchguard", "WatchGuard"),
    ("checkpoint", "Check Point"),
    ("big-ip", "F5 BIG-IP"),
    // Remote-access gateways. `/dana-na/` is the give-away path in the login
    // page of an Ivanti Connect Secure box (and of the Pulse Secure appliances
    // it was renamed from), which is often all these expose about themselves.
    ("ivanti", "Ivanti Connect Secure"),
    ("/dana-na/", "Ivanti Connect Secure"),
    ("dana-na", "Ivanti Connect Secure"),
    ("pulse secure", "Pulse Secure"),
    ("pulsesecure", "Pulse Secure"),
    // A Cisco ASA's WebVPN portal keeps its own paths (/+CSCOE+/logon.html)
    // even when the page is fully branded, and publishes no version at all.
    ("+cscoe+", "Cisco ASA"),
    ("cisco adaptive security", "Cisco ASA"),
    ("cisco asa", "Cisco ASA"),
    ("webex", "Cisco Webex"),
    // Specific before generic: a NetScaler login page says "Citrix" too, and
    // the first hit wins.
    ("netscaler", "Citrix NetScaler"),
    ("citrix gateway", "Citrix Gateway"),
    ("citrix", "Citrix"),
    // Managed file transfer — the ransomware entry point of choice.
    ("moveit", "Progress MOVEit Transfer"),
    ("goanywhere", "Fortra GoAnywhere MFT"),
    ("crushftp", "CrushFTP"),
    ("serv-u", "Serv-U"),
    // Samba names itself in the SMB1 native-OS string and in the banners of
    // NAS front-ends, usually with its version attached. Without this marker
    // the SambaCry signature had nothing to key on: "Samba" only ever appeared
    // inside a dialect description like "Windows 10+ (or Samba)", which lands
    // in `extra`, never in `product`.
    ("samba", "Samba"),
    // AFP has no probe of its own — port 548 says nothing to a stranger — so
    // the name only ever arrives written down somewhere else: a NAS admin page,
    // a service list, a Bonjour service type.
    ("afpovertcp", "Apple AFP file sharing"),
    ("appleshare", "Apple AFP file sharing"),
    ("synology", "Synology DSM"),
    ("diskstation", "Synology DSM"),
    ("qnap", "QNAP QTS"),
    ("truenas", "TrueNAS"),
    ("freenas", "FreeNAS"),
    ("openmediavault", "OpenMediaVault"),
    ("jellyfin", "Jellyfin"),
    ("emby", "Emby"),
    ("plex media server", "Plex Media Server"),
    ("x-plex", "Plex Media Server"),
    ("sonarr", "Sonarr"),
    ("radarr", "Radarr"),
    ("lidarr", "Lidarr"),
    ("prowlarr", "Prowlarr"),
    ("bazarr", "Bazarr"),
    ("transmission", "Transmission"),
    ("qbittorrent", "qBittorrent"),
    ("deluge", "Deluge"),
    ("sabnzbd", "SABnzbd"),
    ("home assistant", "Home Assistant"),
    ("homeassistant", "Home Assistant"),
    ("openhab", "openHAB"),
    ("domoticz", "Domoticz"),
    ("node-red", "Node-RED"),
    ("octoprint", "OctoPrint"),
    ("pi-hole", "Pi-hole"),
    ("pihole", "Pi-hole"),
    ("adguard", "AdGuard Home"),
    ("uptime kuma", "Uptime Kuma"),
    ("minio", "MinIO"),
    ("couchdb", "Apache CouchDB"),
    ("rabbitmq", "RabbitMQ"),
    ("keycloak", "Keycloak"),
    ("wso2", "WSO2"),
    ("confluence", "Atlassian Confluence"),
    ("jira", "Atlassian Jira"),
    ("bitbucket", "Atlassian Bitbucket"),
    ("bamboo", "Atlassian Bamboo"),
    ("solr", "Apache Solr"),
    ("airflow", "Apache Airflow"),
    ("superset", "Apache Superset"),
    ("nifi", "Apache NiFi"),
    ("zeppelin", "Apache Zeppelin"),
    ("hadoop", "Apache Hadoop"),
    ("apache spark", "Apache Spark"),
    ("flink", "Apache Flink"),
    ("druid", "Apache Druid"),
    ("hbase", "Apache HBase"),
    ("tomcat", "Apache Tomcat"),
    ("jetty", "Eclipse Jetty"),
    ("wildfly", "WildFly"),
    ("jboss", "JBoss"),
    ("glassfish", "GlassFish"),
    ("weblogic", "Oracle WebLogic"),
    ("websphere", "IBM WebSphere"),
    ("coldfusion", "Adobe ColdFusion"),
    ("odoo", "Odoo"),
    ("moodle", "Moodle"),
    ("mediawiki", "MediaWiki"),
    ("gogs", "Gogs"),
    ("hasura", "Hasura"),
    ("strapi", "Strapi"),
    ("directus", "Directus"),
    ("swagger", "Swagger UI"),
    ("graphql", "GraphQL endpoint"),
    ("phpinfo", "PHP info page"),
    ("axis2", "Apache Axis2"),
    ("struts", "Apache Struts"),
    ("spring boot", "Spring Boot"),
    ("whitelabel error page", "Spring Boot"),
    ("django", "Django"),
    ("werkzeug", "Werkzeug (Flask)"),
    ("gunicorn", "Gunicorn"),
    ("uvicorn", "Uvicorn"),
    ("hypercorn", "Hypercorn"),
    ("waitress", "Waitress"),
    ("kestrel", "Kestrel (ASP.NET Core)"),
    ("x-powered-by: express", "Express (Node.js)"),
    ("fastapi", "FastAPI"),
    ("laravel", "Laravel"),
    ("symfony", "Symfony"),
    ("ruby on rails", "Ruby on Rails"),
    ("phusion passenger", "Phusion Passenger"),
    ("server: puma", "Puma"),
    ("server: unicorn", "Unicorn"),
    ("openresty", "OpenResty"),
    ("litespeed", "LiteSpeed"),
    ("lighttpd", "lighttpd"),
    ("caddy", "Caddy"),
    ("cherokee", "Cherokee"),
    ("boa/0", "Boa (embedded httpd)"),
    ("thttpd", "thttpd"),
    ("mini_httpd", "mini_httpd"),
    ("goahead", "GoAhead (embedded httpd)"),
    ("mongoose", "Mongoose (embedded httpd)"),
    ("httpfileserver", "HFS File Server"),
    ("cups", "CUPS"),
    ("application/ipp", "IPP printer"),
    ("jetdirect", "HP JetDirect"),
    // Named only where something else writes them down — a service list, a
    // package page — never by a probe: neither daemon greets a stranger.
    ("avahi", "Avahi"),
    ("distcc", "distcc"),
    ("dahua", "Dahua device"),
    ("axis communications", "Axis camera"),
    ("foscam", "Foscam camera"),
    ("reolink", "Reolink camera"),
    ("roku", "Roku device"),
    ("chromecast", "Google Chromecast"),
    ("sonos", "Sonos device"),
    ("philips hue", "Philips Hue bridge"),
    ("tasmota", "Tasmota device"),
    ("esphome", "ESPHome device"),
    ("shelly", "Shelly device"),
    // ── device and appliance names, mostly from nmap's telnet set ───────────
    // The telnet parser strips the IAC negotiation and then runs this same
    // table over whatever login banner is left, which is where a switch, a UPS
    // or a set-top box finally says what it is. Names only: anything that could
    // be an ordinary English word in a web page is left out on purpose.
    ("busybox", "BusyBox (embedded Linux)"),
    ("vxworks", "VxWorks"),
    ("windows ce", "Windows CE device"),
    ("reactos", "ReactOS"),
    ("lantronix", "Lantronix device server"),
    ("polycom command shell", "Polycom device"),
    ("extreme networks", "Extreme Networks switch"),
    ("bay networks", "Bay Networks device"),
    ("nortel networks", "Nortel device"),
    ("livingston portmaster", "Livingston PortMaster"),
    ("packetfront", "PacketFront router"),
    ("stonegate", "Forcepoint StoneGate firewall"),
    ("globespanvirata", "GlobespanVirata device"),
    ("supermicro", "Supermicro BMC"),
    ("connectups", "Eaton ConnectUPS card"),
    ("mge ups", "MGE UPS"),
    ("storagetek", "StorageTek tape library"),
    ("lexmark", "Lexmark printer"),
    ("epson network", "Epson network device"),
    ("ricoh", "Ricoh device"),
    ("iqinvision", "IQinVision camera"),
    ("huacam", "Huacam camera"),
    ("dreambox", "Dreambox set-top box"),
    ("openpli", "OpenPLi set-top box"),
    ("d-box2", "D-BOX2 set-top box"),
    ("tivo", "TiVo device"),
    ("vyos", "VyOS router"),
    ("picotux", "picotux embedded Linux"),
    ("georgia softworks", "Georgia SoftWorks telnetd"),
    ("kpym", "KpyM telnetd"),
    ("goodtech", "GoodTech telnetd"),
    ("ser2net", "ser2net serial bridge"),
    ("dynamips", "Dynamips router emulator"),
    ("mystic bbs", "Mystic BBS"),
    ("synchronet", "Synchronet BBS"),
    ("circlemud", "CircleMUD"),
    ("videolan", "VLC media player"),
    ("mldonkey", "MLDonkey"),
    ("yersinia", "Yersinia (L2 attack tool)"),
    // Modern self-hosted and DevOps web apps — specific needles (product names,
    // cookie names, unique markers) so they don't false-positive on prose.
    ("vaultwarden", "Vaultwarden (Bitwarden)"),
    ("bitwarden", "Bitwarden"),
    ("authelia", "Authelia"),
    ("authentik", "authentik IdP"),
    ("goharbor", "Harbor registry"),
    ("harbor-csrf-token", "Harbor registry"),
    ("argocd.token", "Argo CD"),
    ("argo-cd", "Argo CD"),
    ("paperless", "Paperless-ngx"),
    ("immich", "Immich"),
    ("n8n-auth", "n8n"),
    ("penpot", "Penpot"),
    ("outline_", "Outline wiki"),
    ("syncthing", "Syncthing"),
    ("navidrome", "Navidrome"),
    ("audiobookshelf", "Audiobookshelf"),
    ("calibre-web", "Calibre-Web"),
    ("photoprism", "PhotoPrism"),
    ("filebrowser", "File Browser"),
    ("code-server", "code-server (VS Code)"),
    ("netdata", "Netdata"),
    ("graylog", "Graylog"),
    ("rundeck", "Rundeck"),
    ("woodpecker", "Woodpecker CI"),
    ("droneci", "Drone CI"),
    ("x-drone-version", "Drone CI"),
    ("gitlab-runner", "GitLab Runner"),
    ("uptime-kuma", "Uptime Kuma"),
    ("healthchecks", "Healthchecks.io"),
    ("technitium", "Technitium DNS"),
    ("nocodb", "NocoDB"),
    ("appsmith", "Appsmith"),
    ("pocketbase", "PocketBase"),
    ("supabase", "Supabase"),
    ("meilisearch", "Meilisearch"),
    ("typesense", "Typesense"),
    ("qdrant", "Qdrant vector DB"),
    ("weaviate", "Weaviate vector DB"),
    ("ollama", "Ollama"),
    ("open-webui", "Open WebUI"),
    ("jellyseerr", "Jellyseerr"),
    ("overseerr", "Overseerr"),
    ("romm", "RomM"),
    ("coolify", "Coolify"),
    ("dokploy", "Dokploy"),
    ("headscale", "Headscale"),
    ("wg-easy", "WireGuard (wg-easy)"),
];

fn match_app(hay: &str) -> Option<&'static str> {
    let l = hay.to_ascii_lowercase();
    APP_MARKERS
        .iter()
        .find(|(needle, _)| l.contains(needle))
        .map(|(_, label)| *label)
}

/// Mail servers, which announce themselves in SMTP/IMAP/POP3 greetings and
/// capability lists rather than in a Server header.
pub(crate) const MAIL_PRODUCTS: &[&str] = &[
    "Postfix",
    "Exim",
    "Sendmail",
    "OpenSMTPD",
    "MasqMail",
    "netqmail",
    "qmail",
    "Microsoft ESMTP MAIL Service",
    "Microsoft Exchange",
    "Exchange",
    "Zimbra",
    "Dovecot",
    "Courier",
    "Cyrus",
    "MailEnable",
    "hMailServer",
    "Haraka",
    "SmarterMail",
    "IceWarp",
    "Kerio",
    "Axigen",
    "Mdaemon",
    "Postal",
    "Mailu",
    "Stalwart",
    "UW IMAP",
    "Gordano",
    "Lotus Domino",
    "Domino",
    "Sun Java System",
    "Rspamd",
    "Amavis",
    "ProtonMail",
    // From nmap's smtp/pop3/imap sets: servers that name themselves in the
    // greeting or the capability list. `match_mail_product` takes the first
    // hit, so a two-word name always precedes the word it contains
    // ("CommuniGate Pro" before "CommuniGate", "Merak Mail" before "Merak").
    "CommuniGate Pro",
    "CommuniGate",
    "Mirapoint",
    "MailSite",
    "Mailtraq",
    "MailMarshal",
    "MailMax",
    "MailFrontier",
    "InterMail",
    "IMail",
    "SLmail",
    "XMail",
    "Merak Mail",
    "Merak",
    "SurgeMail",
    "PowerMTA",
    "Mercury",
    "Eudora",
    "Netscape Messaging",
    "iPlanet",
    "PMDF",
    "Qpopper",
    "Teapop",
    "Perdition",
    "DBMail",
    "Scalix",
    "Zarafa",
    "NTMail",
    "WinWebMail",
    "Winmail",
    "ModusMail",
    "FirstClass",
    "Post.Office",
    "SubEtha",
    "Nemesis",
    "eXtremail",
    "Citadel",
    "Atmail",
    "Coremail",
    "Maillennium",
    "StrongMail",
    "Trend Micro InterScan",
    "Symantec Messaging Gateway",
    "Barracuda",
    "MailHog",
    "smtp4dev",
    "Synchronet",
    "ZMailer",
    "Smail",
    "Google",
    "Yahoo",
    "Outlook",
];

fn match_mail_product(s: &str) -> Option<&'static str> {
    let l = s.to_ascii_lowercase();
    MAIL_PRODUCTS
        .iter()
        .find(|p| l.contains(&p.to_ascii_lowercase()))
        .copied()
}

fn extract_product(s: &str, candidates: &[&str]) -> String {
    let l = s.to_ascii_lowercase();
    for c in candidates {
        if l.contains(&c.to_ascii_lowercase()) {
            return c.to_string();
        }
    }
    String::new()
}

/// Split "InspIRCd-3.11.0" or "nginx1.20" into product and version.
fn split_trailing_version(s: &str) -> Option<(String, String)> {
    let idx = s.find(|c: char| c.is_ascii_digit())?;
    if idx == 0 {
        return None;
    }
    let (prod, ver) = s.split_at(idx);
    let prod = prod.trim_end_matches(['-', '_', '/', ' ']).to_string();
    if prod.is_empty() || !ver.contains('.') {
        return None;
    }
    Some((prod, ver.to_string()))
}

/// Extract the first token that looks like a version, e.g. "3.0.3", "1.3.5a", "8.2p1".
fn extract_version(s: &str) -> String {
    for tok in s.split([' ', '(', ')', ',', '\t', '\r', '\n', ';', '"', '/']) {
        let t = tok.trim().trim_end_matches('.');
        if probe::looks_like_version(t) {
            return t.to_string();
        }
    }
    String::new()
}

/// Keep only what a person could actually read, and refuse the string entirely
/// when it's mostly binary — a hexdump of some unknown protocol's framing is
/// worse than an honest blank in the VERSION column.
fn readable(s: &str) -> Option<String> {
    let total = s.chars().count();
    if total == 0 {
        return None;
    }
    let printable = s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').count();
    if printable * 5 < total * 4 {
        return None;
    }
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.trim().len() < 3 {
        return None;
    }
    Some(cleaned.chars().take(60).collect())
}

/// Infer an OS family from banner text (Ubuntu, Debian, Windows, IIS, etc.).
pub fn detect_os_from_text(s: &str, info: &mut ServiceInfo) {
    if !info.os_hint.is_empty() {
        return;
    }
    let l = s.to_ascii_lowercase();
    // Ordered so that a specific distro beats the generic family it belongs to.
    const HINTS: &[(&str, &str)] = &[
        ("ubuntu", "Linux (Ubuntu)"),
        ("debian", "Linux (Debian)"),
        ("raspbian", "Linux (Raspbian)"),
        ("raspberry", "Linux (Raspberry Pi OS)"),
        ("centos", "Linux (CentOS)"),
        ("rocky", "Linux (Rocky Linux)"),
        ("almalinux", "Linux (AlmaLinux)"),
        ("oracle linux", "Linux (Oracle Linux)"),
        ("red hat", "Linux (RHEL)"),
        ("rhel", "Linux (RHEL)"),
        (".el7", "Linux (RHEL/CentOS 7)"),
        (".el8", "Linux (RHEL/CentOS 8)"),
        (".el9", "Linux (RHEL/CentOS 9)"),
        ("fedora", "Linux (Fedora)"),
        ("amzn", "Linux (Amazon Linux)"),
        ("amazon linux", "Linux (Amazon Linux)"),
        ("alpine", "Linux (Alpine)"),
        ("suse", "Linux (SUSE)"),
        ("opensuse", "Linux (openSUSE)"),
        ("arch", "Linux (Arch)"),
        ("gentoo", "Linux (Gentoo)"),
        ("void linux", "Linux (Void)"),
        ("photon", "Linux (VMware Photon)"),
        ("openwrt", "Linux (OpenWrt)"),
        ("dd-wrt", "Linux (DD-WRT)"),
        ("routeros", "MikroTik RouterOS"),
        ("synology", "Linux (Synology DSM)"),
        ("qnap", "Linux (QNAP QTS)"),
        ("unraid", "Linux (Unraid)"),
        ("android", "Android"),
        ("freebsd", "FreeBSD"),
        ("openbsd", "OpenBSD"),
        ("netbsd", "NetBSD"),
        ("dragonfly", "DragonFly BSD"),
        ("pfsense", "FreeBSD (pfSense)"),
        ("opnsense", "FreeBSD (OPNsense)"),
        ("darwin", "macOS / Darwin"),
        ("mac os", "macOS"),
        ("macos", "macOS"),
        ("solaris", "Solaris"),
        ("sunos", "Solaris / SunOS"),
        ("aix", "IBM AIX"),
        ("hp-ux", "HP-UX"),
        ("vxworks", "VxWorks"),
        ("cisco ios", "Cisco IOS"),
        ("junos", "Juniper Junos"),
        ("microsoft-iis", "Windows"),
        ("microsoft-httpapi", "Windows"),
        ("win32", "Windows"),
        ("win64", "Windows"),
        ("windows", "Windows"),
        ("ubnt", "Linux (Ubiquiti)"),
        ("busybox", "Linux (embedded/BusyBox)"),
        ("embedthis", "Embedded (Appweb)"),
        ("unix", "Unix / Linux-like"),
    ];
    for (needle, label) in HINTS {
        if l.contains(needle) {
            info.os_hint = (*label).to_string();
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_response(server: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nServer: {server}\r\nContent-Length: 0\r\n\r\n").into_bytes()
    }

    fn detect_http(server: &str) -> ServiceInfo {
        let mut info = ServiceInfo::default();
        parse_banner(80, &http_response(server), &mut info);
        info
    }

    fn detect_line(port: u16, line: &str) -> ServiceInfo {
        let mut info = ServiceInfo::default();
        parse_banner(port, line.as_bytes(), &mut info);
        info
    }

    /// A handshake packet as a real server sends it, so the parser is tested
    /// against the byte layout and not against a convenient stub.
    fn mysql_handshake(version: &str, plugin: &str, caps_low: u16, collation: u8) -> Vec<u8> {
        let mut body = vec![0x0a];
        body.extend_from_slice(version.as_bytes());
        body.push(0);
        body.extend_from_slice(&[1, 0, 0, 0]); // connection id
        body.extend_from_slice(&[0x41; 8]); // salt part 1
        body.push(0); // filler
        body.extend_from_slice(&caps_low.to_le_bytes());
        body.push(collation);
        body.extend_from_slice(&[2, 0]); // status flags
        body.extend_from_slice(&[0x0f, 0x80]); // capability flags, upper half
        body.push(21); // salt length
        body.extend_from_slice(&[0; 10]); // reserved
        body.extend_from_slice(&[0x42; 12]); // salt part 2
        body.push(0);
        body.extend_from_slice(plugin.as_bytes());
        body.push(0);
        let len = body.len();
        let mut pkt = vec![(len & 0xff) as u8, ((len >> 8) & 0xff) as u8, ((len >> 16) & 0xff) as u8, 0];
        pkt.extend_from_slice(&body);
        pkt
    }

    fn detect_mysql(version: &str) -> ServiceInfo {
        let mut info = ServiceInfo::default();
        // 0x0800 is CLIENT_SSL; every modern build offers it.
        parse_banner(3306, &mysql_handshake(version, "caching_sha2_password", 0x0800, 255), &mut info);
        info
    }

    // ── MySQL and everything else that answers on 3306 ──────────────────────

    #[test]
    fn mysql_handshake_names_branch_build_and_plugin() {
        let info = detect_mysql("8.0.35-0ubuntu0.22.04.1");
        assert_eq!(info.name, "mysql");
        assert_eq!(info.product, "MySQL");
        assert_eq!(info.version, "8.0.35");
        assert!(info.extra.contains("8.0 EOL since Apr 2026"), "{}", info.extra);
        assert!(info.extra.contains("0ubuntu0.22.04.1"), "{}", info.extra);
        assert!(info.extra.contains("caching_sha2_password"), "{}", info.extra);
        assert!(info.extra.contains("TLS supported"), "{}", info.extra);
        assert_eq!(info.os_hint, "Linux (Ubuntu)");
    }

    #[test]
    fn mariadb_strips_the_compatibility_prefix() {
        let info = detect_mysql("5.5.5-10.11.6-MariaDB-1:10.11.6+maria~ubu2204-log");
        assert_eq!(info.product, "MariaDB");
        assert_eq!(info.version, "10.11.6");
        assert!(info.extra.contains("10.11 LTS"), "{}", info.extra);
        assert!(info.extra.contains("binlog enabled"), "{}", info.extra);
    }

    #[test]
    fn a_fork_reports_its_own_version_not_the_one_it_emulates() {
        let tidb = detect_mysql("8.0.11-TiDB-v7.5.0");
        assert_eq!(tidb.product, "TiDB");
        assert_eq!(tidb.version, "7.5.0");
        // TiDB is not MySQL 8.0, so it must not inherit MySQL's calendar.
        assert!(!tidb.extra.contains("EOL"), "{}", tidb.extra);

        let aurora = detect_mysql("8.0.mysql_aurora.3.04.0");
        assert_eq!(aurora.product, "Amazon Aurora MySQL");
        assert_eq!(aurora.version, "3.04.0");

        let vitess = detect_mysql("8.0.30-Vitess");
        assert_eq!(vitess.product, "Vitess");
        assert_eq!(vitess.version, "8.0.30");
    }

    #[test]
    fn managed_rebuilds_keep_the_engine_name_so_findings_still_fire() {
        for (version, product) in [
            ("8.0.31-google", "Google Cloud SQL for MySQL"),
            ("8.0.28-azure", "Azure Database for MySQL"),
            ("8.0.32-polardb", "PolarDB for MySQL"),
        ] {
            let info = detect_mysql(version);
            assert_eq!(info.product, product);
            assert!(
                info.product.contains("MySQL"),
                "{product} must keep the substring vuln::assess matches on"
            );
            assert!(info.extra.contains("8.0 "), "{}", info.extra);
        }
    }

    #[test]
    fn an_end_of_life_branch_is_called_out() {
        let old = detect_mysql("5.6.51-log");
        assert_eq!(old.version, "5.6.51");
        assert!(old.extra.contains("5.6 EOL since Feb 2021"), "{}", old.extra);
        let lts = detect_mysql("8.4.2");
        assert!(lts.extra.contains("8.4 LTS"), "{}", lts.extra);
    }

    #[test]
    fn a_server_without_ssl_says_so() {
        let mut info = ServiceInfo::default();
        parse_banner(3306, &mysql_handshake("5.7.44-log", "mysql_native_password", 0x0000, 8), &mut info);
        assert_eq!(info.version, "5.7.44");
        assert!(info.extra.contains("no TLS offered"), "{}", info.extra);
        assert!(info.extra.contains("latin1_swedish_ci"), "{}", info.extra);
    }

    #[test]
    fn a_refusal_still_identifies_the_service() {
        let msg = b"Host '10.0.0.7' is not allowed to connect to this MariaDB server";
        let mut body = vec![0xff, 0x6a, 0x04]; // 0x046a = 1130
        body.extend_from_slice(msg);
        let mut pkt = vec![body.len() as u8, 0, 0, 0];
        pkt.extend_from_slice(&body);
        let mut info = ServiceInfo::default();
        assert!(parse_mysql(&pkt, &mut info));
        assert_eq!(info.product, "MariaDB");
        assert!(info.extra.contains("host not allowed to connect"), "{}", info.extra);
    }

    #[test]
    fn a_non_mysql_binary_greeting_is_not_claimed() {
        let mut info = ServiceInfo::default();
        assert!(!parse_mysql(&[0x10, 0x00, 0x00, 0x00, 0x33, 0x99, 0x01], &mut info));
        assert!(info.product.is_empty());
    }

    #[test]
    fn mysql_flavor_keys_are_lowercase_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for (needle, product, own) in MYSQL_FLAVORS {
            assert_eq!(
                *needle,
                needle.to_ascii_lowercase(),
                "MYSQL_FLAVORS key {needle:?} ({product}) has upper case and can never match"
            );
            assert!(needle.len() >= 4, "MYSQL_FLAVORS key {needle:?} is too short to anchor on");
            assert!(seen.insert(*needle), "MYSQL_FLAVORS key {needle:?} appears twice");
            assert!(
                own.is_empty() || needle.contains(own) || own.len() >= 4,
                "MYSQL_FLAVORS marker {own:?} is too short to anchor on"
            );
        }
    }

    // ── table hygiene ───────────────────────────────────────────────────────
    // These tables are matched against lowercased text, so an upper-case key is
    // not a style problem: it is a row that can never fire.

    #[test]
    fn marker_keys_are_lowercase_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for (needle, label) in APP_MARKERS {
            assert_eq!(
                *needle,
                needle.to_ascii_lowercase(),
                "APP_MARKERS key {needle:?} ({label}) has upper case and can never match"
            );
            assert!(seen.insert(*needle), "APP_MARKERS key {needle:?} appears twice");
        }
        let mut seen = std::collections::HashSet::new();
        for (key, product) in SERVER_ALIASES {
            assert_eq!(
                *key,
                key.to_ascii_lowercase(),
                "SERVER_ALIASES key {key:?} ({product}) has upper case and can never match"
            );
            assert!(seen.insert(*key), "SERVER_ALIASES key {key:?} appears twice");
            assert!(key.len() >= 4, "SERVER_ALIASES key {key:?} is too short to anchor on");
        }
        let mut seen = std::collections::HashSet::new();
        for (needle, label) in SSH_SOFTWARE {
            assert_eq!(
                *needle,
                needle.to_ascii_lowercase(),
                "SSH_SOFTWARE key {needle:?} ({label}) has upper case and can never match"
            );
            assert!(seen.insert(*needle), "SSH_SOFTWARE key {needle:?} appears twice");
        }
    }

    /// `match_mail_product` returns the first hit, so a name that contains
    /// another name has to come first or the shorter one swallows it — that is
    /// how "Microsoft Exchange" stays ahead of "Exchange".
    #[test]
    fn mail_products_are_ordered_specific_first() {
        for (i, a) in MAIL_PRODUCTS.iter().enumerate() {
            for b in MAIL_PRODUCTS.iter().skip(i + 1) {
                let (la, lb) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
                assert!(
                    !lb.contains(&la),
                    "{a:?} comes before {b:?} and is contained in it, so {b:?} can never be \
                     reported — move the longer name first"
                );
            }
        }
    }

    /// The point of the alias table is headers whose leading token is not the
    /// product. Servers that *do* name themselves must fall through untouched —
    /// this is the guard against a 480-row table quietly renaming nginx.
    #[test]
    fn servers_that_name_themselves_are_left_alone() {
        for (header, product, version) in [
            ("nginx/1.24.0", "nginx", "1.24.0"),
            ("Apache/2.4.62 (Debian)", "Apache", "2.4.62"),
            ("Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"),
            ("lighttpd/1.4.69", "lighttpd", "1.4.69"),
            ("openresty/1.21.4.1", "openresty", "1.21.4.1"),
            ("WebSphere Application Server/8.5", "WebSphere", "8.5"),
            ("GlassFish Server Open Source Edition 4.1", "GlassFish", "4.1"),
            ("TornadoServer/6.2", "TornadoServer", "6.2"),
            ("Jetty(9.4.44.v20210927)", "Jetty", "9.4.44.v20210927"),
            ("MiniServ/1.890", "MiniServ", "1.890"),
            ("RomPager/4.07", "RomPager", "4.07"),
        ] {
            let info = detect_http(header);
            assert_eq!(info.product, product, "{header} was renamed");
            assert_eq!(info.version, version, "{header} lost its version");
        }
    }

    /// And the headers the table exists for: the leading token is a connector,
    /// an OEM string or a codename, and the version still has to survive.
    #[test]
    fn server_aliases_name_what_the_head_token_hides() {
        for (header, product, version) in [
            ("Apache-Coyote/1.1", "Apache Tomcat (Coyote connector)", "1.1"),
            ("Apache Tomcat/9.0.85", "Apache Tomcat", "9.0.85"),
            ("App-webs/", "Hikvision IP camera httpd", ""),
            ("Cougar/9.01.01.5001", "Microsoft Windows Media Services", "9.01.01.5001"),
            ("uc-httpd 1.0.0", "UC-HTTPd (Xiongmai/HiSilicon DVR)", "1.0.0"),
            ("BigIP", "F5 BIG-IP", ""),
            ("cpsrvd/11.52.3.2", "cPanel httpd", "11.52.3.2"),
        ] {
            let info = detect_http(header);
            assert_eq!(info.product, product, "{header} was not recognised");
            assert_eq!(info.version, version, "{header} lost its version");
        }
    }

    /// A version that is in the header but not attached to the leading token
    /// used to be dropped on the floor.
    #[test]
    fn server_version_falls_back_to_the_rest_of_the_line() {
        assert_eq!(detect_http("WWW File Share Pro 2.0").version, "2.0");
        assert_eq!(detect_http("Tomcat Web Server/9.0.85").version, "9.0.85");
        // No digits anywhere is still no version, not a guess.
        assert!(detect_http("DD-WRT httpd").version.is_empty());
    }

    // ── SSH ─────────────────────────────────────────────────────────────────

    #[test]
    fn ssh_software_longest_needle_wins() {
        let win = detect_line(22, "SSH-2.0-OpenSSH_for_Windows_8.1\r\n");
        assert_eq!(win.product, "OpenSSH for Windows");
        assert_eq!(win.version, "8.1", "the tail version was not recovered");
        assert_eq!(win.os_hint, "Windows");

        let plain = detect_line(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n");
        assert_eq!(plain.product, "OpenSSH");
        assert_eq!(plain.version, "8.2p1");
    }

    /// "Sun_SSH_1.1" splits into product "Sun" and version "SSH_1.1", which is
    /// not a version at all. The table names the product and the tail repairs
    /// the number.
    #[test]
    fn ssh_two_token_products_keep_a_real_version() {
        let sun = detect_line(22, "SSH-2.0-Sun_SSH_1.1\r\n");
        assert_eq!(sun.version, "1.1");
        let drop = detect_line(22, "SSH-2.0-dropbear_2019.78\r\n");
        assert_eq!(drop.product, "Dropbear sshd");
        assert_eq!(drop.version, "2019.78");
        let cisco = detect_line(22, "SSH-1.99-Cisco-1.25\r\n");
        assert_eq!(cisco.product, "Cisco SSH");
        assert_eq!(cisco.version, "1.25");
    }

    // ── FTP, mail and telnet ────────────────────────────────────────────────

    #[test]
    fn ftp_banners_name_their_daemon() {
        for (banner, product) in [
            ("220 (vsFTPd 3.0.3)\r\n", "vsFTPd"),
            ("220 ProFTPD 1.3.5 Server (Debian)\r\n", "ProFTPD"),
            ("220 NcFTPd Server (licensed copy) ready.\r\n", "NcFTPd"),
            ("220 Wing FTP Server ready...\r\n", "Wing FTP"),
            ("220 Serv-U FTP Server v6.4 for WinSock ready.\r\n", "Serv-U"),
            ("220 TYPSoft FTP Server 1.10 ready...\r\n", "TYPSoft"),
        ] {
            assert_eq!(detect_line(21, banner).product, product, "banner: {banner:?}");
        }
    }

    #[test]
    fn mail_greetings_name_their_server() {
        for (banner, product) in [
            ("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", "Postfix"),
            ("220 mail ESMTP CommuniGate Pro 6.1.11 is glad to see you!\r\n", "CommuniGate Pro"),
            ("220 mail ESMTP MDaemon 15.0.3 ready\r\n", "Mdaemon"),
            ("220 host ESMTP IceWarp 12.0.1 ready\r\n", "IceWarp"),
            ("220 srv ESMTP XMail 1.27 ESMTP Server\r\n", "XMail"),
        ] {
            assert_eq!(detect_line(25, banner).product, product, "banner: {banner:?}");
        }
    }

    /// The telnet parser strips IAC and then runs the marker table, which is
    /// where an embedded device finally names itself.
    #[test]
    fn telnet_banners_name_the_device() {
        let mut data = vec![0xff, 0xfd, 0x18, 0xff, 0xfb, 0x01];
        data.extend_from_slice(b"\r\nBusyBox on router login: ");
        let mut info = ServiceInfo::default();
        parse_banner(23, &data, &mut info);
        assert_eq!(info.name, "telnet");
        assert_eq!(info.product, "BusyBox (embedded Linux)");
    }
}
