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
}

impl ServiceInfo {
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
    let listen_ms = if probe_bytes.is_some() { 400 } else { 900 };

    let mut stream = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return info,
    };

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
                let req = http_request("/", host, port);
                if timeout(dur, s.write_all(req.as_bytes())).await.is_ok() {
                    let body = read_for(&mut s, dur, 65536).await;
                    if !body.is_empty() {
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

async fn run_binary(kind: Bin, addr: SocketAddr, host: &str, dur: Duration) -> Option<probe::Probed> {
    let mut s = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
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
    // Appliance certificates routinely name the product outright.
    let hay = format!("{} {} {}", t.subject_cn, t.issuer_cn, t.sans.join(" "));
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
        for (needle, label) in [
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
        ] {
            if first.to_ascii_lowercase().contains(needle) {
                info.product = label.to_string();
                if needle == "openssh_for_windows" {
                    info.os_hint = "Windows".into();
                }
                break;
            }
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
/// `[3-byte length][seq][protocol version 0x0a][NUL-terminated server version]`.
fn parse_mysql(data: &[u8], info: &mut ServiceInfo) -> bool {
    if data.len() < 6 {
        return false;
    }
    // Error packet: the server rejected us but still identified itself.
    if data[3] == 0x00 && data[4] == 0xff {
        let msg = String::from_utf8_lossy(&data[7..data.len().min(200)]).to_string();
        if msg.to_ascii_lowercase().contains("mysql") || msg.to_ascii_lowercase().contains("mariadb")
        {
            info.name = "mysql".into();
            info.product = if msg.to_ascii_lowercase().contains("mariadb") {
                "MariaDB".into()
            } else {
                "MySQL".into()
            };
            info.extra = msg.trim().chars().take(120).collect();
            return true;
        }
        return false;
    }
    if data[4] != 0x0a {
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
    // MariaDB fakes a "5.5.5-" prefix so old clients keep working.
    let (product, version) = if let Some(rest) = raw.strip_prefix("5.5.5-") {
        ("MariaDB".to_string(), rest.to_string())
    } else if raw.to_ascii_lowercase().contains("mariadb") {
        ("MariaDB".to_string(), raw.clone())
    } else if raw.to_ascii_lowercase().contains("percona") {
        ("Percona Server".to_string(), raw.clone())
    } else {
        ("MySQL".to_string(), raw.clone())
    };
    info.product = product;
    let mut parts = version.splitn(2, '-');
    info.version = parts.next().unwrap_or("").to_string();
    let suffix = parts.next().unwrap_or("").to_string();

    // The auth plugin at the tail of the handshake distinguishes 8.x defaults.
    let tail = String::from_utf8_lossy(&data[end..]);
    let mut extras = Vec::new();
    if !suffix.is_empty() {
        extras.push(suffix);
    }
    for plugin in [
        "caching_sha2_password",
        "mysql_native_password",
        "sha256_password",
        "auth_gssapi_client",
    ] {
        if tail.contains(plugin) {
            extras.push(plugin.to_string());
            break;
        }
    }
    info.extra = extras.join("; ");
    detect_os_from_text(&raw, info);
    true
}

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

/// Web apps, appliances and devices identifiable from a keyword anywhere in the
/// response (headers, cookies, body markers, certificate names, telnet banners).
/// Ordered most-specific-first so "GitLab" wins over a bare "nginx" cookie.
const APP_MARKERS: &[(&str, &str)] = &[
    ("x-jenkins", "Jenkins"),
    ("jenkins", "Jenkins"),
    ("gitlab", "GitLab"),
    ("gitea", "Gitea"),
    ("forgejo", "Forgejo"),
    ("sonatype nexus", "Sonatype Nexus"),
    ("artifactory", "JFrog Artifactory"),
    ("sonarqube", "SonarQube"),
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
    ("zabbix", "Zabbix"),
    ("nagios", "Nagios"),
    ("icinga", "Icinga"),
    ("cacti", "Cacti"),
    ("librenms", "LibreNMS"),
    ("netbox", "NetBox"),
    ("observium", "Observium"),
    ("proxmox", "Proxmox VE"),
    ("pve-manager", "Proxmox VE"),
    ("vmware", "VMware"),
    ("vsphere", "VMware vSphere"),
    ("esxi", "VMware ESXi"),
    ("xenserver", "Citrix XenServer"),
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
    ("fortinet", "Fortinet"),
    ("pan-os", "Palo Alto PAN-OS"),
    ("sonicwall", "SonicWall"),
    ("sophos", "Sophos"),
    ("watchguard", "WatchGuard"),
    ("checkpoint", "Check Point"),
    ("big-ip", "F5 BIG-IP"),
    ("citrix", "Citrix"),
    ("netscaler", "Citrix NetScaler"),
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
    ("hikvision", "Hikvision device"),
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
const MAIL_PRODUCTS: &[&str] = &[
    "Postfix",
    "Exim",
    "Sendmail",
    "OpenSMTPD",
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
