//! Service & version detection via banner grabbing and light protocol probes.
//! All unprivileged: it just talks to the open TCP port like any client would.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default)]
pub struct ServiceInfo {
    pub name: String,     // e.g. "http", "ssh"
    pub product: String,  // e.g. "OpenSSH", "nginx"
    pub version: String,  // e.g. "8.2p1"
    pub extra: String,    // e.g. "Ubuntu 4ubuntu0.5"
    pub banner: String,   // raw banner (trimmed)
    pub os_hint: String,  // OS inferred from banner, if any
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

/// Probe an open port for its service banner/version. `default_name` is the
/// nmap-services guess used when we cannot read anything useful.
pub async fn detect(addr: SocketAddr, default_name: &str, timeout_ms: u64) -> ServiceInfo {
    let mut info = ServiceInfo {
        name: default_name.to_string(),
        ..Default::default()
    };

    let dur = Duration::from_millis(timeout_ms.max(500));
    let port = addr.port();

    // Connect.
    let stream = match timeout(dur, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return info,
    };
    let mut stream = stream;

    // Some services speak first (SSH, FTP, SMTP, POP3, IMAP). Others (HTTP)
    // wait for a request. Decide a probe by port.
    let probe: Option<&[u8]> = match port {
        // 8060 = Roku's ECP, a genuine HTTP endpoint that replies to GET /
        // with an XML device-info blob naming the product.
        80 | 8080 | 8000 | 8008 | 8888 | 81 | 82 | 591 | 8081 | 8443 | 443 | 9080 | 9090 | 8060 => {
            Some(b"GET / HTTP/1.0\r\nHost: kaisen\r\nUser-Agent: Kaisen\r\n\r\n")
        }
        6379 => Some(b"INFO\r\n"),          // redis
        11211 => Some(b"version\r\n"),      // memcached
        _ => None,
    };

    // Read any immediate banner first (server-speaks-first protocols).
    let mut buf = vec![0u8; 4096];
    let mut data: Vec<u8> = Vec::new();

    if let Ok(Ok(n)) = timeout(Duration::from_millis(700), stream.read(&mut buf)).await {
        if n > 0 {
            data.extend_from_slice(&buf[..n]);
        }
    }

    // If nothing yet and we have a probe, send it and read.
    if data.is_empty() {
        if let Some(p) = probe {
            let _ = timeout(dur, stream.write_all(p)).await;
            if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
                if n > 0 {
                    data.extend_from_slice(&buf[..n]);
                }
            }
        }
    }

    if data.is_empty() {
        return info;
    }

    let text = String::from_utf8_lossy(&data);
    info.banner = text.lines().next().unwrap_or("").trim().to_string();

    parse_banner(port, &text, &mut info);

    // Active FTP probe: the SYST command makes the server announce its OS type,
    // e.g. "215 UNIX Type: L8" or "215 Windows_NT". Strong, unprivileged signal.
    if info.name == "ftp" {
        let _ = timeout(dur, stream.write_all(b"SYST\r\n")).await;
        let mut sbuf = vec![0u8; 512];
        if let Ok(Ok(n)) = timeout(dur, stream.read(&mut sbuf)).await {
            if n > 0 {
                let syst = String::from_utf8_lossy(&sbuf[..n]);
                let line = syst.lines().next().unwrap_or("").trim();
                if let Some(rest) = line.strip_prefix("215 ").or_else(|| line.strip_prefix("215-")) {
                    if info.extra.is_empty() {
                        info.extra = rest.trim().to_string();
                    }
                    let up = rest.to_ascii_uppercase();
                    if up.contains("WINDOWS") || up.contains("WIN32") || up.contains("WIN_NT") {
                        info.os_hint = "Windows".into();
                    } else if (up.contains("UNIX") || up.contains("LINUX") || up.contains("L8"))
                        && info.os_hint.is_empty() {
                            info.os_hint = "Unix / Linux-like".into();
                        }
                    detect_os_from_text(rest, &mut info);
                }
            }
        }
    }

    info
}

fn parse_banner(port: u16, text: &str, info: &mut ServiceInfo) {
    let first = text.lines().next().unwrap_or("").trim();

    // SSH: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    if first.starts_with("SSH-") {
        info.name = "ssh".into();
        if let Some(rest) = first.splitn(3, '-').nth(2) {
            // rest = "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            let mut it = rest.splitn(2, ' ');
            let prodver = it.next().unwrap_or("");
            info.extra = it.next().unwrap_or("").to_string();
            if let Some((prod, ver)) = prodver.split_once('_') {
                info.product = prod.to_string();
                info.version = ver.to_string();
            } else {
                info.product = prodver.to_string();
            }
        }
        detect_os_from_text(first, info);
        return;
    }

    // FTP: "220 (vsFTPd 3.0.3)" or "220 ProFTPD 1.3.5 Server"
    if port == 21 || first.starts_with("220 ") || first.starts_with("220-") {
        info.name = "ftp".into();
        info.product = extract_product(first, &["vsFTPd", "ProFTPD", "FileZilla", "Pure-FTPd", "FTP"]);
        info.version = extract_version(first);
        detect_os_from_text(first, info);
        return;
    }

    // SMTP: "220 mail.example.com ESMTP Postfix (Ubuntu)"
    if port == 25 || port == 587 || port == 465 || first.contains("ESMTP") || first.contains("SMTP") {
        info.name = "smtp".into();
        info.product = extract_product(first, &["Postfix", "Exim", "Sendmail", "Microsoft", "qmail", "OpenSMTPD"]);
        info.version = extract_version(first);
        detect_os_from_text(first, info);
        return;
    }

    // POP3 / IMAP
    if first.starts_with("+OK") {
        info.name = "pop3".into();
        info.version = extract_version(first);
        return;
    }
    if first.contains("* OK") && (port == 143 || port == 993) {
        info.name = "imap".into();
        info.version = extract_version(first);
        return;
    }

    // HTTP: parse the Server: header.
    if text.starts_with("HTTP/") || text.contains("HTTP/1.") {
        info.name = if port == 443 || port == 8443 { "https" } else { "http" }.into();
        for line in text.lines() {
            let l = line.trim();
            if let Some(server) = l.strip_prefix("Server:").or_else(|| l.strip_prefix("server:")) {
                let server = server.trim();
                info.banner = format!("Server: {server}");
                // "nginx/1.18.0 (Ubuntu)" or "Apache/2.4.41 (Ubuntu)" or "Microsoft-IIS/10.0"
                if let Some((prod, rest)) = server.split_once('/') {
                    info.product = prod.to_string();
                    info.version = rest.split_whitespace().next().unwrap_or("").to_string();
                    info.extra = rest
                        .split_once(' ')
                        .map(|(_, e)| e.trim().trim_matches(|c| c == '(' || c == ')').to_string())
                        .unwrap_or_default();
                } else {
                    info.product = server.to_string();
                }
                detect_os_from_text(server, info);
                break;
            }
        }
        return;
    }

    // Redis INFO
    if port == 6379 && text.contains("redis_version:") {
        info.name = "redis".into();
        info.product = "Redis".into();
        for line in text.lines() {
            if let Some(v) = line.trim().strip_prefix("redis_version:") {
                info.version = v.trim().to_string();
                break;
            }
        }
        return;
    }

    // Memcached
    if port == 11211 && text.starts_with("VERSION ") {
        info.name = "memcached".into();
        info.product = "Memcached".into();
        info.version = text.trim_start_matches("VERSION ").trim().to_string();
        return;
    }

    // MySQL greeting contains a version string near the start (binary protocol).
    if port == 3306 || port == 3307 {
        info.name = "mysql".into();
        info.product = "MySQL".into();
        // The server version is an ASCII, NUL-terminated string after a few bytes.
        if let Some(v) = extract_ascii_version(text.as_bytes()) {
            info.version = v;
        }
        detect_os_from_text(text, info);
        return;
    }

    // Fallback: keep whatever readable first line we captured.
    if info.product.is_empty() && !first.is_empty() {
        info.product = first.chars().take(60).collect();
    }
}

fn extract_product(s: &str, candidates: &[&str]) -> String {
    for c in candidates {
        if s.to_ascii_lowercase().contains(&c.to_ascii_lowercase()) {
            return c.to_string();
        }
    }
    String::new()
}

/// Extract the first token that looks like a version, e.g. "3.0.3", "1.3.5a", "8.2p1".
fn extract_version(s: &str) -> String {
    let mut current = String::new();
    for tok in s.split([' ', '(', ')', ',']) {
        let t = tok.trim();
        if t.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
            && t.contains('.')
            && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            current = t.to_string();
            break;
        }
    }
    current
}

fn extract_ascii_version(bytes: &[u8]) -> Option<String> {
    // Find a run like "5.7.34" or "8.0.28-0ubuntu..." in the greeting.
    let s: String = bytes
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { ' ' })
        .collect();
    let v = extract_version(&s);
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Infer an OS family from banner text (Ubuntu, Debian, Windows, IIS, etc.).
pub fn detect_os_from_text(s: &str, info: &mut ServiceInfo) {
    let l = s.to_ascii_lowercase();
    let hint = if l.contains("ubuntu") {
        "Linux (Ubuntu)"
    } else if l.contains("debian") {
        "Linux (Debian)"
    } else if l.contains("centos") {
        "Linux (CentOS)"
    } else if l.contains("red hat") || l.contains("rhel") || l.contains(".el") {
        "Linux (RHEL/CentOS)"
    } else if l.contains("fedora") {
        "Linux (Fedora)"
    } else if l.contains("alpine") {
        "Linux (Alpine)"
    } else if l.contains("freebsd") {
        "FreeBSD"
    } else if l.contains("openbsd") {
        "OpenBSD"
    } else if l.contains("microsoft-iis") || l.contains("windows") || l.contains("win32") || l.contains("win64") {
        "Windows"
    } else if l.contains("raspbian") {
        "Linux (Raspbian)"
    } else {
        ""
    };
    if !hint.is_empty() && info.os_hint.is_empty() {
        info.os_hint = hint.to_string();
    }
}
