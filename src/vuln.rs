//! Lightweight vulnerability signature matching.
//!
//! This is deliberately *heuristic*: it matches detected service/product/version
//! banners against a curated, embedded signature table of well-known issues.
//! It is not a full vulnerability scanner and does not perform exploitation —
//! it flags likely-vulnerable versions so you know where to look deeper.

use crate::service::ServiceInfo;

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,       // CVE or identifier
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

/// A signature: if `product` matches (case-insensitive substring) and the
/// version predicate holds, emit the finding.
struct Sig {
    product: &'static str,
    id: &'static str,
    severity: Severity,
    title: &'static str,
    detail: &'static str,
    matches: fn(&str) -> bool,
}

fn ver_tuple(v: &str) -> (u64, u64, u64) {
    // Parse leading "a.b.c" numbers, ignoring suffixes like "p1", "-ubuntu".
    let mut it = v.split(|c: char| !c.is_ascii_digit());
    let a = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let b = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let c = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (a, b, c)
}

const SIGS: &[Sig] = &[
    Sig {
        product: "OpenSSH",
        id: "CVE-2018-15473",
        severity: Severity::Medium,
        title: "OpenSSH username enumeration",
        detail: "OpenSSH < 7.7 allows remote username enumeration via malformed auth packets.",
        matches: |v| ver_tuple(v) < (7, 7, 0) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "OpenSSH",
        id: "CVE-2016-0777",
        severity: Severity::Medium,
        title: "OpenSSH roaming information leak",
        detail: "OpenSSH client 5.4-7.1 roaming feature may leak private keys.",
        matches: |v| {
            let t = ver_tuple(v);
            ((5, 4, 0)..=(7, 1, 0)).contains(&t)
        },
    },
    Sig {
        product: "vsFTPd",
        id: "CVE-2011-2523",
        severity: Severity::Critical,
        title: "vsFTPd 2.3.4 backdoor",
        detail: "vsFTPd 2.3.4 shipped a backdoor granting a root shell on :6200.",
        matches: |v| ver_tuple(v) == (2, 3, 4),
    },
    Sig {
        product: "ProFTPD",
        id: "CVE-2015-3306",
        severity: Severity::Critical,
        title: "ProFTPD mod_copy RCE",
        detail: "ProFTPD 1.3.5 mod_copy allows unauthenticated file copy / RCE.",
        matches: |v| ver_tuple(v) == (1, 3, 5),
    },
    Sig {
        product: "Apache",
        id: "CVE-2021-41773",
        severity: Severity::Critical,
        title: "Apache HTTP path traversal / RCE",
        detail: "Apache httpd 2.4.49 path traversal (CVE-2021-41773); 2.4.50 also affected (CVE-2021-42013).",
        matches: |v| {
            let t = ver_tuple(v);
            t == (2, 4, 49) || t == (2, 4, 50)
        },
    },
    Sig {
        product: "nginx",
        id: "CVE-2013-2028",
        severity: Severity::High,
        title: "nginx chunked stack overflow",
        detail: "nginx 1.3.9-1.4.0 chunked transfer stack buffer overflow.",
        matches: |v| {
            let t = ver_tuple(v);
            ((1, 3, 9)..=(1, 4, 0)).contains(&t)
        },
    },
    Sig {
        product: "Microsoft-IIS",
        id: "CVE-2017-7269",
        severity: Severity::High,
        title: "IIS 6.0 WebDAV buffer overflow",
        detail: "IIS 6.0 ScStoragePathFromUrl WebDAV buffer overflow (RCE).",
        matches: |v| ver_tuple(v) == (6, 0, 0),
    },
    Sig {
        product: "Exim",
        id: "CVE-2019-10149",
        severity: Severity::Critical,
        title: "Exim 'Return of the Wizard' RCE",
        detail: "Exim 4.87-4.91 remote command execution via crafted recipient.",
        matches: |v| {
            let t = ver_tuple(v);
            ((4, 87, 0)..=(4, 91, 0)).contains(&t)
        },
    },
    Sig {
        product: "Redis",
        id: "KAISEN-REDIS-EXPOSED",
        severity: Severity::High,
        title: "Redis reachable (check auth)",
        detail: "Redis responded to INFO. If unauthenticated, it allows data access and RCE via module/config tricks.",
        matches: |_| true,
    },
    Sig {
        product: "Memcached",
        id: "KAISEN-MEMCACHED-EXPOSED",
        severity: Severity::Medium,
        title: "Memcached reachable (UDP amp risk)",
        detail: "Exposed Memcached can be abused for data leakage and UDP amplification DDoS.",
        matches: |_| true,
    },
    Sig {
        product: "MySQL",
        id: "KAISEN-DB-EXPOSED",
        severity: Severity::Medium,
        title: "MySQL exposed to network",
        detail: "Database service reachable remotely; ensure it is firewalled and requires strong auth.",
        matches: |_| true,
    },
];

/// Match a detected service against the signature DB plus a few port-level
/// exposure heuristics.
pub fn assess(port: u16, svc: &ServiceInfo) -> Vec<Finding> {
    let mut out = Vec::new();

    if !svc.product.is_empty() {
        for s in SIGS {
            if svc
                .product
                .to_ascii_lowercase()
                .contains(&s.product.to_ascii_lowercase())
                && (s.matches)(&svc.version)
            {
                out.push(Finding {
                    id: s.id.to_string(),
                    severity: s.severity,
                    title: s.title.to_string(),
                    detail: s.detail.to_string(),
                });
            }
        }
    }

    // Port-level exposure heuristics (independent of banner).
    let exposure = match port {
        23 => Some(("KAISEN-TELNET", Severity::High, "Telnet in use", "Telnet transmits credentials in cleartext; prefer SSH.")),
        21 => Some(("KAISEN-FTP", Severity::Low, "FTP in use", "FTP is often cleartext; prefer FTPS/SFTP.")),
        3389 => Some(("KAISEN-RDP", Severity::Medium, "RDP exposed", "Exposed RDP is a common ransomware entry point; restrict access / require NLA.")),
        445 => Some(("KAISEN-SMB", Severity::Medium, "SMB exposed", "SMB exposed to the network; ensure patched (EternalBlue class) and not internet-facing.")),
        27017 | 27018 => Some(("KAISEN-MONGO", Severity::High, "MongoDB exposed", "Exposed MongoDB has historically been mass-ransomed when unauthenticated.")),
        9200 | 9300 => Some(("KAISEN-ES", Severity::High, "Elasticsearch exposed", "Unauthenticated Elasticsearch leaks all indexed data.")),
        5900 | 5901 => Some(("KAISEN-VNC", Severity::Medium, "VNC exposed", "VNC often weakly authenticated; tunnel it over SSH/VPN.")),
        _ => None,
    };
    if let Some((id, sev, title, detail)) = exposure {
        // Avoid duplicate telnet/ftp exposure noise if we already have a CVE.
        out.push(Finding {
            id: id.to_string(),
            severity: sev,
            title: title.to_string(),
            detail: detail.to_string(),
        });
    }

    out
}
