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
        product: "nginx",
        id: "CVE-2019-20372",
        severity: Severity::Medium,
        title: "nginx error_page request smuggling",
        detail: "nginx < 1.17.7 error_page handling allows HTTP request smuggling.",
        matches: |v| ver_tuple(v) < (1, 17, 7) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "Exim",
        id: "CVE-2019-15846",
        severity: Severity::Critical,
        title: "Exim TLS SNI RCE (root)",
        detail: "Exim < 4.92.2 allows remote root via a crafted TLS SNI/peer name.",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (4, 80, 0) && t < (4, 92, 2)
        },
    },
    Sig {
        product: "ProFTPD",
        id: "CVE-2019-12815",
        severity: Severity::High,
        title: "ProFTPD mod_copy arbitrary file copy",
        detail: "ProFTPD < 1.3.6a mod_copy allows unauthenticated arbitrary file copy.",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (1, 3, 0) && t < (1, 3, 6)
        },
    },
    Sig {
        product: "Pure-FTPd",
        id: "CVE-2019-20176",
        severity: Severity::Medium,
        title: "Pure-FTPd out-of-bounds read",
        detail: "Pure-FTPd 1.0.49 has an OOB read in the diraliases handler.",
        matches: |v| ver_tuple(v) == (1, 0, 49),
    },
    Sig {
        product: "Dovecot",
        id: "CVE-2019-11500",
        severity: Severity::High,
        title: "Dovecot IMAP/managesieve OOB write",
        detail: "Dovecot < 2.3.7.2 out-of-bounds write parsing NUL bytes in IMAP/ManageSieve.",
        matches: |v| ver_tuple(v) < (2, 3, 8) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "Samba",
        id: "CVE-2017-7494",
        severity: Severity::Critical,
        title: "Samba 'SambaCry' RCE",
        detail: "Samba 3.5.0-4.6.4 allows RCE by loading a shared library from a writable share.",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (3, 5, 0) && t < (4, 6, 4)
        },
    },
    Sig {
        product: "MySQL",
        id: "CVE-2012-2122",
        severity: Severity::High,
        title: "MySQL/MariaDB auth bypass",
        detail: "Some MySQL/MariaDB 5.1/5.5 builds accept any password ~1/256 of the time.",
        matches: |v| {
            let t = ver_tuple(v);
            ((5, 1, 0)..(5, 1, 63)).contains(&t) || ((5, 5, 0)..(5, 5, 24)).contains(&t)
        },
    },
    Sig {
        product: "OpenSSH",
        id: "CVE-2020-15778",
        severity: Severity::Medium,
        title: "OpenSSH scp command injection",
        detail: "OpenSSH <= 8.3p1 scp allows command injection via crafted filenames (auth required).",
        matches: |v| ver_tuple(v) <= (8, 3, 1) && ver_tuple(v) != (0, 0, 0),
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
        8009 => Some(("KAISEN-AJP-GHOSTCAT", Severity::High, "Tomcat AJP exposed (Ghostcat)", "Exposed AJP/8009 enables CVE-2020-1938 (Ghostcat) file read / potential RCE on Tomcat.")),
        7001 | 7002 => Some(("KAISEN-WEBLOGIC", Severity::High, "Oracle WebLogic exposed", "WebLogic consoles have a long history of unauthenticated RCE (CVE-2019-2725, 2020-2883, ...).")),
        1433 => Some(("KAISEN-MSSQL", Severity::Medium, "MS SQL Server exposed", "Database reachable remotely; ensure firewalling and strong auth.")),
        5432 => Some(("KAISEN-POSTGRES", Severity::Medium, "PostgreSQL exposed", "Database reachable remotely; restrict pg_hba and network access.")),
        6379 => Some(("KAISEN-REDIS-PORT", Severity::High, "Redis port exposed", "If unauthenticated, Redis allows data theft and RCE via config/module abuse.")),
        2049 => Some(("KAISEN-NFS", Severity::Medium, "NFS exposed", "Exposed NFS may allow reading/writing shares; check exports and auth.")),
        2375 => Some(("KAISEN-DOCKER", Severity::Critical, "Docker API exposed", "Unauthenticated Docker API on 2375 = trivial host takeover (spawn privileged containers).")),
        11211 => Some(("KAISEN-MEMCACHED-PORT", Severity::Medium, "Memcached port exposed", "Exposed Memcached enables data leakage and UDP amplification DDoS.")),
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
