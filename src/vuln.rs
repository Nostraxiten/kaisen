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
    /// Extra condition: when non-empty, the finding only fires if this text
    /// appears in what the probe reported (case-insensitively). It is how
    /// "RDP is exposed" is kept distinct from "RDP is exposed *without NLA*".
    needle: &'static str,
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
        needle: "",
        matches: |v| ver_tuple(v) < (7, 7, 0) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "vsFTPd",
        id: "CVE-2011-2523",
        severity: Severity::Critical,
        title: "vsFTPd 2.3.4 backdoor",
        detail: "vsFTPd 2.3.4 shipped a backdoor granting a root shell on :6200.",
        needle: "",
        matches: |v| ver_tuple(v) == (2, 3, 4),
    },
    Sig {
        product: "ProFTPD",
        id: "CVE-2015-3306",
        severity: Severity::Critical,
        title: "ProFTPD mod_copy RCE",
        detail: "ProFTPD 1.3.5 mod_copy allows unauthenticated file copy / RCE.",
        needle: "",
        matches: |v| ver_tuple(v) == (1, 3, 5),
    },
    Sig {
        product: "Apache",
        id: "CVE-2021-41773",
        severity: Severity::Critical,
        title: "Apache HTTP path traversal / RCE",
        detail: "Apache httpd 2.4.49 path traversal (CVE-2021-41773); 2.4.50 also affected (CVE-2021-42013).",
        needle: "",
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
        needle: "",
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
        needle: "",
        matches: |v| ver_tuple(v) < (1, 17, 7) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "Exim",
        id: "CVE-2019-15846",
        severity: Severity::Critical,
        title: "Exim TLS SNI RCE (root)",
        detail: "Exim < 4.92.2 allows remote root via a crafted TLS SNI/peer name.",
        needle: "",
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
        needle: "",
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
        needle: "",
        matches: |v| ver_tuple(v) == (1, 0, 49),
    },
    Sig {
        product: "Dovecot",
        id: "CVE-2019-11500",
        severity: Severity::High,
        title: "Dovecot IMAP/managesieve OOB write",
        detail: "Dovecot < 2.3.7.2 out-of-bounds write parsing NUL bytes in IMAP/ManageSieve.",
        needle: "",
        matches: |v| ver_tuple(v) < (2, 3, 8) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "Samba",
        id: "CVE-2017-7494",
        severity: Severity::Critical,
        title: "Samba 'SambaCry' RCE",
        detail: "Samba 3.5.0-4.6.4 allows RCE by loading a shared library from a writable share.",
        needle: "",
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
        needle: "",
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
        needle: "",
        matches: |v| ver_tuple(v) <= (8, 3, 1) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "Microsoft-IIS",
        id: "CVE-2017-7269",
        severity: Severity::High,
        title: "IIS 6.0 WebDAV buffer overflow",
        detail: "IIS 6.0 ScStoragePathFromUrl WebDAV buffer overflow (RCE).",
        needle: "",
        matches: |v| ver_tuple(v) == (6, 0, 0),
    },
    Sig {
        product: "Exim",
        id: "CVE-2019-10149",
        severity: Severity::Critical,
        title: "Exim 'Return of the Wizard' RCE",
        detail: "Exim 4.87-4.91 remote command execution via crafted recipient.",
        needle: "",
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
        needle: "unauthenticated",
        matches: |_| true,
    },
    Sig {
        product: "Memcached",
        id: "KAISEN-MEMCACHED-EXPOSED",
        severity: Severity::Medium,
        title: "Memcached reachable (UDP amp risk)",
        detail: "Exposed Memcached can be abused for data leakage and UDP amplification DDoS.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "MySQL",
        id: "KAISEN-DB-EXPOSED",
        severity: Severity::Medium,
        title: "MySQL exposed to network",
        detail: "Database service reachable remotely; ensure it is firewalled and requires strong auth.",
        needle: "",
        matches: |_| true,
    },
    // ── SSH ─────────────────────────────────────────────────────────────────
    Sig {
        product: "OpenSSH",
        id: "CVE-2024-6387",
        severity: Severity::Critical,
        title: "OpenSSH 'regreSSHion' pre-auth RCE",
        detail: "OpenSSH 8.5p1-9.7p1 (and 4.4-4.7 era code reintroduced) has a signal-handler race giving unauthenticated remote root on glibc Linux.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (8, 5, 0) && t < (9, 8, 0)
        },
    },
    Sig {
        product: "OpenSSH",
        id: "CVE-2023-38408",
        severity: Severity::High,
        title: "OpenSSH ssh-agent PKCS#11 RCE",
        detail: "OpenSSH < 9.3p2 allows code execution on a host whose forwarded agent is used by a malicious server.",
        needle: "",
        matches: |v| ver_tuple(v) < (9, 3, 2) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "OpenSSH",
        id: "CVE-2023-48795",
        severity: Severity::Medium,
        title: "SSH 'Terrapin' prefix truncation",
        detail: "OpenSSH < 9.6 is vulnerable to the Terrapin attack, which can silently downgrade the handshake when ChaCha20-Poly1305 or CBC-EtM is negotiated.",
        needle: "",
        matches: |v| ver_tuple(v) < (9, 6, 0) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "Dropbear",
        id: "CVE-2016-7409",
        severity: Severity::Medium,
        title: "Dropbear key disclosure to log",
        detail: "Dropbear < 2016.74 writes process memory (including keys) to the log in debug mode and has format-string issues.",
        needle: "",
        matches: |v| ver_tuple(v) < (2016, 74, 0) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "libssh",
        id: "CVE-2018-10933",
        severity: Severity::Critical,
        title: "libssh authentication bypass",
        detail: "libssh 0.6-0.8.3 servers accept a client-sent SSH2_MSG_USERAUTH_SUCCESS, bypassing authentication entirely.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (0, 6, 0) && t < (0, 8, 4)
        },
    },
    // ── Web servers ─────────────────────────────────────────────────────────
    Sig {
        product: "Apache",
        id: "CVE-2021-40438",
        severity: Severity::High,
        title: "Apache mod_proxy SSRF",
        detail: "Apache httpd < 2.4.49 mod_proxy allows a crafted request to be forwarded to an attacker-chosen origin (SSRF).",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (2, 4, 0) && t < (2, 4, 49)
        },
    },
    Sig {
        product: "Apache",
        id: "CVE-2023-25690",
        severity: Severity::High,
        title: "Apache mod_proxy request smuggling",
        detail: "Apache httpd 2.4.0-2.4.55 with certain RewriteRule/ProxyPassMatch patterns allows HTTP request smuggling.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (2, 4, 0) && t <= (2, 4, 55)
        },
    },
    Sig {
        product: "Apache",
        id: "CVE-2024-38475",
        severity: Severity::High,
        title: "Apache mod_rewrite substitution escape",
        detail: "Apache httpd < 2.4.60 mis-escapes mod_rewrite output, allowing filesystem paths outside the document root to be served.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (2, 4, 0) && t < (2, 4, 60)
        },
    },
    Sig {
        product: "nginx",
        id: "CVE-2021-23017",
        severity: Severity::High,
        title: "nginx resolver off-by-one",
        detail: "nginx 0.6.18-1.20.0 has an off-by-one in the DNS resolver that can lead to memory disclosure or RCE when 'resolver' is configured.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (0, 6, 18) && t <= (1, 20, 0)
        },
    },
    Sig {
        product: "lighttpd",
        id: "CVE-2018-19052",
        severity: Severity::Medium,
        title: "lighttpd mod_alias path traversal",
        detail: "lighttpd < 1.4.50 allows '..' traversal through mod_alias when an alias prefix lacks a trailing slash.",
        needle: "",
        matches: |v| ver_tuple(v) < (1, 4, 50) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "Microsoft-IIS",
        id: "CVE-2015-1635",
        severity: Severity::Critical,
        title: "IIS HTTP.sys remote code execution",
        detail: "IIS 7.5-8.5 on unpatched Windows allows RCE/DoS via a crafted Range header (MS15-034).",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (7, 5, 0) && t <= (8, 5, 0)
        },
    },
    Sig {
        product: "LiteSpeed",
        id: "CVE-2022-0072",
        severity: Severity::Medium,
        title: "OpenLiteSpeed directory traversal",
        detail: "OpenLiteSpeed < 1.7.16 allows path traversal in the admin interface.",
        needle: "",
        matches: |v| ver_tuple(v) < (1, 7, 16) && ver_tuple(v) != (0, 0, 0),
    },
    Sig {
        product: "Tomcat",
        id: "CVE-2020-1938",
        severity: Severity::Critical,
        title: "Tomcat 'Ghostcat' AJP file read / RCE",
        detail: "Tomcat before 9.0.31/8.5.51/7.0.100 exposes an AJP connector that reads arbitrary webapp files and can reach RCE when uploads are possible.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            (t >= (7, 0, 0) && t < (7, 0, 100))
                || (t >= (8, 0, 0) && t < (8, 5, 51))
                || (t >= (9, 0, 0) && t < (9, 0, 31))
        },
    },
    Sig {
        product: "Tomcat",
        id: "CVE-2025-24813",
        severity: Severity::Critical,
        title: "Tomcat partial-PUT deserialization RCE",
        detail: "Tomcat 9.0.0-9.0.98 / 10.1.0-10.1.34 / 11.0.0-11.0.2 with writable DefaultServlet allows RCE via partial PUT session deserialization.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            (t >= (9, 0, 0) && t <= (9, 0, 98))
                || (t >= (10, 1, 0) && t <= (10, 1, 34))
                || (t >= (11, 0, 0) && t <= (11, 0, 2))
        },
    },
    Sig {
        product: "Jetty",
        id: "CVE-2021-28169",
        severity: Severity::Medium,
        title: "Jetty ConcatServlet WEB-INF disclosure",
        detail: "Eclipse Jetty <= 9.4.40 / 10.0.2 can be made to serve protected WEB-INF resources through double-encoded requests.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            (t >= (9, 0, 0) && t <= (9, 4, 40)) || (t >= (10, 0, 0) && t <= (10, 0, 2))
        },
    },
    // ── Application platforms ───────────────────────────────────────────────
    Sig {
        product: "Jenkins",
        id: "CVE-2024-23897",
        severity: Severity::Critical,
        title: "Jenkins CLI arbitrary file read",
        detail: "Jenkins <= 2.441 (LTS <= 2.426.2) exposes a CLI argument expansion that reads arbitrary files, commonly escalating to full RCE.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t <= (2, 441, 0)
        },
    },
    Sig {
        product: "GitLab",
        id: "CVE-2023-7028",
        severity: Severity::Critical,
        title: "GitLab account takeover via password reset",
        detail: "GitLab 16.1-16.7.1 sends password reset mail to an unverified secondary address, allowing account takeover.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (16, 1, 0) && t < (16, 7, 2)
        },
    },
    Sig {
        product: "Grafana",
        id: "CVE-2021-43798",
        severity: Severity::High,
        title: "Grafana plugin path traversal",
        detail: "Grafana 8.0.0-8.3.0 allows unauthenticated arbitrary file read via /public/plugins/<id>/../..",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (8, 0, 0) && t < (8, 3, 1)
        },
    },
    Sig {
        product: "Confluence",
        id: "CVE-2023-22515",
        severity: Severity::Critical,
        title: "Confluence broken access control",
        detail: "Confluence Data Center/Server 8.0.0-8.5.1 lets a remote attacker create an administrator account.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t >= (8, 0, 0) && t <= (8, 5, 1)
        },
    },
    Sig {
        product: "Elasticsearch",
        id: "CVE-2015-1427",
        severity: Severity::Critical,
        title: "Elasticsearch Groovy sandbox RCE",
        detail: "Elasticsearch 1.3.0-1.3.7 / 1.4.0-1.4.2 allows RCE by escaping the Groovy scripting sandbox.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            (t >= (1, 3, 0) && t <= (1, 3, 7)) || (t >= (1, 4, 0) && t <= (1, 4, 2))
        },
    },
    Sig {
        product: "Elasticsearch",
        id: "KAISEN-ES-OPEN",
        severity: Severity::High,
        title: "Elasticsearch answered without credentials",
        detail: "The cluster returned its version banner to an anonymous request; if the indices are equally open, all indexed data is readable.",
        needle: "unauthenticated",
        matches: |_| true,
    },
    Sig {
        product: "Docker Engine",
        id: "KAISEN-DOCKER-API",
        severity: Severity::Critical,
        title: "Docker Engine API unauthenticated",
        detail: "The Docker daemon answered /version without credentials. Anyone who can reach it can start a privileged container and own the host.",
        needle: "unauthenticated",
        matches: |_| true,
    },
    Sig {
        product: "Kibana",
        id: "CVE-2019-7609",
        severity: Severity::Critical,
        title: "Kibana Timelion prototype-pollution RCE",
        detail: "Kibana < 5.6.15 / 6.6.1 allows RCE through the Timelion visualisation.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && (t < (5, 6, 15) || (t >= (6, 0, 0) && t < (6, 6, 1)))
        },
    },
    Sig {
        product: "Spring Boot",
        id: "KAISEN-ACTUATOR",
        severity: Severity::Medium,
        title: "Spring Boot application exposed",
        detail: "Check /actuator, /env and /heapdump: unsecured actuator endpoints leak credentials and can reach RCE.",
        needle: "",
        matches: |_| true,
    },
    // ── Databases, caches and brokers ───────────────────────────────────────
    Sig {
        product: "MongoDB",
        id: "KAISEN-MONGO-NOAUTH",
        severity: Severity::Critical,
        title: "MongoDB answered buildInfo without credentials",
        detail: "An unauthenticated MongoDB is readable and writable by anyone who can reach the port; this class of exposure has been mass-ransomed repeatedly.",
        needle: "unauthenticated buildinfo",
        matches: |_| true,
    },
    Sig {
        product: "Microsoft SQL Server",
        id: "KAISEN-MSSQL-VERSION",
        severity: Severity::Low,
        title: "SQL Server version disclosed pre-auth",
        detail: "The TDS pre-login response reveals the exact build, letting an attacker pick a matching exploit before authenticating.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Microsoft SQL Server",
        id: "KAISEN-MSSQL-EOL",
        severity: Severity::High,
        title: "End-of-life SQL Server",
        detail: "SQL Server 2012 and older receive no security updates; the build reported here is out of extended support.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (12, 0, 0)
        },
    },
    Sig {
        product: "MariaDB",
        id: "KAISEN-DB-EXPOSED",
        severity: Severity::Medium,
        title: "MariaDB exposed to network",
        detail: "Database service reachable remotely; ensure it is firewalled and requires strong auth.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "MySQL",
        id: "KAISEN-MYSQL-EOL",
        severity: Severity::Medium,
        title: "End-of-life MySQL branch",
        detail: "MySQL 5.6 and earlier are past end of life and receive no security fixes.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (5, 7, 0)
        },
    },
    Sig {
        product: "Oracle TNS",
        id: "KAISEN-TNS-VERSION",
        severity: Severity::Low,
        title: "Oracle listener discloses version",
        detail: "The TNS listener returned VSNNUM in its refusal; older listeners also allow remote registration (TNS poisoning, CVE-2012-1675).",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Oracle TNS",
        id: "CVE-2012-1675",
        severity: Severity::High,
        title: "Oracle TNS Listener poisoning",
        detail: "Listeners from 11.2.0.3 and earlier allow a remote attacker to register a rogue database instance and intercept sessions.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t <= (11, 2, 3)
        },
    },
    Sig {
        product: "MQTT",
        id: "KAISEN-MQTT-ANON",
        severity: Severity::High,
        title: "MQTT broker accepts anonymous clients",
        detail: "The broker returned CONNACK 0x00 with no credentials, so anyone can subscribe to (and publish on) every topic.",
        needle: "accepted",
        matches: |_| true,
    },
    Sig {
        product: "Apache ZooKeeper",
        id: "KAISEN-ZK-4LW",
        severity: Severity::Medium,
        title: "ZooKeeper four-letter-word commands enabled",
        detail: "srvr/stat/conf leak cluster topology and configuration to anyone who can reach the port.",
        needle: "built on",
        matches: |_| true,
    },
    // ── Remote access, file sharing and infrastructure ──────────────────────
    Sig {
        product: "SMB",
        id: "KAISEN-SMB1",
        severity: Severity::High,
        title: "SMBv1 dialect still offered",
        detail: "SMB1 is unauthenticated-attack surface (EternalBlue/WannaCry class) and should be disabled everywhere.",
        needle: "",
        matches: |v| ver_tuple(v) == (1, 0, 0),
    },
    Sig {
        product: "SMB",
        id: "KAISEN-SMB-LEGACY",
        severity: Severity::Medium,
        title: "Legacy SMB2 dialect negotiated",
        detail: "A 2.0.2/2.1 dialect implies Windows 7/2008-era code or a Samba configured for it, and rules out SMB3 encryption.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t == (2, 0, 2) || t == (2, 1, 0)
        },
    },
    Sig {
        product: "Microsoft Terminal Services",
        id: "KAISEN-RDP-NLA",
        severity: Severity::High,
        title: "RDP without Network Level Authentication",
        detail: "The server accepted standard RDP security, exposing the pre-auth code path (BlueKeep, CVE-2019-0708, class of bug).",
        needle: "no nla",
        matches: |_| true,
    },
    Sig {
        product: "X11",
        id: "KAISEN-X11-OPEN",
        severity: Severity::High,
        title: "X11 display reachable",
        detail: "If access control is off, anyone on the network can read the screen, inject keystrokes and capture input.",
        needle: "access granted",
        matches: |_| true,
    },
    Sig {
        product: "SOCKS proxy",
        id: "KAISEN-OPEN-PROXY",
        severity: Severity::High,
        title: "Open SOCKS proxy",
        detail: "The proxy offered 'no authentication required', so anyone can relay traffic through this host.",
        needle: "no authentication required",
        matches: |_| true,
    },
    Sig {
        product: "Microsoft Active Directory LDAP",
        id: "KAISEN-AD-ANON",
        severity: Severity::Medium,
        title: "Active Directory rootDSE readable anonymously",
        detail: "Anonymous LDAP reveals domain and forest naming contexts and the DC's hostname — the starting point for domain enumeration.",
        needle: "",
        matches: |_| true,
    },
    // ── Mail ────────────────────────────────────────────────────────────────
    Sig {
        product: "Exim",
        id: "CVE-2023-42115",
        severity: Severity::Critical,
        title: "Exim SMTP AUTH out-of-bounds write",
        detail: "Exim < 4.96.1 has an out-of-bounds write in the external authenticator, allowing unauthenticated RCE.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (4, 96, 1)
        },
    },
    Sig {
        product: "Exim",
        id: "CVE-2020-28017",
        severity: Severity::High,
        title: "Exim '21Nails' vulnerability set",
        detail: "Exim < 4.94.2 is affected by the 21Nails cluster of bugs, several of which give remote root.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (4, 94, 2)
        },
    },
    Sig {
        product: "Dovecot",
        id: "CVE-2024-23185",
        severity: Severity::Medium,
        title: "Dovecot oversized header DoS",
        detail: "Dovecot < 2.3.21.1 can be driven into excessive memory use by very large message headers.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (2, 3, 21)
        },
    },
    Sig {
        product: "Sendmail",
        id: "CVE-2014-3956",
        severity: Severity::Medium,
        title: "Sendmail file-descriptor leak",
        detail: "Sendmail < 8.14.9 leaks open file descriptors to child processes, which local mail programs can abuse.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (8, 14, 9)
        },
    },
    Sig {
        product: "Postfix",
        id: "CVE-2023-51764",
        severity: Severity::Medium,
        title: "Postfix SMTP smuggling",
        detail: "Postfix before the 2023-12 fixes accepts non-standard line endings, enabling SMTP smuggling and spoofed inbound mail.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (3, 8, 5)
        },
    },
    // ── DNS ─────────────────────────────────────────────────────────────────
    Sig {
        product: "BIND",
        id: "CVE-2023-2828",
        severity: Severity::High,
        title: "BIND cache-cleaning memory exhaustion",
        detail: "BIND 9.11.0-9.16.41 / 9.18.0-9.18.15 can be driven out of memory by a stream of queries, taking the resolver down.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            (t >= (9, 11, 0) && t <= (9, 16, 41)) || (t >= (9, 18, 0) && t <= (9, 18, 15))
        },
    },
    Sig {
        product: "BIND",
        id: "KAISEN-DNS-VERSION",
        severity: Severity::Low,
        title: "DNS server discloses version.bind",
        detail: "The CHAOS TXT record hands attackers the exact build; hide it with 'version none;' unless you need it.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "dnsmasq",
        id: "CVE-2020-25681",
        severity: Severity::High,
        title: "dnsmasq 'DNSpooq' vulnerabilities",
        detail: "dnsmasq < 2.83 is affected by DNSpooq: cache poisoning plus heap overflows reachable from the network.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (2, 83, 0)
        },
    },
    // ── TLS ─────────────────────────────────────────────────────────────────
    Sig {
        product: "TLS",
        id: "KAISEN-TLS-OBSOLETE",
        severity: Severity::Medium,
        title: "Obsolete TLS/SSL version negotiated",
        detail: "SSL 3.0, TLS 1.0 and TLS 1.1 are deprecated (POODLE/BEAST class) and rejected by current clients and compliance regimes.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (1, 2, 0)
        },
    },
    Sig {
        product: "Minecraft",
        id: "KAISEN-MC-LOG4SHELL",
        severity: Severity::High,
        title: "Minecraft server — check for Log4Shell",
        detail: "Java Minecraft servers on 1.7-1.18.0 shipped a vulnerable log4j (CVE-2021-44228); chat input reaches the logger.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (1, 18, 1)
        },
    },
];

/// Match a detected service against the signature DB plus a few port-level
/// exposure heuristics.
pub fn assess(port: u16, svc: &ServiceInfo) -> Vec<Finding> {
    let mut out = Vec::new();

    // Everything a probe reported about this service, for the `needle` checks.
    let reported = format!("{} {} {}", svc.extra, svc.banner, svc.version).to_ascii_lowercase();

    if !svc.product.is_empty() {
        for s in SIGS {
            if svc
                .product
                .to_ascii_lowercase()
                .contains(&s.product.to_ascii_lowercase())
                && (s.needle.is_empty() || reported.contains(&s.needle.to_ascii_lowercase()))
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

    // Certificate hygiene, which the TLS prober establishes independently of
    // any product signature.
    if svc.cert_expired {
        out.push(Finding {
            id: "KAISEN-TLS-EXPIRED".into(),
            severity: Severity::Medium,
            title: "TLS certificate has expired".into(),
            detail: "Clients will refuse or warn on this connection, and users trained to click through it are easy phishing targets.".into(),
        });
    }
    if svc.self_signed {
        out.push(Finding {
            id: "KAISEN-TLS-SELFSIGNED".into(),
            severity: Severity::Low,
            title: "TLS certificate is self-signed".into(),
            detail: "Nothing authenticates this endpoint, so the connection cannot be distinguished from a machine-in-the-middle.".into(),
        });
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
        2049 => Some(("KAISEN-NFS", Severity::Medium, "NFS exposed", "Exposed NFS may allow reading/writing shares; check exports and auth.")),
        2375 => Some(("KAISEN-DOCKER", Severity::Critical, "Docker API exposed", "Unauthenticated Docker API on 2375 = trivial host takeover (spawn privileged containers).")),
        11211 => Some(("KAISEN-MEMCACHED-PORT", Severity::Medium, "Memcached port exposed", "Exposed Memcached enables data leakage and UDP amplification DDoS.")),
        // ── container and cluster control planes ────────────────────────────
        2376 => Some(("KAISEN-DOCKER-TLS", Severity::High, "Docker API (TLS) exposed", "Even with TLS, the Docker API is host-level control; restrict it to a management network.")),
        2377 => Some(("KAISEN-SWARM", Severity::High, "Docker Swarm manager exposed", "The swarm control port lets a node join the cluster; it should never face untrusted networks.")),
        2379 | 2380 => Some(("KAISEN-ETCD", Severity::Critical, "etcd exposed", "etcd holds all Kubernetes state including Secrets; unauthenticated access is full cluster compromise.")),
        6443 | 8443 => Some(("KAISEN-KUBE-API", Severity::Medium, "Kubernetes API server reachable", "Verify anonymous-auth is off and RBAC is enforced; the API server should not be internet-facing.")),
        10250 => Some(("KAISEN-KUBELET", Severity::Critical, "Kubelet API exposed", "An unauthenticated kubelet allows /exec and /run on every pod, i.e. node takeover.")),
        10255 => Some(("KAISEN-KUBELET-RO", Severity::High, "Kubelet read-only port exposed", "Port 10255 serves pod specs and environment variables with no authentication at all.")),
        4243 => Some(("KAISEN-DOCKER-ALT", Severity::Critical, "Docker API on alternate port", "Unauthenticated Docker API = trivial host takeover via a privileged container.")),
        44134 => Some(("KAISEN-TILLER", Severity::Critical, "Helm Tiller exposed", "Tiller runs with cluster-admin and has no authentication; reaching it means owning the cluster.")),
        // ── data stores and search ──────────────────────────────────────────
        5984 => Some(("KAISEN-COUCHDB", Severity::High, "CouchDB exposed", "Unauthenticated CouchDB exposes all databases and has a history of admin-party misconfiguration.")),
        7473 | 7474 | 7687 => Some(("KAISEN-NEO4J", Severity::Medium, "Neo4j exposed", "Default credentials (neo4j/neo4j) and open Bolt access are a common data-loss path.")),
        8086 => Some(("KAISEN-INFLUX", Severity::Medium, "InfluxDB exposed", "InfluxDB 1.x ships without authentication by default; metrics often include hostnames and tokens.")),
        9042 | 9160 => Some(("KAISEN-CASSANDRA", Severity::Medium, "Cassandra exposed", "The default AllowAllAuthenticator accepts any login; restrict the native transport port.")),
        8529 => Some(("KAISEN-ARANGO", Severity::Medium, "ArangoDB exposed", "Check that authentication is enabled; older images defaulted to no root password.")),
        26257 => Some(("KAISEN-COCKROACH", Severity::Medium, "CockroachDB exposed", "Verify the cluster runs in secure mode; insecure mode accepts any client.")),
        4200 | 8123 | 9009 => Some(("KAISEN-CLICKHOUSE", Severity::Medium, "ClickHouse exposed", "The default 'default' user historically had no password and full read access.")),
        6432 => Some(("KAISEN-PGBOUNCER", Severity::Medium, "PgBouncer exposed", "The pooler fronts your database and may hold plaintext credentials in its auth file.")),
        11210 | 8091 => Some(("KAISEN-COUCHBASE", Severity::Medium, "Couchbase exposed", "The management and data ports should be restricted to the cluster network.")),
        6379 | 6380 | 16379 => Some(("KAISEN-REDIS-PORT", Severity::High, "Redis port exposed", "If unauthenticated, Redis allows data theft and RCE via config/module abuse.")),
        // ── brokers, queues and coordination ────────────────────────────────
        2181 => Some(("KAISEN-ZOOKEEPER", Severity::Medium, "ZooKeeper exposed", "ZooKeeper rarely has authentication enabled and holds cluster configuration.")),
        4369 => Some(("KAISEN-EPMD-PORT", Severity::High, "Erlang port mapper exposed", "EPMD plus a weak Erlang cookie yields remote code execution on the node.")),
        5672 | 5671 => Some(("KAISEN-AMQP", Severity::Medium, "AMQP broker exposed", "Check for the default guest/guest account and restrict the port to application hosts.")),
        9092 | 9093 | 9094 => Some(("KAISEN-KAFKA", Severity::Medium, "Kafka broker exposed", "Without SASL and ACLs, any client can read and write every topic.")),
        1883 | 8883 => Some(("KAISEN-MQTT", Severity::Medium, "MQTT broker exposed", "Anonymous MQTT brokers leak sensor and control traffic, and often accept commands.")),
        61616 | 61613 => Some(("KAISEN-ACTIVEMQ", Severity::Medium, "ActiveMQ exposed", "OpenWire and STOMP have had unauthenticated deserialisation RCEs (e.g. CVE-2023-46604).")),
        // ── remote access and management planes ─────────────────────────────
        5985 | 5986 => Some(("KAISEN-WINRM", Severity::Medium, "WinRM exposed", "WinRM is remote PowerShell; exposed to a network it is a direct lateral-movement path.")),
        623 => Some(("KAISEN-IPMI", Severity::High, "IPMI/BMC exposed", "IPMI 2.0 leaks password hashes pre-auth (cipher-zero and RAKP flaws) and controls the host below the OS.")),
        16992 | 16993 => Some(("KAISEN-AMT", Severity::High, "Intel AMT exposed", "AMT sits beneath the OS and has had a complete authentication bypass (CVE-2017-5689).")),
        4899 => Some(("KAISEN-RADMIN", Severity::Medium, "Radmin exposed", "Remote-control software reachable from the network; verify it is not using default credentials.")),
        5938 | 6568 => Some(("KAISEN-REMOTE-DESK", Severity::Low, "Remote-desktop agent detected", "TeamViewer/AnyDesk agents are common initial-access targets; confirm the install is intentional.")),
        3283 => Some(("KAISEN-ARD", Severity::Medium, "Apple Remote Desktop exposed", "ARD grants screen control; it has previously been abused for UDP amplification too.")),
        512 | 513 | 514 => Some(("KAISEN-RSERVICES", Severity::High, "Berkeley r-services exposed", "rexec/rlogin/rsh trust host-based authentication and send credentials in cleartext.")),
        79 => Some(("KAISEN-FINGER", Severity::Low, "finger service exposed", "finger enumerates local user accounts for anyone who asks.")),
        69 => Some(("KAISEN-TFTP", Severity::Medium, "TFTP exposed", "TFTP has no authentication and frequently serves device configurations containing credentials.")),
        111 => Some(("KAISEN-RPCBIND", Severity::Medium, "rpcbind exposed", "The portmapper enumerates RPC services (NFS, NIS) and is usable for DDoS amplification.")),
        873 => Some(("KAISEN-RSYNC-PORT", Severity::Medium, "rsync daemon exposed", "Anonymous rsync modules often expose entire filesystems read-write.")),
        6000..=6009 => Some(("KAISEN-X11-PORT", Severity::High, "X11 exposed", "An X display with access control disabled allows keylogging and screen capture.")),
        // ── application servers with a heavy CVE history ────────────────────
        1099 | 1098 => Some(("KAISEN-RMI", Severity::High, "Java RMI registry exposed", "RMI registries are a classic Java deserialisation RCE target.")),
        8686 | 9010 | 9999 => Some(("KAISEN-JMX", Severity::High, "JMX/RMI management port exposed", "Unauthenticated JMX allows MBean loading and therefore remote code execution.")),
        4848 => Some(("KAISEN-GLASSFISH", Severity::Medium, "GlassFish admin console exposed", "The admin console has had authentication bypass and traversal issues; restrict it.")),
        9990 => Some(("KAISEN-WILDFLY", Severity::Medium, "WildFly/JBoss management exposed", "The management interface allows deployment of arbitrary applications.")),
        8140 => Some(("KAISEN-PUPPET", Severity::Medium, "Puppet master exposed", "The catalog service defines configuration for every managed node.")),
        4505 | 4506 => Some(("KAISEN-SALT", Severity::Critical, "SaltStack master exposed", "Salt's ZeroMQ ports have had unauthenticated RCE (CVE-2020-11651/11652) used at scale.")),
        11371 => Some(("KAISEN-HKP", Severity::Low, "OpenPGP key server exposed", "Key servers are usually intentional; confirm this one is.")),
        // ── industrial and building control ─────────────────────────────────
        502 => Some(("KAISEN-MODBUS", Severity::Critical, "Modbus/TCP exposed", "Modbus has no authentication whatsoever: anyone who can reach it can read and write process values.")),
        20000 => Some(("KAISEN-DNP3", Severity::Critical, "DNP3 exposed", "A SCADA protocol with no authentication in its base form; it must never be internet-facing.")),
        44818 => Some(("KAISEN-ENIP", Severity::Critical, "EtherNet/IP/CIP exposed", "CIP allows PLC configuration and firmware operations without authentication.")),
        47808 => Some(("KAISEN-BACNET", Severity::High, "BACnet exposed", "Building automation with no authentication; reachable devices can be commanded directly.")),
        102 => Some(("KAISEN-S7", Severity::Critical, "Siemens S7comm exposed", "S7 PLC communications are unauthenticated in most configurations.")),
        1911 | 4911 => Some(("KAISEN-FOX", Severity::High, "Niagara Fox exposed", "Tridium Niagara building controllers have had credential disclosure and default-account issues.")),
        // ── device management planes ────────────────────────────────────────
        7547 => Some(("KAISEN-CWMP", Severity::High, "TR-069 CWMP exposed", "The ISP provisioning interface has been used for mass router compromise (Mirai/Annie).")),
        8291 => Some(("KAISEN-WINBOX", Severity::High, "MikroTik Winbox exposed", "Winbox has had an unauthenticated file-read leading to credential disclosure (CVE-2018-14847).")),
        37777 | 34567 => Some(("KAISEN-DVR", Severity::High, "DVR/NVR control port exposed", "Dahua/XiongMai-style DVRs have long-standing unauthenticated access and hardcoded credentials.")),
        554 | 8554 => Some(("KAISEN-RTSP", Severity::Medium, "RTSP stream exposed", "Cameras frequently allow anonymous stream access on well-known paths.")),
        9100 => Some(("KAISEN-JETDIRECT", Severity::Medium, "Raw printing port exposed", "Port 9100 accepts raw PostScript/PJL, which allows printing, filesystem access and firmware tampering.")),
        631 => Some(("KAISEN-IPP", Severity::Low, "IPP/CUPS exposed", "The print service enumerates queues and, in some versions, allows remote job and driver manipulation.")),
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
