//! Matching heurístico de firmas de vulnerabilidades.
//!
//! Esto es deliberadamente *heurístico*: compara los banners de servicio/producto/versión
//! detectados contra una tabla de firmas curada e incrustada de problemas conocidos.
//! No es un escáner de vulnerabilidades completo y no realiza explotación;
//! marca versiones probablemente vulnerables para que sepas dónde mirar más profundo.

pub mod cve;

use crate::service::ServiceInfo;
use crate::util::output::Painter;

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String, // CVE or identifier
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

    /// Ordering for `--min-severity`: higher is worse. The enum is written
    /// worst-first for readability, so this spells the comparison out rather
    /// than leaning on a derived `Ord` that would run the other way.
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
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
            ((2, 4, 0)..(2, 4, 60)).contains(&t)
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
        detail: "Jenkins < 2.442 (LTS < 2.426.3) expands '@' in CLI arguments into file contents, letting an unauthenticated attacker read files — including the secret key material that leads to RCE.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (2, 442, 0)
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
            ((16, 1, 0)..(16, 7, 2)).contains(&t)
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
            ((8, 0, 0)..(8, 3, 1)).contains(&t)
        },
    },
    Sig {
        product: "Confluence",
        id: "CVE-2023-22515",
        severity: Severity::Critical,
        title: "Confluence broken access control (admin creation)",
        detail: "Confluence Data Center/Server 8.0.0-8.5.1 lets an unauthenticated attacker create an administrator account. Exploited in the wild within days; assume compromise on an exposed unpatched instance.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            ((8, 0, 0)..=(8, 5, 1)).contains(&t)
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

    // ════════════════════════════════════════════════════════════════════════
    // Edge and VPN appliances.
    //
    // This is the class that gets mass-exploited within days of a disclosure,
    // and it is also the class that tells you least about itself: a hardened
    // FortiOS or Ivanti box publishes no version at all on an unauthenticated
    // request. So most of these are *exposure* findings — "this is here, and
    // its family has a history of pre-auth RCE; go and check the build" —
    // rather than claims about the instance in front of you. Severity is set
    // accordingly: something to verify, not something already proven.
    // ════════════════════════════════════════════════════════════════════════
    Sig {
        product: "Citrix NetScaler",
        id: "CVE-2023-4966",
        severity: Severity::High,
        title: "Citrix NetScaler ADC/Gateway exposed (CitrixBleed class)",
        detail: "CitrixBleed leaks session tokens from memory pre-auth, and the stolen session survives a password reset — patching alone is not enough, sessions must be terminated. Confirm the build is past 13.1-49.15 / 14.1-8.50 and that this gateway should face the internet at all.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Citrix Gateway",
        id: "CVE-2019-19781",
        severity: Severity::High,
        title: "Citrix Gateway exposed (Shitrix class)",
        detail: "Citrix ADC/Gateway has repeated unauthenticated directory-traversal-to-RCE history (CVE-2019-19781, CVE-2023-3519). Verify the firmware and check for webshells under /netscaler/portal/templates.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Ivanti Connect Secure",
        id: "CVE-2024-21887",
        severity: Severity::High,
        title: "Ivanti Connect Secure exposed (auth bypass + command injection chain)",
        detail: "CVE-2023-46805 chained with CVE-2024-21887 gives unauthenticated RCE, and was exploited at scale before a patch existed. Verify the build, and treat an unpatched-window box as compromised until the integrity checker says otherwise.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Pulse Secure",
        id: "CVE-2019-11510",
        severity: Severity::High,
        title: "Pulse Secure VPN exposed (pre-auth arbitrary file read)",
        detail: "CVE-2019-11510 reads arbitrary files including plaintext credentials, and is still found unpatched years later. Pulse Secure is also end-of-life branding: this appliance may no longer receive fixes at all.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Fortinet FortiOS",
        id: "CVE-2022-42475",
        severity: Severity::High,
        title: "FortiOS SSL-VPN exposed (pre-auth heap overflow class)",
        detail: "FortiOS SSL-VPN has repeated unauthenticated RCE history (CVE-2022-42475, CVE-2023-27997) plus the CVE-2018-13379 path traversal whose leaked credential lists are still circulating. Verify the build and rotate any credential that predates patching.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Fortinet FortiGate",
        id: "KAISEN-FORTIGATE-EXPOSED",
        severity: Severity::Medium,
        title: "FortiGate management or VPN interface reachable",
        detail: "A FortiGate answering here means its web interface faces this network. Fortinet's own guidance is to keep administrative access off untrusted interfaces; SSL-VPN portals in particular have a long pre-auth RCE record.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Fortinet FortiWeb",
        id: "CVE-2021-22123",
        severity: Severity::Medium,
        title: "FortiWeb management interface reachable",
        detail: "FortiWeb's management interface has had authenticated and unauthenticated command injection (CVE-2021-22123, CVE-2021-22122). It should not be reachable from a user network.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Fortinet FortiMail",
        id: "KAISEN-FORTIMAIL-EXPOSED",
        severity: Severity::Low,
        title: "FortiMail interface reachable",
        detail: "Expected for a mail gateway's MTA, but the administrative interface should be restricted; verify which of the two answered here.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Palo Alto GlobalProtect",
        id: "CVE-2024-3400",
        severity: Severity::High,
        title: "PAN-OS GlobalProtect portal exposed",
        detail: "CVE-2024-3400 is an unauthenticated command injection in the GlobalProtect portal, exploited in the wild before disclosure. Verify the PAN-OS build and check device telemetry for the known indicators.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Palo Alto PAN-OS",
        id: "KAISEN-PANOS-MGMT",
        severity: Severity::High,
        title: "PAN-OS management interface reachable",
        detail: "Palo Alto's own hardening guidance is that the management interface must never be internet-facing; CVE-2024-0012 is an authentication bypass that turns exposure directly into administrative access.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "SonicWall",
        id: "CVE-2021-20016",
        severity: Severity::High,
        title: "SonicWall SMA/SSL-VPN exposed",
        detail: "SonicWall SMA 100 series has unauthenticated SQL injection (CVE-2021-20016) and later unauthenticated RCE (CVE-2023-44221, CVE-2024-38475) history, and has been a repeated ransomware entry point.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Check Point",
        id: "CVE-2024-24919",
        severity: Severity::High,
        title: "Check Point Security Gateway remote-access portal exposed",
        detail: "CVE-2024-24919 lets an unauthenticated attacker read arbitrary files, including password hashes and SSH keys, from a gateway with remote access or mobile access enabled. Exploited in the wild.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Sophos",
        id: "CVE-2022-1040",
        severity: Severity::Medium,
        title: "Sophos Firewall interface reachable",
        detail: "The Sophos Firewall user portal and webadmin have had an authentication bypass leading to RCE (CVE-2022-1040) and a SQL injection (CVE-2020-12271) used to steal credentials. Restrict both to a management network.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "F5 BIG-IP",
        id: "CVE-2022-1388",
        severity: Severity::High,
        title: "F5 BIG-IP management interface exposed",
        detail: "The iControl REST interface has had complete authentication bypass to root RCE (CVE-2022-1388) and request smuggling to RCE (CVE-2023-46747). F5's guidance is that the management port must not be internet-facing.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "MikroTik RouterOS",
        id: "CVE-2018-14847",
        severity: Severity::High,
        title: "MikroTik RouterOS management exposed",
        detail: "RouterOS before 6.42.1 allows unauthenticated credential disclosure through Winbox (CVE-2018-14847), the flaw behind the VPNFilter and Meris botnets. Verify the version and keep management off untrusted interfaces.",
        needle: "",
        matches: |v| ver_tuple(v) == (0, 0, 0) || ver_tuple(v) < (6, 42, 1),
    },
    Sig {
        product: "SonicWall",
        id: "CVE-2024-40766",
        severity: Severity::High,
        title: "SonicWall SonicOS access-control flaw (exposed management)",
        detail: "CVE-2024-40766 is an improper access-control bug in SonicOS reachable on the management and SSL-VPN interfaces, tied to Akira ransomware intrusions. This id sits alongside the SMA/SSL-VPN history; verify the firmware and keep management off untrusted networks.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "WatchGuard",
        id: "CVE-2022-26318",
        severity: Severity::High,
        title: "WatchGuard Firebox/XTM exposed (pre-auth RCE class)",
        detail: "CVE-2022-26318 is an unauthenticated buffer overflow in the Firebox/XTM management interface, and CVE-2022-31749 followed with command injection. The Cyclops Blink botnet was built on this family; keep the management interface off the internet.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Zyxel",
        id: "CVE-2022-30525",
        severity: Severity::High,
        title: "Zyxel firewall/VPN exposed (unauthenticated command injection)",
        detail: "Zyxel USG/ATP/VPN and NAS lines have repeated unauthenticated command injection (CVE-2022-30525, CVE-2023-28771) and a hardcoded admin credential (CVE-2020-29583). Verify the firmware and confirm the web interface should be reachable here.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Huawei device",
        id: "KAISEN-HUAWEI-EXPOSED",
        severity: Severity::Low,
        title: "Huawei networking device management reachable",
        detail: "Huawei home routers and enterprise gear have a long record of default credentials and firmware command injection (the Mirai-derived variants targeted CVE-2017-17215 on UPnP). Confirm the management surface should face this network.",
        needle: "",
        matches: |_| true,
    },

    // ════════════════════════════════════════════════════════════════════════
    // Collaboration, CI/CD and web applications. These mostly *do* publish a
    // version, so most of these are real version predicates.
    // ════════════════════════════════════════════════════════════════════════
    Sig {
        product: "Atlassian Confluence",
        id: "CVE-2023-22518",
        severity: Severity::Critical,
        title: "Confluence improper authorisation (full data loss / RCE)",
        detail: "All Confluence Data Center/Server versions before 7.19.16 / 8.5.4 allow an unauthenticated attacker to reset the instance and create an administrator. Used by ransomware operators.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (7, 19, 16)
        },
    },
    Sig {
        product: "Atlassian Confluence",
        id: "CVE-2022-26134",
        severity: Severity::Critical,
        title: "Confluence OGNL injection (pre-auth RCE)",
        detail: "Confluence < 7.4.17 evaluates OGNL from the URL path, giving unauthenticated RCE. One of the most widely exploited bugs of 2022.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (7, 4, 17)
        },
    },
    Sig {
        product: "Atlassian Jira",
        id: "CVE-2022-0540",
        severity: Severity::High,
        title: "Jira authentication bypass in Seraph",
        detail: "Jira before 8.13.18 / 8.20.6 allows an authentication bypass in affected first-party and third-party apps via a crafted URL.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (8, 13, 18)
        },
    },
    Sig {
        product: "GitLab",
        id: "CVE-2021-22205",
        severity: Severity::Critical,
        title: "GitLab ExifTool unauthenticated RCE",
        detail: "GitLab < 13.10.3 passes uploaded images to ExifTool, giving unauthenticated RCE. Mass-exploited for cryptomining and botnets long after the patch.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (13, 10, 3)
        },
    },
    Sig {
        product: "Jenkins",
        id: "KAISEN-JENKINS-EXPOSED",
        severity: Severity::Medium,
        title: "Jenkins reachable",
        detail: "A build server holds credentials to everything it deploys to. Confirm anonymous read is off, the agent port is restricted, and the instance is not internet-facing.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Zimbra",
        id: "CVE-2022-27925",
        severity: Severity::Critical,
        title: "Zimbra mboximport path traversal to RCE",
        detail: "Zimbra 8.8.15 / 9.0 before the mid-2022 patches allow an authenticated (and, chained with CVE-2022-37042, unauthenticated) path traversal leading to webshell deployment. Heavily exploited.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (9, 0, 1)
        },
    },
    Sig {
        product: "Roundcube",
        id: "CVE-2024-42009",
        severity: Severity::High,
        title: "Roundcube stored XSS (email theft)",
        detail: "Roundcube < 1.5.8 / 1.6.8 allows a crafted message to steal mail and send as the victim with no interaction beyond opening it.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (1, 6, 8)
        },
    },
    Sig {
        product: "Zabbix",
        id: "CVE-2024-42327",
        severity: Severity::Critical,
        title: "Zabbix SQL injection via the API",
        detail: "Zabbix 6.0-7.0 before the November 2024 patches allow a non-admin user with API access to escalate to full database control.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            ((6, 0, 0)..(7, 0, 6)).contains(&t)
        },
    },
    Sig {
        product: "Cacti",
        id: "CVE-2022-46169",
        severity: Severity::Critical,
        title: "Cacti unauthenticated command injection",
        detail: "Cacti <= 1.2.22 allows unauthenticated RCE through remote_agent.php when a poller host is defined. Actively exploited.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t <= (1, 2, 22)
        },
    },
    Sig {
        product: "Apache Solr",
        id: "CVE-2019-17558",
        severity: Severity::Critical,
        title: "Solr Velocity template RCE",
        detail: "Solr 5.0-8.3.1 allows RCE through the Velocity response writer when params resource loading is enabled — a setting an attacker can turn on through the config API.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            ((5, 0, 0)..=(8, 3, 1)).contains(&t)
        },
    },
    Sig {
        product: "phpMyAdmin",
        id: "CVE-2019-12922",
        severity: Severity::Medium,
        title: "phpMyAdmin exposed",
        detail: "A database administration console reachable from the network is a credential-stuffing target, and phpMyAdmin has repeated CSRF and file-inclusion history (CVE-2018-12613). It belongs behind authentication or a VPN.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Nextcloud",
        id: "KAISEN-NEXTCLOUD-EXPOSED",
        severity: Severity::Low,
        title: "Nextcloud reachable",
        detail: "Expected for a file-sharing server. Confirm the version is current and that brute-force protection and 2FA are enabled, since it fronts user data directly.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Keycloak",
        id: "KAISEN-KEYCLOAK-EXPOSED",
        severity: Severity::Medium,
        title: "Keycloak identity provider reachable",
        detail: "An identity provider is the key to everything behind it. Confirm the admin console is not exposed alongside the public endpoints, which is the default in older distributions.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Grafana",
        id: "KAISEN-GRAFANA-EXPOSED",
        severity: Severity::Low,
        title: "Grafana reachable",
        detail: "Dashboards routinely leak internal hostnames, query strings and, through data-source proxies, a path to the databases behind them. Confirm anonymous access is off and this instance is meant to be reachable.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Apache Struts",
        id: "CVE-2023-50164",
        severity: Severity::Critical,
        title: "Apache Struts file-upload path traversal (RCE)",
        detail: "Struts has a running history of unauthenticated OGNL RCE — CVE-2017-5638 (the Equifax breach), CVE-2018-11776 and now CVE-2023-50164, a path-traversal-to-webshell in the file-upload logic. Any exposed Struts app should be treated as an urgent patch target.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Adobe ColdFusion",
        id: "CVE-2023-26360",
        severity: Severity::Critical,
        title: "Adobe ColdFusion exposed (unauthenticated RCE class)",
        detail: "ColdFusion has repeated pre-auth deserialisation and access-control RCE (CVE-2023-26360, CVE-2023-29300, CVE-2024-20767), several exploited as zero-days. The administrator interface must never be internet-facing.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "WSO2",
        id: "CVE-2022-29464",
        severity: Severity::Critical,
        title: "WSO2 exposed (unauthenticated file upload to RCE)",
        detail: "CVE-2022-29464 lets an unauthenticated attacker upload a webshell to WSO2 API Manager, Identity Server and Enterprise Integrator, giving RCE. Mass-exploited; verify the build and check the webapp directories for planted files.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "IBM WebSphere",
        id: "CVE-2020-4450",
        severity: Severity::High,
        title: "IBM WebSphere exposed (deserialisation RCE class)",
        detail: "WebSphere's IIOP/SOAP connectors have had unauthenticated Java deserialisation RCE (CVE-2020-4450, CVE-2015-7450). The administrative and ORB ports should be restricted to a management network.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "ownCloud",
        id: "CVE-2023-49103",
        severity: Severity::Critical,
        title: "ownCloud graphapi credential disclosure",
        detail: "The graphapi app (ownCloud 0.2.x/0.3.x before 0.2.1/0.3.1) exposes a phpinfo endpoint that leaks the admin password, mail and license keys and the container environment. Mass-scanned within days; rotate every credential the instance held.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Sonatype Nexus",
        id: "CVE-2024-4956",
        severity: Severity::High,
        title: "Sonatype Nexus Repository exposed (path traversal class)",
        detail: "Nexus Repository has had unauthenticated path traversal (CVE-2024-4956) and remote code execution (CVE-2019-7238, CVE-2020-10199). An artifact repository fronts the software supply chain and should sit behind authentication.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Webmin",
        id: "CVE-2019-15107",
        severity: Severity::Critical,
        title: "Webmin password_change unauthenticated RCE",
        detail: "Webmin 1.882-1.921 shipped a backdoored password_change.cgi allowing unauthenticated command execution as root. Even patched, a Webmin panel is root-level control of the host and must never be internet-facing.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Drupal",
        id: "CVE-2018-7600",
        severity: Severity::Critical,
        title: "Drupal exposed (Drupalgeddon2 class)",
        detail: "Drupal has had unauthenticated RCE through form-render tokens (CVE-2018-7600 Drupalgeddon2 and CVE-2018-7602), mass-exploited for cryptomining. Confirm core and contributed modules are current; the attack surface is largely in the modules.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Joomla",
        id: "CVE-2023-23752",
        severity: Severity::High,
        title: "Joomla exposed (unauthenticated information disclosure)",
        detail: "CVE-2023-23752 leaks the Joomla configuration — including the database user and password — through the REST API with no authentication. Verify the build and rotate the database credentials if this predates the patch.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Magento",
        id: "CVE-2022-24086",
        severity: Severity::Critical,
        title: "Magento/Adobe Commerce exposed (pre-auth RCE)",
        detail: "CVE-2022-24086 is an unauthenticated template-injection RCE in the checkout flow, exploited in the wild against online stores. Magento is also the prime target for Magecart card-skimming; verify the build and audit the checkout templates.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Apache Hadoop",
        id: "KAISEN-HADOOP-YARN",
        severity: Severity::Critical,
        title: "Apache Hadoop exposed (YARN unauthenticated job submission)",
        detail: "An unauthenticated YARN ResourceManager REST API accepts application submissions, which is remote code execution on every node — a workload cryptomining botnets scan for continuously. Enable Kerberos and firewall the ResourceManager.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Apache Spark",
        id: "CVE-2022-33891",
        severity: Severity::High,
        title: "Apache Spark exposed (UI command injection)",
        detail: "With ACLs enabled, Spark before 3.1.3 / 3.2.2 runs shell commands from a user-supplied name (CVE-2022-33891), and the standalone master REST submission API is RCE by design when reachable. Restrict the UI and cluster ports.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Apache Flink",
        id: "CVE-2020-17519",
        severity: Severity::High,
        title: "Apache Flink dashboard exposed (path traversal)",
        detail: "Flink 1.11.0-1.11.2 allows reading any file on the JobManager through the dashboard (CVE-2020-17519), and the dashboard can upload and run a job — RCE — whenever it is reachable unauthenticated.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Apache NiFi",
        id: "KAISEN-NIFI-EXPOSED",
        severity: Severity::High,
        title: "Apache NiFi exposed",
        detail: "NiFi's ExecuteScript/ExecuteProcess processors turn flow-editing access into code execution, and unsecured instances leak the credentials embedded in their data flows. Confirm authentication is enforced and the UI is not internet-facing.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "MinIO",
        id: "CVE-2023-28432",
        severity: Severity::High,
        title: "MinIO exposed (cluster credential disclosure)",
        detail: "In a clustered deployment, CVE-2023-28432 returns all environment variables — including MINIO_ROOT_USER and MINIO_ROOT_PASSWORD — to an unauthenticated request. Verify the build and rotate the root credentials.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Portainer",
        id: "KAISEN-PORTAINER-EXPOSED",
        severity: Severity::High,
        title: "Portainer reachable",
        detail: "Portainer manages Docker and Kubernetes; access to it is access to every container and, through volume mounts, to the host. If the initial-admin setup was never completed, the first request to reach it can claim the admin account.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Proxmox VE",
        id: "KAISEN-PROXMOX-EXPOSED",
        severity: Severity::Medium,
        title: "Proxmox VE management reachable",
        detail: "The Proxmox web interface controls every VM and container on the host. Confirm it is behind a VPN or management network and that two-factor authentication is enabled on the root@pam account.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "HFS File Server",
        id: "CVE-2024-23692",
        severity: Severity::Critical,
        title: "Rejetto HFS exposed (unauthenticated template-injection RCE)",
        detail: "Rejetto HttpFileServer 2.3m and earlier evaluate a template expression from the request, giving unauthenticated RCE (CVE-2024-23692). It is unmaintained; the only fix is to stop exposing it.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Node-RED",
        id: "KAISEN-NODERED-EXPOSED",
        severity: Severity::High,
        title: "Node-RED editor reachable",
        detail: "The Node-RED flow editor includes an exec/function node that runs arbitrary code on the host, so an unauthenticated editor is remote code execution. Set adminAuth and keep the editor off untrusted networks.",
        needle: "",
        matches: |_| true,
    },

    // ════════════════════════════════════════════════════════════════════════
    // Managed file transfer and mail. MFT products are the ransomware entry
    // point of choice, because they sit at the edge and hold everything.
    // ════════════════════════════════════════════════════════════════════════
    Sig {
        product: "Progress MOVEit Transfer",
        id: "CVE-2023-34362",
        severity: Severity::Critical,
        title: "MOVEit Transfer exposed (SQL injection to RCE)",
        detail: "CVE-2023-34362 was mass-exploited by Cl0p as a zero-day, affecting thousands of organisations through a single product. Verify the build, and check for the known webshell (human2.aspx) regardless of version.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Fortra GoAnywhere MFT",
        id: "CVE-2023-0669",
        severity: Severity::Critical,
        title: "GoAnywhere MFT exposed (pre-auth deserialisation RCE)",
        detail: "CVE-2023-0669 gives unauthenticated RCE through the admin console, and CVE-2024-0204 allows creating an administrator outright. The admin port should never face the internet.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "CrushFTP",
        id: "CVE-2024-4040",
        severity: Severity::Critical,
        title: "CrushFTP exposed (unauthenticated template injection)",
        detail: "CVE-2024-4040 allows an unauthenticated attacker to read arbitrary files outside the VFS sandbox, and was exploited in the wild. Verify the build is past 10.7.1 / 11.1.0.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Serv-U",
        id: "CVE-2021-35211",
        severity: Severity::High,
        title: "SolarWinds Serv-U exposed",
        detail: "Serv-U's SSH component had a remotely exploitable memory corruption used in targeted attacks (CVE-2021-35211), and a later path traversal (CVE-2024-28995) leaking arbitrary files.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Microsoft Exchange",
        id: "CVE-2021-34473",
        severity: Severity::Critical,
        title: "Exchange ProxyShell chain",
        detail: "Exchange 2013/2016/2019 before the July 2021 updates are vulnerable to the ProxyShell chain, giving unauthenticated RCE as SYSTEM. Mass-exploited; check for webshells in the OWA paths as well as the build number.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (15, 2, 792)
        },
    },
    Sig {
        product: "Microsoft Exchange",
        id: "KAISEN-EXCHANGE-OWA",
        severity: Severity::Medium,
        title: "Exchange OWA reachable",
        detail: "Outlook Web Access facing the internet is normal but has been the entry point for ProxyLogon, ProxyShell and ProxyNotShell in three consecutive years. Confirm the build is current and that Extended Protection is on.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "Exim",
        id: "CVE-2023-51766",
        severity: Severity::Medium,
        title: "Exim SMTP smuggling",
        detail: "Exim < 4.97.1 accepts non-standard line endings, letting an attacker smuggle a second message past SPF and DMARC checks and spoof any sender the server relays for.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (4, 97, 1)
        },
    },

    // ════════════════════════════════════════════════════════════════════════
    // Web servers, runtimes and virtualisation.
    // ════════════════════════════════════════════════════════════════════════
    Sig {
        product: "PHP",
        id: "CVE-2024-4577",
        severity: Severity::Critical,
        title: "PHP-CGI argument injection (RCE)",
        detail: "PHP < 8.1.29 / 8.2.20 / 8.3.8 on Windows in CGI mode allows unauthenticated RCE through a best-fit character conversion. Exploited within 48 hours of disclosure, including by ransomware.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (8, 1, 29)
        },
    },
    Sig {
        product: "PHP",
        id: "KAISEN-PHP-EOL",
        severity: Severity::Medium,
        title: "PHP branch is end of life",
        detail: "PHP 7.x and earlier receive no security fixes. Any bug found now stays unfixed on this host.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            t != (0, 0, 0) && t < (8, 0, 0)
        },
    },
    Sig {
        product: "Apache",
        id: "CVE-2024-38476",
        severity: Severity::High,
        title: "Apache httpd information disclosure / SSRF via internal handlers",
        detail: "httpd < 2.4.60 can be tricked into serving internal handlers and local content, leading to source disclosure and SSRF.",
        needle: "",
        matches: |v| {
            let t = ver_tuple(v);
            ((2, 4, 0)..(2, 4, 60)).contains(&t)
        },
    },
    Sig {
        product: "VMware vCenter",
        id: "CVE-2023-34048",
        severity: Severity::Critical,
        title: "vCenter Server exposed (DCERPC out-of-bounds write)",
        detail: "CVE-2023-34048 gives unauthenticated RCE, and CVE-2021-21985 before it did the same through the vSAN plugin. vCenter controls every VM in the estate and must not be broadly reachable.",
        needle: "",
        matches: |_| true,
    },
    Sig {
        product: "VMware ESXi",
        id: "CVE-2021-21974",
        severity: Severity::Critical,
        title: "ESXi host exposed (OpenSLP RCE class)",
        detail: "CVE-2021-21974 in OpenSLP drove the ESXiArgs ransomware campaign against thousands of internet-facing hosts. A hypervisor management interface should never be reachable from an untrusted network.",
        needle: "",
        matches: |_| true,
    },
];

/// Assess a UDP port. UDP is its own risk class: most of what matters is not
/// "is this software old" but "will this service answer a stranger, and will it
/// answer with far more bytes than it was asked" — the reflection/amplification
/// property that makes UDP the backbone of DDoS.
/// A port-level exposure heuristic: this service being reachable at all is the
/// finding, whatever version it happens to run.
///
/// These used to be arms of a `match port` inside the two assess functions.
/// They are data, not control flow — keeping them as data is what lets
/// `--vuln-list` enumerate the database and what makes the totals countable
/// instead of guessed at.
pub struct Exposure {
    pub ports: &'static [u16],
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub detail: &'static str,
}

/// Looked up in order, so the first entry that lists the port wins — exactly
/// how the `match` arms behaved.
fn exposure_for(table: &'static [Exposure], port: u16) -> Option<&'static Exposure> {
    table.iter().find(|e| e.ports.contains(&port))
}

/// The verdict of a protocol-confirmation gate on a port exposure.
///
/// A port number is a guess, not a protocol. Some exposures name a specific
/// protocol or CVE — "Tomcat AJP (Ghostcat)", "JMX", "Kubernetes API" — and
/// firing those on the port number alone is how a camera on 9010 gets flagged
/// as exposed JMX. A gate looks at what detection actually found and rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    /// Detection confirmed the protocol. Fire at the declared severity.
    Verified,
    /// Neither confirmed nor refuted. Fire, but degrade to `Info` and say so,
    /// so a heuristic never wears the badge of a confirmed finding.
    Unverified,
    /// Detection found something incompatible with this exposure. Suppress it.
    Refuted,
}

/// A protocol-confirmation gate for one exposure id. Opt-in: only the handful
/// of exposures that name a specific protocol carry one, so the 100-plus plain
/// port heuristics stay exactly as they were. Kept as data, like the exposures
/// themselves.
struct Gate {
    id: &'static str,
    confirm: fn(&ServiceInfo) -> Confirm,
}

const GATES: &[Gate] = &[
    Gate {
        id: "KAISEN-AJP-GHOSTCAT",
        confirm: confirm_ajp,
    },
    Gate {
        id: "KAISEN-JMX",
        confirm: confirm_jmx,
    },
    Gate {
        id: "KAISEN-KUBE-API",
        confirm: confirm_kube,
    },
];

fn gate_for(id: &str) -> Option<&'static Gate> {
    GATES.iter().find(|g| g.id == id)
}

/// Everything a probe learned about the port, lowercased, for substring tests.
fn haystack(svc: &ServiceInfo) -> String {
    format!(
        "{} {} {} {} {}",
        svc.name,
        svc.product,
        svc.banner,
        svc.extra,
        svc.hostnames.join(" ")
    )
    .to_ascii_lowercase()
}

/// Ghostcat is an AJP flaw. The AJP prober (probe::ajp) speaks real AJP13 and
/// only names the port `ajp13` when it answered with the `AB` magic — so a
/// Chromecast on 8009, which answers a TLS handshake instead, never gets that
/// name. If TLS was negotiated, it is categorically not cleartext AJP.
fn confirm_ajp(svc: &ServiceInfo) -> Confirm {
    if !svc.tls_version.is_empty() {
        return Confirm::Refuted;
    }
    if svc.name.eq_ignore_ascii_case("ajp13") || haystack(svc).contains("jserv") {
        return Confirm::Verified;
    }
    Confirm::Unverified
}

/// JMX rides on Java RMI/JRMP. A TLS-speaking device (an Ezviz camera answers
/// TLS on its 9010 command port) is not a JMX registry, and a certificate that
/// names a non-Java appliance settles it outright.
fn confirm_jmx(svc: &ServiceInfo) -> Confirm {
    let hay = haystack(svc);
    // A device that named itself something non-Java on the cert is not JMX.
    const NOT_JMX: &[&str] = &["ezviz", "hikvision", "dahua", "reolink"];
    if NOT_JMX.iter().any(|m| hay.contains(m)) {
        return Confirm::Refuted;
    }
    if !svc.tls_version.is_empty() {
        return Confirm::Refuted;
    }
    if hay.contains("rmi") || hay.contains("jmx") || hay.contains("jrmp") {
        return Confirm::Verified;
    }
    Confirm::Unverified
}

/// The Kubernetes API server answers `/version` with `{"major":"1",...}`. The
/// sync path can't make that request, so it only ever downgrades or refutes;
/// `assess_active` upgrades to Verified when it confirms the JSON. A cert that
/// names a non-Kubernetes appliance refutes it immediately.
fn confirm_kube(svc: &ServiceInfo) -> Confirm {
    let hay = haystack(svc);
    const NOT_KUBE: &[&str] = &["ezviz", "hikvision", "dahua", "reolink", "anydesk"];
    if NOT_KUBE.iter().any(|m| hay.contains(m)) {
        return Confirm::Refuted;
    }
    if hay.contains("kubernetes") || hay.contains("k3s") {
        return Confirm::Verified;
    }
    Confirm::Unverified
}

/// UDP port exposures.
/// A condition the UDP probe actually established, rather than a guess from the
/// port number. Same reasoning as `Exposure`: this is data, so it can be
/// listed and counted instead of hiding as a chain of `if`s.
pub struct UdpCondition {
    /// Matched case-insensitively against everything the probe reported.
    pub needle: &'static str,
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub detail: &'static str,
}

/// Probe-established UDP conditions.
pub const UDP_CONDITIONS: &[UdpCondition] = &[
    UdpCondition {
        needle: "monlist enabled",
        id: "CVE-2013-5211",
        severity: Severity::High,
        title: "NTP monlist enabled (DDoS amplifier)",
        detail: "ntpd answered mode 7 MON_GETLIST. A 234-byte request returns up to 100 addresses, an amplification factor in the hundreds; upgrade past 4.2.7p26 or set 'disable monitor'.",
    },
    UdpCondition {
        needle: "mode 6 control queries allowed",
        id: "KAISEN-NTP-MODE6",
        severity: Severity::Medium,
        title: "NTP mode 6 control queries allowed",
        detail: "The daemon answers readvar to anyone, disclosing its exact version and host OS and offering a smaller amplification vector. Restrict with 'restrict default noquery'.",
    },
    UdpCondition {
        needle: "null authentication permitted",
        id: "KAISEN-IPMI-NULLAUTH",
        severity: Severity::Critical,
        title: "IPMI permits null authentication",
        detail: "The BMC accepts an empty auth type, which typically means unauthenticated access to hardware-level control of the host.",
    },
    UdpCondition {
        needle: "anonymous login enabled",
        id: "KAISEN-IPMI-ANON",
        severity: Severity::Critical,
        title: "IPMI anonymous login enabled",
        detail: "Anyone who can reach the BMC can log in with no credentials and power-cycle, reimage or console into the server.",
    },
    UdpCondition {
        needle: "open resolver",
        id: "KAISEN-DNS-OPENRESOLVER",
        severity: Severity::High,
        title: "Open DNS resolver",
        detail: "The server recursed for an unrelated name on our behalf. Open resolvers are used for cache-poisoning and for DNS amplification attacks against third parties.",
    },
    UdpCondition {
        needle: "aggressive mode accepted",
        id: "KAISEN-IKE-AGGRESSIVE",
        severity: Severity::High,
        title: "IKE aggressive mode accepted",
        detail: "Aggressive mode sends a hash of the pre-shared key before authentication, which can be captured and cracked offline.",
    },
    UdpCondition {
        needle: "unauthenticated",
        id: "KAISEN-UDP-NOAUTH",
        severity: Severity::High,
        title: "UDP service answered without authentication",
        detail: "The probe got a full answer with no credentials; confirm whether the data or control it exposes should be reachable from here.",
    },
];

/// UDP port exposures.
pub const UDP_EXPOSURES: &[Exposure] = &[
    Exposure {
        ports: &[123],
        id: "KAISEN-NTP",
        severity: Severity::Low,
        title: "NTP server reachable",
        detail: "Public NTP is usually intentional; make sure monlist and mode 6/7 queries are disabled.",
    },
    Exposure {
        ports: &[161, 162],
        id: "KAISEN-SNMP",
        severity: Severity::High,
        title: "SNMP exposed",
        detail: "SNMP with a default community leaks the full device inventory, interfaces, ARP tables and routes — and write access can reconfigure the device.",
    },
    Exposure {
        ports: &[137, 138],
        id: "KAISEN-NETBIOS",
        severity: Severity::Medium,
        title: "NetBIOS name service exposed",
        detail: "NBSTAT hands out the hostname, domain, logged-on user and MAC address to anyone who asks.",
    },
    Exposure {
        ports: &[1900],
        id: "KAISEN-SSDP",
        severity: Severity::Medium,
        title: "SSDP/UPnP exposed",
        detail: "SSDP is a strong amplification vector and UPnP has a long history of allowing unauthenticated firewall-hole punching.",
    },
    Exposure {
        ports: &[5353],
        id: "KAISEN-MDNS",
        severity: Severity::Medium,
        title: "mDNS exposed off-link",
        detail: "mDNS answering a unicast query from off the local link leaks hostnames and the service inventory, and amplifies.",
    },
    Exposure {
        ports: &[5355],
        id: "KAISEN-LLMNR",
        severity: Severity::Medium,
        title: "LLMNR enabled",
        detail: "LLMNR (and NBT-NS) allow name-resolution poisoning to capture NetNTLM hashes — the classic Responder attack.",
    },
    Exposure {
        ports: &[11211],
        id: "KAISEN-MEMCACHED-UDP",
        severity: Severity::Critical,
        title: "Memcached UDP enabled",
        detail: "UDP memcached produced the largest DDoS on record (amplification ~51000x). Disable UDP with -U 0.",
    },
    Exposure {
        ports: &[19],
        id: "KAISEN-CHARGEN",
        severity: Severity::High,
        title: "chargen exposed",
        detail: "A classic amplification and loop-attack vector with no legitimate modern use; disable it.",
    },
    Exposure {
        ports: &[17],
        id: "KAISEN-QOTD",
        severity: Severity::Medium,
        title: "qotd exposed",
        detail: "Quote-of-the-day is an amplification vector with no modern purpose.",
    },
    Exposure {
        ports: &[7],
        id: "KAISEN-ECHO-UDP",
        severity: Severity::Medium,
        title: "UDP echo exposed",
        detail: "Echo can be looped against another echo service to sustain traffic between two victims.",
    },
    Exposure {
        ports: &[111],
        id: "KAISEN-RPCBIND-UDP",
        severity: Severity::High,
        title: "rpcbind exposed",
        detail: "The portmapper enumerates every RPC service on the host and is a well-used amplification vector.",
    },
    Exposure {
        ports: &[623, 664],
        // The TCP table has its own KAISEN-IPMI. Every other UDP twin of a TCP
        // exposure in this file carries the -UDP suffix; this one did not, so
        // one id meant two different findings depending on which table you
        // found it in.
        id: "KAISEN-IPMI-UDP",
        severity: Severity::High,
        title: "IPMI/BMC exposed",
        detail: "IPMI 2.0 discloses password hashes pre-auth (RAKP) and controls the machine below the operating system.",
    },
    Exposure {
        ports: &[69],
        id: "KAISEN-TFTP-UDP",
        severity: Severity::Medium,
        title: "TFTP exposed",
        detail: "No authentication at all; TFTP commonly serves device configs and firmware containing credentials.",
    },
    Exposure {
        ports: &[1434],
        id: "KAISEN-MSSQL-BROWSER",
        severity: Severity::Medium,
        title: "SQL Server Browser exposed",
        detail: "It enumerates every instance with its exact version and port before authentication, and amplifies.",
    },
    Exposure {
        ports: &[520],
        id: "KAISEN-RIP",
        severity: Severity::Medium,
        title: "RIP exposed",
        detail: "Unauthenticated RIP accepts route injection, allowing traffic redirection.",
    },
    Exposure {
        ports: &[500, 4500],
        id: "KAISEN-IKE",
        severity: Severity::Low,
        title: "IKE/IPsec endpoint reachable",
        detail: "Expected for a VPN gateway; confirm aggressive mode is off and the PSK is strong.",
    },
    Exposure {
        ports: &[3478, 3479],
        id: "KAISEN-STUN",
        severity: Severity::Low,
        title: "STUN/TURN server reachable",
        detail: "Check that TURN relaying requires credentials, or it can be used as an open relay.",
    },
    Exposure {
        ports: &[177],
        id: "KAISEN-XDMCP",
        severity: Severity::High,
        title: "XDMCP exposed",
        detail: "XDMCP offers remote X sessions with weak or absent authentication.",
    },
    Exposure {
        ports: &[47808],
        id: "KAISEN-BACNET-UDP",
        severity: Severity::High,
        title: "BACnet exposed",
        detail: "Building automation with no authentication by design; reachable devices can be read and commanded.",
    },
    Exposure {
        ports: &[44818],
        id: "KAISEN-ENIP-UDP",
        severity: Severity::Critical,
        title: "EtherNet/IP exposed",
        detail: "CIP allows reading and writing PLC configuration without authentication.",
    },
    Exposure {
        ports: &[20000],
        id: "KAISEN-DNP3-UDP",
        severity: Severity::Critical,
        title: "DNP3 exposed",
        detail: "A SCADA protocol with no authentication in its base form; it must never face an untrusted network.",
    },
    Exposure {
        ports: &[17185],
        id: "KAISEN-VXWORKS",
        severity: Severity::Critical,
        title: "VxWorks WDB debug agent exposed",
        detail: "The WDB agent allows memory read/write and task control on the device with no authentication.",
    },
    Exposure {
        ports: &[30718],
        id: "KAISEN-LANTRONIX",
        severity: Severity::High,
        title: "Lantronix setup port exposed",
        detail: "The configuration port can disclose and change device settings, historically including passwords.",
    },
    Exposure {
        ports: &[427],
        id: "KAISEN-SLP",
        severity: Severity::High,
        title: "SLP exposed",
        detail: "SLP (CVE-2023-29552) permits registration of arbitrary services and amplification factors above 2000x.",
    },
    Exposure {
        ports: &[1194],
        id: "KAISEN-OPENVPN-UDP",
        severity: Severity::Low,
        title: "OpenVPN endpoint reachable",
        detail: "Expected for a VPN; confirm tls-auth/tls-crypt is enabled so unauthenticated peers cannot reach the TLS stack.",
    },
    Exposure {
        ports: &[3702],
        id: "KAISEN-WSD",
        severity: Severity::Medium,
        title: "WS-Discovery exposed",
        detail: "WSD is an amplification vector (~300x) and enumerates printers and cameras on the network.",
    },
    Exposure {
        ports: &[5093],
        id: "KAISEN-SENTINEL",
        severity: Severity::Medium,
        title: "Sentinel LM exposed",
        detail: "The license manager is a known amplification vector.",
    },
    Exposure {
        ports: &[10001],
        id: "KAISEN-UBNT",
        severity: Severity::Medium,
        title: "Ubiquiti discovery exposed",
        detail: "The discovery service leaks model, firmware and MAC, and amplifies (~30x).",
    },
    Exposure {
        ports: &[389],
        id: "KAISEN-CLDAP",
        severity: Severity::High,
        title: "CLDAP exposed (DDoS amplifier)",
        detail: "Connectionless LDAP over UDP answers a small query with a large directory response, an amplification factor around 50-70x that makes it one of the most abused reflection vectors. It should not be reachable over UDP.",
    },
    Exposure {
        ports: &[1812, 1813],
        id: "KAISEN-RADIUS",
        severity: Severity::Medium,
        title: "RADIUS exposed",
        detail: "RADIUS over UDP is the authentication backbone for VPNs and Wi-Fi. Blast-RADIUS (CVE-2024-3596) forges a valid Access-Accept without the shared secret; require Message-Authenticator and keep the port off untrusted networks.",
    },
    Exposure {
        ports: &[5060, 5061],
        id: "KAISEN-SIP-UDP",
        severity: Severity::Medium,
        title: "SIP exposed over UDP",
        detail: "SIP over UDP is trivially spoofable and is scanned continuously for extension enumeration and toll fraud; it also serves as a reflection vector. Restrict it to known peers.",
    },
    Exposure {
        ports: &[5683, 5684],
        id: "KAISEN-COAP",
        severity: Severity::Medium,
        title: "CoAP exposed",
        detail: "Constrained Application Protocol endpoints enumerate IoT resources with no authentication in the base profile and amplify (~30x). Confirm the device should answer off-link.",
    },
    Exposure {
        ports: &[1701],
        id: "KAISEN-L2TP",
        severity: Severity::Low,
        title: "L2TP endpoint reachable",
        detail: "Expected for an L2TP/IPsec VPN; confirm it is wrapped in IPsec and not offering an unauthenticated tunnel on its own.",
    },
];

/// TCP port exposures.
pub const TCP_EXPOSURES: &[Exposure] = &[
    Exposure {
        ports: &[23],
        id: "KAISEN-TELNET",
        severity: Severity::High,
        title: "Telnet in use",
        detail: "Telnet transmits credentials in cleartext; prefer SSH.",
    },
    Exposure {
        ports: &[21],
        id: "KAISEN-FTP",
        severity: Severity::Low,
        title: "FTP in use",
        detail: "FTP is often cleartext; prefer FTPS/SFTP.",
    },
    Exposure {
        ports: &[3389],
        id: "KAISEN-RDP",
        severity: Severity::Medium,
        title: "RDP exposed",
        detail: "Exposed RDP is a common ransomware entry point; restrict access / require NLA.",
    },
    Exposure {
        ports: &[445],
        id: "KAISEN-SMB",
        severity: Severity::Medium,
        title: "SMB exposed",
        detail: "SMB exposed to the network; ensure patched (EternalBlue class) and not internet-facing.",
    },
    Exposure {
        ports: &[27017, 27018],
        id: "KAISEN-MONGO",
        severity: Severity::High,
        title: "MongoDB exposed",
        detail: "Exposed MongoDB has historically been mass-ransomed when unauthenticated.",
    },
    Exposure {
        ports: &[9200, 9300],
        id: "KAISEN-ES",
        severity: Severity::High,
        title: "Elasticsearch exposed",
        detail: "Unauthenticated Elasticsearch leaks all indexed data.",
    },
    Exposure {
        ports: &[5900, 5901],
        id: "KAISEN-VNC",
        severity: Severity::Medium,
        title: "VNC exposed",
        detail: "VNC often weakly authenticated; tunnel it over SSH/VPN.",
    },
    Exposure {
        ports: &[8009],
        id: "KAISEN-AJP-GHOSTCAT",
        severity: Severity::High,
        title: "Tomcat AJP exposed (Ghostcat)",
        detail: "Exposed AJP/8009 enables CVE-2020-1938 (Ghostcat) file read / potential RCE on Tomcat.",
    },
    Exposure {
        ports: &[7001, 7002],
        id: "KAISEN-WEBLOGIC",
        severity: Severity::High,
        title: "Oracle WebLogic exposed",
        detail: "WebLogic consoles have a long history of unauthenticated RCE (CVE-2019-2725, 2020-2883, ...).",
    },
    Exposure {
        ports: &[1433],
        id: "KAISEN-MSSQL",
        severity: Severity::Medium,
        title: "MS SQL Server exposed",
        detail: "Database reachable remotely; ensure firewalling and strong auth.",
    },
    Exposure {
        ports: &[5432],
        id: "KAISEN-POSTGRES",
        severity: Severity::Medium,
        title: "PostgreSQL exposed",
        detail: "Database reachable remotely; restrict pg_hba and network access.",
    },
    Exposure {
        ports: &[2049],
        id: "KAISEN-NFS",
        severity: Severity::Medium,
        title: "NFS exposed",
        detail: "Exposed NFS may allow reading/writing shares; check exports and auth.",
    },
    Exposure {
        ports: &[2375],
        id: "KAISEN-DOCKER",
        severity: Severity::Critical,
        title: "Docker API exposed",
        detail: "Unauthenticated Docker API on 2375 = trivial host takeover (spawn privileged containers).",
    },
    Exposure {
        ports: &[11211],
        id: "KAISEN-MEMCACHED-PORT",
        severity: Severity::Medium,
        title: "Memcached port exposed",
        detail: "Exposed Memcached enables data leakage and UDP amplification DDoS.",
    },
    Exposure {
        ports: &[2376],
        id: "KAISEN-DOCKER-TLS",
        severity: Severity::High,
        title: "Docker API (TLS) exposed",
        detail: "Even with TLS, the Docker API is host-level control; restrict it to a management network.",
    },
    Exposure {
        ports: &[2377],
        id: "KAISEN-SWARM",
        severity: Severity::High,
        title: "Docker Swarm manager exposed",
        detail: "The swarm control port lets a node join the cluster; it should never face untrusted networks.",
    },
    Exposure {
        ports: &[2379, 2380],
        id: "KAISEN-ETCD",
        severity: Severity::Critical,
        title: "etcd exposed",
        detail: "etcd holds all Kubernetes state including Secrets; unauthenticated access is full cluster compromise.",
    },
    Exposure {
        ports: &[6443, 8443],
        id: "KAISEN-KUBE-API",
        severity: Severity::Medium,
        title: "Kubernetes API server reachable",
        detail: "Verify anonymous-auth is off and RBAC is enforced; the API server should not be internet-facing.",
    },
    Exposure {
        ports: &[10250],
        id: "KAISEN-KUBELET",
        severity: Severity::Critical,
        title: "Kubelet API exposed",
        detail: "An unauthenticated kubelet allows /exec and /run on every pod, i.e. node takeover.",
    },
    Exposure {
        ports: &[10255],
        id: "KAISEN-KUBELET-RO",
        severity: Severity::High,
        title: "Kubelet read-only port exposed",
        detail: "Port 10255 serves pod specs and environment variables with no authentication at all.",
    },
    Exposure {
        ports: &[4243],
        id: "KAISEN-DOCKER-ALT",
        severity: Severity::Critical,
        title: "Docker API on alternate port",
        detail: "Unauthenticated Docker API = trivial host takeover via a privileged container.",
    },
    Exposure {
        ports: &[44134],
        id: "KAISEN-TILLER",
        severity: Severity::Critical,
        title: "Helm Tiller exposed",
        detail: "Tiller runs with cluster-admin and has no authentication; reaching it means owning the cluster.",
    },
    Exposure {
        ports: &[5984],
        id: "KAISEN-COUCHDB",
        severity: Severity::High,
        title: "CouchDB exposed",
        detail: "Unauthenticated CouchDB exposes all databases and has a history of admin-party misconfiguration.",
    },
    Exposure {
        ports: &[7473, 7474, 7687],
        id: "KAISEN-NEO4J",
        severity: Severity::Medium,
        title: "Neo4j exposed",
        detail: "Default credentials (neo4j/neo4j) and open Bolt access are a common data-loss path.",
    },
    Exposure {
        ports: &[8086],
        id: "KAISEN-INFLUX",
        severity: Severity::Medium,
        title: "InfluxDB exposed",
        detail: "InfluxDB 1.x ships without authentication by default; metrics often include hostnames and tokens.",
    },
    Exposure {
        ports: &[9042, 9160],
        id: "KAISEN-CASSANDRA",
        severity: Severity::Medium,
        title: "Cassandra exposed",
        detail: "The default AllowAllAuthenticator accepts any login; restrict the native transport port.",
    },
    Exposure {
        ports: &[8529],
        id: "KAISEN-ARANGO",
        severity: Severity::Medium,
        title: "ArangoDB exposed",
        detail: "Check that authentication is enabled; older images defaulted to no root password.",
    },
    Exposure {
        ports: &[26257],
        id: "KAISEN-COCKROACH",
        severity: Severity::Medium,
        title: "CockroachDB exposed",
        detail: "Verify the cluster runs in secure mode; insecure mode accepts any client.",
    },
    Exposure {
        ports: &[4200, 8123, 9009],
        id: "KAISEN-CLICKHOUSE",
        severity: Severity::Medium,
        title: "ClickHouse exposed",
        detail: "The default 'default' user historically had no password and full read access.",
    },
    Exposure {
        ports: &[6432],
        id: "KAISEN-PGBOUNCER",
        severity: Severity::Medium,
        title: "PgBouncer exposed",
        detail: "The pooler fronts your database and may hold plaintext credentials in its auth file.",
    },
    Exposure {
        ports: &[11210, 8091],
        id: "KAISEN-COUCHBASE",
        severity: Severity::Medium,
        title: "Couchbase exposed",
        detail: "The management and data ports should be restricted to the cluster network.",
    },
    Exposure {
        ports: &[6379, 6380, 16379],
        id: "KAISEN-REDIS-PORT",
        severity: Severity::High,
        title: "Redis port exposed",
        detail: "If unauthenticated, Redis allows data theft and RCE via config/module abuse.",
    },
    Exposure {
        ports: &[2181],
        id: "KAISEN-ZOOKEEPER",
        severity: Severity::Medium,
        title: "ZooKeeper exposed",
        detail: "ZooKeeper rarely has authentication enabled and holds cluster configuration.",
    },
    Exposure {
        ports: &[4369],
        id: "KAISEN-EPMD-PORT",
        severity: Severity::High,
        title: "Erlang port mapper exposed",
        detail: "EPMD plus a weak Erlang cookie yields remote code execution on the node.",
    },
    Exposure {
        ports: &[5672, 5671],
        id: "KAISEN-AMQP",
        severity: Severity::Medium,
        title: "AMQP broker exposed",
        detail: "Check for the default guest/guest account and restrict the port to application hosts.",
    },
    Exposure {
        ports: &[9092, 9093, 9094],
        id: "KAISEN-KAFKA",
        severity: Severity::Medium,
        title: "Kafka broker exposed",
        detail: "Without SASL and ACLs, any client can read and write every topic.",
    },
    Exposure {
        ports: &[1883, 8883],
        id: "KAISEN-MQTT",
        severity: Severity::Medium,
        title: "MQTT broker exposed",
        detail: "Anonymous MQTT brokers leak sensor and control traffic, and often accept commands.",
    },
    Exposure {
        ports: &[61616, 61613],
        id: "KAISEN-ACTIVEMQ",
        severity: Severity::Medium,
        title: "ActiveMQ exposed",
        detail: "OpenWire and STOMP have had unauthenticated deserialisation RCEs (e.g. CVE-2023-46604).",
    },
    Exposure {
        ports: &[5985, 5986],
        id: "KAISEN-WINRM",
        severity: Severity::Medium,
        title: "WinRM exposed",
        detail: "WinRM is remote PowerShell; exposed to a network it is a direct lateral-movement path.",
    },
    Exposure {
        ports: &[623],
        id: "KAISEN-IPMI",
        severity: Severity::High,
        title: "IPMI/BMC exposed",
        detail: "IPMI 2.0 leaks password hashes pre-auth (cipher-zero and RAKP flaws) and controls the host below the OS.",
    },
    Exposure {
        ports: &[16992, 16993],
        id: "KAISEN-AMT",
        severity: Severity::High,
        title: "Intel AMT exposed",
        detail: "AMT sits beneath the OS and has had a complete authentication bypass (CVE-2017-5689).",
    },
    Exposure {
        ports: &[4899],
        id: "KAISEN-RADMIN",
        severity: Severity::Medium,
        title: "Radmin exposed",
        detail: "Remote-control software reachable from the network; verify it is not using default credentials.",
    },
    Exposure {
        ports: &[5938, 6568],
        id: "KAISEN-REMOTE-DESK",
        severity: Severity::Low,
        title: "Remote-desktop agent detected",
        detail: "TeamViewer/AnyDesk agents are common initial-access targets; confirm the install is intentional.",
    },
    Exposure {
        ports: &[3283],
        id: "KAISEN-ARD",
        severity: Severity::Medium,
        title: "Apple Remote Desktop exposed",
        detail: "ARD grants screen control; it has previously been abused for UDP amplification too.",
    },
    Exposure {
        ports: &[512, 513, 514],
        id: "KAISEN-RSERVICES",
        severity: Severity::High,
        title: "Berkeley r-services exposed",
        detail: "rexec/rlogin/rsh trust host-based authentication and send credentials in cleartext.",
    },
    Exposure {
        ports: &[79],
        id: "KAISEN-FINGER",
        severity: Severity::Low,
        title: "finger service exposed",
        detail: "finger enumerates local user accounts for anyone who asks.",
    },
    Exposure {
        ports: &[69],
        id: "KAISEN-TFTP",
        severity: Severity::Medium,
        title: "TFTP exposed",
        detail: "TFTP has no authentication and frequently serves device configurations containing credentials.",
    },
    Exposure {
        ports: &[111],
        id: "KAISEN-RPCBIND",
        severity: Severity::Medium,
        title: "rpcbind exposed",
        detail: "The portmapper enumerates RPC services (NFS, NIS) and is usable for DDoS amplification.",
    },
    Exposure {
        ports: &[873],
        id: "KAISEN-RSYNC-PORT",
        severity: Severity::Medium,
        title: "rsync daemon exposed",
        detail: "Anonymous rsync modules often expose entire filesystems read-write.",
    },
    Exposure {
        ports: &[1099, 1098],
        id: "KAISEN-RMI",
        severity: Severity::High,
        title: "Java RMI registry exposed",
        detail: "RMI registries are a classic Java deserialisation RCE target.",
    },
    Exposure {
        ports: &[8686, 9010, 9999],
        id: "KAISEN-JMX",
        severity: Severity::High,
        title: "JMX/RMI management port exposed",
        detail: "Unauthenticated JMX allows MBean loading and therefore remote code execution.",
    },
    Exposure {
        ports: &[4848],
        id: "KAISEN-GLASSFISH",
        severity: Severity::Medium,
        title: "GlassFish admin console exposed",
        detail: "The admin console has had authentication bypass and traversal issues; restrict it.",
    },
    Exposure {
        ports: &[9990],
        id: "KAISEN-WILDFLY",
        severity: Severity::Medium,
        title: "WildFly/JBoss management exposed",
        detail: "The management interface allows deployment of arbitrary applications.",
    },
    Exposure {
        ports: &[8140],
        id: "KAISEN-PUPPET",
        severity: Severity::Medium,
        title: "Puppet master exposed",
        detail: "The catalog service defines configuration for every managed node.",
    },
    Exposure {
        ports: &[4505, 4506],
        id: "KAISEN-SALT",
        severity: Severity::Critical,
        title: "SaltStack master exposed",
        detail: "Salt's ZeroMQ ports have had unauthenticated RCE (CVE-2020-11651/11652) used at scale.",
    },
    Exposure {
        ports: &[11371],
        id: "KAISEN-HKP",
        severity: Severity::Low,
        title: "OpenPGP key server exposed",
        detail: "Key servers are usually intentional; confirm this one is.",
    },
    Exposure {
        ports: &[502],
        id: "KAISEN-MODBUS",
        severity: Severity::Critical,
        title: "Modbus/TCP exposed",
        detail: "Modbus has no authentication whatsoever: anyone who can reach it can read and write process values.",
    },
    Exposure {
        ports: &[20000],
        id: "KAISEN-DNP3",
        severity: Severity::Critical,
        title: "DNP3 exposed",
        detail: "A SCADA protocol with no authentication in its base form; it must never be internet-facing.",
    },
    Exposure {
        ports: &[44818],
        id: "KAISEN-ENIP",
        severity: Severity::Critical,
        title: "EtherNet/IP/CIP exposed",
        detail: "CIP allows PLC configuration and firmware operations without authentication.",
    },
    Exposure {
        ports: &[47808],
        id: "KAISEN-BACNET",
        severity: Severity::High,
        title: "BACnet exposed",
        detail: "Building automation with no authentication; reachable devices can be commanded directly.",
    },
    Exposure {
        ports: &[102],
        id: "KAISEN-S7",
        severity: Severity::Critical,
        title: "Siemens S7comm exposed",
        detail: "S7 PLC communications are unauthenticated in most configurations.",
    },
    Exposure {
        ports: &[1911, 4911],
        id: "KAISEN-FOX",
        severity: Severity::High,
        title: "Niagara Fox exposed",
        detail: "Tridium Niagara building controllers have had credential disclosure and default-account issues.",
    },
    Exposure {
        ports: &[7547],
        id: "KAISEN-CWMP",
        severity: Severity::High,
        title: "TR-069 CWMP exposed",
        detail: "The ISP provisioning interface has been used for mass router compromise (Mirai/Annie).",
    },
    Exposure {
        ports: &[8291],
        id: "KAISEN-WINBOX",
        severity: Severity::High,
        title: "MikroTik Winbox exposed",
        detail: "Winbox has had an unauthenticated file-read leading to credential disclosure (CVE-2018-14847).",
    },
    Exposure {
        ports: &[37777, 34567],
        id: "KAISEN-DVR",
        severity: Severity::High,
        title: "DVR/NVR control port exposed",
        detail: "Dahua/XiongMai-style DVRs have long-standing unauthenticated access and hardcoded credentials.",
    },
    Exposure {
        ports: &[554, 8554],
        id: "KAISEN-RTSP",
        severity: Severity::Medium,
        title: "RTSP stream exposed",
        detail: "Cameras frequently allow anonymous stream access on well-known paths.",
    },
    Exposure {
        ports: &[9100],
        id: "KAISEN-JETDIRECT",
        severity: Severity::Medium,
        title: "Raw printing port exposed",
        detail: "Port 9100 accepts raw PostScript/PJL, which allows printing, filesystem access and firmware tampering.",
    },
    Exposure {
        ports: &[631],
        id: "KAISEN-IPP",
        severity: Severity::Low,
        title: "IPP/CUPS exposed",
        detail: "The print service enumerates queues and, in some versions, allows remote job and driver manipulation.",
    },
    Exposure {
        ports: &[3306, 3307],
        id: "KAISEN-MYSQL",
        severity: Severity::Medium,
        title: "MySQL/MariaDB exposed",
        detail: "The database is reachable from the network; the handshake already leaks the exact version. Restrict it to application hosts, require TLS, and make sure no account still has a blank or default password.",
    },
    Exposure {
        ports: &[1521, 1522, 1526],
        id: "KAISEN-ORACLE",
        severity: Severity::Medium,
        title: "Oracle Database TNS listener exposed",
        detail: "The TNS listener enumerates services and has a history of unauthenticated listener poisoning (CVE-2012-1675) and default-account access. It should never face an untrusted network.",
    },
    Exposure {
        ports: &[389, 636, 3268, 3269],
        id: "KAISEN-LDAP",
        severity: Severity::Medium,
        title: "LDAP directory exposed",
        detail: "If anonymous bind is allowed, LDAP hands out the entire directory — users, groups and often password policy. On Active Directory this is the starting point for AS-REP roasting and enumeration.",
    },
    Exposure {
        ports: &[88],
        id: "KAISEN-KERBEROS",
        severity: Severity::Low,
        title: "Kerberos KDC exposed",
        detail: "An internet-reachable KDC allows username enumeration and, for accounts without pre-authentication, offline AS-REP roasting of their password hashes.",
    },
    Exposure {
        ports: &[135],
        id: "KAISEN-MSRPC",
        severity: Severity::Medium,
        title: "MSRPC endpoint mapper exposed",
        detail: "The DCE/RPC endpoint mapper enumerates the RPC services and dynamic ports behind it, the reconnaissance step for a long line of Windows lateral-movement and DCOM attacks.",
    },
    Exposure {
        ports: &[139],
        id: "KAISEN-NETBIOS-SSN",
        severity: Severity::Medium,
        title: "NetBIOS session service exposed",
        detail: "The legacy SMB-over-NetBIOS transport allows the same share and null-session enumeration as 445 and keeps SMB1 reachable; it should not face an untrusted network.",
    },
    Exposure {
        ports: &[6000, 6001, 6002, 6003, 6004, 6005],
        id: "KAISEN-X11",
        severity: Severity::High,
        title: "X11 server exposed",
        detail: "An X server that accepts remote connections lets anyone read the screen, log keystrokes and inject input. If access control is disabled (xhost +) this is complete session takeover.",
    },
    Exposure {
        ports: &[5555],
        id: "KAISEN-ADB",
        severity: Severity::High,
        title: "Android Debug Bridge exposed",
        detail: "An exposed ADB daemon accepts shell commands and app installs with no authentication — direct remote code execution. It is scanned continuously by cryptomining worms.",
    },
    Exposure {
        ports: &[5060, 5061],
        id: "KAISEN-SIP",
        severity: Severity::Medium,
        title: "SIP service exposed",
        detail: "An exposed SIP server invites extension enumeration, registration hijacking and toll fraud. Restrict it to known peers and rate-limit registration attempts.",
    },
    Exposure {
        ports: &[1723],
        id: "KAISEN-PPTP",
        severity: Severity::Medium,
        title: "PPTP VPN exposed",
        detail: "PPTP relies on MS-CHAPv2, whose handshake can be captured and cracked to the equivalent of a single DES key. It is deprecated; migrate to IKEv2 or WireGuard.",
    },
    Exposure {
        ports: &[3128],
        id: "KAISEN-PROXY",
        severity: Severity::Medium,
        title: "HTTP proxy exposed",
        detail: "An open forward proxy lets a stranger reach internal hosts and cloud metadata endpoints from your address, and launder abuse through your IP. Confirm it requires authentication and is not open by default.",
    },
    Exposure {
        ports: &[5601],
        id: "KAISEN-KIBANA",
        severity: Severity::High,
        title: "Kibana exposed",
        detail: "Kibana fronts Elasticsearch; an unauthenticated instance reads and writes every index and has had server-side RCE (CVE-2019-7609). It belongs behind authentication and off the internet.",
    },
    Exposure {
        ports: &[9090],
        id: "KAISEN-PROMETHEUS",
        severity: Severity::Medium,
        title: "Prometheus exposed",
        detail: "Prometheus has no authentication of its own. Its targets, service-discovery config and metrics map the internal network, and /api/v1/admin can delete series. Put it behind a reverse proxy that authenticates.",
    },
    Exposure {
        ports: &[8088],
        id: "KAISEN-YARN",
        severity: Severity::High,
        title: "Hadoop YARN ResourceManager exposed",
        detail: "An unauthenticated YARN REST API on 8088 accepts application submissions, which is code execution across the cluster — one of the most-scanned cryptomining footholds. Enable Kerberos and firewall it.",
    },
    Exposure {
        ports: &[7077, 6066],
        id: "KAISEN-SPARK",
        severity: Severity::High,
        title: "Apache Spark master exposed",
        detail: "The Spark standalone master and its hidden REST submission API (6066) run submitted jobs as code with no authentication by default. Bind them to the cluster network only.",
    },
    Exposure {
        ports: &[8265],
        id: "KAISEN-RAY",
        severity: Severity::Critical,
        title: "Ray dashboard exposed",
        detail: "The Ray Jobs API (CVE-2023-48022, 'ShadowRay') accepts arbitrary job submission with no authentication, giving RCE on every node. Exploited in the wild for cryptomining; it must never be reachable.",
    },
    Exposure {
        ports: &[2323],
        id: "KAISEN-TELNET-ALT",
        severity: Severity::High,
        title: "Telnet on an alternate port",
        detail: "Telnet on 2323 is the port the Mirai family scans after 23; it is cleartext and, on IoT gear, usually protected by a hardcoded or default password.",
    },
];

pub fn assess_udp(port: u16, svc: Option<&ServiceInfo>) -> Vec<Finding> {
    let mut out = Vec::new();
    let reported = svc
        .map(|s| format!("{} {} {}", s.product, s.version, s.extra).to_ascii_lowercase())
        .unwrap_or_default();

    let mut push = |id: &str, severity: Severity, title: &str, detail: &str| {
        out.push(Finding {
            id: id.to_string(),
            severity,
            title: title.to_string(),
            detail: detail.to_string(),
        });
    };

    // Conditions the probe actually established, which beat any port guess.
    for c in UDP_CONDITIONS {
        if reported.contains(c.needle) {
            push(c.id, c.severity, c.title, c.detail);
        }
    }

    // Port-level exposure, independent of what the banner said.
    let exposure = exposure_for(UDP_EXPOSURES, port);
    if let Some(e) = exposure {
        push(e.id, e.severity, e.title, e.detail);
    }

    out
}

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

    // CVE correlation: detected product + version against the embedded CVE
    // range table. Independent of the exact-version SIGS above — it fires on
    // ranges and only when the version actually lands inside one.
    out.extend(crate::vuln::cve::correlate(svc));

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

    // Port-level exposure heuristics (independent of banner), each passed
    // through its confirmation gate if it has one.
    if let Some(e) = exposure_for(TCP_EXPOSURES, port) {
        let verdict = gate_for(e.id)
            .map(|g| (g.confirm)(svc))
            .unwrap_or(Confirm::Verified);
        match verdict {
            Confirm::Refuted => {}
            Confirm::Verified => out.push(Finding {
                id: e.id.to_string(),
                severity: e.severity,
                title: e.title.to_string(),
                detail: e.detail.to_string(),
            }),
            Confirm::Unverified => out.push(Finding {
                id: e.id.to_string(),
                severity: Severity::Info,
                title: format!("{} (unverified)", e.title),
                detail: format!(
                    "Port {port} is typically {}, but the protocol was not confirmed on this \
                     host — treat as a lead, not a finding. {}",
                    e.title.to_ascii_lowercase(),
                    e.detail
                ),
            }),
        }
    }

    out
}

/// An active check that confirms a finding by speaking one request to the
/// service, rather than inferring it from the port. Kept as data so
/// `--vuln-list` can enumerate them alongside the passive rules.
pub struct ActiveCheck {
    pub id: &'static str,
    /// Human description of what triggers the probe, for `--vuln-list`.
    pub trigger: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub detail: &'static str,
}

pub const ACTIVE_CHECKS: &[ActiveCheck] = &[
    ActiveCheck {
        id: "KAISEN-MEILI-NOAUTH",
        trigger: "7700: GET /indexes returns data, not 401",
        severity: Severity::High,
        title: "Meilisearch has no master key (data exposed)",
        detail: "GET /indexes answered with index data and no Authorization header — every \
                 route is public, so all indexed documents are readable and writable. Set \
                 MEILI_MASTER_KEY.",
    },
    ActiveCheck {
        id: "KAISEN-EZVIZ-9010-CLEARTEXT",
        trigger: "9010 on an Ezviz device: cleartext accepted",
        severity: Severity::High,
        title: "Ezviz command port accepts cleartext (auth not enforced)",
        detail: "The Ezviz command port on 9010 processed an unencrypted request. The AES \
                 pre-shared-key is optional rather than enforced (CVE-2023-48121 class), so \
                 plaintext requests are honoured. Verify manually.",
    },
    ActiveCheck {
        id: "KAISEN-REDIS-NOAUTH",
        trigger: "6379/6380: PING answers +PONG without auth",
        severity: Severity::High,
        title: "Redis reachable without authentication",
        detail: "Redis answered PING with +PONG and no password. Unauthenticated Redis allows \
                 full data theft and, via CONFIG/module abuse, remote code execution. Set \
                 requirepass or bind it to localhost.",
    },
    ActiveCheck {
        id: "KAISEN-ES-NOAUTH",
        trigger: "9200: GET / returns the cluster document, not 401",
        severity: Severity::High,
        title: "Elasticsearch reachable without authentication",
        detail: "GET / answered with the cluster document (name, version, tagline) and no \
                 Authorization header — every index is readable and writable. Enable the \
                 built-in security (xpack.security.enabled) and set passwords.",
    },
    ActiveCheck {
        id: "KAISEN-PROMETHEUS-OPEN",
        trigger: "9090: /api/v1/status/buildinfo answers without auth",
        severity: Severity::Medium,
        title: "Prometheus reachable without authentication",
        detail: "The Prometheus API answered an unauthenticated request. Its targets and \
                 service-discovery config map the internal network, and the admin API can \
                 delete series. Front it with an authenticating reverse proxy.",
    },
    ActiveCheck {
        id: "KAISEN-ACTUATOR-ENV",
        trigger: "Spring Boot: /actuator/env exposes configuration",
        severity: Severity::High,
        title: "Spring Boot actuator env endpoint exposed",
        detail: "/actuator/env (or /env) returned the application's property sources with no \
                 authentication, which routinely include database passwords and API keys. \
                 Restrict the actuator endpoints and require authentication on them.",
    },
    ActiveCheck {
        id: "CVE-2014-0160",
        trigger: "TLS port: Heartbeat memory disclosure (Heartbleed)",
        severity: Severity::Critical,
        title: "OpenSSL TLS Heartbleed (CVE-2014-0160)",
        detail: "The TLS service answered a malformed Heartbeat request with process memory. \
                 Upgrade OpenSSL immediately and rotate exposed private keys.",
    },
    ActiveCheck {
        id: "CVE-2022-22965",
        trigger: "Spring app: classLoader binding parameters accepted",
        severity: Severity::Critical,
        title: "Spring Framework RCE (Spring4Shell, CVE-2022-22965)",
        detail: "Spring Framework on Java 9+ allows unauthenticated RCE via DataBinder classLoader access. \
                 Upgrade Spring Framework to 5.3.18+ / 5.2.20+.",
    },
];

fn active(id: &str) -> &'static ActiveCheck {
    ACTIVE_CHECKS
        .iter()
        .find(|c| c.id == id)
        .expect("active check id must exist in ACTIVE_CHECKS")
}

fn finding_from(c: &ActiveCheck) -> Finding {
    Finding {
        id: c.id.to_string(),
        severity: c.severity,
        title: c.title.to_string(),
        detail: c.detail.to_string(),
    }
}

/// Active `-vuln` confirmation: speak one request to a handful of services to
/// turn a port heuristic into a confirmed (or refuted) finding. Runs only under
/// `-vuln`, only on ports/services that match, and never writes state.
///
/// `host_ezviz` carries the one piece of cross-port context needed: the Ezviz
/// identity lives on the TLS panel's certificate, but the finding is about the
/// separate cleartext command port.
pub async fn assess_active(
    addr: std::net::SocketAddr,
    svc: &ServiceInfo,
    host_ezviz: bool,
    timeout_ms: u64,
) -> Vec<Finding> {
    let dur = std::time::Duration::from_millis(timeout_ms.max(1000));
    let port = addr.port();
    let hay = haystack(svc);
    let mut out = Vec::new();

    // Heartbleed active probe on TLS endpoints
    if !svc.tls_version.is_empty() {
        if crate::tls::check_heartbleed(addr, dur).await {
            out.push(finding_from(active("CVE-2014-0160")));
        }
    }

    // Meilisearch with no master key: every route is public.
    if port == 7700 || hay.contains("meilisearch") {
        if let Some((code, body)) = crate::service::probe::http_get(addr, "", "/indexes", dur).await
        {
            let looks_like_data = body.contains("\"results\"")
                || body.contains("\"uid\"")
                || body.trim_start().starts_with('[');
            if code == 200 && looks_like_data {
                out.push(finding_from(active("KAISEN-MEILI-NOAUTH")));
            }
        }
    }

    // (Docker's unauthenticated API is already confirmed during detection —
    // service.rs probes /version and sets the "UNAUTHENTICATED DOCKER API"
    // marker that the KAISEN-DOCKER-API signature fires on — so no active
    // check is needed here.)

    // Kubernetes API server: confirm via /version, which upgrades the passive
    // KUBE-API lead (Info) to a verified Medium finding once dedup collapses
    // the two by shared id.
    if matches!(port, 6443 | 8443 | 10250) && !svc.tls_version.is_empty() {
        let sni = addr.ip().to_string();
        if let Some((_, body)) = crate::service::probe::https_get(addr, &sni, "/version", dur).await
        {
            let is_kube = body.contains("\"gitVersion\"")
                || (body.contains("\"major\"") && body.contains("\"minor\""));
            if is_kube {
                out.push(Finding {
                    id: "KAISEN-KUBE-API".into(),
                    severity: Severity::Medium,
                    title: "Kubernetes API server confirmed (via /version)".into(),
                    detail: "The /version endpoint returned a Kubernetes version document. \
                             Verify anonymous-auth is off and RBAC is enforced; the API \
                             server should not be internet-facing."
                        .into(),
                });
            }
        }
    }

    // Ezviz command port accepting cleartext, on a host already fingerprinted
    // as Ezviz elsewhere.
    if port == 9010 && host_ezviz && crate::service::probe::ezviz_cleartext(addr, dur).await {
        out.push(finding_from(active("KAISEN-EZVIZ-9010-CLEARTEXT")));
    }

    // Redis answering without a password.
    if (port == 6379 || port == 6380 || hay.contains("redis"))
        && crate::service::probe::redis_unauth(addr, dur).await
    {
        out.push(finding_from(active("KAISEN-REDIS-NOAUTH")));
    }

    // GET over cleartext or the TLS client, whichever the port is speaking, so
    // one call site handles both an http and an https instance of a service.
    let sni = addr.ip().to_string();
    let get = |path: &'static str| {
        let sni = sni.clone();
        let tls = !svc.tls_version.is_empty();
        async move {
            if tls {
                crate::service::probe::https_get(addr, &sni, path, dur).await
            } else {
                crate::service::probe::http_get(addr, "", path, dur).await
            }
        }
    };

    // Elasticsearch answering its cluster document with no credential.
    if port == 9200 || port == 9201 || hay.contains("elasticsearch") {
        if let Some((code, body)) = get("/").await {
            let is_es = body.contains("\"cluster_name\"")
                || body.contains("You Know, for Search")
                || (body.contains("\"lucene_version\"") && body.contains("\"number\""));
            if code == 200 && is_es {
                out.push(finding_from(active("KAISEN-ES-NOAUTH")));
            }
        }
    }

    // Prometheus answering its API with no credential.
    if port == 9090 || hay.contains("prometheus") {
        if let Some((code, body)) = get("/api/v1/status/buildinfo").await {
            let is_prom = body.contains("\"status\":\"success\"")
                && (body.contains("\"version\"") || body.contains("goVersion"));
            if code == 200 && is_prom {
                out.push(finding_from(active("KAISEN-PROMETHEUS-OPEN")));
            }
        }
    }

    // Spring Boot actuator leaking the application's configuration.
    if hay.contains("spring") || hay.contains("actuator") || hay.contains("whitelabel") {
        for path in ["/actuator/env", "/env"] {
            if let Some((code, body)) = get(path).await {
                if code == 200
                    && (body.contains("\"propertySources\"") || body.contains("\"activeProfiles\""))
                {
                    out.push(finding_from(active("KAISEN-ACTUATOR-ENV")));
                    break;
                }
            }
        }
    }

    // Spring4Shell active probe
    if hay.contains("spring") || hay.contains("whitelabel") || hay.contains("tomcat") {
        if let Some((code, body)) = get("/?class.module.classLoader.URLs%5B0%5D=0").await {
            if code == 200 && (body.contains("org.springframework") || body.contains("whitelabel"))
            {
                out.push(finding_from(active("CVE-2022-22965")));
            }
        }
    }

    out
}

/// Collapse findings that share an id, keeping the most severe. The passive and
/// active layers can both speak to one issue (a KUBE-API lead and its /version
/// confirmation); this leaves one row, at the higher severity.
pub fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut kept: Vec<Finding> = Vec::new();
    for cur in findings.drain(..) {
        if let Some(existing) = kept.iter_mut().find(|e| e.id == cur.id) {
            if cur.severity.rank() > existing.severity.rank() {
                *existing = cur;
            }
        } else {
            kept.push(cur);
        }
    }
    *findings = kept;
}

// ── the database, as a thing you can read ──────────────────────────────────

/// The two certificate-hygiene checks. They live in `assess()` because they
/// come from the TLS prober rather than from any product signature, but they
/// are part of the database and are listed as such.
const CERT_CHECKS: &[(&str, Severity, &str)] = &[
    (
        "KAISEN-TLS-EXPIRED",
        Severity::Medium,
        "TLS certificate has expired",
    ),
    (
        "KAISEN-TLS-SELFSIGNED",
        Severity::Low,
        "TLS certificate is self-signed",
    ),
];

/// Column widths, measured from the tables: the longest id is 24 characters
/// (KAISEN-MEMCACHED-EXPOSED) and the longest subject is 31
/// (Microsoft Active Directory LDAP), each with a little room to grow.
const ID_WIDTH: usize = 26;
const SUBJECT_WIDTH: usize = 32;

fn ports_label(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Print the whole database: every rule Kaisen can fire, with no network
/// traffic at all. `min` applies the same severity threshold as --min-severity
/// so the listing and a real scan agree about what is worth showing.
///
/// The totals at the end are counted from the tables themselves, which is the
/// point: the number in the documentation should never be something anyone had
/// to remember.
pub fn print_catalogue(min: Option<Severity>, color: bool) {
    let p = Painter::new(color);
    let keep = |s: Severity| min.map(|m| s.rank() >= m.rank()).unwrap_or(true);

    let sev = |s: Severity| {
        let l = format!("{:<8}", s.label());
        match s {
            Severity::Critical => p.bold(&p.red(&l)),
            Severity::High => p.red(&l),
            Severity::Medium => p.yellow(&l),
            Severity::Low => p.blue(&l),
            Severity::Info => p.dim(&l),
        }
    };

    // Pad first, colour second. Formatting an *already coloured* string counts
    // the ANSI escape bytes as width, which silently eats the padding and
    // ragged-edges every column. That is why this is one helper and not five
    // call sites that each have to remember the order.
    let row = |severity: Severity, id: &str, subject: &str, title: &str| {
        println!(
            "  {} {} {} {}",
            sev(severity),
            p.cyan(&format!("{:<w$}", id, w = ID_WIDTH)),
            format!("{:<w$}", subject, w = SUBJECT_WIDTH),
            title
        );
    };

    println!();
    println!(
        "{} {}",
        p.bold("Kaisen vulnerability database"),
        p.dim("— every rule -vuln can fire. Nothing is sent to the network.")
    );

    let mut shown = 0usize;

    println!();
    println!(
        "{}",
        p.bold("VERSION SIGNATURES  (product + version predicate)")
    );
    for s in SIGS {
        if !keep(s.severity) {
            continue;
        }
        shown += 1;
        row(s.severity, s.id, s.product, s.title);
    }

    println!();
    println!(
        "{}",
        p.bold("CVE CORRELATION  (product + affected version range)")
    );
    for e in crate::vuln::cve::CVE_DB {
        if !keep(e.severity) {
            continue;
        }
        shown += 1;
        row(e.severity, e.cve, e.match_product, e.title);
    }

    println!();
    println!(
        "{}",
        p.bold("TCP PORT EXPOSURE  (reachable at all is the finding)")
    );
    for e in TCP_EXPOSURES {
        if !keep(e.severity) {
            continue;
        }
        shown += 1;
        row(e.severity, e.id, &ports_label(e.ports), e.title);
    }

    println!();
    println!("{}", p.bold("UDP PORT EXPOSURE"));
    for e in UDP_EXPOSURES {
        if !keep(e.severity) {
            continue;
        }
        shown += 1;
        row(e.severity, e.id, &ports_label(e.ports), e.title);
    }

    println!();
    println!(
        "{}",
        p.bold("UDP PROBE CONDITIONS  (what the probe established, not the port)")
    );
    for c in UDP_CONDITIONS {
        if !keep(c.severity) {
            continue;
        }
        shown += 1;
        row(c.severity, c.id, &format!("\"{}\"", c.needle), c.title);
    }

    println!();
    println!(
        "{}",
        p.bold("ACTIVE CHECKS  (-vuln speaks one request to confirm)")
    );
    for c in ACTIVE_CHECKS {
        if !keep(c.severity) {
            continue;
        }
        shown += 1;
        row(c.severity, c.id, c.trigger, c.title);
    }

    println!();
    println!("{}", p.bold("CERTIFICATE HYGIENE"));
    for (id, s, title) in CERT_CHECKS {
        if !keep(*s) {
            continue;
        }
        shown += 1;
        row(*s, id, "any TLS port", title);
    }

    let total = SIGS.len()
        + crate::vuln::cve::CVE_DB.len()
        + TCP_EXPOSURES.len()
        + UDP_EXPOSURES.len()
        + UDP_CONDITIONS.len()
        + ACTIVE_CHECKS.len()
        + CERT_CHECKS.len();
    let tcp_ports: std::collections::BTreeSet<u16> = TCP_EXPOSURES
        .iter()
        .flat_map(|e| e.ports.iter().copied())
        .collect();
    let udp_ports: std::collections::BTreeSet<u16> = UDP_EXPOSURES
        .iter()
        .flat_map(|e| e.ports.iter().copied())
        .collect();
    let cves =
        SIGS.iter().filter(|s| s.id.starts_with("CVE-")).count() + crate::vuln::cve::CVE_DB.len();

    println!();
    println!("{}", p.bold("TOTALS"));
    println!("  {:<34} {}", "version signatures", SIGS.len());
    println!(
        "  {:<34} {}",
        "CVE range correlations",
        crate::vuln::cve::CVE_DB.len()
    );
    println!("  {:<34} {}", "  total carrying a CVE id", cves);
    println!(
        "  {:<34} {} ({} ports)",
        "TCP port exposure heuristics",
        TCP_EXPOSURES.len(),
        tcp_ports.len()
    );
    println!(
        "  {:<34} {} ({} ports)",
        "UDP port exposure heuristics",
        UDP_EXPOSURES.len(),
        udp_ports.len()
    );
    println!("  {:<34} {}", "UDP probe conditions", UDP_CONDITIONS.len());
    println!("  {:<34} {}", "active checks", ACTIVE_CHECKS.len());
    println!("  {:<34} {}", "certificate checks", CERT_CHECKS.len());
    println!(
        "  {} {}",
        p.bold(&format!("{:<34}", "total rules")),
        p.bold(&total.to_string())
    );
    if min.is_some() {
        println!(
            "  {}",
            p.dim(&format!(
                "{shown} shown at this severity threshold; drop --min-severity for all {total}"
            ))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Products that no marker table names, because a protocol probe or a
    /// `Server:` header sets them directly. Each one is a real assignment in
    /// service.rs, probe.rs, tls.rs or udp.rs.
    const PRODUCTS_FROM_PROBES: &[&str] = &[
        "Apache ZooKeeper",
        "BIND",
        "Docker Engine",
        "Elasticsearch",
        "MQTT",
        "MariaDB",
        "Memcached",
        "Microsoft Active Directory LDAP",
        "Microsoft SQL Server",
        "Microsoft Terminal Services",
        "Microsoft-IIS",
        "Minecraft",
        "MongoDB",
        "MySQL",
        "Oracle TNS",
        "PHP",
        "Pure-FTPd",
        "Redis",
        "SMB",
        "SOCKS proxy",
        "TLS",
        "X11",
        "dnsmasq",
        "nginx",
        "vsFTPd",
        "Apache",
        "Postfix",
        "Sendmail",
        // Set while parsing the SSH greeting and the FTP 220 line.
        "OpenSSH",
        "Dropbear sshd",
        "libssh",
        "ProFTPD",
        "FileZilla",
        "Serv-U",
        // Set while parsing the VNC (RFB) greeting.
        "RealVNC",
        // `probe::dns_version` names the daemon from the version.bind TXT.
        "Microsoft DNS",
        // Read straight off a `Server:` header by parse_server_header. MiniServ
        // is Webmin's own httpd, and its version *is* Webmin's version; RomPager
        // is Allegro's embedded server, on a very large number of DSL routers.
        "MiniServ",
        "RomPager",
    ];

    /// Strings the CVE table keys on that live in a service's **banner or
    /// extra** rather than in `product`. `cve::correlate` matches over
    /// product+banner+extra — that is how a library version quoted inside a
    /// `Server:` header correlates at all — so its reachability list is wider
    /// than the signature one. Each entry here is a real substring of something
    /// a probe records.
    const CVE_BANNER_TOKENS: &[&str] = &[
        // "Server: Apache/2.4.7 (Ubuntu) OpenSSL/1.0.1f": parse_server_header
        // keeps everything after the first token in `extra`, modules included.
        "OpenSSL",
        // The same shape, one line further down the same header: a UPnP device
        // announces "Linux/4.1 UPnP/1.0 Portable SDK for UPnP devices/1.6.18",
        // so the library — and its version — live behind the OS that leads.
        "Portable SDK for UPnP devices",
        // The BSD ftpd greeting: "220 h FTP server (Version 6.00LS) ready."
        "FTP server (Version 6.",
        // probe::rdp writes the negotiation result into `extra`, and this is
        // the phrase it uses when the server settled for pre-NLA security.
        "standard RDP security",
        // apply_tls records the negotiated protocol in `tls_version`, which
        // cve::correlate reads alongside the banner: "SSL 3.0", "TLS 1.2".
        "SSL 3.0",
        // Windows and Java libraries/components often checked in banner/extra:
        "Log4j",
        "Netlogon",
    ];

    /// Every product string `service.rs`, `probe.rs`, `tls.rs` or `udp.rs` can
    /// put in `ServiceInfo::product`.
    fn emittable_products() -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        v.extend(
            crate::service::APP_MARKERS
                .iter()
                .map(|(_, label)| label.to_string()),
        );
        v.extend(crate::service::MAIL_PRODUCTS.iter().map(|p| p.to_string()));
        // Canonical names written by the `Server:` and SSH banner parsers.
        v.extend(
            crate::service::SERVER_ALIASES
                .iter()
                .map(|(_, p)| p.to_string()),
        );
        v.extend(
            crate::service::SSH_SOFTWARE
                .iter()
                .map(|(_, p)| p.to_string()),
        );
        v.extend(PRODUCTS_FROM_PROBES.iter().map(|p| p.to_string()));
        v
    }

    fn unreachable_in<'a>(
        products: impl Iterator<Item = &'a str>,
        sources: &[String],
    ) -> Vec<&'a str> {
        products
            .filter(|p| {
                !sources
                    .iter()
                    .any(|e| e.to_ascii_lowercase().contains(&p.to_ascii_lowercase()))
            })
            .collect()
    }

    /// A signature only ever fires if `service.rs` can produce a product string
    /// containing it (`assess` does a case-insensitive substring match). One
    /// that nothing can produce never fails at runtime — it just sits in the
    /// database inflating the count and implying coverage that is not there.
    /// That is exactly how the SambaCry signature came to be dead, so this test
    /// exists to stop it happening again.
    #[test]
    fn every_signature_product_is_reachable() {
        let emittable = emittable_products();
        let unreachable = unreachable_in(SIGS.iter().map(|s| s.product), &emittable);

        assert!(
            unreachable.is_empty(),
            "these signature products can never be produced by service.rs, so the \
             signatures are dead: {unreachable:?}. Either fix the product string or \
             add a marker to APP_MARKERS."
        );
    }

    /// The same rule for the CVE table, which matches over product, banner and
    /// extra rather than product alone — so a key may also be one of the
    /// documented banner tokens. A CVE entry nothing can match is worse than
    /// missing: it counts towards the database's size while covering nothing.
    #[test]
    fn every_cve_product_is_reachable() {
        let mut sources = emittable_products();
        sources.extend(CVE_BANNER_TOKENS.iter().map(|t| t.to_string()));
        let unreachable = unreachable_in(
            crate::vuln::cve::CVE_DB.iter().map(|e| e.match_product),
            &sources,
        );

        assert!(
            unreachable.is_empty(),
            "these CVE match_product strings can never appear in what a probe \
             reports, so the entries are dead: {unreachable:?}. Either fix the \
             string, add a marker to APP_MARKERS, or document the banner it \
             comes from in CVE_BANNER_TOKENS."
        );
    }

    /// No finding may be reported twice for one service.
    ///
    /// `assess` walks the whole table and pushes *every* match, and it matches
    /// products by case-insensitive substring. So two entries sharing an id are
    /// only safe when their products are disjoint — neither a substring of the
    /// other. KAISEN-DB-EXPOSED is the legitimate case: one conclusion reported
    /// for MySQL and for MariaDB, two names that never describe the same
    /// service.
    ///
    /// This replaces an earlier test that only compared severities. Seven
    /// duplicate signatures passed that test, and reached a release, because
    /// duplicates naturally agree about how bad they are. Checking the
    /// accessory property is worse than useless: it looks like coverage.
    #[test]
    fn no_finding_can_be_reported_twice() {
        let mut clashes: Vec<String> = Vec::new();
        for (i, a) in SIGS.iter().enumerate() {
            for b in SIGS.iter().skip(i + 1) {
                if a.id != b.id {
                    continue;
                }
                let (pa, pb) = (
                    a.product.to_ascii_lowercase(),
                    b.product.to_ascii_lowercase(),
                );
                if pa.contains(&pb) || pb.contains(&pa) {
                    clashes.push(format!("{} on {:?} and {:?}", a.id, a.product, b.product));
                }
            }
        }
        assert!(
            clashes.is_empty(),
            "these signatures would both fire on the same service, printing the \
             same finding twice: {clashes:#?}"
        );
    }

    /// An id may deliberately cover several products, but it must always carry
    /// the same severity — otherwise `--min-severity` would keep a given id in
    /// one place and drop it in another.
    #[test]
    fn shared_ids_agree_on_severity() {
        let mut seen: std::collections::HashMap<&str, Severity> = std::collections::HashMap::new();
        for s in SIGS {
            if let Some(prev) = seen.insert(s.id, s.severity) {
                assert_eq!(
                    prev.label(),
                    s.severity.label(),
                    "id {} carries two different severities",
                    s.id
                );
            }
        }
    }

    /// An id is what a user greps for after a scan, so it must mean exactly one
    /// thing across the whole database. The UDP twin of a TCP exposure carries
    /// the -UDP suffix for precisely this reason.
    #[test]
    fn ids_are_unique_across_the_exposure_tables() {
        let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let rows = TCP_EXPOSURES
            .iter()
            .map(|e| (e.id, "TCP"))
            .chain(UDP_EXPOSURES.iter().map(|e| (e.id, "UDP")))
            .chain(UDP_CONDITIONS.iter().map(|c| (c.id, "UDP condition")))
            .chain(CERT_CHECKS.iter().map(|(id, _, _)| (*id, "certificate")));
        for (id, table) in rows {
            if let Some(prev) = seen.insert(id, table) {
                panic!("id {id} is used by both the {prev} and {table} tables");
            }
        }
    }

    /// Every exposure must list at least one port, or it can never be looked up.
    #[test]
    fn exposures_have_ports() {
        for e in TCP_EXPOSURES.iter().chain(UDP_EXPOSURES) {
            assert!(!e.ports.is_empty(), "{} lists no ports", e.id);
        }
    }

    // ── Protocol-confirmation gates ──────────────────────────────────────────

    /// A gate is useless if it names an id no exposure carries — it would
    /// silently never run. Every gate must attach to a real exposure.
    #[test]
    fn every_gate_targets_a_real_exposure() {
        for g in GATES {
            assert!(
                TCP_EXPOSURES.iter().any(|e| e.id == g.id),
                "gate {} targets no exposure",
                g.id
            );
        }
    }

    fn svc(name: &str) -> ServiceInfo {
        ServiceInfo {
            name: name.to_string(),
            ..Default::default()
        }
    }
    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.id.as_str()).collect()
    }
    fn find<'a>(f: &'a [Finding], id: &str) -> Option<&'a Finding> {
        f.iter().find(|x| x.id == id)
    }

    /// Case 3 of the audit: a Chromecast on 8009 answers a TLS handshake with
    /// a UUID CN. That is not cleartext AJP, so Ghostcat must not fire.
    #[test]
    fn cast_on_8009_is_not_ghostcat() {
        let mut cast = svc("https");
        cast.tls_version = "TLS 1.2".into();
        cast.product = "TLS".into();
        cast.hostnames = vec!["a1b2c3d4-0000-1111-2222-334455667788".into()];
        assert_eq!(confirm_ajp(&cast), Confirm::Refuted);
        assert!(!ids(&assess(8009, &cast)).contains(&"KAISEN-AJP-GHOSTCAT"));
    }

    /// A port 8009 that actually speaks AJP13 still trips Ghostcat.
    #[test]
    fn real_ajp_on_8009_still_fires() {
        let mut ajp = svc("ajp13");
        ajp.product = "Apache JServ Protocol".into();
        assert_eq!(confirm_ajp(&ajp), Confirm::Verified);
        let f = assess(8009, &ajp);
        assert_eq!(
            find(&f, "KAISEN-AJP-GHOSTCAT").unwrap().severity,
            Severity::High
        );
    }

    /// Case 2 of the audit: an Ezviz camera on 9010 (cert O=Ezviz, so detection
    /// tags the product "TLS / Ezviz"). It is not JMX and must not be flagged.
    #[test]
    fn ezviz_on_9010_is_not_jmx() {
        let mut cam = svc("https");
        cam.tls_version = "TLS 1.2".into();
        cam.product = "TLS / Ezviz".into();
        assert_eq!(confirm_jmx(&cam), Confirm::Refuted);
        assert!(!ids(&assess(9010, &cam)).contains(&"KAISEN-JMX"));
    }

    /// An unidentified plaintext service on 9010 is neither confirmed nor
    /// refuted, so JMX is emitted — but degraded to Info, not High.
    #[test]
    fn unidentified_9010_is_an_info_lead_not_a_high() {
        let f = assess(9010, &svc("unknown"));
        let jmx = find(&f, "KAISEN-JMX").expect("JMX should still appear as a lead");
        assert_eq!(jmx.severity, Severity::Info);
        assert!(jmx.title.contains("unverified"));
    }

    /// Case 2, second half: the Ezviz management panel on 8443 must not be
    /// reported as a Kubernetes API server.
    #[test]
    fn ezviz_on_8443_is_not_kube_api() {
        let mut panel = svc("https");
        panel.tls_version = "TLS 1.2".into();
        panel.product = "TLS / Ezviz".into();
        assert_eq!(confirm_kube(&panel), Confirm::Refuted);
        assert!(!ids(&assess(8443, &panel)).contains(&"KAISEN-KUBE-API"));
    }

    /// A generic HTTPS service on 8443 is a Kubernetes lead at most — Info,
    /// pending the active /version check that can promote it.
    #[test]
    fn generic_8443_kube_is_only_a_lead() {
        let mut https = svc("https");
        https.tls_version = "TLS 1.2".into();
        https.product = "TLS".into();
        let kube = find(&assess(8443, &https), "KAISEN-KUBE-API").cloned();
        assert_eq!(kube.unwrap().severity, Severity::Info);
    }

    /// Ungated exposures are untouched: a plain port heuristic still fires at
    /// its declared severity with no confirmation dance.
    #[test]
    fn ungated_exposures_are_unchanged() {
        let f = assess(23, &svc("telnet"));
        assert_eq!(find(&f, "KAISEN-TELNET").unwrap().severity, Severity::High);
    }

    // ── Active checks ────────────────────────────────────────────────────────

    /// Every id `active()` looks up must exist, or `finding_from(active(id))`
    /// panics at runtime.
    #[test]
    fn active_check_ids_resolve() {
        for id in [
            "KAISEN-MEILI-NOAUTH",
            "KAISEN-EZVIZ-9010-CLEARTEXT",
            "KAISEN-REDIS-NOAUTH",
            "KAISEN-ES-NOAUTH",
            "KAISEN-PROMETHEUS-OPEN",
            "KAISEN-ACTUATOR-ENV",
        ] {
            assert_eq!(active(id).id, id);
        }
    }

    /// The KUBE-API promotion: the passive lead (Info, unverified) and the
    /// active confirmation (Medium) share an id, and dedup must keep the
    /// Medium — otherwise a confirmed API server would read as a mere lead.
    #[test]
    fn dedup_keeps_the_more_severe_of_a_shared_id() {
        let mut f = vec![
            Finding {
                id: "KAISEN-KUBE-API".into(),
                severity: Severity::Info,
                title: "Kubernetes API server reachable (unverified)".into(),
                detail: String::new(),
            },
            Finding {
                id: "KAISEN-KUBE-API".into(),
                severity: Severity::Medium,
                title: "Kubernetes API server confirmed (via /version)".into(),
                detail: String::new(),
            },
        ];
        dedup_findings(&mut f);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].title.contains("confirmed"));
    }

    /// Distinct ids are all preserved; dedup only collapses collisions.
    #[test]
    fn dedup_preserves_distinct_ids() {
        let mut f = vec![
            Finding {
                id: "A".into(),
                severity: Severity::Low,
                title: "a".into(),
                detail: String::new(),
            },
            Finding {
                id: "B".into(),
                severity: Severity::High,
                title: "b".into(),
                detail: String::new(),
            },
        ];
        dedup_findings(&mut f);
        assert_eq!(f.len(), 2);
    }
}
