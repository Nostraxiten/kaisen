//! Hand-rolled argument parser.
//!
//! We can't use a standard `-x` short-flag parser because Kaisen's headline
//! flags are *multi-letter* shorts (`-OS`, `-HS`, `-PF`, `-PA`, `-sV`, `-Pn`).
//! A getopt-style parser would split `-OS` into `-O -S`. So we tokenise
//! explicitly and match whole tokens, while still supporting stacked
//! verbosity (`-vvv`) and nmap-style long options.

use crate::ports;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Scan,
    Dns,
    Mail,
    Lookup,
    Whois,
    Neighbor,
    NsAudit,
    /// --vuln-list: print the signature database and exit, touching nothing.
    VulnList,
    Help,
    Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    /// TCP connect() — works without root. The default and the fast path.
    Connect,
    /// SYN half-open — needs raw sockets/root; falls back to Connect if denied.
    Syn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    Any,
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct Timing {
    pub concurrency: usize,
    pub connect_timeout_ms: u64,
    pub retries: u32,
    pub host_delay_ms: u64,
    /// Maximum new TCP connections launched per second (token-bucket rate
    /// limiter). 0 means unlimited. Set for T0–T3 to avoid filling the NAT
    /// router's conntrack table — each timed-out connect() leaves a zombie
    /// entry for up to 120 s even after Kaisen moves on. T4/T5 skip the
    /// limiter because they target local nets with no NAT in the path.
    pub max_rate: u32,
}

impl Timing {
    /// Map an nmap-style timing template (0..5) to concrete parameters.
    ///
    /// ## connect() and NAT conntrack
    ///
    /// Unlike nmap's raw-SYN scan (`-sS`), Kaisen uses `connect()` which goes
    /// through the kernel's normal TCP stack. Every outgoing SYN creates an
    /// entry in the NAT router's conntrack table. When a port times out (no
    /// SYN-ACK), Kaisen moves on — but the **router** keeps that zombie entry
    /// for its own `nf_conntrack_tcp_timeout_syn_sent` (typically 60–120 s),
    /// independent of Kaisen's timeout. If the table fills up, the router drops
    /// all traffic (including DNS), killing the local internet connection.
    ///
    /// T3's concurrency of 30 is chosen to stay well within the conntrack table
    /// of a typical home router (usually 1 024–4 096 entries). T4 stays
    /// WAN-safe too — faster, but still rate-capped, because users reach for it
    /// to speed up internet scans, not just LAN ones. Only T5 (and `-HS`) drop
    /// the guard rails entirely, for a LAN or isolated lab with no NAT and no
    /// stateful firewall in the path.
    pub fn from_template(t: u8) -> Timing {
        match t {
            0 => Timing { concurrency: 1,   connect_timeout_ms: 5000, retries: 3, host_delay_ms: 500, max_rate: 5   },
            1 => Timing { concurrency: 10,  connect_timeout_ms: 3000, retries: 2, host_delay_ms: 100, max_rate: 15  },
            2 => Timing { concurrency: 20,  connect_timeout_ms: 2000, retries: 2, host_delay_ms: 10,  max_rate: 30  },
            // T3 (default): 30 concurrent, 50/s rate cap — safe for home-router
            // NAT conntrack. Each timed-out connect() leaves a zombie entry in
            // the router for 60-120 s; the rate cap keeps the SYN rate low
            // enough that a stateful firewall doesn't flag the sweep and start
            // dropping every packet — the failure mode that returns "0 open" on
            // a reachable host. nmap avoids this via raw SYN (-sS); connect()
            // cannot.
            3 => Timing { concurrency: 30,  connect_timeout_ms: 1500, retries: 1, host_delay_ms: 0,   max_rate: 50  },
            // T4: fast but still WAN-safe. 100 concurrent with a 150/s cap is
            // ~3x T3's throughput while staying under the burst threshold that
            // makes a home router drop the whole sweep (including the open
            // ports). Uncapped 150-concurrency here used to return "0 open" on
            // real internet hosts even though 80/443 were up.
            4 => Timing { concurrency: 100, connect_timeout_ms: 1000, retries: 1, host_delay_ms: 0,   max_rate: 150 },
            // T5: insane — no rate cap, LAN / lab only (no NAT, no stateful
            // firewall). On the internet this will drop packets; that's the
            // trade you opt into. Override the cap back on with --max-rate.
            5 => Timing { concurrency: 500, connect_timeout_ms: 400,  retries: 0, host_delay_ms: 0,   max_rate: 0   },
            _ => Timing::from_template(3),
        }
    }

    /// Hyper-speed (`-HS`): as fast as the host machine can reasonably push
    /// without exhausting file descriptors on constrained systems like Termux.
    pub fn hyper() -> Timing {
        Timing { concurrency: 3000, connect_timeout_ms: 300, retries: 0, host_delay_ms: 0, max_rate: 0 }
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub mode: Mode,
    pub targets: Vec<String>,

    // scan
    pub scan_kind: ScanKind,
    pub ports: Vec<u16>,
    pub port_specs: Vec<ports::PortSpec>,
    pub ports_explicit: bool,
    pub ports_selected: bool,
    pub service_detection: bool,
    pub udp_scan: bool,         // -sU: probe UDP ports with protocol payloads
    pub udp_ports: Vec<u16>,
    pub udp_ports_explicit: bool,
    pub os_detection: bool,
    /// -WW: web fingerprint (whatweb-style) on open HTTP/HTTPS ports. Implies
    /// -sV so we know which ports are web to begin with.
    pub web_scan: bool,
    pub mac_info: bool,        // -MC: MAC address from the local ARP/neighbor cache
    pub device_detection: bool, // -DP: best-effort device-type guess (phone/console/PC/...)
    pub vuln: bool,
    pub only_open: bool,
    pub reason: bool,
    /// -FW: firewall/middlebox pre-check. Before touching the real ports, sample
    /// three random high ports (6000–60000). A host that answers all three
    /// "open" is a firewall/CPE completing every handshake, so the scan is
    /// aborted with a warning instead of reporting meaningless open ports. This
    /// flag is also what gates the "a handshake proves nothing here" warning:
    /// without it, Kaisen simply reports what answered and stays out of the way.
    pub firewall_check: bool,
    /// Stream each open port to the terminal the instant it is confirmed,
    /// instead of waiting for the whole sweep to finish. On by default for the
    /// human-readable output; JSON/grepable always emit the complete report at
    /// the end. Turn off with `--no-stream`.
    pub stream: bool,
    pub no_ping: bool, // -Pn: skip host discovery, assume every target is up
    pub timing: Timing,
    pub ip_version: IpVersion,
    pub verbosity: u8,
    pub color: bool,
    pub output: OutputFormat,

    // scope control
    /// --exclude / --exclude-file: hosts, hostnames or CIDRs to drop from the
    /// expanded target list. Kept as raw specs; matching happens after
    /// expansion, in main, where the IPs are known.
    pub exclude: Vec<String>,
    /// --exclude-ports: ports removed from both the TCP and UDP lists once
    /// every other port selection has been resolved.
    pub exclude_ports: Vec<u16>,
    /// --progress / --stats-every: seconds between progress lines on stderr.
    /// 0 disables it.
    pub progress_secs: u64,
    /// --min-severity: hide -vuln findings below this severity. None shows all.
    pub min_severity: Option<crate::vuln::Severity>,

    // dns
    pub dns_types: Vec<String>,
    pub dns_server: Option<String>,
    pub dns_port: u16,
    pub dns_reverse: bool,
    pub dns_short: bool,
    pub dns_tcp: bool,
    pub dns_trace_ttl: bool,
    pub dns_dnssec: bool,   // +dnssec: set the EDNS0 DO bit
    pub dns_nsid: bool,     // +nsid: identify the answering anycast node
    pub dns_norec: bool,    // +norec: clear RD, ask the server for its own data
    pub dns_trace: bool,    // +trace: iterate from the root
    pub dns_all: bool,      // +all: show authority/additional sections too
    /// +subnet: EDNS Client Subnet — ask as if from this network (RFC 7871).
    pub dns_subnet: Option<(std::net::IpAddr, u8)>,
    /// +dot: send the query over TLS 1.3 on port 853 instead of in the clear.
    pub dns_dot: bool,
    /// --doh: send the query over HTTPS to this URL.
    pub dns_doh: Option<String>,

    /// `--help <topic>`: which section to print. None means the summary.
    pub help_topic: Option<String>,
    /// `--ayuda`: Spanish help flag
    pub help_spanish: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Normal,
    Json,
    Grepable,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            mode: Mode::Scan,
            targets: Vec::new(),
            scan_kind: ScanKind::Connect,
            ports: Vec::new(),
            port_specs: Vec::new(),
            ports_explicit: false,
            ports_selected: false,
            service_detection: false,
            udp_scan: false,
            udp_ports: Vec::new(),
            udp_ports_explicit: false,
            os_detection: false,
            web_scan: false,
            mac_info: false,
            device_detection: false,
            vuln: false,
            only_open: false,
            reason: false,
            firewall_check: false,
            stream: false,
            no_ping: false,
            timing: Timing::from_template(3),
            ip_version: IpVersion::Any,
            verbosity: 0,
            color: true,
            output: OutputFormat::Normal,
            exclude: Vec::new(),
            exclude_ports: Vec::new(),
            progress_secs: 0,
            min_severity: None,
            dns_types: Vec::new(),
            dns_server: None,
            dns_port: 53,
            dns_reverse: false,
            dns_short: false,
            dns_tcp: false,
            dns_trace_ttl: false,
            dns_dnssec: false,
            dns_nsid: false,
            dns_norec: false,
            dns_trace: false,
            dns_all: false,
            dns_subnet: None,
            dns_dot: false,
            dns_doh: None,
            help_topic: None,
            help_spanish: false,
        }
    }
}

/// Whether a bare token in DNS mode names a record type (dig-style
/// `kaisen dns DNSKEY example.com`). Delegating to the resolver's own table
/// means every type it can parse is also a type you can ask for — including
/// the `TYPE###` escape hatch.
fn is_dns_type(s: &str) -> bool {
    // A token containing a dot is a name, never a type; this keeps a domain
    // that happens to collide with a type mnemonic from being swallowed.
    !s.contains('.') && crate::dns::type_to_num(s).is_some()
}

/// Read a list of entries from a file: one per line, extra entries may be
/// separated by whitespace, `#` starts a comment and blank lines are skipped.
/// A path of `-` reads standard input, so a pipeline can feed targets straight
/// in (`printf '10.0.0.1\n' | kaisen -iL -`).
fn read_list_file(path: &str) -> Result<Vec<String>, String> {
    let raw = if path == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .map_err(|e| format!("cannot read standard input: {e}"))?;
        s
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?
    };

    let mut out = Vec::new();
    for line in raw.lines() {
        let body = line.split('#').next().unwrap_or("");
        for tok in body.split_whitespace() {
            out.push(tok.to_string());
        }
    }
    if out.is_empty() {
        return Err(format!("{path} contains no entries"));
    }
    Ok(out)
}

/// Split a comma-separated list, dropping empty fields so `a,,b` and a trailing
/// comma both behave.
fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// Every option Kaisen accepts, for suggesting a correction. Kept next to the
/// parser so a new flag added above without an entry here is visible as the
/// omission it is.
const KNOWN_FLAGS: &[&str] = &[
    "--help", "--version", "--connect", "--syn", "--udp", "--udp-scan", "--port-famous",
    "--ports-all", "--top-ports", "--ports", "--fast", "--exclude-ports", "--target-file",
    "--exclude", "--exclude-file", "--service-version", "--udp-ports", "--top-udp",
    "--os-detection", "--mac", "--device", "--vuln", "--aggressive", "--all-out", "--no-ping",
    "-WW", "--webscan", "--web",
    "--hyper-speed", "--concurrency", "--max-concurrency", "--timeout", "--retries",
    "--scan-delay", "--max-rate", "--open", "--reason", "--progress", "--stats-every", "--min-severity",
    "--firewall", "--firewall-check", "--no-stream", "--no-live", "--stream", "--live", "-FW",
    "--output-normal", "--json", "--grepable", "--no-color", "--color", "--dns", "--reverse",
    "--mail", "--mail-audit", "--whois", "--lookup", "--neighbor", "--neighbour", "--ns",
    "--nameservers", "--short", "--dnssec", "--nsid", "--no-recurse", "--trace",
    "--all-sections", "--dns-tcp", "--ttl", "--dns-port", "--subnet", "--client-subnet",
    "--dot", "--dns-tls", "--doh", "--dns-https", "--vuln-list", "--list-vulns",
    "-h", "-V", "-sT", "-sS", "-sU", "-sV", "-PF", "-PA", "-p-", "-p", "-pU", "-F", "-iL",
    "-OS", "-O", "-MC", "-DP", "-A", "-AA", "-Pn", "-HS", "-oN", "-oJ", "-oG", "-4", "-6",
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5", "-D", "-x", "-M", "-w", "-L", "-N", "-NS", "-v",
    "+short", "+tcp", "+ttl", "+dnssec", "+do", "+nsid", "+norec", "+trace", "+all", "+subnet",
    "+dot", "+tls", "+https",
];

/// Levenshtein distance, used only to say "did you mean".
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// The closest known flag to something the parser did not recognise.
///
/// Case is checked first and separately, because Kaisen's shorts are
/// multi-letter and case-carrying (`-sV`, `-OS`, `-PF`, `-AA`) — typing `-sv`
/// is the single most likely mistake, and an edit distance of 0 makes it the
/// unambiguous answer.
fn suggest_flag(unknown: &str) -> Option<&'static str> {
    let lower = unknown.to_ascii_lowercase();
    if let Some(f) = KNOWN_FLAGS
        .iter()
        .find(|f| f.to_ascii_lowercase() == lower && **f != unknown)
    {
        return Some(f);
    }
    // Otherwise the nearest neighbour, but only when it is actually near: a
    // wrong guess is worse than no guess.
    let limit = if unknown.len() <= 4 { 1 } else { 2 };
    KNOWN_FLAGS
        .iter()
        .map(|f| (edit_distance(&lower, &f.to_ascii_lowercase()), *f))
        .filter(|(d, _)| *d <= limit)
        .min_by_key(|(d, f)| (*d, f.len()))
        .map(|(_, f)| f)
}

fn parse_severity(s: &str) -> Result<crate::vuln::Severity, String> {
    use crate::vuln::Severity;
    match s.to_ascii_lowercase().as_str() {
        "info" | "informational" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" | "med" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" | "crit" => Ok(Severity::Critical),
        _ => Err(format!(
            "invalid severity '{s}' — use info, low, medium, high or critical"
        )),
    }
}

pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut timing_template: Option<u8> = None;
    let mut hyper = false;
    let mut want_top: Option<usize> = None;
    let mut want_all = false;
    let mut ov_concurrency: Option<usize> = None;
    let mut ov_timeout: Option<u64> = None;
    let mut ov_retries: Option<u32> = None;
    let mut ov_delay: Option<u64> = None;
    let mut ov_max_rate: Option<u32> = None;
    let mut dns_port_explicit = false;

    // color default: on only when stdout is a real terminal, so redirecting to
    // a file (`kaisen ... > out.txt`) yields clean, ANSI-free text. NO_COLOR and
    // explicit --color/--no-color flags override this below.
    o.color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    if std::env::var_os("NO_COLOR").is_some() {
        o.color = false;
    }

    let mut i = 0;
    // First token may be a subcommand.
    if let Some(first) = args.first() {
        match first.as_str() {
            "dns" | "resolve" | "dig" => {
                o.mode = Mode::Dns;
                i = 1;
            }
            "mail" | "email" | "mx" => {
                o.mode = Mode::Mail;
                i = 1;
            }
            "lookup" | "profile" | "host" => {
                o.mode = Mode::Lookup;
                i = 1;
            }
            "whois" => {
                o.mode = Mode::Whois;
                i = 1;
            }
            "neighbor" | "neighbour" | "neig" | "fierce" | "recon" => {
                o.mode = Mode::Neighbor;
                i = 1;
            }
            "ns" | "nameservers" | "delegation" => {
                o.mode = Mode::NsAudit;
                i = 1;
            }
            "scan" => {
                o.mode = Mode::Scan;
                i = 1;
            }
            "help" => return Ok(Options { mode: Mode::Help, ..o }),
            "version" => return Ok(Options { mode: Mode::Version, ..o }),
            _ => {}
        }
    }

    while i < args.len() {
        let a = &args[i];

        // @server  (dig-style DNS server selection). Implies DNS mode only if we
        // aren't already in an explicit DNS/mail subcommand.
        if let Some(server) = a.strip_prefix('@') {
            o.dns_server = Some(server.to_string());
            if o.mode == Mode::Scan {
                o.mode = Mode::Dns;
            }
            i += 1;
            continue;
        }

        match a.as_str() {
            "-h" | "-help" | "--help" => {
                // Consume a following word as the topic. A mistyped one is
                // answered with the index rather than silently ignored, which
                // is the whole point of having named topics.
                let topic = args
                    .get(i + 1)
                    .filter(|t| !t.starts_with('-') && !t.starts_with('@') && !t.starts_with('+'))
                    .cloned();
                return Ok(Options { mode: Mode::Help, help_topic: topic, help_spanish: false, ..o });
            }
            "-ayuda" | "--ayuda" => {
                // Spanish help: consume a following word as the topic
                let topic = args
                    .get(i + 1)
                    .filter(|t| !t.starts_with('-') && !t.starts_with('@') && !t.starts_with('+'))
                    .cloned();
                return Ok(Options { mode: Mode::Help, help_topic: topic, help_spanish: true, ..o });
            }
            "-V" | "--version" => return Ok(Options { mode: Mode::Version, ..o }),

            // ---- scan type ----
            "-sT" | "--connect" => o.scan_kind = ScanKind::Connect,
            "-sS" | "--syn" => o.scan_kind = ScanKind::Syn,

            // ---- port selection ----
            "-PF" | "--port-famous" => {
                want_top = Some(1000);
                o.ports_selected = true;
            }
            "-PA" | "--ports-all" | "-p-" => {
                want_all = true;
                o.ports_selected = true;
            }
            "--top-ports" => {
                i += 1;
                let v = args.get(i).ok_or("--top-ports requires a number")?;
                want_top = Some(v.parse().map_err(|_| "invalid --top-ports value")?);
                o.ports_selected = true;
            }
            "-p" | "--ports" => {
                i += 1;
                let v = args.get(i).ok_or("-p requires a port spec")?;
                let specs = ports::parse_port_specs(v)?;
                o.ports = specs.iter().map(|s| s.port).collect();
                o.port_specs = specs;
                o.ports_explicit = true;
                o.ports_selected = true;
            }
            "-F" | "--fast" => {
                want_top = Some(100);
                o.ports_selected = true;
            }
            "--exclude-ports" | "--exclude-port" => {
                i += 1;
                let v = args.get(i).ok_or("--exclude-ports requires a port spec")?;
                o.exclude_ports = ports::parse_ports(v)?;
            }

            // ---- target selection ----
            "-iL" | "--target-file" | "--targets-file" => {
                i += 1;
                let v = args.get(i).ok_or("-iL requires a file (or - for stdin)")?;
                o.targets.extend(read_list_file(v)?);
            }
            "--exclude" => {
                i += 1;
                let v = args.get(i).ok_or("--exclude requires a host/CIDR list")?;
                o.exclude.extend(split_list(v));
            }
            "--exclude-file" | "--excludefile" => {
                i += 1;
                let v = args.get(i).ok_or("--exclude-file requires a file")?;
                o.exclude.extend(read_list_file(v)?);
            }

            // ---- detection ----
            "-sV" | "--service-version" | "-SV" => o.service_detection = true,
            // Web fingerprint. Needs -sV to know which open ports are web.
            "-WW" | "--webscan" | "--web" => {
                o.web_scan = true;
                o.service_detection = true;
            }
            "-sU" | "--udp" | "--udp-scan" => o.udp_scan = true,
            "-pU" | "--udp-ports" => {
                i += 1;
                let v = args.get(i).ok_or("-pU requires a port spec")?;
                o.udp_ports = ports::parse_ports(v)?;
                o.udp_ports_explicit = true;
                o.udp_scan = true;
            }
            "--top-udp" => {
                i += 1;
                let v = args.get(i).ok_or("--top-udp requires a number")?;
                let n: usize = v.parse().map_err(|_| "invalid --top-udp value")?;
                o.udp_ports = crate::udp::top_udp_ports(n);
                o.udp_ports_explicit = true;
                o.udp_scan = true;
            }
            "-OS" | "--os-detection" | "-O" => o.os_detection = true,
            "-MC" | "--mac" => o.mac_info = true,
            "-DP" | "--device" => o.device_detection = true,
            "-vuln" | "--vuln" | "--script=vuln" => o.vuln = true,
            "-A" | "--aggressive" => {
                o.service_detection = true;
                o.os_detection = true;
                o.vuln = true;
            }
            // Everything -A does, plus the UDP sweep. Kept separate because a
            // UDP scan waits on timeouts that TCP never pays.
            "-AA" | "--all-out" => {
                o.service_detection = true;
                o.os_detection = true;
                o.vuln = true;
                o.udp_scan = true;
                o.mac_info = true;
                o.device_detection = true;
            }

            // ---- host discovery ----
            "-Pn" | "--no-ping" => o.no_ping = true,

            // ---- timing ----
            "-T0" => timing_template = Some(0),
            "-T1" => timing_template = Some(1),
            "-T2" => timing_template = Some(2),
            "-T3" => timing_template = Some(3),
            "-T4" => timing_template = Some(4),
            "-T5" => timing_template = Some(5),
            "-HS" | "--hyper-speed" | "--hyper" => hyper = true,
            "--concurrency" | "--max-concurrency" => {
                i += 1;
                let v = args.get(i).ok_or("--concurrency requires a number")?;
                let c: usize = v.parse().map_err(|_| "invalid concurrency")?;
                ov_concurrency = Some(c.max(1));
            }
            "--timeout" => {
                i += 1;
                let v = args.get(i).ok_or("--timeout requires ms")?;
                ov_timeout = Some(v.parse().map_err(|_| "invalid timeout")?);
            }
            "--retries" => {
                i += 1;
                let v = args.get(i).ok_or("--retries requires a number")?;
                ov_retries = Some(v.parse().map_err(|_| "invalid retries")?);
            }
            "--scan-delay" => {
                i += 1;
                let v = args.get(i).ok_or("--scan-delay requires ms")?;
                ov_delay = Some(v.parse().map_err(|_| "invalid scan delay")?);
            }
            "--max-rate" => {
                i += 1;
                let v = args.get(i).ok_or("--max-rate requires connections/second (0 = unlimited)")?;
                ov_max_rate = Some(v.parse().map_err(|_| "invalid max-rate")?);
            }

            // ---- firewall check / live output ----
            "-FW" | "--firewall" | "--firewall-check" => o.firewall_check = true,
            "--no-stream" | "--no-live" => o.stream = false,
            "--stream" | "--live" => o.stream = true,

            // ---- output / display ----
            "--open" => o.only_open = true,
            "--reason" => o.reason = true,
            "--progress" => o.progress_secs = 2,
            "--stats-every" => {
                i += 1;
                let v = args.get(i).ok_or("--stats-every requires seconds")?;
                let s: u64 = v.parse().map_err(|_| "invalid --stats-every value")?;
                o.progress_secs = s.max(1);
            }
            "--vuln-list" | "--list-vulns" | "--vulns" => o.mode = Mode::VulnList,
            "--min-severity" | "--severity" => {
                i += 1;
                let v = args.get(i).ok_or("--min-severity requires a level")?;
                o.min_severity = Some(parse_severity(v)?);
            }
            "-oN" | "--output-normal" => o.output = OutputFormat::Normal,
            "-oJ" | "--json" => o.output = OutputFormat::Json,
            "-oG" | "--grepable" => o.output = OutputFormat::Grepable,
            "--no-color" => o.color = false,
            "--color" => o.color = true,
            "-4" => o.ip_version = IpVersion::V4,
            "-6" => o.ip_version = IpVersion::V6,

            // ---- DNS ----
            "-D" | "--dns" => {
                o.mode = Mode::Dns;
                i += 1;
                let v = args.get(i).ok_or("-D requires a record type (A, MX, ...)")?;
                o.dns_types.push(v.to_ascii_uppercase());
            }
            "-x" | "--reverse" => {
                o.mode = Mode::Dns;
                o.dns_reverse = true;
            }
            "-M" | "--mail" | "--mail-audit" => o.mode = Mode::Mail,
            "-w" | "--whois" => o.mode = Mode::Whois,
            "-L" | "--lookup" => o.mode = Mode::Lookup,
            "-N" | "--neighbor" | "--neighbour" | "--neig" => o.mode = Mode::Neighbor,
            "-NS" | "--ns" | "--nameservers" => o.mode = Mode::NsAudit,
            "+short" | "--short" => o.dns_short = true,
            "+dnssec" | "+do" | "--dnssec" => {
                o.dns_dnssec = true;
                o.mode = Mode::Dns;
            }
            "+nsid" | "--nsid" => {
                o.dns_nsid = true;
                o.mode = Mode::Dns;
            }
            "+norec" | "+norecurse" | "--no-recurse" => o.dns_norec = true,
            "+dot" | "+tls" | "--dot" | "--dns-tls" => {
                o.dns_dot = true;
                o.mode = Mode::Dns;
            }
            "--doh" | "+https" | "--dns-https" => {
                // The URL is optional: the next token is only consumed when it
                // actually looks like one, so `--doh example.com` still treats
                // the domain as the name to resolve.
                let takes_url = args
                    .get(i + 1)
                    .map(|v| v.starts_with("https://"))
                    .unwrap_or(false);
                o.dns_doh = Some(if takes_url {
                    i += 1;
                    args[i].clone()
                } else {
                    crate::dns::DEFAULT_DOH_URL.to_string()
                });
                o.mode = Mode::Dns;
            }
            "+subnet" | "--subnet" | "--client-subnet" => {
                i += 1;
                let v = args.get(i).ok_or("+subnet requires a network (e.g. 203.0.113.0/24)")?;
                o.dns_subnet = Some(crate::dns::parse_client_subnet(v)?);
                o.mode = Mode::Dns;
            }
            "+trace" | "--trace" => {
                o.dns_trace = true;
                o.mode = Mode::Dns;
            }
            "+all" | "--all-sections" => o.dns_all = true,
            "+multi" | "+noall" | "+cmd" | "+nocmd" | "+question" | "+noquestion" => {
                // Accepted and ignored: common dig noise, so muscle memory
                // doesn't turn into an "unknown option" error.
            }
            "+tcp" | "--dns-tcp" => o.dns_tcp = true,
            "+ttl" | "--ttl" => o.dns_trace_ttl = true,
            "--dns-port" => {
                i += 1;
                let v = args.get(i).ok_or("--dns-port requires a number")?;
                o.dns_port = v.parse().map_err(|_| "invalid dns port")?;
                dns_port_explicit = true;
            }

            other => {
                // stacked verbosity: -v, -vv, -vvv, ...
                if other.len() >= 2 && other.starts_with('-') && other[1..].chars().all(|c| c == 'v') {
                    o.verbosity += (other.len() - 1) as u8;
                }
                // Accept any unambiguous abbreviation of --help / --version
                // (e.g. `--h`, `--hel`, `--ver`).
                else if other.len() >= 3 && "--help".starts_with(other) {
                    return Ok(Options { mode: Mode::Help, ..o });
                } else if other.len() >= 3 && "--version".starts_with(other) {
                    return Ok(Options { mode: Mode::Version, ..o });
                }
                // --doh=https://... , the form people type out of habit.
                else if let Some(v) = other.strip_prefix("--doh=") {
                    o.dns_doh = Some(v.to_string());
                    o.mode = Mode::Dns;
                }
                // dig also writes this option as `+subnet=1.2.3.0/24`.
                else if let Some(v) = other.strip_prefix("+subnet=") {
                    o.dns_subnet = Some(crate::dns::parse_client_subnet(v)?);
                    o.mode = Mode::Dns;
                }
                // bare DNS record type token in DNS mode (dig-style: `kaisen dns MX host`)
                else if o.mode == Mode::Dns && is_dns_type(other) {
                    o.dns_types.push(other.to_ascii_uppercase());
                } else if other.starts_with('-') {
                    return Err(match suggest_flag(other) {
                        Some(best) => format!("unknown option: {other} — did you mean {best}?"),
                        None => format!("unknown option: {other}"),
                    });
                } else {
                    // positional -> target
                    o.targets.push(other.to_string());
                }
            }
        }
        i += 1;
    }

    // Resolve timing precedence: hyper > explicit template > default,
    // then apply any explicit fine-grained overrides on top.
    if hyper {
        o.timing = Timing::hyper();
    } else if let Some(t) = timing_template {
        o.timing = Timing::from_template(t);
    }
    if let Some(c) = ov_concurrency {
        o.timing.concurrency = c;
    }
    if let Some(t) = ov_timeout {
        o.timing.connect_timeout_ms = t;
    }
    if let Some(r) = ov_retries {
        o.timing.retries = r;
    }
    if let Some(d) = ov_delay {
        o.timing.host_delay_ms = d;
    }
    if let Some(mr) = ov_max_rate {
        o.timing.max_rate = mr;
    }

    // +dot lives on its own port, so asking for it is enough — no one should
    // have to remember 853 as well.
    if o.dns_dot && !dns_port_explicit {
        o.dns_port = 853;
    }

    if o.udp_scan && !o.udp_ports_explicit {
        o.udp_ports = crate::udp::top_udp_ports(40);
    }

    // Resolve port selection precedence: explicit -p > all > top.
    if !o.ports_explicit {
        if want_all {
            o.ports = ports::all_ports();
        } else if let Some(n) = want_top {
            o.ports = ports::top_ports(n);
        } else {
            o.ports = ports::top_ports(1000); // sensible default like nmap
        }
        o.port_specs = o.ports.iter().map(|&p| ports::PortSpec::new(p)).collect();
    }

    // --exclude-ports applies last, so it subtracts from whatever the selection
    // above produced — -p, -PF, -PA and --top-ports alike — and from the UDP
    // list too. Emptying the list is a mistake worth naming: a scan with no
    // ports left would otherwise just print an empty report.
    if !o.exclude_ports.is_empty() {
        let drop: std::collections::HashSet<u16> = o.exclude_ports.iter().copied().collect();
        o.ports.retain(|p| !drop.contains(p));
        o.port_specs.retain(|s| !drop.contains(&s.port));
        o.udp_ports.retain(|p| !drop.contains(p));
        if o.ports.is_empty() && o.udp_ports.is_empty() {
            return Err("--exclude-ports removed every selected port".into());
        }
    }

    Ok(o)
}

// ── Help ───────────────────────────────────────────────────────────────────
//
// The full reference runs to a couple of hundred lines, which is a wall on a
// phone and unsearchable anywhere. So it is kept as named sections: bare
// `--help` prints a screenful, `--help <topic>` prints one section, and
// `--help all` prints everything, unchanged from what it always was.

/// Every topic `--help <topic>` accepts, with the one-line description shown
/// in the index. Order is the order they print under `--help all`.
pub const HELP_TOPICS: &[(&str, &str)] = &[
    ("scan", "scan types: TCP connect, SYN, UDP"),
    ("targets", "what to scan, from a file, and what to leave alone"),
    ("ports", "choosing and excluding ports"),
    ("detection", "-sV, -OS, -MC, -DP, -vuln and the aggressive presets"),
    ("timing", "speed, concurrency, delays and progress"),
    ("output", "formats, colour, verbosity, filtering findings"),
    ("udp", "how UDP scanning gets a real answer without root"),
    ("dns", "the dig replacement, including encrypted DNS"),
    ("ns", "name server audit"),
    ("mail", "email posture audit"),
    ("recon", "lookup, whois and neighbour recon"),
    ("examples", "worked command lines"),
    ("all", "the complete reference"),
];

const HEADER: &str = "Kaisen v{VERSION} — a fast nmap + dig hybrid network scanner (no root required)
";

const USAGE: &str = "USAGE:
    kaisen [SCAN OPTIONS] <target> [<target> ...]
    kaisen dns  [DNS OPTIONS] <name> [@server]
    kaisen mail <domain>          kaisen ns    <domain>
    kaisen lookup <domain>        kaisen whois <domain|ip>
    kaisen neighbor <domain>

    Targets may be a hostname, IPv4, IPv6, or CIDR (e.g. 192.168.1.0/24, max /16).
    The binary is also installed as `kai` and `kaison`.
";

const S_SCAN: &str = "  ── SCAN TYPE ──────────────────────────────────────────────────────────────
    -sT, --connect         TCP connect() scan (DEFAULT, works without root)
    -sS, --syn             SYN half-open scan (needs root; auto-falls back to -sT)
    -sU, --udp             UDP scan with per-protocol payloads (see `--help udp`)

  ── HOST DISCOVERY ─────────────────────────────────────────────────────────
    -Pn, --no-ping         Skip discovery, treat every target as up
                           (default: ICMP ping + TCP 80/443 + ARP cache)
";

const S_TARGETS: &str = "  ── TARGET SELECTION ───────────────────────────────────────────────────────
    <target>               Hostname, IPv4, IPv6 or IPv4 CIDR (max /16). A
                           hostname is scanned at its primary address
    -iL, --target-file <FILE>  Read targets from a file: one per line, '#'
                           starts a comment, '-' reads standard input
         --exclude <LIST>  Skip these hosts/CIDRs, comma-separated, even when
                           a CIDR target contains them. Excluding a hostname
                           removes every address it resolves to
         --exclude-file <FILE>  Same, read from a file
    -4 / -6                Force IPv4 / IPv6
";

const S_PORTS: &str = "  ── PORT SELECTION ─────────────────────────────────────────────────────────
    -PF, --port-famous     Top 1000 famous TCP ports (DEFAULT)
    -PA, --ports-all, -p-  All TCP ports (1-65535)
    -F,  --fast            Top 100 TCP ports
    -p,  --ports <SPEC>    Explicit TCP ports: -p 22,80,443,8000-8100
         --top-ports <N>   Top N famous TCP ports
    -pU, --udp-ports <SPEC>  Explicit UDP ports (implies -sU)
         --top-udp <N>     Top N UDP ports (implies -sU; default 40 with -sU)
         --exclude-ports <SPEC>  Remove ports from the selection above, TCP and
                           UDP alike. Applied last, so it subtracts from -p,
                           -PF, -PA and --top-ports the same way
";

const S_DETECTION: &str = "  ── DETECTION ──────────────────────────────────────────────────────────────
    -sV, --service-version Identify service and version on open ports
    -OS, --os-detection    Infer the OS. Used ALONE it prints a focused OS
                           report instead of a port table
    -MC, --mac             MAC address from the local ARP/neighbour cache
    -DP, --device          Guess the device type (phone, camera, NAS, router...)
    -WW, --webscan         Web fingerprint on open HTTP/HTTPS ports (whatweb-style):
                           CMS/framework/server + version, WAF/CDN, page title,
                           security-header grade and a Shodan favicon hash.
                           Implies -sV.
    -vuln, --vuln          Match findings against the vulnerability signature DB
    -A,  --aggressive      -sV + -OS + -vuln
    -AA, --all-out         -A plus -sU, -MC and -DP (slower: UDP waits on timeouts)
    -FW, --firewall        Firewall pre-check: probe 3 random high ports first.
                           If a host answers ALL of them 'open' it is a firewall
                           or CPE faking every handshake, so Kaisen stops at once
                           and says so instead of listing meaningless ports. If
                           they are closed/filtered the host is scannable and the
                           normal scan runs. Also required to see the
                           'a handshake proves nothing here' warning at all.

    What -sV actually does, in three tiers:
      1. LISTEN  protocols that greet first (SSH, SMTP, FTP, IMAP, VNC, MySQL...)
      2. PROBE   a per-port plan that makes silent services talk — an HTTP
                 request, a TLS ClientHello, or a binary handshake: SMB2,
                 MSSQL TDS, MongoDB, Oracle TNS, PostgreSQL, RDP, AMQP, Kafka,
                 Cassandra, LDAP, DNS version.bind, MQTT, X11, epmd, Minecraft,
                 AJP, SOCKS, git
      3. FALLBACK for unplanned ports: try HTTP, then TLS
    TLS ports yield the negotiated version, cipher, ALPN, certificate CN,
    issuer, SAN hostnames and expiry — all read before any encryption starts.
";

const S_TIMING: &str = "  ── TIMING & PERFORMANCE ───────────────────────────────────────────────────
    -T0 .. -T5             Timing template: 0=paranoid .. 3=normal .. 5=insane
    -HS, --hyper-speed     Maximum concurrency, minimal timeouts
         --concurrency <N> Max simultaneous connections
         --timeout <MS>    Per-connection timeout in milliseconds
         --retries <N>     Retries for filtered/timed-out ports
         --scan-delay <MS> Pause between hosts. Quieter on the network and on
                           whatever is watching it
         --max-rate <N>    Cap new connections per second (0 = unlimited). The
                           knob that keeps a big sweep from overwhelming a home
                           router into dropping everything. Defaults: T3 50, T4
                           150, T5/-HS unlimited. Raise it on a fast link, lower
                           it on a fragile one
         --progress        Set the progress refresh cadence (--progress = every 2s).
                           A live counter (done/total, %, rate, ETA) already turns
                           itself on for any scan that keeps you waiting, in every
                           output format — these flags only change how often it ticks.
         --stats-every <S> The same, refreshed every S seconds

    Progress goes to stderr and only when stderr is a terminal, so redirects,
    -oJ output and CI logs stay clean.

    The connect timeout above is a ceiling, not a fixed wait: the moment any port
    answers, Kaisen learns the host's real round-trip time and stops waiting the
    full timeout on every silent port — the reason a WAN sweep now finishes in a
    fraction of the old time without touching how gently it treats the network.
";

const S_OUTPUT: &str = "  ── OUTPUT & DISPLAY ───────────────────────────────────────────────────────
    --open                 Only show open ports
    --reason               Show why a port is in the state it is
    --no-stream            Don't print open ports live as they are found; wait
                           for the full report. (Live streaming is on by default
                           for the normal output; JSON/grepable never stream.)
    --min-severity <LEVEL> Hide -vuln findings below info|low|medium|high|critical.
                           Detection still runs in full; this filters the report,
                           and JSON is filtered identically
    --vuln-list            Print every rule -vuln can fire — signatures, port
                           exposure, probe conditions — and exit. No network
                           traffic, no target needed. Honours --min-severity
    -v, -vv, -vvv          Increase verbosity (-vv shows vuln detail)
    -oN | -oJ | -oG        Output: Normal | JSON | Grepable
    --color / --no-color   Toggle ANSI colour (honours NO_COLOR)
    -h, --help [TOPIC]     This help, or one section of it
    -V, --version          Show version

    Everything goes to stdout, so > and >> work as usual. Colour turns off
    automatically when the output is not a terminal, so saved files stay clean.
";

const S_UDP: &str = "  ── UDP SCANNING (-sU) ─────────────────────────────────────────────────────
    Each UDP port gets a payload the service will actually answer, so one
    round trip both proves the port is open and identifies what is on it:

      NTP asked three ways (client, mode 6 readvar for the daemon version and
      host OS, mode 7 monlist), SNMP v1/v2c/v3, NetBIOS node status (hostname,
      workgroup, MAC), SQL Server Browser (every instance and its version),
      IPMI (null-auth and anonymous-login bits), DNS version.bind, rpcbind
      DUMP, SSDP/UPnP, mDNS, LLMNR, IKE, STUN, CoAP, TFTP, XDMCP, memcached,
      EtherNet/IP, BACnet, RakNet, Steam A2S, Mumble, and more.

    States: 'open' means something replied. 'closed' means an ICMP port
    unreachable came back. 'open|filtered' means silence, which a drop and a
    quiet service produce identically — Kaisen will not guess between them.
";

const S_DNS: &str = "  ── DNS (dig replacement) ──────────────────────────────────────────────────
    dns, dig, resolve      DNS subcommand
    -D, --dns <TYPE>       Record type. Also accepted as a bare token:
                           A AAAA NS CNAME SOA PTR MX TXT SRV CAA NAPTR SVCB
                           HTTPS TLSA SSHFP DS DNSKEY CDS CDNSKEY RRSIG NSEC
                           NSEC3 CERT DNAME URI HINFO LOC KX EUI48 EUI64 ZONEMD
                           OPENPGPKEY SMIMEA AXFR ANY, or TYPE### for anything else
    -x, --reverse          Reverse (PTR) lookup for an IP address
    @server                Query a specific DNS server (e.g. @1.1.1.1)
    --dns-port <N>         DNS server port (default 53, or 853 with +dot)
    +short, --short        Terse output (answers only)
    +tcp, --dns-tcp        Force DNS over TCP
    +ttl, --ttl            Show TTL values
    +dnssec, +do           Set the EDNS0 DO bit and show RRSIG/DNSKEY records
    +nsid                  Ask which anycast node answered (RFC 5001)
    +norec                 Clear RD: ask a server for its own data, not a recursion
    +trace                 Resolve iteratively from the root, one hop per line
    +all                   Also print the authority and additional sections
    +subnet <CIDR>         EDNS Client Subnet (RFC 7871): ask as if from that
                           network, and report the scope the server used —
                           how a CDN splits traffic by region. Also +subnet=CIDR
    +dot, --dns-tls        Query over TLS 1.3 on port 853 (RFC 7858), so the
                           network cannot read or rewrite the question.
                           Defaults to @one.one.one.one when no @server is given
    --doh [URL]            Query over HTTPS (RFC 8484). Defaults to
                           https://cloudflare-dns.com/dns-query

    EDNS0 is advertised by default (1232-byte payload, per DNS Flag Day 2020),
    with an automatic retry without it for servers too old to cope.
    Asking for AXFR performs a zone transfer and reports whether it was allowed.

    Encryption is a from-scratch TLS 1.3 client: X25519 with ChaCha20-Poly1305
    or AES-128-GCM. The certificate's names and dates are checked, but the
    issuer chain is NOT verified — that defeats an eavesdropper, not an active
    attacker. Kaisen prints this caveat with every encrypted answer.
";

const S_NS: &str = "  ── NAME SERVER AUDIT ──────────────────────────────────────────────────────
    ns, nameservers        Audit a domain's authoritative name servers
    -NS, --ns              Same as the `ns` subcommand
                           Per server: reachability, AA flag (lame delegation),
                           SOA serial agreement, recursion for strangers (open
                           resolver), TCP/53, EDNS support, version.bind, and
                           whether AXFR is allowed. Plus network diversity and
                           the DNSSEC DS/DNSKEY chain. Detects when the network
                           is intercepting DNS and says the results are unreliable.
";

const S_MAIL: &str = "  ── MAIL (email posture audit) ─────────────────────────────────────────────
    mail, email, mx        Audit a domain's mail posture in one shot
    -M, --mail             Same as the `mail` subcommand
                           MX and null-MX, SPF including the RFC 7208 ten-lookup
                           budget, DMARC with pct/sp/alignment/rua, DKIM across
                           78 known selectors, DANE/TLSA per MX, a live STARTTLS
                           check against each MX, BIMI, MTA-STS, TLS-RPT, CAA
";

const S_RECON: &str = "  ── LOOKUP, WHOIS & RECON ──────────────────────────────────────────────────
    lookup, profile, host  Full DNS profile: A AAAA CNAME NS MX TXT SOA CAA at once
    -L, --lookup           Same as the `lookup` subcommand
    whois                  WHOIS for a domain or IP (from scratch, TCP/43)
    -w, --whois            Same as the `whois` subcommand (-v for the raw record)
    neighbor, neig, fierce Subdomain brute force + neighbourhood reverse DNS
    -N, --neighbor         Same as the `neighbor` subcommand
";

const S_EXAMPLES: &str = "EXAMPLES:
  Scanning
    kaisen -sV 10.0.0.5                     # versions on the top 1000 ports
    kaisen -A scanme.example.com            # versions + OS + vulnerabilities
    kaisen -A --min-severity high 10.0.0.5  # only the findings worth waking up for
    kaisen -AA 192.168.1.10                 # everything, including UDP
    kaisen -OS 192.168.1.2                  # focused OS report, no port table
    kaisen -MC -DP 192.168.1.0/24           # MAC + device type across a subnet
    kaisen -HS -PA --open 10.0.0.5          # every port, fastest, open only
    kaisen -PA --progress 10.0.0.5          # watch a long scan advance
    kaisen -iL hosts.txt --exclude 10.0.0.1 # a list, minus the gateway
    kaisen -F 10.0.0.0/24 --scan-delay 250  # slow and quiet across a subnet
    kaisen -sU -pU 123,161,1900 10.0.0.5    # specific UDP services
    kaisen -sV -oJ 10.0.0.5 | jq .          # JSON for tooling

  DNS
    kaisen dns MX example.com @8.8.8.8
    kaisen dns HTTPS cloudflare.com         # ALPN, ECH and address hints
    kaisen dns +dnssec DNSKEY example.com   # keys with their DNSSEC key tags
    kaisen dns +trace A example.com         # follow the delegation from the root
    kaisen dns +dot A example.com           # encrypted, over TLS 1.3
    kaisen dns --doh A example.com          # encrypted, over HTTPS
    kaisen dns A example.com +subnet=1.2.3.0/24   # how a CDN answers that region
    kaisen dns AXFR example.com @ns1.example.com
    kaisen -x 1.1.1.1                       # reverse lookup

  Audits
    kaisen ns example.com                   # name server health and exposure
    kaisen mail paypal.com                  # full email posture
    kaisen whois 8.8.8.8 -v
    kaisen neighbor example.com
";

const FOOTER: &str = "Kaisen defaults to unprivileged, root-free operation. SYN scanning and raw
ICMP degrade gracefully when raw-socket privileges are unavailable (e.g. on
an unrooted Termux). Scan only hosts you are authorised to test.
";

fn section_body(topic: &str) -> Option<&'static str> {
    Some(match topic {
        "scan" => S_SCAN,
        "targets" => S_TARGETS,
        "ports" => S_PORTS,
        "detection" => S_DETECTION,
        "timing" => S_TIMING,
        "output" => S_OUTPUT,
        "udp" => S_UDP,
        "dns" => S_DNS,
        "ns" => S_NS,
        "mail" => S_MAIL,
        "recon" => S_RECON,
        "examples" => S_EXAMPLES,
        _ => return None,
    })
}

// ── SPANISH HELP (Ayuda en español) ──────────────────────────────────────────

const HEADER_ES: &str = "Kaisen v{VERSION} — un escáner de red rápido que combina nmap + dig (sin requerir root)
";

const USAGE_ES: &str = "USO:
    kaisen [OPCIONES DE ESCANEO] <objetivo> [<objetivo> ...]
    kaisen dns  [OPCIONES DNS] <nombre> [@servidor]
    kaisen mail <dominio>          kaisen ns    <dominio>
    kaisen lookup <dominio>        kaisen whois <dominio|ip>
    kaisen neighbor <dominio>

    Los objetivos pueden ser un nombre de host, IPv4, IPv6 o CIDR (ej. 192.168.1.0/24, máx /16).
    El binario también se instala como `kai` y `kaison`.
";

const S_SCAN_ES: &str = "  ── TIPO DE ESCANEO ────────────────────────────────────────────────────────
    -sT, --connect         Escaneo TCP connect() (PREDETERMINADO, funciona sin root)
    -sS, --syn             Escaneo SYN semi-abierto (requiere root; regresa a -sT automáticamente)
    -sU, --udp             Escaneo UDP con payloads por protocolo (ver `--ayuda udp`)

  ── DESCUBRIMIENTO DE HOSTS ────────────────────────────────────────────────
    -Pn, --no-ping         Omitir descubrimiento, asumir que cada objetivo está activo
                           (predeterminado: ping ICMP + TCP 80/443 + caché ARP)
";

const S_TARGETS_ES: &str = "  ── SELECCIÓN DE OBJETIVOS ────────────────────────────────────────────────
    <objetivo>             Nombre de host, IPv4, IPv6 o CIDR IPv4 (máx /16). Un nombre
                           de host se escanea en su dirección primaria
    -iL, --target-file <ARCHIVO>  Leer objetivos de un archivo: uno por línea, '#'
                           inicia un comentario, '-' lee entrada estándar
         --exclude <LISTA>  Omitir estos hosts/CIDRs, separados por comas, incluso si
                           un objetivo CIDR los contiene. Excluir un nombre de host
                           elimina cada dirección que resuelve
         --exclude-file <ARCHIVO>  Igual, leer desde un archivo
    -4 / -6                Forzar IPv4 / IPv6
";

const S_PORTS_ES: &str = "  ── SELECCIÓN DE PUERTOS ───────────────────────────────────────────────────
    -PF, --port-famous     Top 1000 puertos TCP famosos (PREDETERMINADO)
    -PA, --ports-all, -p-  Todos los puertos TCP (1-65535)
    -F,  --fast            Top 100 puertos TCP
    -p,  --ports <ESPECIFICACIÓN>    Puertos TCP explícitos: -p 22,80,443,8000-8100
         --top-ports <N>   Top N puertos TCP famosos
    -pU, --udp-ports <ESPECIFICACIÓN>  Puertos UDP explícitos (implica -sU)
         --top-udp <N>     Top N puertos UDP (implica -sU; predeterminado 40 con -sU)
         --exclude-ports <ESPECIFICACIÓN>  Remover puertos de la selección anterior, TCP y
                           UDP por igual. Aplicado al final, así que resta de -p,
                           -PF, -PA y --top-ports de la misma manera
";

const S_DETECTION_ES: &str = "  ── DETECCIÓN ──────────────────────────────────────────────────────────────
    -sV, --service-version Identificar servicio y versión en puertos abiertos
    -OS, --os-detection    Inferir el SO. Usado SOLO imprime un reporte OS enfocado
                           en lugar de una tabla de puertos
    -MC, --mac             Dirección MAC del caché ARP/vecino local
    -DP, --device          Adivinar el tipo de dispositivo (teléfono, cámara, NAS, router...)
    -vuln, --vuln          Emparejar hallazgos contra la base de datos de firmas de vulnerabilidades
    -A,  --aggressive      -sV + -OS + -vuln
    -AA, --all-out         -A más -sU, -MC y -DP (más lento: UDP espera en timeouts)
    -WW, --webscan         Fingerprint web en puertos HTTP/HTTPS abiertos (estilo whatweb):
                           CMS/framework/servidor + versión, WAF/CDN, título de la
                           página, nota de cabeceras de seguridad y un hash de favicon
                           compatible con Shodan. Implica -sV.
    -FW, --firewall        Chequeo previo de firewall: prueba 3 puertos altos al azar.
                           Si el host responde a los TRES como 'open' es un firewall
                           o CPE fingiendo cada handshake, así que Kaisen para al
                           instante y lo dice en vez de listar puertos sin sentido. Si
                           salen cerrados/filtered el host es escaneable y sigue el
                           escaneo normal. También es lo que activa el aviso
                           'un handshake completado no prueba nada aquí'.

    Lo que -sV realmente hace, en tres capas:
      1. LISTEN  protocolos que saludan primero (SSH, SMTP, FTP, IMAP, VNC, MySQL...)
      2. PROBE   un plan por puerto que hace hablar a servicios silenciosos — una solicitud
                 HTTP, un ClientHello TLS, o un apretón de manos binario: SMB2,
                 MSSQL TDS, MongoDB, Oracle TNS, PostgreSQL, RDP, AMQP, Kafka,
                 Cassandra, LDAP, DNS version.bind, MQTT, X11, epmd, Minecraft,
                 AJP, SOCKS, git
      3. FALLBACK para puertos no planificados: intentar HTTP, luego TLS
    Los puertos TLS producen la versión negociada, cifra, ALPN, CN del certificado,
    emisor, nombres SAN y caducidad — todo leído antes de que comience cualquier encriptación.
";

const S_TIMING_ES: &str = "  ── TIEMPO Y RENDIMIENTO ───────────────────────────────────────────────────
    -T0 .. -T5             Plantilla de tiempo: 0=paranoia .. 3=normal .. 5=insano
    -HS, --hyper-speed     Concurrencia máxima, timeouts mínimos
         --concurrency <N> Máximo de conexiones simultáneas
         --timeout <MS>    Timeout por conexión en milisegundos
         --retries <N>     Reintentos para puertos filtrados/agotados
         --scan-delay <MS> Pausa entre hosts. Más silencioso en la red y en
                           lo que lo está observando
         --max-rate <N>    Limita conexiones nuevas por segundo (0 = sin límite).
                           Es lo que evita que un barrido grande desborde el
                           router de casa y lo haga descartar todo. Por defecto:
                           T3 50, T4 150, T5/-HS sin límite. Súbelo en una red
                           rápida, bájalo en una frágil
         --progress        Ajusta la cadencia de refresco (--progress = cada 2s).
                           Un contador en vivo (hecho/total, %, tasa, ETA) ya se
                           activa solo en cualquier escaneo que te haga esperar, en
                           todos los formatos — estas flags solo cambian cada cuánto.
         --stats-every <S> Lo mismo, actualizado cada S segundos

    El progreso va a stderr y solo cuando stderr es una terminal, así que redirecciones,
    salida -oJ y logs de CI se mantienen limpios.

    El timeout de conexión de arriba es un techo, no una espera fija: en cuanto un
    puerto responde, Kaisen aprende el RTT real del host y deja de esperar el
    timeout completo en cada puerto en silencio — por eso un barrido WAN ahora
    termina en una fracción del tiempo de antes sin cambiar lo suave que es con
    la red.
";

const S_OUTPUT_ES: &str = "  ── SALIDA Y VISUALIZACIÓN ─────────────────────────────────────────────────
    --open                 Mostrar solo puertos abiertos
    --no-stream            No imprimir los puertos abiertos en vivo según se encuentran;
                           esperar al reporte completo. (El streaming en vivo está
                           activado por defecto en la salida normal; JSON/grep nunca
                           hacen streaming.)
    --reason               Mostrar por qué un puerto está en ese estado
    --min-severity <NIVEL> Ocultar hallazgos -vuln por debajo de info|low|medium|high|critical.
                           La detección aún se ejecuta en su totalidad; esto filtra el reporte,
                           y JSON se filtra de manera idéntica
    --vuln-list            Imprimir cada regla que -vuln puede disparar — firmas, exposición
                           de puertos, condiciones de sondeo — y salir. Sin tráfico de red,
                           sin objetivo necesario. Honra --min-severity
    -v, -vv, -vvv          Aumentar verbosidad (-vv muestra detalle de vuln)
    -oN | -oJ | -oG        Salida: Normal | JSON | Grep
    --color / --no-color   Alternar color ANSI (honra NO_COLOR)
    -h, --help [TEMA]      Esta ayuda, o una sección de ella
    -V, --version          Mostrar versión

    Todo va a stdout, así que > y >> funcionan como de costumbre. El color se apaga
    automáticamente cuando la salida no es una terminal, así que los archivos guardados se mantienen limpios.
";

const S_UDP_ES: &str = "  ── ESCANEO UDP (-sU) ──────────────────────────────────────────────────────
    Cada puerto UDP recibe un payload que el servicio realmente responderá, así que un
    viaje redondo prueba que el puerto está abierto e identifica qué hay en él:

      NTP preguntado de tres formas (cliente, modo 6 readvar para la versión del demonio
      y SO del host, modo 7 monlist), SNMP v1/v2c/v3, estado del nodo NetBIOS (nombre de host,
      grupo de trabajo, MAC), SQL Server Browser (cada instancia y su versión),
      IPMI (bits de autenticación nula e inicio de sesión anónimo), DNS version.bind, rpcbind
      DUMP, SSDP/UPnP, mDNS, LLMNR, IKE, STUN, CoAP, TFTP, XDMCP, memcached,
      EtherNet/IP, BACnet, RakNet, Steam A2S, Mumble, y más.

    Estados: 'abierto' significa que algo respondió. 'cerrado' significa que llegó un ICMP
    puerto inalcanzable. 'abierto|filtrado' significa silencio, que una caída y un
    servicio silencioso producen de manera idéntica — Kaisen no adivinará entre ellos.
";

const S_DNS_ES: &str = "  ── DNS (sustituto de dig) ─────────────────────────────────────────────────
    dns, dig, resolve      Subcomando DNS
    -D, --dns <TIPO>       Tipo de registro. También aceptado como un token solo:
                           A AAAA NS CNAME SOA PTR MX TXT SRV CAA NAPTR SVCB
                           HTTPS TLSA SSHFP DS DNSKEY CDS CDNSKEY RRSIG NSEC
                           NSEC3 CERT DNAME URI HINFO LOC KX EUI48 EUI64 ZONEMD
                           OPENPGPKEY SMIMEA AXFR ANY, o TYPE### para cualquier otro
    -x, --reverse          Búsqueda inversa (PTR) para una dirección IP
    @servidor              Consultar un servidor DNS específico (ej. @1.1.1.1)
    --dns-port <N>         Puerto del servidor DNS (predeterminado 53, o 853 con +dot)
    +short, --short        Salida lacónica (solo respuestas)
    +tcp, --dns-tcp        Forzar DNS sobre TCP
    +ttl, --ttl            Mostrar valores TTL
    +dnssec, +do           Establecer el bit EDNS0 DO y mostrar registros RRSIG/DNSKEY
    +nsid                  Preguntar qué nodo anycast respondió (RFC 5001)
    +norec                 Limpiar RD: preguntar a un servidor por sus propios datos, no una recursión
    +trace                 Resolver iterativamente desde la raíz, un salto por línea
    +all                   También imprimir las secciones de autoridad y adicionales
    +subnet <CIDR>         EDNS Client Subnet (RFC 7871): preguntar como si fuera de esa
                           red, e informar el alcance que usó el servidor —
                           cómo un CDN divide el tráfico por región. También +subnet=CIDR
    +dot, --dns-tls        Consultar sobre TLS 1.3 en puerto 853 (RFC 7858), así la
                           red no puede leer o reescribir la pregunta.
                           Por defecto a @one.one.one.one cuando no se da @servidor
    --doh [URL]            Consultar sobre HTTPS (RFC 8484). Por defecto a
                           https://cloudflare-dns.com/dns-query

    EDNS0 se anuncia por defecto (payload de 1232 bytes, por DNS Flag Day 2020),
    con un reintento automático sin él para servidores demasiado antiguos para manejarlo.
    Pedir AXFR realiza una transferencia de zona e informa si fue permitida.

    La encriptación es un cliente TLS 1.3 desde cero: X25519 con ChaCha20-Poly1305
    o AES-128-GCM. Los nombres y fechas del certificado se verifican, pero la
    cadena de emisor NO se verifica — eso derrota a un atacante pasivo, no a uno activo.
    Kaisen imprime esta advertencia con cada respuesta encriptada.
";

const S_NS_ES: &str = "  ── AUDITORÍA DE SERVIDORES DE NOMBRES ──────────────────────────────────────
    ns, nameservers        Auditar los servidores de nombres autorizados de un dominio
    -NS, --ns              Igual que el subcomando `ns`
                           Por servidor: alcanzabilidad, bandera AA (delegación coja),
                           acuerdo serial SOA, recursión para extraños (servidor abierto
                           de resolver), TCP/53, soporte EDNS, version.bind, y
                           si se permite AXFR. Más diversidad de red y
                           la cadena de DNSSEC DS/DNSKEY. Detecta cuando la red
                           está interceptando DNS y dice que los resultados no son confiables.
";

const S_MAIL_ES: &str = "  ── MAIL (auditoría de postura de correo) ────────────────────────────────────
    mail, email, mx        Auditar la postura de correo de un dominio en un solo golpe
    -M, --mail             Igual que el subcomando `mail`
                           MX y null-MX, SPF incluyendo el presupuesto de diez búsquedas RFC 7208,
                           DMARC con pct/sp/alineación/rua, DKIM en 78 selectores conocidos,
                           DANE/TLSA por MX, una verificación STARTTLS en vivo contra cada MX,
                           BIMI, MTA-STS, TLS-RPT, CAA
";

const S_RECON_ES: &str = "  ── LOOKUP, WHOIS Y RECONOCIMIENTO ───────────────────────────────────────
    lookup, profile, host  Perfil DNS completo: A AAAA CNAME NS MX TXT SOA CAA a la vez
    -L, --lookup           Igual que el subcomando `lookup`
    whois                  WHOIS para un dominio o IP (desde cero, TCP/43)
    -w, --whois            Igual que el subcomando `whois` (-v para el registro bruto)
    neighbor, neig, fierce Fuerza bruta de subdominio + DNS inverso de vecindad
    -N, --neighbor         Igual que el subcomando `neighbor`
";

const S_EXAMPLES_ES: &str = "EJEMPLOS:
  Escaneo
    kaisen -sV 10.0.0.5                     # versiones en los top 1000 puertos
    kaisen -A scanme.example.com            # versiones + SO + vulnerabilidades
    kaisen -A --min-severity high 10.0.0.5  # solo los hallazgos que vale la pena considerar
    kaisen -AA 192.168.1.10                 # todo, incluyendo UDP
    kaisen -OS 192.168.1.2                  # reporte OS enfocado, sin tabla de puertos
    kaisen -MC -DP 192.168.1.0/24           # MAC + tipo de dispositivo a través de una subred
    kaisen -HS -PA --open 10.0.0.5          # cada puerto, más rápido, solo abiertos
    kaisen -PA --progress 10.0.0.5          # ver un escaneo largo avanzar
    kaisen -iL hosts.txt --exclude 10.0.0.1 # una lista, menos la puerta de enlace
    kaisen -F 10.0.0.0/24 --scan-delay 250  # lento y silencioso a través de una subred
    kaisen -sU -pU 123,161,1900 10.0.0.5    # servicios UDP específicos
    kaisen -sV -oJ 10.0.0.5 | jq .          # JSON para herramientas

  DNS
    kaisen dns MX example.com @8.8.8.8
    kaisen dns HTTPS cloudflare.com         # ALPN, ECH e indicaciones de dirección
    kaisen dns +dnssec DNSKEY example.com   # claves con sus etiquetas de clave DNSSEC
    kaisen dns +trace A example.com         # seguir la delegación desde la raíz
    kaisen dns +dot A example.com           # encriptado, sobre TLS 1.3
    kaisen dns --doh A example.com          # encriptado, sobre HTTPS
    kaisen dns A example.com +subnet=1.2.3.0/24   # cómo un CDN responde esa región
    kaisen dns AXFR example.com @ns1.example.com
    kaisen -x 1.1.1.1                       # búsqueda inversa

  Auditorías
    kaisen ns example.com                   # salud y exposición del servidor de nombres
    kaisen mail paypal.com                  # postura de correo completa
    kaisen whois 8.8.8.8 -v
    kaisen neighbor example.com
";

const FOOTER_ES: &str = "Kaisen tiene como predeterminada la operación sin privilegios y sin root. Los escaneos SYN
y ICMP sin procesar se degradan correctamente cuando no hay privilegios de socket sin procesar disponibles
(ej. en Termux sin root). Escanee solo los hosts que está autorizado a probar.
";

fn section_body_es(topic: &str) -> Option<&'static str> {
    Some(match topic {
        "scan" | "escaneo" => S_SCAN_ES,
        "targets" | "objetivos" => S_TARGETS_ES,
        "ports" | "puertos" => S_PORTS_ES,
        "detection" | "detección" => S_DETECTION_ES,
        "timing" | "tiempo" => S_TIMING_ES,
        "output" | "salida" => S_OUTPUT_ES,
        "udp" => S_UDP_ES,
        "dns" => S_DNS_ES,
        "ns" | "nameservers" | "servidores" => S_NS_ES,
        "mail" | "correo" => S_MAIL_ES,
        "recon" | "reconocimiento" => S_RECON_ES,
        "examples" | "ejemplos" => S_EXAMPLES_ES,
        _ => return None,
    })
}

const S_MOST_USED_ES: &str = "  ── MÁS USADO ──────────────────────────────────────────────────────────────
    -sV                    Identificar el servicio y versión en puertos abiertos
    -OS                    Inferir el SO (solo: un reporte SO enfocado)
    -A / -AA               -sV + -OS + -vuln  /  lo mismo más UDP, MAC, dispositivo
    -p <ESPECIFICACIÓN> / -F / -PA   Puertos explícitos / top 100 / todos los 65535
    -Pn                    Omitir descubrimiento de host, asumir que el objetivo está activo
    -T4 / -HS              Más rápido / el más rápido
    --open                 Mostrar solo puertos abiertos
    --progress             Progreso en vivo con un ETA
    -oJ                    Salida JSON

    kaisen dns MX example.com @1.1.1.1      DNS, al estilo dig
    kaisen mail <dominio>                   auditoría de postura de correo
    kaisen ns <dominio>                     auditoría de servidor de nombres
";

fn topic_index() -> String {
    let mut s = String::from("  ── MORE HELP ──────────────────────────────────────────────────────────────\n");
    for (name, desc) in HELP_TOPICS {
        s.push_str(&format!("    kaisen --help {name:<10} {desc}\n"));
    }
    s
}

fn topic_index_es() -> String {
    let mut s = String::from("  ── MÁS AYUDA ──────────────────────────────────────────────────────────────\n");
    s.push_str("    kaisen --ayuda escaneo      tipos de escaneo: TCP connect, SYN, UDP\n");
    s.push_str("    kaisen --ayuda objetivos    qué escanear, desde un archivo, y qué dejar solo\n");
    s.push_str("    kaisen --ayuda puertos      elegir y excluir puertos\n");
    s.push_str("    kaisen --ayuda detección    -sV, -OS, -MC, -DP, -vuln y los presets agresivos\n");
    s.push_str("    kaisen --ayuda tiempo       velocidad, concurrencia, retrasos y progreso\n");
    s.push_str("    kaisen --ayuda salida       formatos, color, verbosidad, filtrado de hallazgos\n");
    s.push_str("    kaisen --ayuda udp          cómo UDP escanea obtiene una respuesta real sin root\n");
    s.push_str("    kaisen --ayuda dns          el reemplazo de dig, incluyendo DNS encriptado\n");
    s.push_str("    kaisen --ayuda servidores   auditoría de servidor de nombres\n");
    s.push_str("    kaisen --ayuda correo       auditoría de postura de correo\n");
    s.push_str("    kaisen --ayuda reconocimiento lookup, whois y recon de vecindad\n");
    s.push_str("    kaisen --ayuda ejemplos     líneas de comandos trabajadas\n");
    s.push_str("    kaisen --ayuda todo         la referencia completa\n");
    s
}

fn help_summary() -> String {
    format!(
        "{}\n{}\n{}\n{}",
        HEADER.replace("{VERSION}", VERSION),
        USAGE,
        S_MOST_USED,
        topic_index()
    )
}

fn help_summary_es() -> String {
    format!(
        "{}\n{}\n{}\n{}",
        HEADER_ES.replace("{VERSION}", VERSION),
        USAGE_ES,
        S_MOST_USED_ES,
        topic_index_es()
    )
}

const S_MOST_USED: &str = "  ── MOST USED ──────────────────────────────────────────────────────────────
    -sV                    Identify the service and version on open ports
    -OS                    Infer the OS (alone: a focused OS report)
    -A / -AA               -sV + -OS + -vuln  /  the same plus UDP, MAC, device
    -p <SPEC> / -F / -PA   Explicit ports / top 100 / all 65535
    -Pn                    Skip host discovery, assume the target is up
    -T4 / -HS              Faster / fastest
    --open                 Only show open ports
    --progress             Live progress with an ETA
    -oJ                    JSON output

    kaisen dns MX example.com @1.1.1.1      DNS, the dig way
    kaisen mail <domain>                    email posture audit
    kaisen ns <domain>                      name server audit
";

fn help_all() -> String {
    let mut s = String::new();
    s.push_str(&HEADER.replace("{VERSION}", VERSION));
    s.push('\n');
    s.push_str(USAGE);
    s.push('\n');
    for (name, _) in HELP_TOPICS {
        if let Some(body) = section_body(name) {
            s.push_str(body);
            s.push('\n');
        }
    }
    s.push_str(FOOTER);
    s
}

fn help_all_es() -> String {
    let mut s = String::new();
    s.push_str(&HEADER_ES.replace("{VERSION}", VERSION));
    s.push('\n');
    s.push_str(USAGE_ES);
    s.push('\n');
    s.push_str(S_SCAN_ES);
    s.push('\n');
    s.push_str(S_TARGETS_ES);
    s.push('\n');
    s.push_str(S_PORTS_ES);
    s.push('\n');
    s.push_str(S_DETECTION_ES);
    s.push('\n');
    s.push_str(S_TIMING_ES);
    s.push('\n');
    s.push_str(S_OUTPUT_ES);
    s.push('\n');
    s.push_str(S_UDP_ES);
    s.push('\n');
    s.push_str(S_DNS_ES);
    s.push('\n');
    s.push_str(S_NS_ES);
    s.push('\n');
    s.push_str(S_MAIL_ES);
    s.push('\n');
    s.push_str(S_RECON_ES);
    s.push('\n');
    s.push_str(S_EXAMPLES_ES);
    s.push('\n');
    s.push_str(FOOTER_ES);
    s
}

/// `--help` with no topic gives the summary; `--help <topic>` gives one
/// section; `--help all` gives the lot. An unknown topic lists what there is
/// instead of failing — being wrong about a topic name is not worth an error.
pub fn help_text(topic: Option<&str>, spanish: bool) -> String {
    if spanish {
        match topic {
            None => help_summary_es(),
            Some("all") | Some("todo") => help_all_es(),
            Some(t) => match section_body_es(t) {
                Some(body) => format!(
                    "{}\n{}\n{}",
                    HEADER_ES.replace("{VERSION}", VERSION),
                    body,
                    topic_index_es()
                ),
                None => format!(
                    "kaisen: no hay tema de ayuda llamado '{t}'.\n\n{}",
                    topic_index_es()
                ),
            },
        }
    } else {
        match topic {
            None => help_summary(),
            Some("all") => help_all(),
            Some(t) => match section_body(t) {
                Some(body) => format!(
                    "{}\n{}\n{}",
                    HEADER.replace("{VERSION}", VERSION),
                    body,
                    topic_index()
                ),
                None => format!(
                    "kaisen: no help topic called '{t}'.\n\n{}",
                    topic_index()
                ),
            },
        }
    }
}

pub fn version_text() -> String {
    format!("kaisen {VERSION}")
}
