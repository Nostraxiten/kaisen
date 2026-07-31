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
}

impl Timing {
    /// Map an nmap-style timing template (0..5) to concrete parameters.
    pub fn from_template(t: u8) -> Timing {
        match t {
            0 => Timing { concurrency: 1, connect_timeout_ms: 5000, retries: 3, host_delay_ms: 500 },
            1 => Timing { concurrency: 10, connect_timeout_ms: 3000, retries: 2, host_delay_ms: 100 },
            2 => Timing { concurrency: 100, connect_timeout_ms: 2000, retries: 2, host_delay_ms: 10 },
            3 => Timing { concurrency: 500, connect_timeout_ms: 1200, retries: 1, host_delay_ms: 0 },
            4 => Timing { concurrency: 1000, connect_timeout_ms: 700, retries: 1, host_delay_ms: 0 },
            5 => Timing { concurrency: 2000, connect_timeout_ms: 400, retries: 0, host_delay_ms: 0 },
            _ => Timing::from_template(3),
        }
    }

    /// Hyper-speed (`-HS`): as fast as the host machine can reasonably push
    /// without exhausting file descriptors on constrained systems like Termux.
    pub fn hyper() -> Timing {
        Timing { concurrency: 3000, connect_timeout_ms: 300, retries: 0, host_delay_ms: 0 }
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub mode: Mode,
    pub targets: Vec<String>,

    // scan
    pub scan_kind: ScanKind,
    pub ports: Vec<u16>,
    pub ports_explicit: bool,
    pub ports_selected: bool,
    pub service_detection: bool,
    pub os_detection: bool,
    pub vuln: bool,
    pub only_open: bool,
    pub reason: bool,
    pub no_ping: bool, // -Pn (default true; we can't ICMP without root)
    pub timing: Timing,
    pub ip_version: IpVersion,
    pub verbosity: u8,
    pub color: bool,
    pub output: OutputFormat,

    // dns
    pub dns_types: Vec<String>,
    pub dns_server: Option<String>,
    pub dns_port: u16,
    pub dns_reverse: bool,
    pub dns_short: bool,
    pub dns_tcp: bool,
    pub dns_trace_ttl: bool,
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
            ports_explicit: false,
            ports_selected: false,
            service_detection: false,
            os_detection: false,
            vuln: false,
            only_open: false,
            reason: false,
            no_ping: true,
            timing: Timing::from_template(3),
            ip_version: IpVersion::Any,
            verbosity: 0,
            color: true,
            output: OutputFormat::Normal,
            dns_types: Vec::new(),
            dns_server: None,
            dns_port: 53,
            dns_reverse: false,
            dns_short: false,
            dns_tcp: false,
            dns_trace_ttl: false,
        }
    }
}

fn is_dns_type(s: &str) -> bool {
    matches!(
        s.to_ascii_uppercase().as_str(),
        "A" | "AAAA" | "NS" | "CNAME" | "SOA" | "PTR" | "MX" | "TXT" | "SRV" | "CAA" | "ANY"
    )
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

        // @server  (dig-style DNS server selection -> implies DNS mode)
        if let Some(server) = a.strip_prefix('@') {
            o.dns_server = Some(server.to_string());
            o.mode = Mode::Dns;
            i += 1;
            continue;
        }

        match a.as_str() {
            "-h" | "-help" | "--help" => return Ok(Options { mode: Mode::Help, ..o }),
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
                o.ports = ports::parse_ports(v)?;
                o.ports_explicit = true;
                o.ports_selected = true;
            }
            "-F" | "--fast" => {
                want_top = Some(100);
                o.ports_selected = true;
            }

            // ---- detection ----
            "-sV" | "--service-version" | "-SV" => o.service_detection = true,
            "-OS" | "--os-detection" | "-O" => o.os_detection = true,
            "-vuln" | "--vuln" | "--script=vuln" => o.vuln = true,
            "-A" | "--aggressive" => {
                o.service_detection = true;
                o.os_detection = true;
                o.vuln = true;
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

            // ---- output / display ----
            "--open" => o.only_open = true,
            "--reason" => o.reason = true,
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
            "+short" | "--short" => o.dns_short = true,
            "+tcp" | "--dns-tcp" => o.dns_tcp = true,
            "+ttl" | "--ttl" => o.dns_trace_ttl = true,
            "--dns-port" => {
                i += 1;
                let v = args.get(i).ok_or("--dns-port requires a number")?;
                o.dns_port = v.parse().map_err(|_| "invalid dns port")?;
            }

            other => {
                // stacked verbosity: -v, -vv, -vvv, ...
                if other.len() >= 2 && other.starts_with('-') && other[1..].chars().all(|c| c == 'v') {
                    o.verbosity += (other.len() - 1) as u8;
                }
                // bare DNS record type token in DNS mode (dig-style: `kaisen dns MX host`)
                else if o.mode == Mode::Dns && is_dns_type(other) {
                    o.dns_types.push(other.to_ascii_uppercase());
                } else if other.starts_with('-') {
                    return Err(format!("unknown option: {other}"));
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

    // Resolve port selection precedence: explicit -p > all > top.
    if !o.ports_explicit {
        if want_all {
            o.ports = ports::all_ports();
        } else if let Some(n) = want_top {
            o.ports = ports::top_ports(n);
        } else {
            o.ports = ports::top_ports(1000); // sensible default like nmap
        }
    }

    Ok(o)
}

pub fn help_text() -> String {
    format!(
        "\
Kaisen v{VERSION} — a fast nmap + dig hybrid network scanner (no root required)

USAGE:
    kaisen [SCAN OPTIONS] <target> [<target> ...]
    kaisen dns [DNS OPTIONS] <name> [@server]
    kaisen -D <TYPE> <name> [@server]

    Targets may be: hostname, IPv4, IPv6, or CIDR (e.g. 192.168.1.0/24).
    The binary is also installed as `kai` and `kaison`.

  ── SCAN TYPE ──────────────────────────────────────────────────────────────
    -sT, --connect         TCP connect() scan (DEFAULT, works without root)
    -sS, --syn             SYN half-open scan (needs root; auto-falls back to -sT)

  ── PORT SELECTION ─────────────────────────────────────────────────────────
    -PF, --port-famous     Scan the 1000 most famous ports (default)
    -PA, --ports-all, -p-  Scan ALL ports (1-65535)
    -F,  --fast            Fast: top 100 ports
    -p,  --ports <SPEC>    Explicit ports, e.g. -p 22,80,443,8000-8100
        --top-ports <N>    Scan the top N famous ports

  ── DETECTION ──────────────────────────────────────────────────────────────
    -sV, --service-version Probe open ports to detect service & version (banner)
    -OS, --os-detection    Detect the OS. Used ALONE it is a focused action:
                           probes high-signal ports and reports OS + host role
                           (no port table). Combined with a scan it adds an
                           'OS guess' line. Heuristic, works without root.
    -vuln, --vuln          Match detected services against known-vuln signatures
    -A,  --aggressive      Enable -sV, -OS and -vuln together

  ── HOST DISCOVERY ─────────────────────────────────────────────────────────
    -Pn, --no-ping         Treat hosts as online, skip discovery (default: no root)

  ── TIMING & PERFORMANCE ───────────────────────────────────────────────────
    -T0 .. -T5             Timing template: 0=paranoid .. 3=normal .. 5=insane
    -HS, --hyper-speed     Hyper speed: maximum concurrency, minimal timeouts
        --concurrency <N>  Max simultaneous connections
        --timeout <MS>     Per-connection timeout in milliseconds
        --retries <N>      Retries for filtered/timed-out ports

  ── OUTPUT & DISPLAY ───────────────────────────────────────────────────────
    --open                 Only show open ports
    --reason               Show why a port is in its state
    -v, -vv, -vvv          Increase verbosity
    -oN | -oJ | -oG        Output: Normal | JSON | Grepable
    --color / --no-color   Toggle ANSI colour (honours NO_COLOR)
    -4 / -6                Force IPv4 / IPv6

  ── DNS (dig replacement) ──────────────────────────────────────────────────
    dns, dig, resolve      DNS subcommand
    -D, --dns <TYPE>       Query a record type: A AAAA NS CNAME SOA PTR MX TXT SRV CAA ANY
    -x, --reverse          Reverse (PTR) lookup for an IP address
    @server                Query a specific DNS server (e.g. @1.1.1.1)
    --dns-port <N>         DNS server port (default 53)
    +short, --short        Terse output (answers only)
    +tcp, --dns-tcp        Force DNS over TCP
    +ttl, --ttl            Show TTL values
    -h, --help             Show this help
    -V, --version          Show version

EXAMPLES:
    kaisen -OS 192.168.1.2                 # just the OS + host info (focused)
    kaison -OS -sV -Pn -T4 -vvv -PA -vuln 192.168.1.2
    kaisen -PF -sV 10.0.0.5
    kaisen -HS -p 1-65535 --open scanme.example.com
    kaisen -sV 10.0.0.5 > scan.txt          # redirect: colours auto-off in files
    kaisen dns MX example.com @8.8.8.8
    kaisen -D ANY example.com +short
    kaisen -x 1.1.1.1

TIP: All results go to stdout, so you can redirect or append with > and >>
     (e.g. 'kaisen -sV host >> report.txt'). Colours turn off automatically
     when the output is not a terminal, so files stay clean.

Kaisen defaults to unprivileged, root-free scanning. SYN/ICMP features degrade
gracefully when raw-socket privileges are unavailable (e.g. unrooted Termux).
"
    )
}

pub fn version_text() -> String {
    format!("kaisen {VERSION}")
}
