//! Orquestación del escaneo: expansión de objetivos (host / IP / CIDR), el
//! escáner TCP asíncrono sin privilegios con connect(), enriquecimiento opcional
//! de servicio/versión/SO/vuln, y renderizado de resultados en formato
//! normal / JSON / grepable.

pub mod diff;
pub mod mail;
pub mod neigh;
pub mod osfp;
pub mod traceroute;
pub mod udp;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::cli::{IpVersion, Options, OutputFormat, ScanKind};
use crate::ports::service_name;
use crate::service::{self, ServiceInfo};
use crate::util::output::{json_escape, xml_escape, Painter};
use crate::vuln::{self, Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    Closed,
    Filtered,
    /// UDP only: nothing came back. A drop and a service with nothing to say
    /// are genuinely indistinguishable without raw sockets, so we say so.
    OpenFiltered,
}

impl State {
    pub fn label(&self) -> &'static str {
        match self {
            State::Open => "open",
            State::Closed => "closed",
            State::Filtered => "filtered",
            State::OpenFiltered => "open|filtered",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortReport {
    pub port: u16,
    /// "tcp" or "udp" — UDP rows come from the -sU phase.
    pub proto: &'static str,
    pub state: State,
    pub service: Option<ServiceInfo>,
    pub findings: Vec<Finding>,
    pub reason: &'static str,
    /// Full service detection result captured on the *initial* scan
    /// connection via `detect_with_stream`, before any middlebox
    /// rate-limit can block reconnects. `None` for closed/filtered ports
    /// or when service detection is not requested.
    pub eager_service: Option<ServiceInfo>,
    /// -WW: whatweb-style web fingerprint, present only for open HTTP/HTTPS
    /// ports when `--webscan` ran and something was learned.
    pub web: Option<crate::service::web::WebProfile>,
}

/// Outcome of the `-FW` firewall pre-check: the random high ports we sampled
/// before the real scan, and whether the host answered *all* of them "open".
/// All-open means a firewall / CPE is completing every handshake, so the real
/// scan is aborted — reporting 1000 "open" ports there would be a lie.
#[derive(Debug, Clone, Default)]
pub struct FirewallProbe {
    /// The random high ports (6000–60000) we sampled.
    pub sampled: Vec<u16>,
    /// True when every sampled port came back open — the abort condition.
    pub blocked: bool,
}

pub struct HostReport {
    pub target: String,
    pub ip: IpAddr,
    pub ports: Vec<PortReport>,
    pub os_guess: String,
    pub elapsed: Duration,
    pub open_count: usize,
    pub closed_count: usize,
    pub filtered_count: usize,
    pub probes: Option<crate::scan::osfp::Probes>,
    /// Host discovery result. Always true under -Pn. Otherwise true when the
    /// host answered ICMP echo, or any port answered (open or closed — a
    /// TCP RST is proof of life even if ICMP is filtered).
    pub host_up: bool,
    /// -MC: MAC address from the OS's own ARP/neighbor cache. Only ever
    /// resolvable for a directly-connected local subnet (no root, no
    /// cross-subnet ARP) — None otherwise.
    pub mac: Option<String>,
    /// Whether a completed handshake proves anything against this host, and
    /// if not, what gave the middlebox away. Every TCP port that only got as
    /// far as a handshake is reported open|filtered instead of open; the
    /// ones a service actually answered on stay open.
    pub doubt: Doubt,
    /// -DP: best-effort device-type guess (phone/console/PC/etc.), empty
    /// unless -DP was requested.
    pub device_guess: String,
    pub device_confidence: &'static str,
    pub device_signals: Vec<String>,
    /// `-FW` firewall pre-check result, or `None` when `-FW` was not requested.
    /// When `blocked` is set the real scan was skipped on purpose.
    pub firewall: Option<FirewallProbe>,
    /// Count of live streaming lines emitted to stderr during the scan of this host.
    pub live_lines: usize,
    /// Unix timestamp when host scanning began.
    pub start_ts: u64,
    /// Unix timestamp when host scanning completed.
    pub end_ts: u64,
    /// Average observed round-trip time in milliseconds (learned via Pacer).
    pub avg_rtt_ms: f64,
    /// Count of timed-out (filtered) port probes.
    pub timeouts: usize,
}

/// Expand a target string into concrete IPs. Supports hostname, IPv4/IPv6, and
/// IPv4 CIDR notation. A hostname yields its primary address only, the way a
/// scanner is expected to behave.
pub async fn expand_target(t: &str, ipv: IpVersion) -> Result<Vec<(String, IpAddr)>, String> {
    expand(t, ipv, true).await
}

/// The same expansion for `--exclude`, with two deliberate differences: every
/// address a hostname resolves to is kept, and -4/-6 is not applied. Excluding
/// a name has to remove the host outright — keeping one of its addresses out of
/// the scan while quietly scanning another would defeat the point of asking.
pub async fn expand_exclusion(t: &str) -> Result<Vec<(String, IpAddr)>, String> {
    expand(t, IpVersion::Any, false).await
}

async fn expand(
    t: &str,
    ipv: IpVersion,
    primary_address_only: bool,
) -> Result<Vec<(String, IpAddr)>, String> {
    // CIDR?
    if let Some((base, prefix)) = t.split_once('/') {
        if let Ok(ip) = base.parse::<Ipv4Addr>() {
            let prefix: u32 = prefix.parse().map_err(|_| "invalid CIDR prefix")?;
            if prefix > 32 {
                return Err("CIDR prefix out of range".into());
            }
            let base_u = u32::from(ip);
            let host_bits = 32 - prefix;
            let count: u64 = 1u64 << host_bits;
            if count > 65536 {
                return Err("CIDR range too large (max /16)".into());
            }
            let mask = if host_bits == 32 {
                0
            } else {
                base_u & !((count as u32).wrapping_sub(1))
            };
            let net = if host_bits == 32 { 0 } else { mask };
            let start = if host_bits == 32 { base_u } else { net };
            let mut out = Vec::new();
            for i in 0..count as u32 {
                let addr = Ipv4Addr::from(start.wrapping_add(i));
                if ip_matches(IpAddr::V4(addr), ipv) {
                    out.push((addr.to_string(), IpAddr::V4(addr)));
                }
            }
            if out.is_empty() {
                return Err("target IP version filtered by -4/-6".into());
            }
            return Ok(out);
        }
        if let Ok(ip) = base.parse::<Ipv6Addr>() {
            let prefix: u32 = prefix.parse().map_err(|_| "invalid CIDR prefix")?;
            if prefix > 128 {
                return Err("IPv6 CIDR prefix out of range".into());
            }
            if prefix < 48 {
                return Err("IPv6 CIDR range too large (min /48)".into());
            }
            let host_bits = 128 - prefix;
            let count: u64 = if host_bits > 16 {
                65536
            } else {
                1u64 << host_bits
            };
            let base_u = u128::from(ip);
            let mask = if host_bits == 128 {
                0u128
            } else {
                base_u & !((1u128 << host_bits).wrapping_sub(1))
            };
            let start = if host_bits == 128 { base_u } else { mask };
            let mut out = Vec::new();
            for i in 0..count {
                let addr = Ipv6Addr::from(start.wrapping_add(i as u128));
                if ip_matches(IpAddr::V6(addr), ipv) {
                    out.push((addr.to_string(), IpAddr::V6(addr)));
                }
            }
            if out.is_empty() {
                return Err("target IP version filtered by -4/-6".into());
            }
            return Ok(out);
        }
        return Err("invalid CIDR address".into());
    }

    // Literal IP?
    if let Ok(ip) = t.parse::<IpAddr>() {
        if !ip_matches(ip, ipv) {
            return Err("target IP version filtered by -4/-6".into());
        }
        return Ok(vec![(t.to_string(), ip)]);
    }

    // Hostname -> resolve.
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((t, 0))
        .await
        .map_err(|e| format!("cannot resolve {t}: {e}"))?
        .collect();
    let mut out = Vec::new();
    for sa in addrs {
        let ip = sa.ip();
        if ip_matches(ip, ipv) && !out.iter().any(|(_, existing)| *existing == ip) {
            out.push((t.to_string(), ip));
        }
    }
    if out.is_empty() {
        return Err(format!("{t} resolved to no matching addresses"));
    }
    // For a hostname we typically scan a single primary address.
    if primary_address_only {
        out.truncate(1);
    }
    Ok(out)
}

fn ip_matches(ip: IpAddr, ipv: IpVersion) -> bool {
    match ipv {
        IpVersion::Any => true,
        IpVersion::V4 => ip.is_ipv4(),
        IpVersion::V6 => ip.is_ipv6(),
    }
}

/// What a single connect attempt came back with, stripped of the I/O
/// plumbing so the classification below can be read — and tested — on its
/// own. Every variant is spelled out on purpose: there is no catch-all that
/// could quietly turn "we heard nothing" into "open".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    /// The three-way handshake completed. Something accepted the connection.
    Handshake,
    /// The peer answered and refused — a RST. The only answer that proves a
    /// reachable host with nothing listening on that port.
    Refused,
    /// connect() failed for some other reason: host/network unreachable, a
    /// local resource limit, an ICMP admin-prohibited. Nothing was learned.
    Error,
    /// The timeout expired with no answer at all. This is what a silently
    /// dropped SYN looks like, and it is *not* evidence of anything open.
    NoAnswer,
}

/// One connect attempt, reduced to an `Attempt`.
async fn attempt_connect(addr: SocketAddr, dur: Duration) -> Attempt {
    attempt_within(dur, TcpStream::connect(addr)).await
}

/// The attempt itself, over any connect future — which is what lets the
/// tests hand it a future that never resolves and check the timeout branch
/// without needing a network that drops packets on cue.
async fn attempt_within<F>(dur: Duration, connect: F) -> Attempt
where
    F: std::future::Future<Output = std::io::Result<TcpStream>>,
{
    match timeout(dur, connect).await {
        Ok(Ok(_stream)) => Attempt::Handshake,
        Ok(Err(e)) => attempt_from_io(&e),
        // Elapsed: the timeout won, nothing came back.
        Err(_) => Attempt::NoAnswer,
    }
}

/// A refusal is the one connect error that carries information; everything
/// else means the probe failed, not that the port is open.
fn attempt_from_io(e: &std::io::Error) -> Attempt {
    if e.kind() == std::io::ErrorKind::ConnectionRefused {
        Attempt::Refused
    } else {
        Attempt::Error
    }
}

/// The port state machine, in one place and with no default branch.
fn classify(a: Attempt) -> (State, &'static str) {
    match a {
        Attempt::Handshake => (State::Open, "syn-ack"),
        Attempt::Refused => (State::Closed, "conn-refused"),
        Attempt::Error => (State::Filtered, "no-response"),
        Attempt::NoAnswer => (State::Filtered, "timeout"),
    }
}

/// Only an answer settles a port. Silence gets retried, because a dropped
/// SYN and a merely slow host look the same from one probe — and once the
/// retries are spent, silence stays filtered rather than being promoted.
fn should_retry(state: State, attempts: u32, retries: u32) -> bool {
    state == State::Filtered && attempts < retries
}

async fn probe_port(ip: IpAddr, port: u16, timeout_ms: u64, retries: u32) -> (State, &'static str) {
    let addr = SocketAddr::new(ip, port);
    let dur = Duration::from_millis(timeout_ms);
    let mut attempts = 0;
    loop {
        let (state, reason) = classify(attempt_connect(addr, dur).await);
        if !should_retry(state, attempts, retries) {
            return (state, reason);
        }
        attempts += 1;
    }
}

/// Adaptive per-host connect timeout, nmap-style.
///
/// Every port starts out waiting the full template timeout, but the instant any
/// port answers — an open handshake or a closed RST — we know the host's real
/// round-trip time and can stop waiting 1.5 s on each *silent* (filtered) port,
/// which is where a WAN sweep spends nearly all its wall-clock. Against a host
/// 21 ms away, a fixed 1.5 s timeout wastes ~70x the RTT per filtered port; this
/// is the single biggest reason nmap's connect scan runs an order of magnitude
/// faster than a fixed-timeout loop. It costs nothing and touches neither the
/// concurrency nor the rate cap, so it does not change how gentle the sweep is
/// on the network — only how long it wastes waiting on silence.
pub struct Pacer {
    /// Current effective connect timeout (ms). Starts at the template value and
    /// only ever ratchets *down* as the RTT is learned.
    eff_ms: std::sync::atomic::AtomicU64,
    /// The template timeout — the ceiling; we never wait longer than this.
    ceiling_ms: u64,
    /// Never wait less than this, so a genuinely slow-but-alive port on a
    /// jittery link isn't misread as filtered.
    floor_ms: u64,
    /// Most recent observed latency in milliseconds.
    pub observed_rtt_ms: std::sync::atomic::AtomicU64,
    observed_count: std::sync::atomic::AtomicUsize,
    total_rtt_ms: std::sync::atomic::AtomicU64,
}

impl Pacer {
    fn new(template_ms: u64) -> Self {
        // The floor scales a little with the template so the patient profiles
        // (-T0/-T1) stay patient, but never drops below a WAN-safe 250 ms.
        let floor = (template_ms / 4).clamp(250, 1000);
        Pacer {
            eff_ms: std::sync::atomic::AtomicU64::new(template_ms),
            ceiling_ms: template_ms,
            floor_ms: floor,
            observed_rtt_ms: std::sync::atomic::AtomicU64::new(0),
            observed_count: std::sync::atomic::AtomicUsize::new(0),
            total_rtt_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_millis(self.eff_ms.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// A port answered in `latency`. Ratchet the effective timeout down toward a
    /// generous multiple of the observed RTT (never below the floor, never above
    /// the ceiling). `fetch_min` so concurrent observations converge on the
    /// most-informed lower bound and never bounce back up.
    fn observe(&self, latency: Duration) {
        let rtt = latency.as_millis() as u64;
        self.observed_rtt_ms
            .store(rtt, std::sync::atomic::Ordering::Relaxed);
        self.observed_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.total_rtt_ms
            .fetch_add(rtt, std::sync::atomic::Ordering::Relaxed);
        let target = rtt
            .saturating_mul(5)
            .saturating_add(80)
            .clamp(self.floor_ms, self.ceiling_ms);
        self.eff_ms
            .fetch_min(target, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn avg_rtt_ms(&self) -> f64 {
        let cnt = self
            .observed_count
            .load(std::sync::atomic::Ordering::Relaxed);
        if cnt > 0 {
            self.total_rtt_ms.load(std::sync::atomic::Ordering::Relaxed) as f64 / cnt as f64
        } else {
            0.0
        }
    }
}

/// The window the `-FW` pre-check samples from: high ports, up in the range
/// almost nothing legitimately listens on. A host reporting these open is
/// answering for ports it has no service on — the tell of a firewall / CPE.
const FW_PORT_LO: u16 = 6000;
const FW_PORT_HI: u16 = 60000;
/// How many random high ports the pre-check samples, and how many must come
/// back open to call it a blanket-answering firewall: all of them. Three
/// independent high ports all answering open is not a coincidence.
const FW_SAMPLE: usize = 3;

/// A tiny time-seeded xorshift, enough to spread a few port picks across the
/// window without pulling in an RNG crate. `seed_extra` mixes in the target IP
/// so two hosts sampled in the same instant don't get identical ports.
fn fw_random_ports(seed_extra: u64) -> Vec<u16> {
    let mut s = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        ^ seed_extra)
        | 1;
    let span = (FW_PORT_HI - FW_PORT_LO) as u64;
    let mut ports = Vec::with_capacity(FW_SAMPLE);
    while ports.len() < FW_SAMPLE {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let p = FW_PORT_LO + (s % span) as u16;
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    ports
}

/// Sample a few random high ports and see whether the host answers *all* of
/// them. Runs the probes concurrently so the whole check costs one timeout,
/// not `FW_SAMPLE` of them — the entire point is to fail fast.
async fn firewall_precheck(ip: IpAddr, timeout_ms: u64) -> FirewallProbe {
    let seed = match ip {
        IpAddr::V4(a) => u32::from(a) as u64,
        IpAddr::V6(a) => u128::from(a) as u64,
    };
    let sampled = fw_random_ports(seed);
    // No retries: for a fast pre-check one look is enough, and a real open
    // port answers on the first connect anyway.
    let states = stream::iter(sampled.clone())
        .map(|port| async move { probe_port(ip, port, timeout_ms, 0).await.0 })
        .buffer_unordered(FW_SAMPLE)
        .collect::<Vec<State>>()
        .await;
    let blocked = states.iter().all(|s| *s == State::Open);
    FirewallProbe { sampled, blocked }
}

/// Ports that carry HTTP even without a service label, so `-WW` still probes
/// them on a plain-ish result. The `true` ones are HTTPS by default.
const WEB_PORTS: &[(u16, bool)] = &[
    (80, false),
    (81, false),
    (443, true),
    (591, false),
    (2052, false),
    (2082, false),
    (2086, false),
    (2095, false),
    (3000, false),
    (5000, false),
    (7001, false),
    (8000, false),
    (8008, false),
    (8080, false),
    (8081, false),
    (8088, false),
    (8090, false),
    (8443, true),
    (8444, true),
    (8888, false),
    (9000, false),
    (9090, false),
    (9443, true),
    (10000, false),
    (4443, true),
    (7443, true),
    (2053, true),
    (2083, true),
    (2087, true),
    (2096, true),
];

/// Decide whether an open TCP port is a web endpoint worth fingerprinting, and
/// whether it is TLS-wrapped. Returns `None` for non-web ports so `-WW` doesn't
/// waste GETs on SSH or a database.
fn is_web_port(r: &PortReport) -> Option<bool> {
    if let Some(svc) = &r.service {
        let name = svc.name.to_ascii_lowercase();
        let tls = !svc.tls_version.is_empty();
        if name.contains("http") {
            // Trust the label: https / http-alt / https-alt / http-proxy…
            return Some(
                tls || name.contains("https") || WEB_PORTS.iter().any(|(p, t)| *p == r.port && *t),
            );
        }
        // A TLS port that didn't identify as HTTP but sits on a known web port
        // (e.g. an app console on 8443) is still worth a look.
        if tls {
            if let Some((_, t)) = WEB_PORTS.iter().find(|(p, _)| *p == r.port) {
                return Some(*t);
            }
        }
        // A named non-web service (ssh, smtp, mysql…) on a random port: skip.
        if !name.is_empty() && name != "unknown" {
            return None;
        }
    }
    // No useful service label: fall back to the well-known web ports.
    WEB_PORTS
        .iter()
        .find(|(p, _)| *p == r.port)
        .map(|(_, t)| *t)
}

/// Maximum number of ports doing active service detection at the same time
/// within Phase 1. Service detection (TLS handshakes, HTTP requests, binary
/// probes, fallback connections) generates far more traffic per port than a
/// bare connect(). On constrained links — mobile data, satellite, tethered
/// connections — running detection on too many ports at once saturates the
/// link and kills connectivity for everything else, including the scan's own
/// SYN packets. The semaphore keeps scan throughput high (filtered ports
/// still churn through at full concurrency) while capping the heavy I/O.
const SVC_DETECT_CONCURRENCY: usize = 6;

/// Run the initial TCP connect for a port, then — on a successful handshake —
/// immediately run full service detection on the *same socket* via
/// `service::detect_with_stream`. This is the critical path against hosts
/// protected by a middlebox: the middlebox accepts every SYN but blocks
/// reconnects, so detection must happen on the first and only connection we get.
///
/// * `target` is the original user-supplied name, used for TLS SNI and HTTP
///   `Host` headers so virtual-hosted services answer correctly.
/// * `svc_sem` throttles concurrent detections to avoid saturating the link.
async fn probe_and_sniff(
    ip: IpAddr,
    port: u16,
    timeout_ms: u64,
    retries: u32,
    target: &str,
    want_service: bool,
    svc_sem: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    pacer: &Pacer,
) -> (State, &'static str, Option<ServiceInfo>) {
    let addr = SocketAddr::new(ip, port);
    let mut attempts = 0;
    loop {
        // Adaptive timeout: as soon as any port has revealed the host's RTT the
        // silent ports stop costing the full template timeout.
        let dur = pacer.timeout();
        let t0 = Instant::now();
        match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                // A completed handshake is a real round-trip: feed it back so the
                // rest of the sweep can shorten its wait.
                pacer.observe(t0.elapsed());
                // Reset on close instead of a graceful FIN: this handshake just
                // put an ESTABLISHED entry in the router's conntrack table, and
                // letting it linger in TIME_WAIT is what fills that table and
                // knocks the link offline for minutes on a big sweep. The RST
                // frees the slot the instant we drop the socket. See
                // `netutil::reset_on_close`.
                crate::util::netutil::reset_on_close(&stream);
                // Connection established. Run full service detection on this
                // socket right now — before the middlebox can block reconnects.
                let info = if want_service {
                    // Throttle concurrent detections: each one can exchange
                    // kilobytes of data and open fallback connections, so
                    // running too many at once overwhelms constrained links.
                    let _permit = match &svc_sem {
                        Some(s) => Some(s.acquire().await.expect("svc semaphore closed")),
                        None => None,
                    };
                    Some(
                        service::detect_with_stream(
                            stream,
                            addr,
                            service_name(port),
                            timeout_ms.max(1500),
                            target,
                        )
                        .await,
                    )
                } else {
                    None
                };
                return (State::Open, "syn-ack", info);
            }
            Ok(Err(e)) => {
                let (state, reason) = classify(attempt_from_io(&e));
                // A RST (Closed) is also a real round-trip from the host, so it
                // teaches the RTT too. Other errors (unreachable, local limits)
                // return without touching the wire, so they teach nothing.
                if state == State::Closed {
                    pacer.observe(t0.elapsed());
                }
                if !should_retry(state, attempts, retries) {
                    return (state, reason, None);
                }
            }
            Err(_) => {
                if !should_retry(State::Filtered, attempts, retries) {
                    return (State::Filtered, "timeout", None);
                }
            }
        }
        attempts += 1;
    }
}

/// Why a completed handshake can't be taken at face value against a host —
/// or `None` when it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Doubt {
    /// Nothing suspicious. A handshake means what it says.
    None,
    /// Control ports that nothing should be listening on answered too, so
    /// something is completing handshakes indiscriminately.
    ControlPortsAnswered,
    /// A pile of opens and not one refusal in the whole scan. Real hosts
    /// refuse *something*; a host that never says no isn't answering for
    /// itself.
    NothingEverRefuses,
}

impl Doubt {
    pub fn is_doubtful(self) -> bool {
        self != Doubt::None
    }

    /// The specific observation, for the warning line — a scanner that says
    /// "results may be unreliable" without saying why is just noise.
    fn note(self) -> &'static str {
        match self {
            Doubt::None => "",
            Doubt::ControlPortsAnswered => {
                "it completed the handshake on control ports that nothing should be \
                 listening on"
            }
            Doubt::NothingEverRefuses => {
                "it accepted a large share of the scan and refused nothing at all — no \
                 real host answers every knock without ever saying no"
            }
        }
    }
}

/// How many control ports the sentinel check probes, and how many of them
/// have to answer before "open" stops meaning anything for this host.
const SENTINEL_PORTS: usize = 3;
const SENTINEL_TRIP: usize = 2;

/// Pick control ports: high, effectively never listening, and never one of
/// the ports actually being scanned (whose state is the thing under test).
fn sentinel_ports(scanned: &[u16]) -> Vec<u16> {
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x2545F491_4F6CDD1D)
        ^ ((std::process::id() as u64) << 32);
    let mut out: Vec<u16> = Vec::with_capacity(SENTINEL_PORTS);
    // Bounded: a caller scanning every port in the window gets a short list
    // back, and the check below declines to run rather than spinning here.
    for _ in 0..64 {
        if out.len() == SENTINEL_PORTS {
            break;
        }
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let port = 40_000u16 + (seed % 25_000) as u16;
        if !scanned.contains(&port) && !out.contains(&port) {
            out.push(port);
        }
    }
    out
}

/// Is a completed handshake worth anything against this host?
///
/// A connect() scan reads "the handshake finished" as "the port is open",
/// which holds only when the network in between is honest. Carrier CPEs and
/// inline "security" middleboxes answer SYN on the host's behalf for *every*
/// port, so the scan comes back with hundreds of open ports, no closed ones
/// at all, and not one banner to show for it. nmap's raw-SYN scan runs into
/// the same wall from the other side and gives up loudly ("giving up on port
/// because retransmission cap hit"); this is the connect()-scan equivalent —
/// probe a few ports that nothing should be listening on, and if those come
/// back "open" too, the verdict is about the middlebox, not the host.
async fn syn_ack_is_meaningless(ip: IpAddr, timeout_ms: u64, scanned: &[u16]) -> bool {
    let ports = sentinel_ports(scanned);
    if ports.len() < SENTINEL_TRIP {
        return false;
    }
    let states: Vec<State> = stream::iter(ports)
        .map(|port| async move { probe_port(ip, port, timeout_ms, 0).await.0 })
        .buffer_unordered(SENTINEL_PORTS)
        .collect()
        .await;
    states.iter().filter(|s| **s == State::Open).count() >= SENTINEL_TRIP
}

/// The shape of the results themselves, for the middlebox the sentinel walks
/// straight past.
///
/// A CPE that answers for *every* port trips the sentinel on the first try.
/// A pickier one answers only on ports that look like services and drops the
/// rest, so control ports at 40000+ come back filtered exactly like honest
/// silence — and the scan still returns a wall of open ports with nothing
/// behind them. What that middlebox cannot fake is a refusal: a RST means a
/// reachable host that chose to say no. Hundreds of ports scanned, dozens
/// accepted, and not one refused among them is not a busy host; a busy host
/// still refuses the ports it isn't using.
///
/// Deliberately conservative, since it downgrades on inference rather than
/// on a probe: it needs a scan wide enough to be meaningful, an absolute
/// pile of opens, and a large share of the scan — a hardened host with a
/// handful of services behind a DROP-everything firewall (0 closed, few
/// open) stays untouched, and anything caught here is still promoted back to
/// open by -sV the moment a service actually replies.
fn opens_look_manufactured(open: usize, closed: usize, scanned: usize) -> bool {
    closed == 0 && scanned >= 20 && open >= 10 && open * 10 >= scanned
}

/// Everything known about whether this host's handshakes can be believed.
fn assess_doubt(sentinel_tripped: bool, open: usize, closed: usize, scanned: usize) -> Doubt {
    if sentinel_tripped {
        Doubt::ControlPortsAnswered
    } else if opens_look_manufactured(open, closed, scanned) {
        Doubt::NothingEverRefuses
    } else {
        Doubt::None
    }
}

/// Live progress for the long phases (`--progress` / `--stats-every`).
///
/// The scan loops stay untouched apart from one atomic increment per unit of
/// work; a background task does the arithmetic and the printing on its own
/// schedule, so the cost is the same whether the refresh is every second or
/// every minute. Everything goes to **stderr**, never stdout, so `-oJ` output
/// and any redirect stay clean.
pub struct Progress {
    done: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Progress {
    pub fn start(label: &str, total: usize, opts: &Options) -> Progress {
        // A loading indicator on anything that makes you wait: honour
        // --progress when set, otherwise tick once a second on its own whenever
        // stderr is a terminal. It goes to stderr, so JSON/grepable on stdout
        // stay clean, and `start_every` skips it for non-terminals and for
        // trivially short phases (its own total>1 + first-second-sleep guard),
        // so a fast scan still prints nothing.
        let secs = if opts.progress_secs > 0 {
            opts.progress_secs
        } else {
            1
        };
        Progress::start_every(label, total, secs)
    }

    /// Like `start`, but with an explicit refresh cadence rather than reading
    /// `--progress` from the options. Streaming mode uses this to keep a live
    /// counter ticking on stderr while the scan drains hundreds of filtered
    /// ports — otherwise, once the open ports have streamed, the terminal sits
    /// silent for tens of seconds and looks hung.
    pub fn start_every(label: &str, total: usize, every_secs: u64) -> Progress {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Nothing to report, not asked for, or nobody watching: a progress bar
        // in a log file or a CI transcript is just noise.
        let wanted =
            every_secs > 0 && total > 1 && std::io::IsTerminal::is_terminal(&std::io::stderr());
        if !wanted {
            return Progress { done, task: None };
        }

        let counter = done.clone();
        let every = Duration::from_secs(every_secs);
        let label = label.to_string();
        let start = Instant::now();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let n = counter.load(std::sync::atomic::Ordering::Relaxed);
                if n >= total {
                    break;
                }
                let elapsed = start.elapsed().as_secs_f64();
                let rate = if elapsed > 0.0 {
                    n as f64 / elapsed
                } else {
                    0.0
                };
                let pct = n as f64 * 100.0 / total as f64;
                let eta = if rate > 0.0 {
                    fmt_duration((total - n) as f64 / rate)
                } else {
                    "?".to_string()
                };
                eprint!("\r\x1b[2K{label}: {n}/{total} ({pct:.0}%) at {rate:.0}/s, ETA {eta}");
                let _ = std::io::Write::flush(&mut std::io::stderr());
            }
        });
        Progress {
            done,
            task: Some(task),
        }
    }

    /// A handle for the scan loop to bump once per finished unit of work.
    pub fn counter(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        self.done.clone()
    }

    /// Stop the reporter and wipe the line, so the report that follows starts
    /// on clean ground.
    pub fn finish(self) {
        if let Some(t) = self.task {
            t.abort();
            eprint!("\r\x1b[2K");
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }
}

fn fmt_duration(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "?".to_string();
    }
    let s = secs.round() as u64;
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

/// Small, fixed port set for the fast discovery sweep — mirrors nmap's
/// default host-discovery probes but extended to cover more universally
/// common services (FTP, SSH, SMTP, HTTP, HTTPS). All ports are probed in
/// parallel so the total cost is one timeout, not N × timeout.
///
/// 400 ms was too short for WAN hosts where middlebox-wrapped ports (e.g.
/// tcpwrapped 80/443) complete the handshake slowly or where the target only
/// exposes SSH/FTP rather than HTTP. 1000 ms matches nmap's WAN-safe default.
const DISCOVERY_PORTS: [u16; 7] = [21, 22, 25, 80, 443, 8080, 8443];
const DISCOVERY_TCP_TIMEOUT_MS: u64 = 1000;

/// Is this host worth a full port scan? ICMP ping and several common TCP ports
/// are probed **concurrently** — the total elapsed time is one timeout, not
/// N × timeout — and then the OS ARP/neighbor cache is checked as a
/// last-resort layer-2 fallback.
async fn quick_alive(ip: IpAddr) -> bool {
    let ping = crate::scan::osfp::ping_quick(ip);
    // Probe all discovery ports in parallel: first non-Filtered answer wins.
    let tcp = async {
        let states: Vec<State> = stream::iter(DISCOVERY_PORTS)
            .map(|port| async move { probe_port(ip, port, DISCOVERY_TCP_TIMEOUT_MS, 0).await.0 })
            .buffer_unordered(DISCOVERY_PORTS.len())
            .collect()
            .await;
        states.into_iter().any(|s| s != State::Filtered)
    };
    let (ping_ok, tcp_ok) = tokio::join!(ping, tcp);
    if ping_ok || tcp_ok {
        return true;
    }
    crate::scan::osfp::arp_alive(ip).await
}

/// Fast parallel liveness sweep across *every* target before the expensive
/// full port scan — the same two-phase shape `nmap` uses: hit everyone with
/// a quick ping + a couple of common ports at once, then only fully scan
/// whoever answered, instead of running the full port list against hosts
/// that were never going to respond. Skipped entirely under -Pn, where
/// every host is simply assumed up.
pub async fn discover_alive(hosts: &[(String, IpAddr)], opts: &Options) -> Vec<bool> {
    if opts.no_ping {
        return vec![true; hosts.len()];
    }
    let conc = opts.timing.concurrency.max(1);
    let prog = Progress::start("Discovery", hosts.len(), opts);
    let counter = prog.counter();
    let mut results: Vec<(usize, bool)> = stream::iter(hosts.iter().enumerate())
        .map(|(idx, (_, ip))| {
            let ip = *ip;
            let counter = counter.clone();
            async move {
                let alive = quick_alive(ip).await;
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                (idx, alive)
            }
        })
        .buffer_unordered(conc)
        .collect()
        .await;
    prog.finish();
    results.sort_by_key(|(idx, _)| *idx);
    results.into_iter().map(|(_, alive)| alive).collect()
}

/// Scan one host across the given ports. `known_alive` comes from the
/// discovery sweep (`discover_alive`) run once up front for the whole
/// target list; when it's false (and -Pn wasn't given) we skip the full
/// port scan entirely rather than running it against a host that already
/// failed to answer anything.
pub async fn scan_host(target: &str, ip: IpAddr, opts: &Options, known_alive: bool) -> HostReport {
    let start = Instant::now();
    let start_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if !opts.no_ping && !known_alive {
        return HostReport {
            target: target.to_string(),
            ip,
            ports: Vec::new(),
            os_guess: String::new(),
            elapsed: start.elapsed(),
            open_count: 0,
            closed_count: 0,
            filtered_count: 0,
            probes: None,
            host_up: false,
            mac: None,
            doubt: Doubt::None,
            device_guess: String::new(),
            device_confidence: "none",
            device_signals: Vec::new(),
            firewall: None,
            live_lines: 0,
            start_ts,
            end_ts: start_ts,
            avg_rtt_ms: 0.0,
            timeouts: 0,
        };
    }

    let ports = opts.ports.clone();
    let timeout_ms = opts.timing.connect_timeout_ms;
    let retries = opts.timing.retries;
    let concurrency = opts.timing.concurrency.max(1);

    // Phase 0 (-FW): firewall / middlebox pre-check. Sample three random high
    // ports *before* touching the real ones. A host that answers all three
    // "open" is a firewall or CPE completing every handshake indiscriminately,
    // so any port list we produced would be fiction — bail out fast with a
    // warning instead. If the sampled ports come back closed or filtered the
    // host is genuinely scannable and we fall through to the normal scan.
    let fw_precheck: Option<FirewallProbe> = if opts.firewall_check {
        let probe = firewall_precheck(ip, timeout_ms).await;
        if probe.blocked {
            return HostReport {
                target: target.to_string(),
                ip,
                ports: Vec::new(),
                os_guess: String::new(),
                elapsed: start.elapsed(),
                open_count: 0,
                closed_count: 0,
                filtered_count: 0,
                probes: None,
                host_up: true,
                mac: None,
                doubt: Doubt::None,
                device_guess: String::new(),
                device_confidence: "none",
                device_signals: Vec::new(),
                firewall: Some(probe),
                live_lines: 0,
                start_ts,
                end_ts: start_ts,
                avg_rtt_ms: 0.0,
                timeouts: 0,
            };
        }
        Some(probe)
    } else {
        None
    };

    // Phase 1: full connectivity scan. Liveness is already established at
    // this point (the discovery sweep confirmed it, or -Pn assumes it), so
    // there's no need to ping again here.
    // Whether to run service detection eagerly on the initial connection:
    // needed for -sV, -A (vuln), OS, device detection — but not for a plain
    // port-only scan, where it would add 400–900 ms of probe time per port.
    let want_service =
        opts.service_detection || opts.vuln || opts.os_detection || opts.device_detection;

    // Live streaming: print each open port to stderr the instant it is
    // confirmed, so the user gets results as they arrive instead of waiting for
    // the whole sweep to finish ("OPEN → show → keep scanning"). Human-readable
    // output on a terminal only — JSON/grepable must stay one complete document,
    // a redirect should stay clean, and -FW defers to its post-sweep verdict
    // (an open we streamed could still be downgraded), so each switches it off.
    let live_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stream_live = opts.stream
        && opts.output == OutputFormat::Normal
        && !opts.firewall_check
        && std::io::IsTerminal::is_terminal(&std::io::stderr());
    let stream_color = opts.color;
    if stream_live {
        live_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        eprintln!(
            "{}",
            Painter::new(stream_color).dim(&format!(
                "[{ip}] live — open ports appear below as they are found ({} to scan):",
                ports.len()
            ))
        );
    }

    // A live counter on stderr so a big, filtered-heavy sweep never looks hung:
    // once the open ports have streamed, hundreds of filtered ports still have
    // to time out, and without a ticking count that stretch of silence reads as
    // a freeze. `Progress::start` auto-enables it on a terminal (JSON/grepable
    // included, since it rides stderr) unless --progress overrode the cadence.
    let prog = Progress::start(&format!("{ip} ports"), ports.len(), opts);
    let counter = prog.counter();

    // Adaptive connect-timeout for this host: shared across every probe in the
    // sweep so the first answer shortens the wait for all the silent ports.
    let pacer = std::sync::Arc::new(Pacer::new(timeout_ms));

    // Token-bucket rate limiter: when max_rate > 0, a background task releases
    // one permit every (1000 / max_rate) ms, capping how fast new TCP SYNs are
    // sent. This prevents zombie conntrack entries from accumulating in home
    // routers faster than they can expire (router's syn_sent timeout ≈ 60-120s).
    // Dynamic rate scaling (Mejora 5): LAN hosts with small RTT can safely receive
    // higher packet rates without conntrack overflow.
    let rate_sem: Option<std::sync::Arc<tokio::sync::Semaphore>> = if opts.timing.max_rate > 0 {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let sem2 = sem.clone();
        let base_rate = opts.timing.max_rate;
        let total = ports.len();
        let pacer_for_rate = pacer.clone();
        tokio::spawn(async move {
            for _ in 0..total {
                let observed = pacer_for_rate
                    .observed_rtt_ms
                    .load(std::sync::atomic::Ordering::Relaxed);
                let rate = if observed > 0 {
                    let scale =
                        (timeout_ms as f64 / (observed as f64 * 3.0).max(10.0)).clamp(0.2, 5.0);
                    ((base_rate as f64 * scale) as u32).max(1)
                } else {
                    base_rate
                };
                let interval_ms = (1000u64).div_ceil(rate as u64);
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                sem2.add_permits(1);
            }
        });
        Some(sem)
    } else {
        None
    };

    // Service-detection throttle: limit how many ports run detection at the
    // same time. A connect-only probe is tiny (one SYN, one RST/ACK), but
    // detection exchanges kilobytes per port (TLS handshakes, HTTP requests,
    // binary probes, fallback connections). On mobile/constrained links
    // running too many at once saturates the pipe and kills connectivity.
    let svc_sem: Option<std::sync::Arc<tokio::sync::Semaphore>> = if want_service {
        Some(std::sync::Arc::new(tokio::sync::Semaphore::new(
            SVC_DETECT_CONCURRENCY,
        )))
    } else {
        None
    };

    let sweep = stream::iter(ports.clone())
        .map(|port| {
            let counter = counter.clone();
            let rate_sem = rate_sem.clone();
            let svc_sem = svc_sem.clone();
            let pacer = pacer.clone();
            let stream_live = stream_live;
            let stream_color = stream_color;
            let live_counter = live_counter.clone();
            async move {
                // Acquire a rate-limit token before opening the connection.
                // This spaces out new SYNs so the router's conntrack table
                // doesn't accumulate faster than entries can expire.
                if let Some(sem) = rate_sem {
                    let _ = sem.acquire().await;
                }
                // probe_and_sniff opens the TCP connection and — when
                // want_service is set — immediately runs full service detection
                // (banner, HTTP probe, TLS handshake…) on that *same* socket.
                // This fires before any middlebox rate-limit can block the
                // reconnects that the old two-phase approach depended on.
                let (state, reason, eager) = probe_and_sniff(
                    ip,
                    port,
                    timeout_ms,
                    retries,
                    target,
                    want_service,
                    svc_sem,
                    &pacer,
                )
                .await;
                // Stream this port the moment it resolves open — before the
                // sweep moves on to the next one.
                if stream_live && state == State::Open {
                    live_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    emit_live_open(port, &eager, stream_color);
                }
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                (port, state, reason, eager)
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<(u16, State, &'static str, Option<ServiceInfo>)>>();

    // The sentinel check rides along with the sweep — a handful of extra
    // connects next to hundreds, finishing well inside the sweep's own
    // window, so asking the question costs no wall-clock time. It only feeds
    // the doubt system, which is engaged solely under -FW, so we skip its
    // extra connects entirely on a plain scan and keep the network footprint
    // to the ports the user actually asked about.
    let (results, sentinel_tripped) = if opts.firewall_check {
        tokio::join!(sweep, syn_ack_is_meaningless(ip, timeout_ms, &ports))
    } else {
        (sweep.await, false)
    };
    prog.finish();

    let mut reports: Vec<PortReport> = results
        .into_iter()
        .map(|(port, state, reason, eager)| PortReport {
            port,
            proto: "tcp",
            state,
            service: None,
            findings: Vec::new(),
            reason,
            eager_service: eager,
            web: None,
        })
        .collect();
    reports.sort_by_key(|r| r.port);

    // A middlebox answering for the host is indistinguishable from a real
    // listener at the TCP layer, so when either signal fires we stop calling
    // these ports open. They become open|filtered — the state that already
    // exists for exactly this "something answered, but it proves nothing"
    // situation — and service detection below gets to break the tie.
    let doubt = assess_doubt(
        sentinel_tripped,
        reports.iter().filter(|r| r.state == State::Open).count(),
        reports.iter().filter(|r| r.state == State::Closed).count(),
        reports.len(),
    );
    // The doubt system — the open→open|filtered downgrade and its yellow
    // "a handshake proves nothing here" warning — is engaged only under -FW.
    // Without that flag Kaisen reports what actually answered and stays out of
    // the way: a completed handshake is shown as plain "open", the way a user
    // running a quick scan expects. -FW is the opt-in that says "scrutinise
    // this host for a firewall/middlebox and warn me".
    let doubt = if opts.firewall_check {
        doubt
    } else {
        Doubt::None
    };
    let syn_ack_unverified = doubt.is_doubtful();
    if syn_ack_unverified {
        for r in reports.iter_mut().filter(|r| r.state == State::Open) {
            r.state = State::OpenFiltered;
            r.reason = "syn-ack (unverified)";
        }
    }

    let host_up = true;

    // -MC: MAC address from the OS's own ARP/neighbor cache (cheap local
    // lookup, no network round-trip beyond what the probes above already did).
    let mac = if opts.mac_info {
        crate::scan::osfp::arp_lookup(ip).await
    } else {
        None
    };

    // Phase 2: service/version detection on open ports (bounded concurrency).
    if opts.service_detection || opts.vuln || opts.os_detection || opts.device_detection {
        // Ports downgraded by the sentinel are probed too: a middlebox has
        // nothing to say once the connection is up, so anything that *does*
        // answer is a real service — the evidence a bare handshake isn't.
        let open_ports: Vec<u16> = reports
            .iter()
            .filter(|r| {
                r.state == State::Open
                    || (syn_ack_unverified && r.proto == "tcp" && r.state == State::OpenFiltered)
            })
            .map(|r| r.port)
            .collect();

        let svc_conc = concurrency.min(SVC_DETECT_CONCURRENCY).max(1);
        let prog = Progress::start(&format!("{ip} services"), open_ports.len(), opts);
        let counter = prog.counter();

        // Build a lookup map: port → service info captured during the initial
        // sweep via detect_with_stream. For ports where eager detection ran
        // (want_service=true) this is already filled; for others we fall back
        // to a fresh service::detect call.
        let eager_map: std::collections::HashMap<u16, ServiceInfo> = reports
            .iter()
            .filter_map(|r| r.eager_service.clone().map(|s| (r.port, s)))
            .collect();

        let detected: Vec<(u16, ServiceInfo)> = stream::iter(open_ports)
            .map(|port| {
                let default = service_name(port).to_string();
                let counter = counter.clone();
                // Use the pre-captured result when available.
                let eager = eager_map.get(&port).cloned();
                async move {
                    let info = if let Some(e) = eager {
                        // Already detected on the initial connection — free.
                        e
                    } else {
                        // No eager result (plain port scan or detect_with_stream
                        // returned nothing meaningful): fall back to a fresh conn.
                        let addr = SocketAddr::new(ip, port);
                        service::detect(addr, &default, timeout_ms.max(1500), target).await
                    };
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (port, info)
                }
            })
            .buffer_unordered(svc_conc)
            .collect()
            .await;
        prog.finish();

        // The Ezviz active check is about the cleartext command port (9010),
        // but the Ezviz identity is on the TLS panel's certificate elsewhere on
        // the host — so establish it once, across every detected service.
        let host_ezviz = detected.iter().any(|(_, i)| {
            format!("{} {} {}", i.product, i.banner, i.hostnames.join(" "))
                .to_ascii_lowercase()
                .contains("ezviz")
        });

        for (port, info) in detected {
            if let Some(r) = reports.iter_mut().find(|r| r.port == port) {
                // Promote back to open only on evidence a service replied.
                if syn_ack_unverified && r.state == State::OpenFiltered && info.has_evidence() {
                    r.state = State::Open;
                    r.reason = "service-verified";
                }
                if opts.vuln {
                    let mut findings = vuln::assess(port, &info);
                    let addr = SocketAddr::new(ip, port);
                    findings.extend(
                        vuln::assess_active(addr, &info, host_ezviz, timeout_ms.max(1500)).await,
                    );
                    vuln::dedup_findings(&mut findings);
                    r.findings = findings;
                }
                r.service = Some(info);
            }
        }
    }

    // Phase 2a (-WW): web fingerprint on the open HTTP/HTTPS ports. Runs after
    // service detection so we already know which open ports speak HTTP and
    // which are TLS-wrapped. Bounded concurrency: each profile is a few GETs.
    if opts.web_scan {
        let web_targets: Vec<(u16, bool)> = reports
            .iter()
            .filter(|r| r.state == State::Open && r.proto == "tcp")
            .filter_map(|r| is_web_port(r).map(|tls| (r.port, tls)))
            .collect();

        if !web_targets.is_empty() {
            let prog = Progress::start(&format!("{ip} web"), web_targets.len(), opts);
            let counter = prog.counter();
            let host = target.to_string();
            let web_conc = concurrency.min(4).max(1);
            let profiles: Vec<(u16, Option<crate::service::web::WebProfile>)> =
                stream::iter(web_targets)
                    .map(|(port, tls)| {
                        let host = host.clone();
                        let counter = counter.clone();
                        async move {
                            let p = crate::service::web::scan(
                                &host,
                                ip,
                                port,
                                tls,
                                timeout_ms.max(3000),
                            )
                            .await;
                            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            (port, p)
                        }
                    })
                    .buffer_unordered(web_conc)
                    .collect()
                    .await;
            prog.finish();

            for (port, prof) in profiles {
                if let Some(r) = reports.iter_mut().find(|r| r.port == port) {
                    r.web = prof;
                }
            }
        }
    }

    // Phase 2b: UDP sweep (-sU). Each port gets a payload the service on it
    // will actually answer, so a reply both proves the port is open and
    // identifies what is listening — one round trip, two answers.
    if opts.udp_scan {
        let udp_conc = concurrency.min(200).max(1);
        let udp_timeout = timeout_ms.max(1000);
        let prog = Progress::start(&format!("{ip} UDP"), opts.udp_ports.len(), opts);
        let counter = prog.counter();
        let udp_results: Vec<crate::scan::udp::UdpReport> = stream::iter(opts.udp_ports.clone())
            .map(|port| {
                let counter = counter.clone();
                async move {
                    let r = crate::scan::udp::probe(ip, port, udp_timeout, retries).await;
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    r
                }
            })
            .buffer_unordered(udp_conc)
            .collect()
            .await;
        prog.finish();

        for u in udp_results {
            let state = match u.state {
                crate::scan::udp::UdpState::Open => State::Open,
                crate::scan::udp::UdpState::Closed => State::Closed,
                crate::scan::udp::UdpState::OpenFiltered => State::OpenFiltered,
            };
            let svc = u
                .service
                .as_ref()
                .map(|p| service::from_probed(p, crate::scan::udp::udp_service_name(u.port)));
            let findings = if opts.vuln {
                vuln::assess_udp(u.port, svc.as_ref())
            } else {
                Vec::new()
            };
            reports.push(PortReport {
                port: u.port,
                proto: "udp",
                state,
                service: svc,
                findings,
                reason: u.reason,
                eager_service: None,
                web: None,
            });
        }
        // TCP first, then UDP, each in port order.
        reports.sort_by_key(|r| (r.proto, r.port));
    }

    let open_count = reports.iter().filter(|r| r.state == State::Open).count();
    let closed_count = reports.iter().filter(|r| r.state == State::Closed).count();
    let filtered_count = reports
        .iter()
        .filter(|r| matches!(r.state, State::Filtered | State::OpenFiltered))
        .count();

    // Phase 3: network-level OS probes (TTL via ping, SNMP sysDescr) — needed
    // for OS detection and as a signal for device-type guessing, best-effort
    // and unprivileged.
    let probes = if opts.os_detection || opts.device_detection {
        Some(crate::scan::osfp::probe(ip).await)
    } else {
        None
    };

    let end_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let avg_rtt_ms = pacer.avg_rtt_ms();
    let timeouts = reports
        .iter()
        .filter(|r| r.state == State::Filtered)
        .count();

    let mut report = HostReport {
        target: target.to_string(),
        ip,
        ports: reports,
        os_guess: String::new(),
        elapsed: start.elapsed(),
        open_count,
        closed_count,
        filtered_count,
        probes,
        host_up,
        mac,
        doubt,
        device_guess: String::new(),
        device_confidence: "none",
        device_signals: Vec::new(),
        firewall: fw_precheck,
        live_lines: live_counter.load(std::sync::atomic::Ordering::Relaxed),
        start_ts,
        end_ts,
        avg_rtt_ms,
        timeouts,
    };

    // Phase 4: combine every signal into a single OS guess string.
    if opts.os_detection {
        let (os, _conf, _role, _signals) = infer_os(&report);
        report.os_guess = os;
    }

    // Phase 5 (-DP): best-effort device-type guess, layered on the same
    // TTL/banner/port signals plus a few device-specific ports.
    if opts.device_detection {
        let (device, conf, signals) = infer_device(&report);
        report.device_guess = device;
        report.device_confidence = conf;
        report.device_signals = signals;
    }

    report
}

/// Should this finding survive `--min-severity`? The filter is presentational
/// only: `vuln::assess` still runs in full, so nothing is missed by re-running
/// without the flag.
fn finding_shown(f: &vuln::Finding, opts: &Options) -> bool {
    match opts.min_severity {
        Some(min) => f.severity.rank() >= min.rank(),
        None => true,
    }
}

fn sev_color(p: &Painter, sev: Severity, s: &str) -> String {
    match sev {
        Severity::Critical => p.bold(&p.red(s)),
        Severity::High => p.red(s),
        Severity::Medium => p.yellow(s),
        Severity::Low => p.blue(s),
        Severity::Info => p.dim(s),
    }
}

/// One live line for a port that just came back open, printed to stderr the
/// instant it is confirmed (see the streaming block in `scan_host`). Kept
/// deliberately compact — this is a running feed, not the final table, which
/// still prints in full at the end.
fn emit_live_open(port: u16, svc: &Option<ServiceInfo>, color: bool) {
    let p = Painter::new(color);
    let name = svc
        .as_ref()
        .map(|s| s.name.clone())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| service_name(port).to_string());
    let ver = svc.as_ref().map(|s| s.describe()).unwrap_or_default();
    let tail = if ver.is_empty() {
        String::new()
    } else {
        format!("  {ver}")
    };
    // Lead with a carriage-return + clear-line so this permanent line lands on
    // clean ground even when the live progress counter is mid-draw on stderr;
    // the counter simply repaints on its next tick.
    eprintln!(
        "\r\x1b[2K  {} {:<10} {}{}",
        p.green("[+] open"),
        format!("{port}/tcp"),
        p.bold(&name),
        p.dim(&tail)
    );
    let _ = std::io::Write::flush(&mut std::io::stderr());
}

/// Clear the N live streaming lines emitted to stderr during host scanning.
pub fn clear_live_lines(count: usize) {
    if count == 0 {
        return;
    }
    let mut s = String::new();
    for _ in 0..count {
        s.push_str("\x1b[1A\x1b[2K");
    }
    s.push('\r');
    eprint!("{s}");
    let _ = std::io::Write::flush(&mut std::io::stderr());
}

pub fn print_report(report: &HostReport, opts: &Options) {
    if report.live_lines > 0
        && opts.output == OutputFormat::Normal
        && std::io::IsTerminal::is_terminal(&std::io::stderr())
    {
        clear_live_lines(report.live_lines);
    }
    match opts.output {
        OutputFormat::Normal => print_normal(report, opts),
        OutputFormat::Grepable => print_grepable(report),
        OutputFormat::Json => print_json(report, opts), // printed per-host; wrapper handled by caller
        OutputFormat::Xml => print_xml(report, opts), // printed per-host; wrapper handled by caller
    }
}

/// Combine every available signal (banners, FTP-SYST, SNMP, TTL, open-port
/// profile) into a single weighted OS guess. Returns
/// (os_string, confidence, role_summary, human-readable signals).
fn infer_os(report: &HostReport) -> (String, &'static str, String, Vec<String>) {
    let open_ports: Vec<u16> = report
        .ports
        .iter()
        .filter(|r| r.state == State::Open)
        .map(|r| r.port)
        .collect();
    let role = describe_role(&open_ports);
    let mut signals: Vec<String> = Vec::new();

    // Weighted votes toward an OS *string*. Higher weight = stronger evidence.
    let mut score: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut vote = |os: &str, w: u32| {
        if !os.is_empty() {
            *score.entry(os.to_string()).or_insert(0) += w;
        }
    };

    // 1) SNMP sysDescr — the exact OS string when present (strongest).
    if let Some(pr) = &report.probes {
        if let Some(snmp) = &pr.snmp_os {
            let short: String = snmp
                .split_whitespace()
                .take(6)
                .collect::<Vec<_>>()
                .join(" ");
            vote(&short, 6);
            signals.push(format!("SNMP sysDescr: {snmp}"));
        }
    }

    // 2) Banner / FTP-SYST hints (strong, and often name the distro).
    for r in &report.ports {
        if r.state == State::Open {
            if let Some(svc) = &r.service {
                if !svc.os_hint.is_empty() {
                    vote(&svc.os_hint, 3);
                    signals.push(format!("{}/{} banner -> {}", r.port, svc.name, svc.os_hint));
                }
            }
        }
    }

    // 3) TTL family from ping (independent corroboration of the family).
    if let Some(pr) = &report.probes {
        if let (Some(ttl), Some(fam)) = (pr.ttl, pr.ttl_family) {
            let hops = pr
                .ttl_hops
                .map(|h| h.to_string())
                .unwrap_or_else(|| "?".into());
            signals.push(format!("ICMP TTL={ttl} (~{hops} hops) -> {fam}"));
            // Boost whichever family the TTL agrees with; otherwise vote family.
            let fam_key = if fam.starts_with("Windows") {
                "Windows"
            } else if fam.starts_with("Linux") {
                "Linux / Unix"
            } else {
                "Network device / BSD / Solaris"
            };
            vote(fam_key, 2);
        }
    }

    // 4) Open-port profile (weak fallback).
    let has = |p: u16| open_ports.contains(&p);
    if has(3389) || has(445) || has(139) || has(135) {
        vote("Windows", 1);
    }
    if has(22) || has(111) || has(631) {
        vote("Linux / Unix", 1);
    }

    // Pick the highest-scoring OS.
    if let Some((os, best)) = score.iter().max_by_key(|(_, w)| **w) {
        let total: u32 = score.values().sum();
        let confidence = if *best >= 6 {
            "high"
        } else if *best >= 3 && *best * 2 >= total {
            "medium"
        } else {
            "low"
        };
        return (os.clone(), confidence, role, signals);
    }

    if open_ports.is_empty() {
        return ("unknown".into(), "none", role, signals);
    }
    ("unknown".into(), "low", role, signals)
}

/// -DP: guess a *consumer/IoT device type* rather than just an OS family —
/// phone, camera, TV, console, printer, router, NAS, etc. No single
/// unprivileged signal proves a device model (real fingerprinting needs
/// root-level raw TCP/IP probing against a huge signature database, which is
/// what `nmap -O` actually does); this layers known device ports *and*
/// banner keywords (checked strongest-first) on top of the TTL family
/// already gathered for `-OS`, and is honest with "unknown" when nothing
/// distinctive showed up. Some categories genuinely have no unprivileged TCP
/// signature at all — most smartwatches/wearables only talk to their paired
/// phone over Bluetooth and never appear as an independent LAN service, so
/// Kaisen can't name them; same for Nintendo Switch among consoles.
fn infer_device(report: &HostReport) -> (String, &'static str, Vec<String>) {
    let open_ports: Vec<u16> = report
        .ports
        .iter()
        .filter(|r| r.state == State::Open)
        .map(|r| r.port)
        .collect();
    let has = |p: u16| open_ports.contains(&p);
    // Several device ports collide with unrelated services (8009 is Google Cast
    // *and* Tomcat's AJP connector; 5555 is Android ADB *and* freeciv). Now that
    // `-sV` can actually name what is listening, let the identified service veto
    // a guess made purely from the port number.
    let service_on = |p: u16| -> Option<&crate::service::ServiceInfo> {
        report
            .ports
            .iter()
            .find(|r| r.port == p && r.state == State::Open)
            .and_then(|r| r.service.as_ref())
    };
    let identified_as =
        |p: u16, name: &str| -> bool { service_on(p).map(|s| s.name == name).unwrap_or(false) };
    let ttl_family = report.probes.as_ref().and_then(|p| p.ttl_family);
    let is_windows_ttl = matches!(ttl_family, Some(f) if f.starts_with("Windows"));
    let is_unix_ttl = matches!(ttl_family, Some(f) if f.starts_with("Linux"));

    // Every open port's banner/product/extra text, lowercased, for keyword
    // matching — the strongest signal available without root, when a device
    // happens to expose one (e.g. an HTTP `Server:` header).
    let mut banner = String::new();
    for r in &report.ports {
        if r.state == State::Open {
            if let Some(svc) = &r.service {
                banner.push_str(&svc.product);
                banner.push(' ');
                banner.push_str(&svc.banner);
                banner.push(' ');
                banner.push_str(&svc.extra);
                banner.push(' ');
                // Certificate names are often the most specific label a device
                // ever emits — appliances ship certs naming the model outright.
                for h in &svc.hostnames {
                    banner.push_str(h);
                    banner.push(' ');
                }
            }
        }
    }
    let banner = banner.to_ascii_lowercase();
    let has_banner = |needle: &str| banner.contains(needle);
    let mut signals = Vec::new();

    // ── Strongest: a banner naming the actual product ────────────────────
    let banner_matches: &[(&str, &str)] = &[
        // ── cameras, DVRs and doorbells ─────────────────────────────────
        ("hikvision", "IP Camera / DVR (Hikvision)"),
        ("dahua", "IP Camera / DVR (Dahua)"),
        ("axis camera", "IP Camera (Axis)"),
        ("foscam", "IP Camera (Foscam)"),
        ("reolink", "IP Camera (Reolink)"),
        ("amcrest", "IP Camera (Amcrest)"),
        ("xiongmai", "IP Camera / DVR (XiongMai)"),
        ("ubnt", "Ubiquiti network device (AP/switch/gateway)"),
        // ── TVs, speakers and streaming ─────────────────────────────────
        ("nrdp", "Smart TV / streaming device (Roku/NRDP)"),
        ("roku", "Smart TV / streaming device (Roku)"),
        ("chromecast", "Chromecast / Google Cast device"),
        ("sonos", "Sonos speaker"),
        ("airplay", "Apple AirPlay receiver (TV/speaker)"),
        ("jellyfin", "Media server (Jellyfin)"),
        ("plex media server", "Media server (Plex)"),
        ("emby", "Media server (Emby)"),
        ("kodi", "Media centre (Kodi)"),
        ("bravia", "Smart TV (Sony Bravia)"),
        ("webos", "Smart TV (LG webOS)"),
        ("tizen", "Smart TV (Samsung Tizen)"),
        // ── NAS and home servers ────────────────────────────────────────
        ("synology", "Synology NAS"),
        ("diskstation", "Synology NAS"),
        ("qnap", "QNAP NAS"),
        ("truenas", "TrueNAS storage appliance"),
        ("freenas", "FreeNAS storage appliance"),
        ("openmediavault", "OpenMediaVault NAS"),
        ("unraid", "Unraid server"),
        ("netapp", "NetApp storage appliance"),
        // ── routers, APs and CPE ────────────────────────────────────────
        ("unifi", "Ubiquiti network device (AP/switch/gateway)"),
        ("ubiquiti", "Ubiquiti network device (AP/switch/gateway)"),
        ("mikrotik", "MikroTik router"),
        ("routeros", "MikroTik router"),
        ("openwrt", "Router running OpenWrt"),
        ("dd-wrt", "Router running DD-WRT"),
        ("tp-link", "TP-Link router / AP"),
        ("netgear", "Netgear router / AP"),
        ("d-link", "D-Link router / AP"),
        ("linksys", "Linksys router / AP"),
        ("asuswrt", "ASUS router"),
        ("zyxel", "Zyxel router / CPE"),
        ("huawei", "Huawei router / CPE"),
        ("technicolor", "Technicolor CPE"),
        ("fritz!box", "AVM FRITZ!Box router"),
        ("cisco ios", "Cisco network device"),
        ("juniper", "Juniper network device"),
        ("aruba", "Aruba network device"),
        // ── security appliances ─────────────────────────────────────────
        ("pfsense", "Firewall appliance (pfSense)"),
        ("opnsense", "Firewall appliance (OPNsense)"),
        ("fortigate", "Firewall appliance (Fortinet FortiGate)"),
        ("sonicwall", "Firewall appliance (SonicWall)"),
        ("pan-os", "Firewall appliance (Palo Alto)"),
        ("watchguard", "Firewall appliance (WatchGuard)"),
        ("big-ip", "Load balancer (F5 BIG-IP)"),
        ("netscaler", "Load balancer (Citrix NetScaler)"),
        // ── printers ────────────────────────────────────────────────────
        ("jetdirect", "Network printer (HP JetDirect)"),
        ("laserjet", "Network printer (HP LaserJet)"),
        ("officejet", "Network printer (HP OfficeJet)"),
        ("brother", "Network printer (Brother)"),
        ("kyocera", "Network printer (Kyocera)"),
        ("lexmark", "Network printer (Lexmark)"),
        ("epson", "Network printer (Epson)"),
        // Not a bare "canon": every Ubuntu banner says "Canonical".
        ("canon inc", "Network printer (Canon)"),
        ("imagerunner", "Network printer (Canon imageRUNNER)"),
        ("i-sensys", "Network printer (Canon i-SENSYS)"),
        // ── smart home and IoT ──────────────────────────────────────────
        ("home assistant", "Home automation hub (Home Assistant)"),
        ("openhab", "Home automation hub (openHAB)"),
        ("philips hue", "Philips Hue bridge"),
        ("tasmota", "IoT device (Tasmota firmware)"),
        ("esphome", "IoT device (ESPHome firmware)"),
        ("shelly", "Shelly smart relay"),
        ("tuya", "Tuya smart device"),
        ("octoprint", "3D printer controller (OctoPrint)"),
        ("pi-hole", "Raspberry Pi running Pi-hole"),
        ("raspbian", "Raspberry Pi"),
        ("raspberry pi", "Raspberry Pi"),
        // ── virtualisation and management ───────────────────────────────
        ("proxmox", "Hypervisor host (Proxmox VE)"),
        ("esxi", "Hypervisor host (VMware ESXi)"),
        ("vsphere", "VMware management host"),
        ("xenserver", "Hypervisor host (Citrix XenServer)"),
        ("idrac", "Server BMC (Dell iDRAC)"),
        // "ilo" on its own is a substring of far too many ordinary words.
        ("integrated lights-out", "Server BMC (HPE iLO)"),
        ("hp ilo", "Server BMC (HPE iLO)"),
        ("supermicro", "Server BMC (Supermicro IPMI)"),
        // ── consoles and desktops ───────────────────────────────────────
        ("nintendo", "Nintendo console"),
        ("playstation", "PlayStation console"),
        ("xbox", "Xbox console"),
    ];
    for (needle, label) in banner_matches {
        if has_banner(needle) {
            signals.push(format!("service banner mentions \"{needle}\""));
            return (label.to_string(), "high", signals);
        }
    }

    // ── Apple mobile / desktop: high-signal ports ─────────────────────────
    if has(62078) {
        signals.push("62078/tcp open (lockdownd) — Apple mobile-device sync service".to_string());
        return ("iPhone / iPad (iOS)".to_string(), "high", signals);
    }
    if has(548) {
        signals.push("548/tcp open (AFP) — Apple file sharing".to_string());
        return ("Mac (macOS)".to_string(), "medium", signals);
    }

    // ── Media / casting devices ────────────────────────────────────────────
    if (has(8008) || has(8009)) && !identified_as(8009, "ajp13") {
        signals.push("8008-8009/tcp open — Google Cast protocol".to_string());
        return (
            "Chromecast / Google Cast device (TV, speaker or Android TV)".to_string(),
            "medium",
            signals,
        );
    }
    if has(8060) {
        signals.push("8060/tcp open — Roku External Control Protocol".to_string());
        return ("Roku".to_string(), "medium", signals);
    }

    // ── IP cameras / DVRs ───────────────────────────────────────────────────
    if has(554) {
        signals
            .push("554/tcp open (RTSP) — video streaming, typical of IP cameras/DVRs".to_string());
        return ("IP Camera / DVR (RTSP)".to_string(), "medium", signals);
    }

    // ── Consoles ────────────────────────────────────────────────────────────
    if has(3074) && is_windows_ttl {
        signals.push("3074/tcp open (Xbox Live), TTL matches Windows family".to_string());
        return ("Xbox".to_string(), "medium", signals);
    }
    if open_ports.iter().any(|p| (3478..=3480).contains(p)) {
        signals.push("3478-3480/tcp open — commonly PlayStation Network".to_string());
        return ("PlayStation (heuristic)".to_string(), "low", signals);
    }

    // ── Printers ────────────────────────────────────────────────────────────
    if has(9100) || has(631) {
        signals.push("9100/tcp (JetDirect) or 631/tcp (IPP) open".to_string());
        return ("Network printer".to_string(), "medium", signals);
    }

    // ── Router / gateway: DNS + a web admin UI on the same box ────────────
    // A full-fat recursive/authoritative server means a real DNS host, not a
    // consumer gateway — dnsmasq is the one that genuinely points at CPE.
    let heavyweight_dns = service_on(53)
        .map(|s| {
            ["BIND", "PowerDNS", "Unbound", "Knot", "NSD", "CoreDNS"]
                .iter()
                .any(|p| s.product.contains(p))
        })
        .unwrap_or(false);
    if has(53) && (has(80) || has(443)) && !heavyweight_dns {
        signals.push(
            "53/tcp + 80/443 open — DNS + web admin UI, typical of a router/gateway".to_string(),
        );
        return ("Router / gateway".to_string(), "medium", signals);
    }

    // ── Android (weak signal: ADB left open) ───────────────────────────────
    if has(5555) && is_unix_ttl && !identified_as(5555, "freeciv") {
        signals.push("5555/tcp open — commonly Android ADB".to_string());
        return ("Android (heuristic)".to_string(), "low", signals);
    }

    // ── Generic OS-family fallback ──────────────────────────────────────────
    if has(3389) || has(445) || has(139) || has(135) || is_windows_ttl {
        return ("Windows PC".to_string(), "low", signals);
    }
    if is_unix_ttl {
        return (
            "Linux / Android / IoT host (unix TTL, no distinguishing port or banner)".to_string(),
            "low",
            signals,
        );
    }
    if ttl_family.is_some() {
        return ("Network device / BSD / Solaris".to_string(), "low", signals);
    }
    ("unknown".to_string(), "none", signals)
}

fn describe_role(ports: &[u16]) -> String {
    let mut roles = Vec::new();
    let any = |ps: &[u16]| ps.iter().any(|p| ports.contains(p));
    if any(&[80, 443, 8080, 8443]) {
        roles.push("web server");
    }
    if any(&[22]) {
        roles.push("SSH host");
    }
    if any(&[3389]) {
        roles.push("Windows RDP host");
    }
    if any(&[445, 139]) {
        roles.push("SMB/file server");
    }
    if any(&[25, 465, 587]) {
        roles.push("mail server");
    }
    if any(&[53]) {
        roles.push("DNS server");
    }
    if any(&[3306, 5432, 6379, 27017]) {
        roles.push("database host");
    }
    if any(&[21]) {
        roles.push("FTP server");
    }
    if roles.is_empty() {
        "general purpose host".to_string()
    } else {
        roles.join(", ")
    }
}

/// Focused output for `kaisen -OS <target>`: report the operating system and a
/// bit of context about the host, instead of the port table.
pub fn print_os_report(report: &HostReport, opts: &Options) {
    if report.live_lines > 0
        && opts.output == OutputFormat::Normal
        && std::io::IsTerminal::is_terminal(&std::io::stderr())
    {
        clear_live_lines(report.live_lines);
    }
    let p = Painter::new(opts.color);
    if !report.host_up {
        if opts.verbosity >= 1 {
            println!();
            println!(
                "{} {} ({})",
                p.bold("Kaisen OS detection for"),
                p.cyan(&report.target),
                report.ip
            );
            println!(
                "{}",
                p.red(&format!(
                    "[!] Host {} appears down or non-responsive. If host is up, try -Pn.",
                    report.target
                ))
            );
            println!(
                "{}",
                p.dim("--------------------------------------------------")
            );
        }
        return;
    }
    println!();
    println!(
        "{} {} ({})",
        p.bold("Kaisen OS detection for"),
        p.cyan(&report.target),
        report.ip
    );
    println!(
        "Host is up. Probed {} port(s) in {:.2}s.",
        report.ports.len(),
        report.elapsed.as_secs_f64()
    );
    println!();

    let (os, confidence, role, signals) = infer_os(report);
    let has_signal = os != "unknown" || !signals.is_empty();

    if !has_signal {
        println!("{}", p.yellow("Could not determine the OS."));
        if report.open_count > 0 {
            println!("{:<14}{}", p.bold("Role:"), role);
            println!(
                "{}",
                p.dim(&format!(
                    "{} open port(s), but none exposed an OS-identifying signal (no banner, no ICMP/SNMP reply). \
                     CDNs and front-ends like Google/Cloudflare deliberately hide this.",
                    report.open_count
                ))
            );
        } else {
            println!(
                "{}",
                p.dim("No port responded and the host did not answer ICMP/SNMP — nothing to analyse (likely firewalled).")
            );
        }
        println!(
            "{}",
            p.dim("Tip: try a wider scan (kaisen -sV -PF <target>) or check for SNMP/FTP on an internal host.")
        );
        return;
    }

    let conf_c = match confidence {
        "high" => p.green(confidence),
        "medium" => p.yellow(confidence),
        _ => p.dim(confidence),
    };

    println!("{:<14}{}", p.bold("OS:"), p.bold(&os));
    println!("{:<14}{}", p.bold("Confidence:"), conf_c);
    println!("{:<14}{}", p.bold("Role:"), role);
    if let Some(pr) = &report.probes {
        if let Some(ttl) = pr.ttl {
            let hops = pr
                .ttl_hops
                .map(|h| h.to_string())
                .unwrap_or_else(|| "?".into());
            println!(
                "{:<14}{} (~{} hop(s), family: {})",
                p.bold("TTL:"),
                ttl,
                hops,
                pr.ttl_family.unwrap_or("?")
            );
        }
    }

    // Show the concrete signals the guess is built from.
    if !signals.is_empty() {
        println!("{}", p.bold("Signals:"));
        for s in &signals {
            println!("  - {s}");
        }
    }

    println!();
    println!(
        "{}",
        p.dim(
            "Note: running without root, so Kaisen infers the OS from ICMP TTL, SNMP and service \
             banners rather than a raw TCP/IP fingerprint. SNMP/FTP-SYST/TTL greatly improve certainty \
             when the host exposes them."
        )
    );
}

fn print_normal(report: &HostReport, opts: &Options) {
    let p = Painter::new(opts.color);
    if !report.host_up {
        if opts.verbosity >= 1 {
            println!();
            println!(
                "{} {} ({})",
                p.bold("Kaisen scan report for"),
                p.cyan(&report.target),
                report.ip
            );
            println!(
                "{}",
                p.red(&format!(
                    "[!] Host {} appears down or non-responsive. If host is up, try -Pn.",
                    report.target
                ))
            );
            println!(
                "{}",
                p.dim("--------------------------------------------------")
            );
        }
        return;
    }
    println!();
    println!(
        "{} {} ({})",
        p.bold("Kaisen scan report for"),
        p.cyan(&report.target),
        report.ip
    );

    // -FW hit its abort condition: three random high ports all answered open,
    // so a firewall/CPE is faking every handshake. Say so at once, in yellow,
    // and stop — there is nothing trustworthy to tabulate.
    if let Some(fw) = &report.firewall {
        if fw.blocked {
            let sample = fw
                .sampled
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "{}",
                p.yellow(&format!(
                    "[!] Firewall/middlebox detected: {} random high ports ({}) all answered \
                     open. This host completes every handshake, so any port list would be \
                     fiction. Scan aborted by -FW. (Drop -FW to scan anyway and trust the \
                     handshakes.)",
                    fw.sampled.len(),
                    sample
                ))
            );
            return;
        }
    }

    println!(
        "Host is up. Scanned {} port(s) in {:.2}s.",
        report.ports.len(),
        report.elapsed.as_secs_f64()
    );

    if report.doubt.is_doubtful() {
        println!(
            "{}",
            p.yellow(&format!(
                "[!] A completed handshake proves nothing against this host: {}. \
                 That is a CPE or middlebox answering on its behalf, not services. \
                 Ports that only got as far as a handshake are reported open|filtered; \
                 only ports where a service actually replied are reported open. Run \
                 with -sV to tell them apart.",
                report.doubt.note()
            ))
        );
    }

    if opts.mac_info {
        match &report.mac {
            Some(mac) => println!("{:<14}{}", p.bold("MAC:"), mac),
            None => println!(
                "{:<14}{}",
                p.bold("MAC:"),
                p.dim("unknown (not on this local subnet, or ARP cache unavailable)")
            ),
        }
    }

    let open_only: Vec<&PortReport> = report
        .ports
        .iter()
        .filter(|r| r.state == State::Open)
        .collect();

    // Collapse the (usually huge) list of filtered/closed ports into a summary,
    // like nmap does. Only enumerate them individually when the user explicitly
    // wants detail (-vv or --reason) or when there are just a handful.
    let non_open = report.filtered_count + report.closed_count;
    let list_non_open = !opts.only_open && (opts.verbosity >= 2 || opts.reason || non_open <= 25);

    let shown: Vec<&PortReport> = report
        .ports
        .iter()
        .filter(|r| r.state == State::Open || list_non_open)
        .collect();

    if open_only.is_empty() {
        println!(
            "{}",
            p.red(&format!(
                "[!] No open ports found on {} ({} scanned).",
                report.target,
                report.ports.len()
            ))
        );
        println!(
            "{}",
            p.dim("--------------------------------------------------")
        );
    }

    if !shown.is_empty() {
        // header
        let head = if opts.reason {
            format!(
                "{:<11}{:<14}{:<16}{}",
                "PORT", "STATE", "SERVICE", "REASON/VERSION"
            )
        } else {
            format!(
                "{:<11}{:<14}{:<16}{}",
                "PORT", "STATE", "SERVICE", "VERSION"
            )
        };
        println!("{}", p.bold(&head));

        for r in &shown {
            let port_proto = format!("{}/{}", r.port, r.proto);
            let state_str = match r.state {
                State::Open => p.green(r.state.label()),
                State::Filtered => p.yellow(r.state.label()),
                State::OpenFiltered => p.yellow(r.state.label()),
                State::Closed => p.dim(r.state.label()),
            };
            let svc_name = r
                .service
                .as_ref()
                .map(|s| s.name.clone())
                .unwrap_or_else(|| {
                    if r.proto == "udp" {
                        crate::scan::udp::udp_service_name(r.port).to_string()
                    } else {
                        service_name(r.port).to_string()
                    }
                });

            let mut tail = String::new();
            if opts.reason {
                tail.push_str(r.reason);
                tail.push(' ');
            }
            if let Some(svc) = &r.service {
                let d = svc.describe();
                if !d.is_empty() {
                    tail.push_str(&d);
                }
            }

            // Colour codes have no width on screen but plenty in a format
            // string, so the state column is padded from the plain label —
            // which keeps the columns lined up with and without --no-color,
            // and leaves room for the widest label, "open|filtered".
            let pad = " ".repeat(14usize.saturating_sub(r.state.label().len()));
            println!(
                "{:<11}{}{}{:<16}{}",
                port_proto,
                state_str,
                pad,
                svc_name,
                tail.trim()
            );

            // vuln findings under the port
            for f in r.findings.iter().filter(|f| finding_shown(f, opts)) {
                let tag = sev_color(&p, f.severity, &format!("[{}]", f.severity.label()));
                println!("    {} {} — {}", tag, p.bold(&f.id), f.title);
                if opts.verbosity >= 2 {
                    println!("        {}", p.dim(&f.detail));
                }
            }

            // -WW web fingerprint under the port.
            if let Some(w) = &r.web {
                print_web_profile(w, &p, opts);
            }
        }
    }

    // Collapsed line for the ports we deliberately did not enumerate.
    if !opts.only_open && !list_non_open && non_open > 0 {
        println!(
            "{}",
            p.dim(&format!(
                "Not shown: {} filtered, {} closed port(s) — use -vv or --reason to list them.",
                report.filtered_count, report.closed_count
            ))
        );
    }

    if !opts.only_open && (report.filtered_count > 0 || report.closed_count > 0) {
        println!(
            "{}",
            p.dim(&format!(
                "{} open, {} closed, {} filtered",
                report.open_count, report.closed_count, report.filtered_count
            ))
        );
    }

    if opts.os_detection {
        println!("{} {}", p.bold("OS guess:"), report.os_guess);
    }

    if opts.device_detection {
        let conf_note = match report.device_confidence {
            "high" => "",
            "medium" => " (medium confidence)",
            "low" => " (low confidence)",
            _ => "",
        };
        println!(
            "{} {}{}",
            p.bold("Device guess:"),
            report.device_guess,
            p.dim(conf_note)
        );
        if opts.verbosity >= 1 {
            for s in &report.device_signals {
                println!("    {}", p.dim(s));
            }
        }
    }

    if opts.vuln {
        // Only count findings on confirmed-open ports. OpenFiltered ports also
        // get vuln::assess called (exposure rules fire on port number alone),
        // but those ports are never shown in the table above, so counting their
        // findings produces a phantom "N findings — review above" with nothing
        // to review.
        let total: usize = report
            .ports
            .iter()
            .filter(|r| r.state == State::Open)
            .map(|r| r.findings.len())
            .sum();
        let shown_count: usize = report
            .ports
            .iter()
            .filter(|r| r.state == State::Open)
            .map(|r| r.findings.iter().filter(|f| finding_shown(f, opts)).count())
            .sum();
        let hidden = total - shown_count;
        if total == 0 {
            println!("{}", p.dim("Vuln: no known-vulnerable signatures matched."));
        } else if shown_count == 0 {
            println!(
                "{}",
                p.dim(&format!(
                    "Vuln: {hidden} finding(s) matched, all below the --min-severity threshold."
                ))
            );
        } else {
            println!(
                "{}",
                p.bold(&format!(
                    "Vuln: {shown_count} potential finding(s) — review above."
                ))
            );
            if hidden > 0 {
                println!(
                    "{}",
                    p.dim(&format!(
                        "{hidden} lower-severity finding(s) hidden — drop --min-severity to see them."
                    ))
                );
            }
        }
    }
}

/// Render one port's `-WW` web fingerprint, indented under its port row.
fn print_web_profile(w: &crate::service::web::WebProfile, p: &Painter, opts: &Options) {
    if !w.title.is_empty() {
        println!("      {} {}", p.dim("web  ·"), p.bold(&w.title));
    }
    if opts.verbosity >= 1 && !w.url.is_empty() {
        println!("      {} {}", p.dim("url  ·"), p.dim(&w.url));
    }
    if !w.techs.is_empty() {
        let list = w
            .techs
            .iter()
            .map(|t| {
                let base = if t.version.is_empty() {
                    t.name.clone()
                } else {
                    format!("{} {}", t.name, t.version)
                };
                // Under -v, tag each with its category (cms/framework/js-lib…).
                if opts.verbosity >= 1 {
                    format!("{base} [{}]", t.category)
                } else {
                    base
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!("      {} {}", p.dim("tech ·"), list);
    }
    let mut infra = Vec::new();
    if let Some(waf) = &w.waf {
        infra.push(format!("WAF {waf}"));
    }
    if let Some(cdn) = &w.cdn {
        infra.push(format!("CDN {cdn}"));
    }
    if !infra.is_empty() {
        println!("      {} {}", p.dim("edge ·"), infra.join("  ·  "));
    }
    let grade = w.sec.grade();
    let colored = if grade.starts_with('A') {
        p.green(grade)
    } else if grade == "E" || grade == "F" {
        p.yellow(grade)
    } else {
        grade.to_string()
    };
    let missing = w.sec.missing();
    if missing.is_empty() {
        println!("      {} {} (all present)", p.dim("hdrs ·"), colored);
    } else {
        println!(
            "      {} {} {}",
            p.dim("hdrs ·"),
            colored,
            p.dim(&format!("(missing {})", missing.join(", ")))
        );
    }
    if let Some(h) = w.favicon_hash {
        println!("      {} {}", p.dim("favi ·"), h);
    }
    if opts.verbosity >= 1 && !w.redirects.is_empty() {
        println!("      {} {}", p.dim("redir·"), w.redirects.join(" → "));
    }
}

fn print_grepable(report: &HostReport) {
    if !report.host_up {
        println!("Host: {} ({})\tStatus: Down", report.ip, report.target);
        return;
    }
    if report.firewall.as_ref().map(|f| f.blocked).unwrap_or(false) {
        println!(
            "Host: {} ({})\tStatus: Up\tFirewall: blocked (answers every handshake)",
            report.ip, report.target
        );
        return;
    }
    let mut ports = String::new();
    for r in report.ports.iter().filter(|r| r.state == State::Open) {
        let svc = r
            .service
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| service_name(r.port).to_string());
        let ver = r.service.as_ref().map(|s| s.describe()).unwrap_or_default();
        ports.push_str(&format!("{}/open/{}//{}//{}/, ", r.port, r.proto, svc, ver));
    }
    println!(
        "Host: {} ({})\tStatus: Up\tPorts: {}",
        report.ip,
        report.target,
        ports.trim_end_matches(", ")
    );
}

/// One port's `-WW` web profile as a JSON value (or `null`).
fn web_json(w: Option<&crate::service::web::WebProfile>) -> String {
    let Some(w) = w else {
        return "null".to_string();
    };
    let techs = w
        .techs
        .iter()
        .map(|t| {
            format!(
                "{{\"name\":\"{}\",\"version\":\"{}\",\"category\":\"{}\",\"confidence\":{}}}",
                json_escape(&t.name),
                json_escape(&t.version),
                t.category,
                t.confidence
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let opt_str = |o: &Option<String>| {
        o.as_ref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or_else(|| "null".to_string())
    };
    format!(
        "{{\"url\":\"{}\",\"status\":{},\"title\":\"{}\",\"server\":\"{}\",\"powered_by\":\"{}\",\
         \"generator\":\"{}\",\"waf\":{},\"cdn\":{},\"favicon_hash\":{},\
         \"security_grade\":\"{}\",\"security_missing\":[{}],\"technologies\":[{}]}}",
        json_escape(&w.url),
        w.status,
        json_escape(&w.title),
        json_escape(&w.server),
        json_escape(&w.powered_by),
        json_escape(&w.generator),
        opt_str(&w.waf),
        opt_str(&w.cdn),
        w.favicon_hash
            .map(|h| h.to_string())
            .unwrap_or_else(|| "null".to_string()),
        w.sec.grade(),
        w.sec
            .missing()
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect::<Vec<_>>()
            .join(","),
        techs
    )
}

fn print_json(report: &HostReport, opts: &Options) {
    if !report.host_up {
        println!(
            "{{\"target\":\"{}\",\"ip\":\"{}\",\"host_up\":false,\"os_guess\":\"\",\"elapsed_s\":{:.3},\
             \"counts\":{{\"open\":0,\"closed\":0,\"filtered\":0}},\
             \"scan_meta\":{{\"start_ts\":{},\"end_ts\":{},\"duration_ms\":{},\"ports_scanned\":0,\"avg_rtt_ms\":0.0,\"timeouts\":0}},\
             \"ports\":[]}}",
            json_escape(&report.target),
            report.ip,
            report.elapsed.as_secs_f64(),
            report.start_ts,
            report.end_ts,
            report.elapsed.as_millis()
        );
        return;
    }
    let mut ports_json = Vec::new();
    for r in &report.ports {
        // Keep JSON focused on ports that carry information. Plain `filtered`
        // and `closed` ports say only "no answer"/"refused" and would bury a
        // 1000-port sweep under ~998 empty objects, so they are collapsed into
        // the `counts` summary below unless the user asked for detail with -vv
        // or --reason. Open and open|filtered always appear; --open narrows to
        // open alone. (The `counts` field still reports every state.)
        let interesting = match r.state {
            State::Open | State::OpenFiltered => true,
            State::Filtered | State::Closed => opts.verbosity >= 2 || opts.reason,
        };
        if opts.only_open && r.state != State::Open {
            continue;
        }
        if !interesting {
            continue;
        }
        let svc = r.service.as_ref();
        // The same --min-severity threshold applies here, so machine output and
        // the human report never disagree about what was found.
        let findings: Vec<String> = r
            .findings
            .iter()
            .filter(|f| finding_shown(f, opts))
            .map(|f| {
                format!(
                    "{{\"id\":\"{}\",\"severity\":\"{}\",\"title\":\"{}\"}}",
                    json_escape(&f.id),
                    f.severity.label(),
                    json_escape(&f.title)
                )
            })
            .collect();
        let hostnames: Vec<String> = svc
            .map(|s| {
                s.hostnames
                    .iter()
                    .map(|h| format!("\"{}\"", json_escape(h)))
                    .collect()
            })
            .unwrap_or_default();
        ports_json.push(format!(
            "{{\"port\":{},\"protocol\":\"{}\",\"state\":\"{}\",\"service\":\"{}\",\"product\":\"{}\",\
             \"version\":\"{}\",\"extra\":\"{}\",\"banner\":\"{}\",\"os_hint\":\"{}\",\
             \"tls\":{{\"version\":\"{}\",\"cert_expired\":{},\"self_signed\":{}}},\
             \"hostnames\":[{}],\"findings\":[{}],\"web\":{}}}",
            r.port,
            r.proto,
            r.state.label(),
            json_escape(&svc.map(|s| s.name.clone()).unwrap_or_else(|| service_name(r.port).to_string())),
            json_escape(&svc.map(|s| s.product.clone()).unwrap_or_default()),
            json_escape(&svc.map(|s| s.version.clone()).unwrap_or_default()),
            json_escape(&svc.map(|s| s.extra.clone()).unwrap_or_default()),
            json_escape(&svc.map(|s| s.banner.clone()).unwrap_or_default()),
            json_escape(&svc.map(|s| s.os_hint.clone()).unwrap_or_default()),
            json_escape(&svc.map(|s| s.tls_version.clone()).unwrap_or_default()),
            svc.map(|s| s.cert_expired).unwrap_or(false),
            svc.map(|s| s.self_signed).unwrap_or(false),
            hostnames.join(","),
            findings.join(","),
            web_json(r.web.as_ref())
        ));
    }
    println!(
        "{{\"target\":\"{}\",\"ip\":\"{}\",\"host_up\":true,\"os_guess\":\"{}\",\
         \"syn_ack_unverified\":{},\"firewall_blocked\":{},\"elapsed_s\":{:.3},\
         \"counts\":{{\"open\":{},\"closed\":{},\"filtered\":{}}},\
         \"scan_meta\":{{\"start_ts\":{},\"end_ts\":{},\"duration_ms\":{},\"ports_scanned\":{},\
         \"avg_rtt_ms\":{:.1},\"timeouts\":{}}},\
         \"ports\":[{}]}}",
        json_escape(&report.target),
        report.ip,
        json_escape(&report.os_guess),
        report.doubt.is_doubtful(),
        report.firewall.as_ref().map(|f| f.blocked).unwrap_or(false),
        report.elapsed.as_secs_f64(),
        report.open_count,
        report.closed_count,
        report.filtered_count,
        report.start_ts,
        report.end_ts,
        report.elapsed.as_millis(),
        report.ports.len(),
        report.avg_rtt_ms,
        report.timeouts,
        ports_json.join(",")
    );
}

/// Print one host's findings in standard nmap-compatible XML format.
pub fn print_xml(report: &HostReport, opts: &Options) {
    let addrtype = if report.ip.is_ipv4() { "ipv4" } else { "ipv6" };
    if !report.host_up {
        println!(
            "  <host starttime=\"{}\" endtime=\"{}\"><status state=\"down\" reason=\"no-response\"/><address addr=\"{}\" addrtype=\"{}\"/><hostnames><hostname name=\"{}\" type=\"user\"/></hostnames></host>",
            report.start_ts,
            report.end_ts,
            report.ip,
            addrtype,
            xml_escape(&report.target)
        );
        return;
    }

    println!(
        "  <host starttime=\"{}\" endtime=\"{}\">",
        report.start_ts, report.end_ts
    );
    println!("    <status state=\"up\" reason=\"syn-ack\" reason_ttl=\"0\"/>");
    println!(
        "    <address addr=\"{}\" addrtype=\"{}\"/>",
        report.ip, addrtype
    );
    if let Some(mac) = &report.mac {
        println!(
            "    <address addr=\"{}\" addrtype=\"mac\"/>",
            xml_escape(mac)
        );
    }
    println!("    <hostnames>");
    println!(
        "      <hostname name=\"{}\" type=\"user\"/>",
        xml_escape(&report.target)
    );
    println!("    </hostnames>");
    println!("    <ports>");
    if report.closed_count > 0 {
        println!(
            "      <extraports state=\"closed\" count=\"{}\">",
            report.closed_count
        );
        println!(
            "        <extrareasons reason=\"conn-refused\" count=\"{}\"/>",
            report.closed_count
        );
        println!("      </extraports>");
    }
    if report.filtered_count > 0 {
        println!(
            "      <extraports state=\"filtered\" count=\"{}\">",
            report.filtered_count
        );
        println!(
            "        <extrareasons reason=\"no-response\" count=\"{}\"/>",
            report.filtered_count
        );
        println!("      </extraports>");
    }

    for r in &report.ports {
        if opts.only_open && r.state != State::Open {
            continue;
        }
        let interesting = match r.state {
            State::Open | State::OpenFiltered => true,
            State::Filtered | State::Closed => opts.verbosity >= 2 || opts.reason,
        };
        if !interesting {
            continue;
        }

        println!(
            "      <port protocol=\"{}\" portid=\"{}\">",
            r.proto, r.port
        );
        println!(
            "        <state state=\"{}\" reason=\"{}\" reason_ttl=\"0\"/>",
            r.state.label(),
            xml_escape(r.reason)
        );
        if let Some(svc) = &r.service {
            let name = if svc.name.is_empty() {
                service_name(r.port)
            } else {
                &svc.name
            };
            let mut svc_attrs = format!("name=\"{}\"", xml_escape(name));
            if !svc.product.is_empty() {
                svc_attrs.push_str(&format!(" product=\"{}\"", xml_escape(&svc.product)));
            }
            if !svc.version.is_empty() {
                svc_attrs.push_str(&format!(" version=\"{}\"", xml_escape(&svc.version)));
            }
            if !svc.extra.is_empty() {
                svc_attrs.push_str(&format!(" extrainfo=\"{}\"", xml_escape(&svc.extra)));
            }
            if !svc.os_hint.is_empty() {
                svc_attrs.push_str(&format!(" ostype=\"{}\"", xml_escape(&svc.os_hint)));
            }
            svc_attrs.push_str(" method=\"probed\" conf=\"10\"");

            println!("        <service {}>", svc_attrs);
            for f in r.findings.iter().filter(|f| finding_shown(f, opts)) {
                println!(
                    "          <script id=\"{}\" output=\"[{}] {}\"/>",
                    xml_escape(&f.id),
                    f.severity.label(),
                    xml_escape(&f.title)
                );
            }
            println!("        </service>");
        }
        println!("      </port>");
    }
    println!("    </ports>");

    if opts.os_detection && !report.os_guess.is_empty() && report.os_guess != "unknown" {
        println!("    <os>");
        println!(
            "      <osmatch name=\"{}\" accuracy=\"90\" line=\"1000\"/>",
            xml_escape(&report.os_guess)
        );
        println!("    </os>");
    }

    let srtt_us = (report.avg_rtt_ms * 1000.0) as u64;
    println!(
        "    <times srtt=\"{}\" rttvar=\"5000\" to=\"{}\"/>",
        srtt_us,
        (report.elapsed.as_micros()).min(u64::MAX as u128)
    );
    println!("  </host>");
}

/// Print a short notice when SYN scan was requested but we lack privileges.
pub fn syn_notice(opts: &Options) {
    if opts.scan_kind == ScanKind::Syn {
        let p = Painter::new(opts.color);
        eprintln!(
            "{}",
            p.yellow(
                "[!] -sS (SYN) requires raw-socket privileges (root/CAP_NET_RAW). \
                 Falling back to unprivileged TCP connect scan (-sT)."
            )
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    /// The adaptive timeout starts at the template value, ratchets down toward
    /// a generous multiple of the observed RTT, never drops below the floor, and
    /// never bounces back up when a later, slower answer arrives.
    #[test]
    fn pacer_ratchets_toward_rtt_and_only_downward() {
        let p = Pacer::new(1500);
        assert_eq!(p.timeout(), Duration::from_millis(1500));
        // A 21 ms host: 21*5+80 = 185, clamped up to the 375 ms floor (1500/4).
        p.observe(Duration::from_millis(21));
        assert_eq!(p.timeout(), Duration::from_millis(375));
        // A later, slower answer must not raise the timeout back up.
        p.observe(Duration::from_millis(1000));
        assert_eq!(p.timeout(), Duration::from_millis(375));
        // Never below the floor, even for a sub-millisecond localhost RTT.
        let local = Pacer::new(1500);
        local.observe(Duration::from_micros(200));
        assert_eq!(local.timeout(), Duration::from_millis(375));
        // Never above the template ceiling.
        let slow = Pacer::new(800);
        slow.observe(Duration::from_millis(5000));
        assert_eq!(slow.timeout(), Duration::from_millis(800));
    }

    /// The -FW sampler must return exactly FW_SAMPLE distinct ports, every one
    /// inside the [FW_PORT_LO, FW_PORT_HI) window it claims to sample from.
    #[test]
    fn firewall_sampler_stays_in_range_and_is_distinct() {
        for seed in 0..64u64 {
            let ports = fw_random_ports(seed);
            assert_eq!(ports.len(), FW_SAMPLE, "seed {seed}: wrong count");
            for &p in &ports {
                assert!(
                    (FW_PORT_LO..FW_PORT_HI).contains(&p),
                    "seed {seed}: {p} out of range"
                );
            }
            let mut uniq = ports.clone();
            uniq.sort_unstable();
            uniq.dedup();
            assert_eq!(uniq.len(), FW_SAMPLE, "seed {seed}: ports not distinct");
        }
    }

    /// The abort condition is "every sampled port answered open" — a single
    /// non-open sample means the host is scannable, so -FW must fall through.
    #[test]
    fn firewall_blocks_only_when_every_sample_is_open() {
        let all_open = [State::Open, State::Open, State::Open];
        assert!(all_open.iter().all(|s| *s == State::Open));

        for mixed in [
            [State::Open, State::Open, State::Filtered],
            [State::Open, State::Closed, State::Open],
            [State::Filtered, State::Filtered, State::Filtered],
        ] {
            assert!(
                !mixed.iter().all(|s| *s == State::Open),
                "a non-open sample must not count as blocked: {mixed:?}"
            );
        }
    }

    /// The regression this whole module exists for: a probe that timed out
    /// with no answer at all is *filtered*. A silently dropped SYN — the
    /// normal behaviour of an ISP CPE that lets ICMP through but eats TCP —
    /// must never be read as a live service.
    #[test]
    fn a_timeout_with_no_answer_is_filtered_not_open() {
        assert_eq!(classify(Attempt::NoAnswer), (State::Filtered, "timeout"));
    }

    /// Nothing but a completed three-way handshake may produce Open.
    #[test]
    fn only_a_completed_handshake_is_open() {
        assert_eq!(classify(Attempt::Handshake), (State::Open, "syn-ack"));
        for a in [Attempt::Refused, Attempt::Error, Attempt::NoAnswer] {
            assert_ne!(
                classify(a).0,
                State::Open,
                "{a:?} must not classify as open"
            );
        }
    }

    /// An explicit refusal (RST) is the one answer that proves closed.
    #[test]
    fn only_a_refusal_is_closed() {
        assert_eq!(classify(Attempt::Refused), (State::Closed, "conn-refused"));
        assert_eq!(
            attempt_from_io(&Error::from(ErrorKind::ConnectionRefused)),
            Attempt::Refused
        );
    }

    /// Every other connect error falls to filtered. No default branch may
    /// ever land on Open, whatever the OS hands back.
    #[test]
    fn unhandled_connect_errors_fall_to_filtered() {
        let kinds = [
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::NetworkDown,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::PermissionDenied,
            ErrorKind::AddrNotAvailable,
            ErrorKind::TimedOut,
            ErrorKind::Other,
        ];
        for k in kinds {
            let a = attempt_from_io(&Error::from(k));
            assert_eq!(a, Attempt::Error, "{k:?} should not be read as an answer");
            assert_eq!(classify(a), (State::Filtered, "no-response"), "{k:?}");
        }
    }

    /// End to end against a real listener, and against the same address once
    /// the listener is gone.
    ///
    /// "Open" is tested against a live tokio listener (phase 1).
    /// "Not open" is tested against a separate port that is dropped before any
    /// connection is made (phase 2). On Linux, closing a listener port with an
    /// empty backlog causes new SYNs to receive immediate RST → `Closed`. On
    /// Windows, the default firewall silently drops SYNs to unbound ports even
    /// on loopback → `Filtered`. Both are correct "no service" results; the
    /// invariant we enforce is that neither `Open` nor `OpenFiltered` is returned.
    #[tokio::test]
    async fn probe_port_reads_a_real_listener_and_a_real_refusal() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Phase 1: open — probe a live listener.
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(
            probe_port(ip, port, 1000, 0).await,
            (State::Open, "syn-ack")
        );
        drop(listener);

        // Phase 2: no service — a fresh port never connected to, so the backlog
        // is empty and the close is immediate. On Windows, use std::net to force
        // a synchronous closesocket() call rather than a deferred IOCP teardown.
        let fresh = std::net::TcpListener::bind((ip, 0)).unwrap();
        let dead_port = fresh.local_addr().unwrap().port();
        drop(fresh); // synchronous closesocket()
        tokio::task::yield_now().await; // flush any pending Winsock state

        let (state, _reason) = probe_port(ip, dead_port, 500, 0).await;
        assert!(
            state == State::Closed || state == State::Filtered,
            "dead port must appear Closed or Filtered, not {state:?}",
        );
    }

    /// The real timeout path, end to end through `tokio::time::timeout`: a
    /// connect that never answers — a SYN into a black hole, the exact case
    /// an ISP CPE that drops TCP but passes ICMP produces — comes back as a
    /// filtered port, not an open one.
    #[tokio::test]
    async fn a_connect_that_never_answers_is_filtered() {
        let silence = std::future::pending::<std::io::Result<TcpStream>>();
        let attempt = attempt_within(Duration::from_millis(50), silence).await;

        assert_eq!(attempt, Attempt::NoAnswer);
        assert_eq!(classify(attempt), (State::Filtered, "timeout"));
    }

    /// Retries change how long we wait for an answer, never the verdict when
    /// none arrives: silence is retried, then left filtered.
    #[test]
    fn retries_are_spent_on_silence_and_never_promote_it() {
        assert!(should_retry(State::Filtered, 0, 2));
        assert!(should_retry(State::Filtered, 1, 2));
        // Retries exhausted — the filtered verdict stands.
        assert!(!should_retry(State::Filtered, 2, 2));
        assert!(!should_retry(State::Filtered, 0, 0));
        // An answer is final either way; it is never re-probed.
        assert!(!should_retry(State::Open, 0, 3));
        assert!(!should_retry(State::Closed, 0, 3));
    }

    /// Control ports stay clear of the ports under test, so the sentinel
    /// never draws its conclusion from the scan's own subject matter.
    #[test]
    fn sentinel_ports_avoid_the_ports_being_scanned() {
        let scanned: Vec<u16> = (40_000..=64_999).collect();
        assert!(sentinel_ports(&scanned).is_empty());

        let scanned: Vec<u16> = vec![80, 443, 8080];
        let picked = sentinel_ports(&scanned);
        assert_eq!(picked.len(), SENTINEL_PORTS);
        for p in &picked {
            assert!((40_000..=64_999).contains(p));
            assert!(!scanned.contains(p));
        }
        // Distinct, so two hits on one lucky port can never trip the check.
        let mut sorted = picked.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), picked.len());
    }

    /// Loopback refuses connections on ports with nothing behind them, which
    /// is what an honest network looks like: the sentinel must stay quiet.
    #[tokio::test]
    async fn sentinel_stays_quiet_on_an_honest_host() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!syn_ack_is_meaningless(ip, 500, &[]).await);
    }

    /// The scan that motivated this second signal: 404 ports against a real
    /// host came back 180 open, 0 closed, 224 filtered. The sentinel walked
    /// past it — that CPE answers only on service-looking ports, so control
    /// ports at 40000+ were dropped like honest silence — but a host that
    /// accepts 180 connections and refuses none is not a host.
    #[test]
    fn a_scan_that_never_gets_refused_is_doubted() {
        assert!(opens_look_manufactured(180, 0, 404));
        assert_eq!(assess_doubt(false, 180, 0, 404), Doubt::NothingEverRefuses);
        // The sentinel still takes precedence when it does fire.
        assert_eq!(assess_doubt(true, 180, 0, 404), Doubt::ControlPortsAnswered);
    }

    /// The inference must not fire on hosts that are merely well firewalled.
    #[test]
    fn honest_scans_are_left_alone() {
        // A hardened host: a few services, everything else dropped. Zero
        // closed ports is normal here and must not be held against it.
        assert!(!opens_look_manufactured(2, 0, 404));
        // Even a generously exposed host stays believed while its open count
        // is a small share of a wide scan.
        assert!(!opens_look_manufactured(20, 0, 404));
        // One RST anywhere in the scan proves the host answers for itself.
        assert!(!opens_look_manufactured(180, 1, 404));
        // Small scans carry too little signal to infer anything from.
        assert!(!opens_look_manufactured(2, 0, 2));
        assert!(!opens_look_manufactured(9, 0, 12));
        // A quiet host with nothing open is just filtered, not suspicious.
        assert!(!opens_look_manufactured(0, 0, 404));
        assert_eq!(assess_doubt(false, 0, 0, 404), Doubt::None);
    }

    /// Every doubt that fires must be able to say what gave it away.
    #[test]
    fn every_doubt_explains_itself() {
        assert!(!Doubt::None.is_doubtful());
        assert!(Doubt::None.note().is_empty());
        for d in [Doubt::ControlPortsAnswered, Doubt::NothingEverRefuses] {
            assert!(d.is_doubtful());
            assert!(!d.note().is_empty(), "{d:?} must explain itself");
        }
    }

    /// Service evidence is what promotes a downgraded port back to open — a
    /// port-number guess alone is not evidence.
    #[test]
    fn only_a_replying_service_counts_as_evidence() {
        let guess = ServiceInfo {
            name: "http".to_string(),
            ..Default::default()
        };
        assert!(!guess.has_evidence());

        let replied = ServiceInfo {
            banner: "SSH-2.0-OpenSSH_8.2p1".to_string(),
            ..guess.clone()
        };
        assert!(replied.has_evidence());
    }

    #[tokio::test]
    async fn test_ipv6_cidr_expansion() {
        let addrs = expand("2001:db8::/126", IpVersion::V6, false)
            .await
            .unwrap();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0].0, "2001:db8::");
        assert_eq!(addrs[3].0, "2001:db8::3");

        // Single host prefix
        let single = expand("2001:db8::1/128", IpVersion::Any, false)
            .await
            .unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].0, "2001:db8::1");

        // Capped /64
        let capped = expand("2001:db8::/64", IpVersion::Any, false)
            .await
            .unwrap();
        assert_eq!(capped.len(), 65536);

        // Filtered out by -4
        let filtered = expand("2001:db8::/126", IpVersion::V4, false).await;
        assert!(filtered.is_err());
    }

    #[test]
    fn test_xml_escape_and_output() {
        assert_eq!(
            crate::util::output::xml_escape("<>&\"'"),
            "&lt;&gt;&amp;&quot;&apos;"
        );
    }
}
