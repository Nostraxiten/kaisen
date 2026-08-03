//! Scan orchestration: target expansion (host / IP / CIDR), the unprivileged
//! async TCP connect scanner, optional service/version/OS/vuln enrichment, and
//! result rendering in normal / JSON / grepable formats.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::cli::{IpVersion, Options, OutputFormat, ScanKind};
use crate::output::{json_escape, Painter};
use crate::ports::service_name;
use crate::service::{self, ServiceInfo};
use crate::vuln::{self, Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    Closed,
    Filtered,
}

impl State {
    fn label(&self) -> &'static str {
        match self {
            State::Open => "open",
            State::Closed => "closed",
            State::Filtered => "filtered",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortReport {
    pub port: u16,
    pub state: State,
    pub service: Option<ServiceInfo>,
    pub findings: Vec<Finding>,
    pub reason: &'static str,
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
    pub probes: Option<crate::osfp::Probes>,
    /// Host discovery result. Always true under -Pn. Otherwise true when the
    /// host answered ICMP echo, or any port answered (open or closed — a
    /// TCP RST is proof of life even if ICMP is filtered).
    pub host_up: bool,
}

/// Expand a target string into concrete IPs. Supports hostname, IPv4/IPv6, and
/// IPv4 CIDR notation.
pub async fn expand_target(t: &str, ipv: IpVersion) -> Result<Vec<(String, IpAddr)>, String> {
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
            let mask = if host_bits == 32 { 0 } else { base_u & !((count as u32).wrapping_sub(1)) };
            let net = if host_bits == 32 { 0 } else { mask };
            let start = if host_bits == 32 { base_u } else { net };
            let mut out = Vec::new();
            for i in 0..count as u32 {
                let addr = Ipv4Addr::from(start.wrapping_add(i));
                out.push((addr.to_string(), IpAddr::V4(addr)));
            }
            return Ok(out);
        }
        return Err("only IPv4 CIDR is supported".into());
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
    out.truncate(1);
    Ok(out)
}

fn ip_matches(ip: IpAddr, ipv: IpVersion) -> bool {
    match ipv {
        IpVersion::Any => true,
        IpVersion::V4 => ip.is_ipv4(),
        IpVersion::V6 => ip.is_ipv6(),
    }
}

async fn probe_port(ip: IpAddr, port: u16, timeout_ms: u64, retries: u32) -> (State, &'static str) {
    let addr = SocketAddr::new(ip, port);
    let dur = Duration::from_millis(timeout_ms);
    let mut attempts = 0;
    loop {
        match timeout(dur, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => return (State::Open, "syn-ack"),
            Ok(Err(e)) => {
                use std::io::ErrorKind::*;
                match e.kind() {
                    ConnectionRefused => return (State::Closed, "conn-refused"),
                    _ => {
                        // Host unreachable / network down etc. -> filtered, but retry.
                        if attempts >= retries {
                            return (State::Filtered, "no-response");
                        }
                    }
                }
            }
            Err(_) => {
                if attempts >= retries {
                    return (State::Filtered, "timeout");
                }
            }
        }
        attempts += 1;
    }
}

/// Scan one host across the given ports.
pub async fn scan_host(target: &str, ip: IpAddr, opts: &Options) -> HostReport {
    let start = Instant::now();
    let ports = opts.ports.clone();
    let timeout_ms = opts.timing.connect_timeout_ms;
    let retries = opts.timing.retries;
    let concurrency = opts.timing.concurrency.max(1);

    // Phase 1: connectivity scan, plus an unprivileged ICMP host-discovery
    // probe run concurrently (unless -Pn asked us to skip it and just assume
    // every target is up).
    let port_scan = stream::iter(ports.into_iter())
        .map(|port| async move {
            let (state, reason) = probe_port(ip, port, timeout_ms, retries).await;
            (port, state, reason)
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<(u16, State, &'static str)>>();

    let ping = async {
        if opts.no_ping {
            None
        } else {
            crate::osfp::ttl_via_ping(ip).await
        }
    };

    let (results, ping_ttl) = tokio::join!(port_scan, ping);

    let mut reports: Vec<PortReport> = results
        .into_iter()
        .map(|(port, state, reason)| PortReport {
            port,
            state,
            service: None,
            findings: Vec::new(),
            reason,
        })
        .collect();
    reports.sort_by_key(|r| r.port);

    let open_count = reports.iter().filter(|r| r.state == State::Open).count();
    let closed_count = reports.iter().filter(|r| r.state == State::Closed).count();
    let filtered_count = reports.iter().filter(|r| r.state == State::Filtered).count();

    let mut host_up = opts.no_ping || ping_ttl.is_some() || open_count > 0 || closed_count > 0;

    if !host_up {
        // Last resort: on a local subnet, a host can silently drop every
        // ping and every TCP probe at the OS firewall and still be up — the
        // port scan above already forced the kernel to try resolving its MAC
        // address, so check whether that resolution actually succeeded.
        host_up = crate::osfp::arp_alive(ip).await;
    }

    if !host_up {
        // Confirmed down (or unreachable/firewalled with zero signal): don't
        // waste time on service/OS probes that can't possibly answer.
        return HostReport {
            target: target.to_string(),
            ip,
            ports: reports,
            os_guess: String::new(),
            elapsed: start.elapsed(),
            open_count,
            closed_count,
            filtered_count,
            probes: None,
            host_up,
        };
    }

    // Phase 2: service/version detection on open ports (bounded concurrency).
    if opts.service_detection || opts.vuln || opts.os_detection {
        let open_ports: Vec<u16> = reports
            .iter()
            .filter(|r| r.state == State::Open)
            .map(|r| r.port)
            .collect();

        let svc_conc = concurrency.min(200).max(1);
        let detected: Vec<(u16, ServiceInfo)> = stream::iter(open_ports.into_iter())
            .map(|port| {
                let default = service_name(port).to_string();
                async move {
                    let addr = SocketAddr::new(ip, port);
                    let info = service::detect(addr, &default, timeout_ms.max(1500)).await;
                    (port, info)
                }
            })
            .buffer_unordered(svc_conc)
            .collect()
            .await;

        for (port, info) in detected {
            if let Some(r) = reports.iter_mut().find(|r| r.port == port) {
                if opts.vuln {
                    r.findings = vuln::assess(port, &info);
                }
                r.service = Some(info);
            }
        }
    }

    // Phase 3: network-level OS probes (TTL via ping, SNMP sysDescr) — only in
    // OS-detection mode, run best-effort and unprivileged.
    let probes = if opts.os_detection {
        Some(crate::osfp::probe(ip).await)
    } else {
        None
    };

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
    };

    // Phase 4: combine every signal into a single OS guess string.
    if opts.os_detection {
        let (os, _conf, _role, _signals) = infer_os(&report);
        report.os_guess = os;
    }

    report
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

pub fn print_report(report: &HostReport, opts: &Options) {
    match opts.output {
        OutputFormat::Normal => print_normal(report, opts),
        OutputFormat::Grepable => print_grepable(report),
        OutputFormat::Json => print_json(report, opts), // printed per-host; wrapper handled by caller
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
            let short: String = snmp.split_whitespace().take(6).collect::<Vec<_>>().join(" ");
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
                    signals.push(format!(
                        "{}/{} banner -> {}",
                        r.port, svc.name, svc.os_hint
                    ));
                }
            }
        }
    }

    // 3) TTL family from ping (independent corroboration of the family).
    if let Some(pr) = &report.probes {
        if let (Some(ttl), Some(fam)) = (pr.ttl, pr.ttl_family) {
            let hops = pr.ttl_hops.map(|h| h.to_string()).unwrap_or_else(|| "?".into());
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
                p.yellow("Note: Host seems down. If it is really up, but blocking our probes, try -Pn.")
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
            let hops = pr.ttl_hops.map(|h| h.to_string()).unwrap_or_else(|| "?".into());
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
        // Match nmap's default terseness: a dead/silent address gets no
        // report block at all, just a line in the final tally — only show
        // the per-host note when the user explicitly asked for detail.
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
                p.yellow("Note: Host seems down. If it is really up, but blocking our probes, try -Pn.")
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
    println!(
        "Host is up. Scanned {} port(s) in {:.2}s.",
        report.ports.len(),
        report.elapsed.as_secs_f64()
    );

    let open_only: Vec<&PortReport> =
        report.ports.iter().filter(|r| r.state == State::Open).collect();

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
            p.yellow(&format!("No open ports found ({} scanned).", report.ports.len()))
        );
    }

    if !shown.is_empty() {
        // header
        let head = if opts.reason {
            format!("{:<11}{:<9}{:<16}{}", "PORT", "STATE", "SERVICE", "REASON/VERSION")
        } else {
            format!("{:<11}{:<9}{:<16}{}", "PORT", "STATE", "SERVICE", "VERSION")
        };
        println!("{}", p.bold(&head));

        for r in &shown {
            let port_proto = format!("{}/tcp", r.port);
            let state_str = match r.state {
                State::Open => p.green(r.state.label()),
                State::Filtered => p.yellow(r.state.label()),
                State::Closed => p.dim(r.state.label()),
            };
            let svc_name = r
                .service
                .as_ref()
                .map(|s| s.name.clone())
                .unwrap_or_else(|| service_name(r.port).to_string());

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

            // Note: padding uses the uncolored widths, so we build plainly then colorize state.
            println!(
                "{:<11}{:<18}{:<16}{}",
                port_proto,
                state_str,
                svc_name,
                tail.trim()
            );

            // vuln findings under the port
            for f in &r.findings {
                let tag = sev_color(&p, f.severity, &format!("[{}]", f.severity.label()));
                println!("    {} {} — {}", tag, p.bold(&f.id), f.title);
                if opts.verbosity >= 2 {
                    println!("        {}", p.dim(&f.detail));
                }
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

    if opts.vuln {
        let total: usize = report.ports.iter().map(|r| r.findings.len()).sum();
        if total == 0 {
            println!("{}", p.dim("Vuln: no known-vulnerable signatures matched."));
        } else {
            println!("{}", p.bold(&format!("Vuln: {total} potential finding(s) — review above.")));
        }
    }
}

fn print_grepable(report: &HostReport) {
    if !report.host_up {
        println!("Host: {} ({})\tStatus: Down", report.ip, report.target);
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
        ports.push_str(&format!("{}/open/tcp//{}//{}/, ", r.port, svc, ver));
    }
    println!(
        "Host: {} ({})\tStatus: Up\tPorts: {}",
        report.ip,
        report.target,
        ports.trim_end_matches(", ")
    );
}

fn print_json(report: &HostReport, opts: &Options) {
    if !report.host_up {
        println!(
            "{{\"target\":\"{}\",\"ip\":\"{}\",\"host_up\":false,\"os_guess\":\"\",\"elapsed_s\":{:.3},\"ports\":[]}}",
            json_escape(&report.target),
            report.ip,
            report.elapsed.as_secs_f64()
        );
        return;
    }
    let mut ports_json = Vec::new();
    for r in &report.ports {
        // Closed ports are never emitted; with --open, only open ports are.
        if r.state == State::Closed || (opts.only_open && r.state != State::Open) {
            continue;
        }
        let svc = r.service.as_ref();
        let findings: Vec<String> = r
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"id\":\"{}\",\"severity\":\"{}\",\"title\":\"{}\"}}",
                    json_escape(&f.id),
                    f.severity.label(),
                    json_escape(&f.title)
                )
            })
            .collect();
        ports_json.push(format!(
            "{{\"port\":{},\"protocol\":\"tcp\",\"state\":\"{}\",\"service\":\"{}\",\"product\":\"{}\",\"version\":\"{}\",\"findings\":[{}]}}",
            r.port,
            r.state.label(),
            json_escape(&svc.map(|s| s.name.clone()).unwrap_or_else(|| service_name(r.port).to_string())),
            json_escape(&svc.map(|s| s.product.clone()).unwrap_or_default()),
            json_escape(&svc.map(|s| s.version.clone()).unwrap_or_default()),
            findings.join(",")
        ));
    }
    println!(
        "{{\"target\":\"{}\",\"ip\":\"{}\",\"host_up\":true,\"os_guess\":\"{}\",\"elapsed_s\":{:.3},\"ports\":[{}]}}",
        json_escape(&report.target),
        report.ip,
        json_escape(&report.os_guess),
        report.elapsed.as_secs_f64(),
        ports_json.join(",")
    );
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
