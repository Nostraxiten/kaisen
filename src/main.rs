//! Kaisen — a fast nmap + dig hybrid network scanner that runs without root.
//!
//! Entry point: parse args, then dispatch to the scanner or the DNS resolver.

mod cli;
mod dns;
mod ports;
mod scan;
mod service;
mod tls;
mod util;
mod vuln;

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Instant;

use cli::{Mode, Options, OutputFormat};
use util::output::Painter;
use dns::{nsaudit, whois};
use scan::{neigh, mail};

fn banner(p: &Painter) {
    let art = r#"
 _  __     _
| |/ /__ _(_)___  ___ _ __
| ' // _` | / __|/ _ \ '_ \
| . \ (_| | \__ \  __/ | | |
|_|\_\__,_|_|___/\___|_| |_|
"#;
    eprintln!("{}", p.cyan(art));
}

/// Restore the default SIGPIPE behaviour.
///
/// Rust's runtime ignores SIGPIPE, so a write to a closed pipe returns EPIPE
/// and `println!` panics on it. For a command-line tool that means
/// `kaisen --vuln-list | head` dies with a backtrace instead of stopping
/// quietly, which is what every other Unix tool does. There is no std API for
/// this, and pulling in libc for one constant would be a poor trade, so the
/// one symbol is declared here. SIGPIPE is 13 and SIG_DFL is 0 on Linux,
/// Android and macOS alike.
#[cfg(unix)]
fn restore_sigpipe() {
    extern "C" {
        fn signal(sig: i32, handler: usize) -> usize;
    }
    unsafe {
        signal(13, 0);
    }
}

#[cfg(not(unix))]
fn restore_sigpipe() {}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    restore_sigpipe();
    let args: Vec<String> = std::env::args().skip(1).collect();

    let opts = match cli::parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("kaisen: {e}");
            eprintln!("Try 'kaisen --help' for usage.");
            return ExitCode::from(2);
        }
    };

    match opts.mode {
        Mode::Help => {
            print!("{}", cli::help_text(opts.help_topic.as_deref(), opts.help_spanish));
            ExitCode::SUCCESS
        }
        Mode::Version => {
            println!("{}", cli::version_text());
            ExitCode::SUCCESS
        }
        Mode::Dns => run_dns(&opts).await,
        Mode::Mail => run_mail(&opts).await,
        Mode::Lookup => run_lookup(&opts).await,
        Mode::Whois => run_whois(&opts).await,
        Mode::Neighbor => run_neighbor(&opts).await,
        Mode::NsAudit => run_nsaudit(&opts).await,
        Mode::VulnList => {
            vuln::print_catalogue(opts.min_severity, opts.color);
            ExitCode::SUCCESS
        }
        Mode::Scan => run_scan(&opts).await,
    }
}

async fn run_nsaudit(opts: &Options) -> ExitCode {
    let p = Painter::new(opts.color);
    if opts.targets.is_empty() {
        eprintln!("kaisen: no domain for the name server audit");
        eprintln!("Try 'kaisen ns <domain>'.");
        return ExitCode::from(2);
    }
    let server = match resolve_dns_server(opts).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", p.red(&format!("kaisen: {e}")));
            return ExitCode::FAILURE;
        }
    };
    let timeout_ms = opts.timing.connect_timeout_ms.max(2500);
    for domain in &opts.targets {
        nsaudit::audit(domain, server, timeout_ms, opts.color, opts.verbosity).await;
    }
    ExitCode::SUCCESS
}

async fn run_neighbor(opts: &Options) -> ExitCode {
    let p = Painter::new(opts.color);
    if opts.targets.is_empty() {
        eprintln!("kaisen: no domain for neighbor recon");
        eprintln!("Try 'kaisen neighbor <domain>'.");
        return ExitCode::from(2);
    }
    let server = match resolve_dns_server(opts).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", p.red(&format!("kaisen: {e}")));
            return ExitCode::FAILURE;
        }
    };
    let timeout_ms = opts.timing.connect_timeout_ms.max(2000);
    let conc = opts.timing.concurrency;
    for domain in &opts.targets {
        neigh::run(domain, server, timeout_ms, opts.color, conc).await;
    }
    ExitCode::SUCCESS
}

async fn run_whois(opts: &Options) -> ExitCode {
    let p = Painter::new(opts.color);
    if opts.targets.is_empty() {
        eprintln!("kaisen: no domain/IP for whois");
        eprintln!("Try 'kaisen whois <domain|ip>'.");
        return ExitCode::from(2);
    }
    let timeout_ms = opts.timing.connect_timeout_ms.max(6000);
    let mut ok = true;
    for t in &opts.targets {
        if !whois::run(t, timeout_ms, opts.color, opts.verbosity).await {
            ok = false;
        }
    }
    let _ = p;
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

async fn run_lookup(opts: &Options) -> ExitCode {
    let p = Painter::new(opts.color);
    if opts.targets.is_empty() {
        eprintln!("kaisen: no name to look up");
        eprintln!("Try 'kaisen lookup <domain>'.");
        return ExitCode::from(2);
    }
    let server = match resolve_dns_server(opts).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", p.red(&format!("kaisen: {e}")));
            return ExitCode::FAILURE;
        }
    };
    let timeout_ms = opts.timing.connect_timeout_ms.max(2500);
    for name in &opts.targets {
        lookup_profile(name, server, timeout_ms, &p).await;
    }
    ExitCode::SUCCESS
}

async fn lookup_profile(name: &str, server: std::net::SocketAddr, timeout_ms: u64, p: &Painter) {
    println!();
    println!(
        "{} {} {}",
        p.bold("Kaisen DNS profile for"),
        p.cyan(name),
        p.dim(&format!("(via {})", server.ip()))
    );

    let types = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA"];
    let queries = types.iter().map(|t| {
        let qt = dns::type_to_num(t).unwrap();
        async move { (*t, dns::query(server, name, qt, false, timeout_ms).await) }
    });
    let results = futures::future::join_all(queries).await;

    for (t, res) in results {
        match res {
            Ok(resp) if !resp.answers.is_empty() => {
                for a in &resp.answers {
                    println!(
                        "{:<7} {:<7} {}",
                        p.magenta(&dns::num_to_type(a.rtype)),
                        a.ttl,
                        a.data.render()
                    );
                }
            }
            Ok(resp) => {
                let _ = resp;
                if p_verbose_none(t) {
                    println!("{:<7} {}", p.magenta(t), p.dim("(none)"));
                }
            }
            Err(e) => {
                println!("{:<7} {}", p.magenta(t), p.dim(&format!("(query failed: {e})")));
            }
        }
    }
}

// Only show "(none)" lines for the record types users usually care to confirm.
fn p_verbose_none(t: &str) -> bool {
    matches!(t, "A" | "AAAA" | "MX" | "NS")
}

/// Resolve the DNS server to use (explicit @server / --dns-port, else system default).
async fn resolve_dns_server(opts: &Options) -> Result<std::net::SocketAddr, String> {
    let server_ip: IpAddr = match &opts.dns_server {
        Some(s) => match s.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => tokio::net::lookup_host((s.as_str(), opts.dns_port))
                .await
                .map_err(|e| format!("cannot resolve DNS server {s}: {e}"))?
                .next()
                .map(|sa| sa.ip())
                .ok_or_else(|| format!("cannot resolve DNS server {s}"))?,
        },
        None => dns::default_server(),
    };
    Ok(std::net::SocketAddr::new(server_ip, opts.dns_port))
}

async fn run_mail(opts: &Options) -> ExitCode {
    let p = Painter::new(opts.color);
    if opts.targets.is_empty() {
        eprintln!("kaisen: no domain to audit");
        eprintln!("Try 'kaisen mail <domain>'.");
        return ExitCode::from(2);
    }
    let server = match resolve_dns_server(opts).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", p.red(&format!("kaisen: {e}")));
            return ExitCode::FAILURE;
        }
    };
    let timeout_ms = opts.timing.connect_timeout_ms.max(2500);
    for domain in &opts.targets {
        mail::audit(domain, server, timeout_ms, opts.color, opts.verbosity).await;
    }
    ExitCode::SUCCESS
}

async fn run_scan(opts_in: &Options) -> ExitCode {
    // Focused `-OS` mode: when the user asks only for OS detection (no explicit
    // ports, no -sV/-vuln/--open, normal output), Kaisen probes a small,
    // high-signal port set and reports the OS + host context instead of the
    // full port table. Each flag should mean one clear thing.
    let os_focus = opts_in.os_detection
        && !opts_in.service_detection
        && !opts_in.vuln
        && !opts_in.only_open
        && !opts_in.ports_selected
        && !opts_in.device_detection
        && !opts_in.mac_info
        && opts_in.output == OutputFormat::Normal;

    let mut owned;
    let opts: &Options = if os_focus {
        owned = opts_in.clone();
        owned.ports = ports::os_probe_ports();
        &owned
    } else if opts_in.device_detection {
        // -DP needs a few device-signature ports (e.g. iPhone's 62078) that
        // aren't in the default top-N list — union them in rather than
        // replacing whatever port selection the user already made.
        owned = opts_in.clone();
        let mut set: std::collections::BTreeSet<u16> = owned.ports.iter().copied().collect();
        set.extend(ports::DEVICE_PROBE_PORTS.iter().copied());
        owned.ports = set.into_iter().collect();
        &owned
    } else {
        opts_in
    };

    let p = Painter::new(opts.color);

    if opts.targets.is_empty() {
        eprintln!("kaisen: no target specified");
        eprintln!("Try 'kaisen --help' for usage.");
        return ExitCode::from(2);
    }

    if opts.verbosity >= 1 && opts.output == OutputFormat::Normal {
        banner(&p);
    }

    scan::syn_notice(opts);

    if opts.output == OutputFormat::Normal {
        eprintln!(
            "{}",
            p.dim(&format!(
                "Kaisen v{}: scanning {} target(s), {} port(s) each, concurrency={}, timeout={}ms",
                cli::VERSION,
                opts.targets.len(),
                opts.ports.len(),
                opts.timing.concurrency,
                opts.timing.connect_timeout_ms
            ))
        );
    }

    // Expand all targets first.
    let mut hosts: Vec<(String, IpAddr)> = Vec::new();
    for t in &opts.targets {
        match scan::expand_target(t, opts.ip_version).await {
            Ok(list) => hosts.extend(list),
            Err(e) => eprintln!("{}", p.red(&format!("[!] {t}: {e}"))),
        }
    }

    // --exclude / --exclude-file: expand the exclusions the same way targets
    // are expanded, so an exclusion can be written as an IP, a hostname or a
    // CIDR exactly like a target, then drop any address that matches. Removing
    // hosts silently would be the wrong kind of quiet, so the count is stated.
    if !opts.exclude.is_empty() {
        let mut excluded: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();
        for spec in &opts.exclude {
            match scan::expand_exclusion(spec).await {
                Ok(list) => excluded.extend(list.into_iter().map(|(_, ip)| ip)),
                Err(e) => eprintln!("{}", p.yellow(&format!("[!] --exclude {spec}: {e}"))),
            }
        }
        let before = hosts.len();
        hosts.retain(|(_, ip)| !excluded.contains(ip));
        let dropped = before - hosts.len();
        if dropped > 0 && opts.output == OutputFormat::Normal {
            eprintln!("{}", p.dim(&format!("Excluded {dropped} host(s) by request.")));
        }
    }

    if hosts.is_empty() {
        eprintln!("{}", p.red("No scannable hosts."));
        return ExitCode::FAILURE;
    }

    let json = opts.output == OutputFormat::Json;
    if json {
        println!("[");
    }

    let total = hosts.len();
    let mut any_open = false;
    let mut up_count = 0usize;
    let sweep_start = Instant::now();

    // Fast liveness sweep across every target at once (ping + a couple of
    // common ports), the same shape nmap uses — so the expensive full port
    // scan below only runs against hosts that actually answered something.
    let alive = scan::discover_alive(&hosts, opts).await;

    for (idx, (target, ip)) in hosts.into_iter().enumerate() {
        if idx > 0 && opts.timing.host_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(opts.timing.host_delay_ms)).await;
        }
        let report = scan::scan_host(&target, ip, opts, alive[idx]).await;
        if report.host_up {
            up_count += 1;
        }
        if report.open_count > 0 {
            any_open = true;
        }
        if json && idx > 0 {
            println!(",");
        }
        if os_focus {
            scan::print_os_report(&report, opts);
        } else {
            scan::print_report(&report, opts);
        }
    }

    if json {
        println!("]");
    }

    // Nmap-style tally: with many targets and mostly-silent hosts skipped
    // from the report above, this is the only place their count shows up.
    if opts.output == OutputFormat::Normal {
        println!();
        println!(
            "{}",
            p.dim(&format!(
                "Kaisen done: {total} IP address(es) ({up_count} host(s) up) scanned in {:.2}s",
                sweep_start.elapsed().as_secs_f64()
            ))
        );
    }

    if any_open {
        ExitCode::SUCCESS
    } else {
        // Not an error, but signal "nothing open" via code 1 for scripting.
        ExitCode::SUCCESS
    }
}

async fn run_dns(opts: &Options) -> ExitCode {
    let p = Painter::new(opts.color);

    if opts.targets.is_empty() {
        eprintln!("kaisen: no name/address to resolve");
        eprintln!("Try 'kaisen --help' for usage.");
        return ExitCode::from(2);
    }

    // Warn if scan options were mixed with a DNS action (-x / -D / @server /
    // dns subcommand). These belong to different subsystems, so the scan flags
    // are ignored here — tell the user instead of silently dropping them.
    if opts.os_detection
        || opts.service_detection
        || opts.vuln
        || opts.only_open
        || opts.ports_selected
        || opts.scan_kind == cli::ScanKind::Syn
    {
        eprintln!(
            "{}",
            p.yellow(
                "[!] DNS mode is active (from -x / -D / @server), so scan options like \
                 -OS/-sV/-F/-PA are ignored. Run the scan without a DNS flag, e.g. \
                 'kaisen -OS <ip>'."
            )
        );
    }

    // Determine server. With +dot and no @server, the system resolver is the
    // wrong default — it almost certainly does not listen on 853 — so a named
    // DoT resolver stands in, and the name is stated in --help rather than
    // being a surprise.
    let explicit_server = opts.dns_server.clone();
    let dot_name = match (&explicit_server, opts.dns_dot) {
        (Some(s), _) => s.clone(),
        (None, true) => dns::DEFAULT_DOT_HOST.to_string(),
        (None, false) => String::new(),
    };
    let effective_server = if opts.dns_dot && explicit_server.is_none() {
        Some(dns::DEFAULT_DOT_HOST.to_string())
    } else {
        explicit_server
    };

    let server_ip: IpAddr = match &effective_server {
        Some(s) => match s.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                // resolve the server hostname
                match tokio::net::lookup_host((s.as_str(), opts.dns_port)).await {
                    Ok(mut it) => match it.next() {
                        Some(sa) => sa.ip(),
                        None => {
                            eprintln!("kaisen: cannot resolve DNS server {s}");
                            return ExitCode::FAILURE;
                        }
                    },
                    Err(e) => {
                        eprintln!("kaisen: cannot resolve DNS server {s}: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        },
        None => dns::default_server(),
    };
    let server = std::net::SocketAddr::new(server_ip, opts.dns_port);

    let timeout_ms = opts.timing.connect_timeout_ms.max(2000);
    let mut had_error = false;

    // +trace: walk the delegation chain from the root instead of asking one
    // resolver for the final answer.
    if opts.dns_trace {
        for target in &opts.targets {
            let qtype_s = opts.dns_types.first().cloned().unwrap_or_else(|| "A".to_string());
            let qtype = dns::type_to_num(&qtype_s).unwrap_or(1);
            print_trace(target, &qtype_s, qtype, timeout_ms, &p).await;
        }
        return ExitCode::SUCCESS;
    }

    // An explicit AXFR request is a zone transfer, not an ordinary query.
    if opts.dns_types.iter().any(|t| t == "AXFR") {
        for target in &opts.targets {
            match dns::axfr(server, target, timeout_ms).await {
                Ok(records) => {
                    println!();
                    println!(
                        "{} {} {} ({} records)",
                        p.bold("Kaisen zone transfer of"),
                        p.cyan(target),
                        p.dim(&format!("from {}", server.ip())),
                        records.len()
                    );
                    println!(
                        "{}",
                        p.red("[!] This server allowed a full zone transfer to an unauthenticated client.")
                    );
                    for r in &records {
                        print_record(r, opts, &p);
                    }
                }
                Err(e) => {
                    println!();
                    println!(
                        "{} {} {}",
                        p.bold("Kaisen zone transfer of"),
                        p.cyan(target),
                        p.dim(&format!("from {}", server.ip()))
                    );
                    println!("{}", p.green(&format!("[ok] refused — {e}")));
                }
            }
        }
        return ExitCode::SUCCESS;
    }

    for target in &opts.targets {
        // Build the list of (query_name, type) pairs.
        let queries: Vec<(String, String)> = if opts.dns_reverse {
            match target.parse::<IpAddr>() {
                Ok(ip) => vec![(dns::reverse_name(ip), "PTR".to_string())],
                Err(_) => {
                    eprintln!("{}", p.red(&format!("[!] -x needs an IP address, got '{target}'")));
                    had_error = true;
                    continue;
                }
            }
        } else if opts.dns_types.is_empty() {
            vec![(target.clone(), "A".to_string())]
        } else {
            opts.dns_types
                .iter()
                .map(|t| (target.clone(), t.clone()))
                .collect()
        };

        for (qname, qtype_s) in queries {
            let qtype = match dns::type_to_num(&qtype_s) {
                Some(n) => n,
                None => {
                    eprintln!("{}", p.red(&format!("[!] unknown DNS type: {qtype_s}")));
                    had_error = true;
                    continue;
                }
            };

            let qopts = dns::QueryOpts {
                force_tcp: opts.dns_tcp,
                timeout_ms,
                dnssec: opts.dns_dnssec,
                nsid: opts.dns_nsid,
                no_recurse: opts.dns_norec,
                udp_size: if opts.dns_dnssec || opts.dns_nsid { 4096 } else { 0 },
                client_subnet: opts.dns_subnet,
            };
            // +dot / --doh take the query down an encrypted channel; anything
            // else is the ordinary UDP-with-TCP-fallback path.
            let result = if let Some(url) = &opts.dns_doh {
                dns::query_doh(url, &qname, qtype, &qopts)
                    .await
                    .map(|(r, i)| (r, Some(i)))
            } else if opts.dns_dot {
                dns::query_dot(server, &dot_name, &qname, qtype, &qopts)
                    .await
                    .map(|(r, i)| (r, Some(i)))
            } else {
                dns::query_opts(server, &qname, qtype, &qopts)
                    .await
                    .map(|r| (r, None))
            };

            match result {
                Ok((resp, secure)) => {
                    print_dns(&qname, &qtype_s, &resp, opts, &p);
                    if let Some(info) = secure {
                        print_secure_info(&info, opts, &p);
                    }
                }
                Err(e) => {
                    eprintln!("{}", p.red(&format!("[!] {qname} {qtype_s}: {e}")));
                    had_error = true;
                }
            }
        }
    }

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Render an iterative resolution the way `dig +trace` does: one block per
/// delegation hop, so a broken delegation is visible as the hop where the
/// chain stops rather than as a bare SERVFAIL.
async fn print_trace(name: &str, qtype_s: &str, qtype: u16, timeout_ms: u64, p: &Painter) {
    println!();
    println!(
        "{} {} {} {}",
        p.bold("Kaisen DNS trace for"),
        p.cyan(name),
        p.magenta(qtype_s),
        p.dim("(iterative, starting at the root)")
    );

    let steps = dns::trace(name, qtype, timeout_ms).await;
    if steps.is_empty() {
        println!("{}", p.red("[!] no root server answered — check outbound UDP/53"));
        return;
    }

    for (i, step) in steps.iter().enumerate() {
        println!();
        println!(
            "{} {} {}",
            p.bold(&format!("[{}]", i + 1)),
            p.cyan(&step.server_name),
            p.dim(&format!(
                "({}) zone {} — {}ms",
                step.server.ip(),
                step.zone,
                step.response.elapsed_ms
            ))
        );
        if !step.response.answers.is_empty() {
            for a in &step.response.answers {
                println!(
                    "    {:<28} {:<7} {:<8} {}",
                    a.name,
                    a.ttl,
                    dns::num_to_type(a.rtype),
                    a.data.render()
                );
            }
        } else {
            // A referral: list the nameservers this level delegates to.
            for a in step.response.authorities.iter().take(8) {
                println!(
                    "    {:<28} {:<7} {:<8} {}",
                    a.name,
                    a.ttl,
                    dns::num_to_type(a.rtype),
                    a.data.render()
                );
            }
        }
    }

    let answered = steps.last().map(|s| !s.response.answers.is_empty()).unwrap_or(false);
    println!();
    if answered {
        println!("{}", p.green(&format!("Resolved in {} hop(s).", steps.len())));
    } else {
        println!(
            "{}",
            p.yellow(&format!(
                "Chain stopped after {} hop(s) without an answer — check the delegation at that level.",
                steps.len()
            ))
        );
    }
}

/// Say how an encrypted query travelled, and what that does and does not
/// prove. The caveat is printed every time, not only under -v: a user reading
/// "encrypted" should never have to guess how far the guarantee reaches.
fn print_secure_info(info: &dns::SecureInfo, opts: &Options, p: &Painter) {
    if opts.dns_short {
        return;
    }
    let alpn = match &info.alpn {
        Some(a) => format!(", ALPN {a}"),
        None => String::new(),
    };
    println!(
        ";; TRANSPORT: {} — {}",
        p.green(info.transport),
        p.dim(&format!("{}{alpn}", info.suite))
    );
    println!(";; CERTIFICATE: {}", p.dim(&info.certificate));
    println!(";; {}", p.yellow(info.note));
}

fn print_dns(qname: &str, qtype: &str, resp: &dns::Response, opts: &Options, p: &Painter) {
    if opts.dns_short {
        for a in &resp.answers {
            println!("{}", a.data.render());
        }
        if resp.answers.is_empty() {
            eprintln!(
                "{}",
                p.dim(&format!(";; {} {} -> {}", qname, qtype, dns::rcode_str(resp.rcode)))
            );
        }
        return;
    }

    println!();
    println!(
        "{} {} {} @{} ({})",
        p.bold("Kaisen DNS"),
        p.cyan(qname),
        p.magenta(qtype),
        resp.server.ip(),
        if resp.via_tcp { "TCP" } else { "UDP" }
    );
    let status = dns::rcode_str(resp.rcode);
    let status_c = if resp.rcode == 0 { p.green(status) } else { p.red(status) };
    println!(
        ";; status: {}, flags: {}, answers: {}, authority: {}, additional: {}, time: {}ms",
        status_c,
        resp.flag_str(),
        resp.answers.len(),
        resp.authorities.len(),
        resp.additionals.len(),
        resp.elapsed_ms
    );
    if let Some(nsid) = &resp.nsid {
        println!(";; NSID: {}", p.cyan(nsid));
    }
    if let Some(scope) = resp.ecs_scope {
        // The scope is the server's own statement about how location-dependent
        // this answer is: 0 means it would say the same thing to everyone.
        let note = if scope == 0 {
            "the answer does not depend on the client network".to_string()
        } else {
            format!("tailored to the first {scope} bits of the network")
        };
        println!(";; CLIENT-SUBNET: scope /{} — {}", p.cyan(&scope.to_string()), p.dim(&note));
    }
    if resp.ad {
        println!(";; {}", p.green("DNSSEC: answer validated by the resolver (AD flag set)"));
    }

    if !resp.answers.is_empty() {
        println!("{}", p.bold(";; ANSWER SECTION:"));
        for a in &resp.answers {
            print_record(a, opts, p);
        }
    }

    if (opts.verbosity >= 1 || opts.dns_all) && !resp.authorities.is_empty() {
        println!("{}", p.bold(";; AUTHORITY SECTION:"));
        for a in &resp.authorities {
            print_record(a, opts, p);
        }
    }

    if opts.verbosity >= 2 && !resp.additionals.is_empty() {
        println!("{}", p.bold(";; ADDITIONAL SECTION:"));
        for a in &resp.additionals {
            print_record(a, opts, p);
        }
    }

    if resp.answers.is_empty() && resp.rcode == 0 {
        println!("{}", p.dim(";; (no answer records)"));
    }
}

fn print_record(r: &dns::Record, _opts: &Options, p: &Painter) {
    println!(
        "{:<28} {:<7} IN  {:<7} {}",
        p.cyan(&r.name),
        r.ttl,
        p.magenta(&dns::num_to_type(r.rtype)),
        r.data.render()
    );
}
