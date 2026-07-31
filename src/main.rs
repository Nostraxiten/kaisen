//! Kaisen — a fast nmap + dig hybrid network scanner that runs without root.
//!
//! Entry point: parse args, then dispatch to the scanner or the DNS resolver.

mod cli;
mod dns;
mod osfp;
mod output;
mod ports;
mod scan;
mod service;
mod vuln;

use std::net::IpAddr;
use std::process::ExitCode;

use cli::{Mode, Options, OutputFormat};
use output::Painter;

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

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
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
            print!("{}", cli::help_text());
            ExitCode::SUCCESS
        }
        Mode::Version => {
            println!("{}", cli::version_text());
            ExitCode::SUCCESS
        }
        Mode::Dns => run_dns(&opts).await,
        Mode::Scan => run_scan(&opts).await,
    }
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
        && opts_in.output == OutputFormat::Normal;

    let mut owned;
    let opts: &Options = if os_focus {
        owned = opts_in.clone();
        owned.ports = ports::os_probe_ports();
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
    for (idx, (target, ip)) in hosts.into_iter().enumerate() {
        if idx > 0 && opts.timing.host_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(opts.timing.host_delay_ms)).await;
        }
        let report = scan::scan_host(&target, ip, opts).await;
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
        let _ = total;
    }

    if json {
        println!("]");
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

    // Determine server.
    let server_ip: IpAddr = match &opts.dns_server {
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

            match dns::query(server, &qname, qtype, opts.dns_tcp, timeout_ms).await {
                Ok(resp) => print_dns(&qname, &qtype_s, &resp, opts, &p),
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
        ";; status: {}, answers: {}, authority: {}, additional: {}, time: {}ms",
        status_c,
        resp.answers.len(),
        resp.authorities.len(),
        resp.additionals.len(),
        resp.elapsed_ms
    );

    if !resp.answers.is_empty() {
        println!("{}", p.bold(";; ANSWER SECTION:"));
        for a in &resp.answers {
            print_record(a, opts, p);
        }
    }

    if opts.verbosity >= 1 && !resp.authorities.is_empty() {
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
