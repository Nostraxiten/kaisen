//! Kaisen — escáner de red rápido, híbrido de nmap + dig, sin necesidad de root.
//!
//! Punto de entrada: parsea los argumentos y despacha al escáner o al resolvedor DNS.

#![allow(
    clippy::manual_range_contains,
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::format_in_format_args,
    clippy::redundant_locals,
    clippy::manual_clamp,
    clippy::manual_pattern_char_comparison,
    clippy::question_mark,
    clippy::collapsible_match,
    clippy::if_same_then_else,
    clippy::single_element_loop,
    clippy::doc_lazy_continuation
)]

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
use dns::{nsaudit, whois};
use scan::{mail, neigh};
use util::output::Painter;

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

/// Restaura el comportamiento por defecto de SIGPIPE.
///
/// El runtime de Rust ignora SIGPIPE, por lo que una escritura en un pipe
/// cerrado devuelve EPIPE y `println!` entra en pánico. Para una herramienta
/// de línea de comandos eso significa que `kaisen --vuln-list | head` muere
/// con un backtrace en lugar de detenerse en silencio, que es lo que hace
/// cualquier otra herramienta Unix.
///
/// No hay API estándar para esto. SIGPIPE es 13 y SIG_DFL es 0 en Linux,
/// Android y macOS por igual.
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
            print!(
                "{}",
                cli::help_text(opts.help_topic.as_deref(), opts.help_spanish)
            );
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
        Mode::Path => run_path(&opts).await,
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
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
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
                if mostrar_ninguno(t) {
                    println!("{:<7} {}", p.magenta(t), p.dim("(none)"));
                }
            }
            Err(e) => {
                println!(
                    "{:<7} {}",
                    p.magenta(t),
                    p.dim(&format!("(query failed: {e})"))
                );
            }
        }
    }
}

/// Solo muestra líneas "(none)" para los tipos de registro que los usuarios
/// suelen querer confirmar explícitamente.
fn mostrar_ninguno(t: &str) -> bool {
    matches!(t, "A" | "AAAA" | "MX" | "NS")
}

/// Resuelve el servidor DNS a usar (--dns / --dns-port explícito, o el predeterminado del sistema).
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
    // Modo `-OS` enfocado: cuando el usuario solo pide detección de SO (sin puertos
    // explícitos, sin -sV/-vuln/--open, salida normal), Kaisen sondea un conjunto
    // pequeño de puertos de alta señal y muestra el SO + contexto del host en lugar
    // de la tabla completa de puertos. Cada flag debe significar una sola cosa.
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
        // -DP necesita algunos puertos de firma de dispositivo (ej. 62078 del iPhone)
        // que no están en la lista top-N por defecto — se unen en lugar de reemplazar
        // la selección de puertos que el usuario ya haya hecho.
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

    // Expandir todos los objetivos primero.
    let mut hosts: Vec<(String, IpAddr)> = Vec::new();
    for t in &opts.targets {
        match scan::expand_target(t, opts.ip_version).await {
            Ok(list) => hosts.extend(list),
            Err(e) => eprintln!("{}", p.red(&format!("[!] {t}: {e}"))),
        }
    }

    // --exclude / --exclude-file: expandir las exclusiones del mismo modo que los
    // objetivos, para que una exclusión pueda escribirse como IP, hostname o CIDR
    // exactamente igual que un target, y luego descartar cualquier dirección que
    // coincida. Eliminar hosts en silencio sería el tipo equivocado de silencio,
    // así que se indica el recuento.
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
            eprintln!(
                "{}",
                p.dim(&format!("Excluded {dropped} host(s) by request."))
            );
        }
    }

    if hosts.is_empty() {
        eprintln!("{}", p.red("No scannable hosts."));
        return ExitCode::FAILURE;
    }

    let json = opts.output == OutputFormat::Json;
    let xml = opts.output == OutputFormat::Xml;
    let sweep_start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if json {
        println!("[");
    } else if xml {
        println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        println!("<!DOCTYPE nmaprun>");
        println!("<?xml-stylesheet href=\"file:///usr/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?>");
        println!(
            "<nmaprun scanner=\"kaisen\" args=\"kaisen\" start=\"{}\" version=\"{}\" xmloutputversion=\"1.05\">",
            sweep_start_time,
            cli::VERSION
        );
        println!(
            "<scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"{}\" services=\"1-65535\"/>",
            opts.ports.len()
        );
        println!("<verbose level=\"{}\"/>", opts.verbosity);
        println!("<debugging level=\"0\"/>");
    }

    let total = hosts.len();
    let mut any_open = false;
    let mut up_count = 0usize;
    let sweep_start = Instant::now();

    // Barrido rápido de disponibilidad sobre todos los objetivos a la vez (ping +
    // un par de puertos comunes), con la misma forma que usa nmap — así el costoso
    // escaneo de puertos completo solo se ejecuta contra los hosts que respondieron.
    let alive = scan::discover_alive(&hosts, opts).await;

    // Mejora 6 (Host parallelism): Escaneo concurrente entre hosts cuando hay varios
    let host_conc = if opts.timing.host_delay_ms > 0 || total == 1 {
        1
    } else {
        (opts.timing.concurrency / 10).clamp(1, 16).min(total)
    };

    let reports: Vec<(usize, scan::HostReport)> = if host_conc > 1 {
        use futures::stream::{self, StreamExt};
        let alive_ref = &alive;
        stream::iter(hosts.into_iter().enumerate())
            .map(|(idx, (target, ip))| async move {
                let report = scan::scan_host(&target, ip, opts, alive_ref[idx]).await;
                (idx, report)
            })
            .buffer_unordered(host_conc)
            .collect()
            .await
    } else {
        let mut list = Vec::with_capacity(total);
        for (idx, (target, ip)) in hosts.into_iter().enumerate() {
            if idx > 0 && opts.timing.host_delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(opts.timing.host_delay_ms)).await;
            }
            let report = scan::scan_host(&target, ip, opts, alive[idx]).await;
            list.push((idx, report));
        }
        list
    };

    let mut sorted_reports = reports;
    sorted_reports.sort_by_key(|(idx, _)| *idx);

    for (idx, report) in &sorted_reports {
        if report.host_up {
            up_count += 1;
        }
        if report.open_count > 0 {
            any_open = true;
        }
        if json && *idx > 0 {
            println!(",");
        }
        if os_focus {
            scan::print_os_report(report, opts);
        } else {
            scan::print_report(report, opts);
        }
    }

    if json {
        println!("]");
    } else if xml {
        let sweep_end_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let elapsed_s = sweep_start.elapsed().as_secs_f64();
        println!("<runstats>");
        println!(
            "  <finished time=\"{}\" elapsed=\"{:.2}\" exit=\"success\" summary=\"Kaisen done: {} IP address(es) ({} host(s) up) scanned in {:.2} seconds\"/>",
            sweep_end_time,
            elapsed_s,
            total,
            up_count,
            elapsed_s
        );
        println!("  <hosts up=\"{}\" down=\"{}\" total=\"{}\"/>", up_count, total - up_count, total);
        println!("</runstats>");
        println!("</nmaprun>");
    }


    // Recuento al estilo nmap: con muchos objetivos y hosts mayormente silenciosos
    // omitidos del informe anterior, este es el único lugar donde su recuento aparece.
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

    if let Some(prev_file) = &opts.diff_file {
        match std::fs::read_to_string(prev_file) {
            Ok(prev_content) => {
                match scan::diff::parse_json_report(&prev_content) {
                    Ok(prev_snap) => {
                        let mut curr_snap = std::collections::BTreeMap::new();
                        for (_, report) in &sorted_reports {
                            let mut ports_map = std::collections::BTreeMap::new();
                            for r in &report.ports {
                                let svc = r.service.as_ref();
                                ports_map.insert(
                                    r.port,
                                    scan::diff::PortInfo {
                                        port: r.port,
                                        proto: r.proto.to_string(),
                                        state: r.state.label().to_string(),
                                        service: svc.map(|s| s.name.clone()).unwrap_or_else(|| ports::service_name(r.port).to_string()),
                                        product: svc.map(|s| s.product.clone()).unwrap_or_default(),
                                        version: svc.map(|s| s.version.clone()).unwrap_or_default(),
                                        findings: r.findings.iter().map(|f| f.id.clone()).collect(),
                                    },
                                );
                            }
                            curr_snap.insert(
                                report.ip.to_string(),
                                scan::diff::HostSnapshot {
                                    target: report.target.clone(),
                                    ip: report.ip.to_string(),
                                    os_guess: report.os_guess.clone(),
                                    ports: ports_map,
                                },
                            );
                        }
                        let diffs = scan::diff::diff_snapshots(&prev_snap, &curr_snap);
                        scan::diff::print_diff_report(&diffs, opts.color);
                    }
                    Err(e) => {
                        eprintln!("{}", p.red(&format!("kaisen diff: failed to parse {prev_file}: {e}")));
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", p.red(&format!("kaisen diff: failed to read {prev_file}: {e}")));
            }
        }
    }


    if any_open {
        ExitCode::SUCCESS
    } else {
        // No es un error, pero señala "nada abierto" mediante código 1 para scripting.
        ExitCode::SUCCESS
    }
}

async fn run_path(opts: &Options) -> ExitCode {
    let p = Painter::new(opts.color);
    if opts.targets.is_empty() {
        eprintln!("kaisen: no target specified for path trace");
        eprintln!("Try 'kaisen path <target>'.");
        return ExitCode::from(2);
    }
    let timeout_ms = opts.timing.connect_timeout_ms.max(1000);
    for target in &opts.targets {
        match scan::expand_target(target, opts.ip_version).await {
            Ok(hosts) => {
                for (name, ip) in hosts {
                    scan::traceroute::run_traceroute(
                        &name,
                        ip,
                        opts.path_port,
                        opts.max_hops,
                        timeout_ms,
                        opts.color,
                    )
                    .await;
                }
            }
            Err(e) => {
                eprintln!("{}", p.red(&format!("kaisen: {target}: {e}")));
            }
        }
    }
    ExitCode::SUCCESS
}


async fn run_dns(opts: &Options) -> ExitCode {
    let p = Painter::new(opts.color);

    if opts.targets.is_empty() {
        eprintln!("kaisen: no name/address to resolve");
        eprintln!("Try 'kaisen --help' for usage.");
        return ExitCode::from(2);
    }

    // Avisar si se mezclaron opciones de escaneo con una acción DNS (-x / -D / @server /
    // subcomando dns). Pertenecen a subsistemas diferentes, así que los flags de escaneo
    // se ignoran aquí — informar al usuario en lugar de descartarlos en silencio.
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

    // Determinar el servidor. Con +dot y sin @server, el resolvedor del sistema es el
    // predeterminado incorrecto — casi con certeza no escucha en el 853 — así que se
    // usa un resolvedor DoT nombrado, y el nombre se indica en --help en lugar de ser
    // una sorpresa.
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
                // Resolver el hostname del servidor
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

    // +trace: recorre la cadena de delegación desde la raíz en lugar de preguntar a un
    // resolvedor por la respuesta final.
    if opts.dns_trace {
        for target in &opts.targets {
            let qtype_s = opts
                .dns_types
                .first()
                .cloned()
                .unwrap_or_else(|| "A".to_string());
            let qtype = dns::type_to_num(&qtype_s).unwrap_or(1);
            print_trace(target, &qtype_s, qtype, timeout_ms, &p).await;
        }
        return ExitCode::SUCCESS;
    }

    // Una petición AXFR explícita es una transferencia de zona, no una consulta ordinaria.
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
        // Construir la lista de pares (nombre_consulta, tipo).
        let queries: Vec<(String, String)> = if opts.dns_reverse {
            match target.parse::<IpAddr>() {
                Ok(ip) => vec![(dns::reverse_name(ip), "PTR".to_string())],
                Err(_) => {
                    eprintln!(
                        "{}",
                        p.red(&format!("[!] -x needs an IP address, got '{target}'"))
                    );
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
                udp_size: if opts.dns_dnssec || opts.dns_nsid {
                    4096
                } else {
                    0
                },
                client_subnet: opts.dns_subnet,
            };
            // +dot / --doh envían la consulta por un canal cifrado; cualquier otra cosa
            // usa el camino UDP con fallback TCP automático en caso de truncamiento.
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

/// Muestra una resolución iterativa al estilo `dig +trace`: un bloque por salto
/// de delegación, para que una delegación rota sea visible como el salto donde
/// la cadena se detiene en lugar de como un simple SERVFAIL.
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
        println!(
            "{}",
            p.red("[!] no root server answered — check outbound UDP/53")
        );
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
            // Referral: listar los servidores de nombres a los que delega este nivel.
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

    let answered = steps
        .last()
        .map(|s| !s.response.answers.is_empty())
        .unwrap_or(false);
    println!();
    if answered {
        println!(
            "{}",
            p.green(&format!("Resolved in {} hop(s).", steps.len()))
        );
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

/// Muestra cómo viajó una consulta cifrada y qué demuestra y qué no demuestra.
/// La advertencia se imprime siempre, no solo con -v: un usuario que lee
/// "encrypted" no debería tener que adivinar hasta dónde llega la garantía.
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
                p.dim(&format!(
                    ";; {} {} -> {}",
                    qname,
                    qtype,
                    dns::rcode_str(resp.rcode)
                ))
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
    let status_c = if resp.rcode == 0 {
        p.green(status)
    } else {
        p.red(status)
    };
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
        // El scope es la declaración propia del servidor sobre cuánto depende la respuesta
        // de la ubicación: 0 significa que diría lo mismo a cualquiera.
        let note = if scope == 0 {
            "the answer does not depend on the client network".to_string()
        } else {
            format!("tailored to the first {scope} bits of the network")
        };
        println!(
            ";; CLIENT-SUBNET: scope /{} — {}",
            p.cyan(&scope.to_string()),
            p.dim(&note)
        );
    }
    if resp.ad {
        println!(
            ";; {}",
            p.green("DNSSEC: answer validated by the resolver (AD flag set)")
        );
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
