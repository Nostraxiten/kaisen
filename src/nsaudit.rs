//! `kaisen ns <domain>` — audit a domain's authoritative name servers.
//!
//! Ordinary DNS tools answer "what does this name resolve to". This one asks
//! the questions you only think to ask when something is broken or exposed:
//! do all the name servers agree, do they admit to being authoritative, will
//! they recurse for a stranger, will they hand over the whole zone, and what
//! software are they running?
//!
//! Every check is a plain DNS query, so it runs unprivileged and touches only
//! the servers the domain itself publishes.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use crate::dns::{self, QueryOpts, RData};
use crate::output::Painter;

#[derive(Clone, Copy)]
enum Mark {
    Ok,
    Warn,
    Bad,
    Info,
}

fn mark(p: &Painter, m: Mark) -> String {
    match m {
        Mark::Ok => p.green("[OK] "),
        Mark::Warn => p.yellow("[!]  "),
        Mark::Bad => p.red("[X]  "),
        Mark::Info => p.blue("[i]  "),
    }
}

/// What one name server told us about itself.
struct NsResult {
    name: String,
    ip: Option<IpAddr>,
    reachable: bool,
    authoritative: bool,
    serial: Option<u32>,
    recursive: bool,
    edns: bool,
    tcp: bool,
    version: Option<String>,
    axfr: Option<usize>,
}

pub async fn audit(domain: &str, resolver: SocketAddr, timeout_ms: u64, color: bool, verbosity: u8) {
    let p = Painter::new(color);
    let domain = domain.trim_end_matches('.');

    println!();
    println!(
        "{} {} {}",
        p.bold("Kaisen name server audit for"),
        p.cyan(domain),
        p.dim(&format!("(via {})", resolver.ip()))
    );
    println!();

    // ── the NS set ──────────────────────────────────────────────────────────
    let ns_qt = dns::type_to_num("NS").unwrap();
    let ns_names: Vec<String> = match dns::query(resolver, domain, ns_qt, false, timeout_ms).await {
        Ok(resp) => resp
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Name(n) => Some(n.trim_end_matches('.').to_string()),
                _ => None,
            })
            .collect(),
        Err(e) => {
            println!("{}", p.red(&format!("[X]  NS query failed: {e}")));
            return;
        }
    };

    if ns_names.is_empty() {
        println!(
            "{}",
            p.red("[X]  no NS records — the domain has no delegation, or it does not exist")
        );
        return;
    }

    println!(
        "{}{:<11} {} server(s): {}",
        mark(&p, Mark::Ok),
        "NS",
        ns_names.len(),
        ns_names.join(", ")
    );
    if ns_names.len() < 2 {
        println!(
            "{}{:<11} only one name server — a single failure takes the whole domain offline (RFC 1034 asks for at least two)",
            mark(&p, Mark::Warn),
            "REDUNDANCY"
        );
    }

    // ── interrogate each server in parallel ─────────────────────────────────
    let checks = ns_names
        .iter()
        .map(|ns| check_one(ns.clone(), domain.to_string(), timeout_ms));
    let results: Vec<NsResult> = futures::future::join_all(checks).await;

    println!();
    println!(
        "{}",
        p.bold(&format!(
            "{:<28} {:<16} {:<6} {:<11} {}",
            "NAME SERVER", "ADDRESS", "AUTH", "SERIAL", "NOTES"
        ))
    );
    for r in &results {
        let addr = r.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into());
        let auth = if !r.reachable {
            p.red("down")
        } else if r.authoritative {
            p.green("yes")
        } else {
            p.yellow("no")
        };
        let serial = r.serial.map(|s| s.to_string()).unwrap_or_else(|| "-".into());
        let mut notes = Vec::new();
        if r.recursive {
            notes.push(p.red("OPEN RESOLVER"));
        }
        if !r.tcp && r.reachable {
            notes.push(p.yellow("no TCP/53"));
        }
        if !r.edns && r.reachable {
            notes.push(p.yellow("no EDNS"));
        }
        if let Some(n) = r.axfr {
            notes.push(p.red(&format!("AXFR ALLOWED ({n} records)")));
        }
        if let Some(v) = &r.version {
            notes.push(p.dim(v));
        }
        println!(
            "{:<28} {:<16} {:<6} {:<11} {}",
            truncate(&r.name, 27),
            truncate(&addr, 15),
            auth,
            serial,
            notes.join(", ")
        );
    }

    // ── cross-server consistency ────────────────────────────────────────────
    println!();
    let reachable: Vec<&NsResult> = results.iter().filter(|r| r.reachable).collect();
    if reachable.is_empty() {
        println!("{}{:<11} no name server answered", mark(&p, Mark::Bad), "REACHABLE");
        return;
    }

    // Five independent authoritative servers that are all simultaneously lame
    // *and* open resolvers is not a real configuration — it is the signature of
    // something on the path answering DNS on their behalf (a captive portal,
    // a corporate resolver, an ISP redirect). Say so rather than reporting a
    // page of alarming findings that belong to the network, not the domain.
    let intercepted = reachable.len() > 1
        && reachable.iter().all(|r| !r.authoritative && r.recursive);
    if intercepted {
        println!(
            "{}{:<11} every server answered non-authoritatively *and* recursed — this network is \n{:<16}intercepting DNS, so the per-server results below describe the interceptor, not the domain.",
            mark(&p, Mark::Warn),
            "INTERCEPTED",
            ""
        );
        println!(
            "{:<16}{}",
            "",
            p.dim("Re-run from a network without a transparent DNS proxy for meaningful results.")
        );
        println!();
    }
    if reachable.len() < results.len() {
        let down: Vec<&str> = results
            .iter()
            .filter(|r| !r.reachable)
            .map(|r| r.name.as_str())
            .collect();
        println!(
            "{}{:<11} {} of {} name servers did not answer: {}",
            mark(&p, Mark::Bad),
            "REACHABLE",
            down.len(),
            results.len(),
            down.join(", ")
        );
    } else {
        println!(
            "{}{:<11} all {} name servers answered",
            mark(&p, Mark::Ok),
            "REACHABLE",
            results.len()
        );
    }

    // A serial mismatch means the secondaries have not caught up with the
    // primary — the classic cause of "it works for some people".
    let mut serials: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
    for r in &reachable {
        if let Some(s) = r.serial {
            serials.entry(s).or_default().push(&r.name);
        }
    }
    match serials.len() {
        0 => {}
        1 => println!(
            "{}{:<11} all servers agree on SOA serial {}",
            mark(&p, Mark::Ok),
            "SERIAL",
            serials.keys().next().unwrap()
        ),
        _ => {
            println!(
                "{}{:<11} servers disagree on the SOA serial — zone transfers are lagging or broken",
                mark(&p, Mark::Bad),
                "SERIAL"
            );
            for (serial, hosts) in &serials {
                println!("{:<16}{} {}", "", p.dim(&format!("{serial}:")), hosts.join(", "));
            }
        }
    }

    let non_auth: Vec<&str> = reachable
        .iter()
        .filter(|r| !r.authoritative)
        .map(|r| r.name.as_str())
        .collect();
    if !non_auth.is_empty() && !intercepted {
        println!(
            "{}{:<11} listed as authoritative but did not set the AA flag: {} (lame delegation)",
            mark(&p, Mark::Bad),
            "LAME",
            non_auth.join(", ")
        );
    } else if !intercepted {
        println!(
            "{}{:<11} every server answers authoritatively",
            mark(&p, Mark::Ok),
            "DELEGATION"
        );
    }

    let open: Vec<&str> = reachable
        .iter()
        .filter(|r| r.recursive)
        .map(|r| r.name.as_str())
        .collect();
    if !open.is_empty() && !intercepted {
        println!(
            "{}{:<11} {} recurse for strangers — usable for cache poisoning and DNS amplification",
            mark(&p, Mark::Bad),
            "RECURSION",
            open.join(", ")
        );
    } else if !intercepted {
        println!(
            "{}{:<11} no server recurses for third parties",
            mark(&p, Mark::Ok),
            "RECURSION"
        );
    }

    let leaky: Vec<&str> = reachable
        .iter()
        .filter(|r| r.axfr.is_some())
        .map(|r| r.name.as_str())
        .collect();
    if !leaky.is_empty() {
        println!(
            "{}{:<11} {} allowed a full zone transfer to an unauthenticated client",
            mark(&p, Mark::Bad),
            "AXFR",
            leaky.join(", ")
        );
    } else {
        println!("{}{:<11} zone transfers refused", mark(&p, Mark::Ok), "AXFR");
    }

    // Name servers all inside one network are a shared failure domain.
    let networks: Vec<String> = reachable
        .iter()
        .filter_map(|r| r.ip)
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Some(format!("{}.{}.{}", o[0], o[1], o[2]))
            }
            IpAddr::V6(_) => None,
        })
        .collect();
    if networks.len() > 1 {
        let distinct: std::collections::HashSet<&String> = networks.iter().collect();
        if distinct.len() == 1 {
            println!(
                "{}{:<11} every name server is in the same /24 — no protection against a network-level outage",
                mark(&p, Mark::Warn),
                "DIVERSITY"
            );
        } else {
            println!(
                "{}{:<11} name servers span {} distinct networks",
                mark(&p, Mark::Ok),
                "DIVERSITY",
                distinct.len()
            );
        }
    }

    // ── DNSSEC posture ──────────────────────────────────────────────────────
    let ds_qt = dns::type_to_num("DS").unwrap();
    let dnskey_qt = dns::type_to_num("DNSKEY").unwrap();
    let (ds, dnskey) = futures::join!(
        dns::query(resolver, domain, ds_qt, false, timeout_ms),
        dns::query(resolver, domain, dnskey_qt, false, timeout_ms)
    );
    let has_ds = matches!(&ds, Ok(r) if r.answers.iter().any(|a| a.rtype == 43));
    let has_key = matches!(&dnskey, Ok(r) if r.answers.iter().any(|a| a.rtype == 48));
    match (has_ds, has_key) {
        (true, true) => println!(
            "{}{:<11} signed, and the parent publishes a DS record — the chain of trust is complete",
            mark(&p, Mark::Ok),
            "DNSSEC"
        ),
        // Keys without a DS means the zone is signed but nothing validates it.
        (false, true) => println!(
            "{}{:<11} zone is signed but the parent publishes no DS — validators cannot verify it",
            mark(&p, Mark::Warn),
            "DNSSEC"
        ),
        (true, false) => println!(
            "{}{:<11} parent publishes a DS but the zone has no DNSKEY — validation will FAIL",
            mark(&p, Mark::Bad),
            "DNSSEC"
        ),
        (false, false) => println!("{}{:<11} not signed", mark(&p, Mark::Info), "DNSSEC"),
    }

    if verbosity >= 1 {
        println!();
        println!(
            "{}",
            p.dim(
                "AXFR, recursion and version checks query only the name servers this domain \
                 publishes. Run them against infrastructure you are authorised to test."
            )
        );
    }
}

/// Ask one name server about itself. Every question goes to that server
/// directly rather than through a resolver, which is the only way to learn
/// whether *it* is healthy rather than whether the cache is.
async fn check_one(name: String, zone: String, timeout_ms: u64) -> NsResult {
    let mut result = NsResult {
        name: name.clone(),
        ip: None,
        reachable: false,
        authoritative: false,
        serial: None,
        recursive: false,
        edns: false,
        tcp: false,
        version: None,
        axfr: None,
    };

    let Some(addr) = tokio::net::lookup_host((name.as_str(), 53))
        .await
        .ok()
        .and_then(|mut it| it.next())
    else {
        return result;
    };
    result.ip = Some(addr.ip());
    let server = SocketAddr::new(addr.ip(), 53);

    // SOA with RD cleared: the AA flag in the reply is what proves this server
    // really is authoritative for the zone rather than just caching it.
    let soa_qt = dns::type_to_num("SOA").unwrap();
    let opts = QueryOpts { timeout_ms, no_recurse: true, udp_size: 1232, ..Default::default() };
    if let Ok(resp) = dns::query_opts(server, &zone, soa_qt, &opts).await {
        result.reachable = true;
        result.authoritative = resp.aa;
        result.edns = resp.additionals.iter().any(|r| r.rtype == 41);
        result.serial = resp.answers.iter().find_map(|r| match &r.data {
            RData::Soa { serial, .. } => Some(*serial),
            _ => None,
        });
    }
    if !result.reachable {
        return result;
    }

    // Does it recurse for a name it is not authoritative for? A "yes" here is
    // an open resolver, whatever the server thinks it is configured as.
    let a_qt = dns::type_to_num("A").unwrap();
    let rec_opts = QueryOpts { timeout_ms, no_recurse: false, udp_size: 1232, ..Default::default() };
    if let Ok(resp) = dns::query_opts(server, "www.google.com", a_qt, &rec_opts).await {
        result.recursive = resp.ra && !resp.answers.is_empty() && resp.rcode == 0;
    }

    // TCP/53 must work: it is required for large answers and for DNSSEC, and
    // firewalls that allow only UDP break both.
    let tcp_opts = QueryOpts { timeout_ms, force_tcp: true, no_recurse: true, ..Default::default() };
    result.tcp = dns::query_opts(server, &zone, soa_qt, &tcp_opts).await.is_ok();

    // version.bind, the same CHAOS TXT question the port scanner asks.
    let txt_qt = 16u16;
    let ver_opts = QueryOpts { timeout_ms, no_recurse: true, udp_size: 0, ..Default::default() };
    if let Ok(resp) = dns::query_chaos(server, "version.bind", txt_qt, &ver_opts).await {
        if let Some(RData::Txt(parts)) = resp.answers.first().map(|r| &r.data) {
            let v = parts.concat();
            if !v.is_empty() {
                result.version = Some(v.chars().take(40).collect());
            }
        }
    }

    // And the big one: will it hand over the zone?
    if let Ok(records) = dns::axfr(server, &zone, timeout_ms).await {
        result.axfr = Some(records.len());
    }

    result
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}
