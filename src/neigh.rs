//! `kaisen neighbor <domain>` — a from-scratch `fierce`-style DNS recon tool.
//!
//! It (1) resolves the apex, (2) detects wildcard DNS, (3) brute-forces a
//! built-in subdomain list to discover live hosts, and (4) walks the reverse
//! DNS of the neighbourhood around each discovered IP to find "neighbours" —
//! other hostnames sharing the same address space. All plain DNS, unprivileged.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use futures::stream::{self, StreamExt};

use crate::dns::{self, RData};
use crate::output::Painter;

/// Common subdomain labels to probe.
const SUBDOMAINS: &[&str] = &[
    "www", "mail", "smtp", "pop", "pop3", "imap", "webmail", "ns1", "ns2", "ns3",
    "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "ftp", "sftp", "ssh", "vpn",
    "remote", "gateway", "gw", "router", "portal", "admin", "administrator",
    "cpanel", "whm", "webdisk", "autodiscover", "autoconfig", "dev", "development",
    "staging", "stage", "test", "testing", "qa", "uat", "demo", "sandbox", "beta",
    "alpha", "preview", "api", "api1", "api2", "apis", "app", "apps", "mobile", "m",
    "wap", "cdn", "cdn1", "cdn2", "static", "assets", "img", "images", "media",
    "video", "files", "download", "downloads", "upload", "uploads", "docs", "wiki",
    "blog", "news", "forum", "forums", "community", "support", "help", "helpdesk",
    "status", "monitor", "monitoring", "grafana", "kibana", "prometheus", "jenkins",
    "ci", "cd", "git", "gitlab", "svn", "jira", "confluence", "nexus", "registry",
    "docker", "k8s", "kube", "rancher", "db", "database", "sql", "mysql", "postgres",
    "mongo", "redis", "cache", "search", "elastic", "es", "ldap", "ad", "auth", "sso",
    "login", "id", "identity", "accounts", "account", "billing", "pay", "payment",
    "payments", "shop", "store", "cart", "checkout", "secure", "ssl", "vault",
    "proxy", "lb", "loadbalancer", "edge", "origin", "internal", "intranet", "extranet",
    "partner", "partners", "client", "clients", "customer", "crm", "erp", "hr",
    "mail2", "email", "exchange", "owa", "lyncdiscover", "sip", "voip", "pbx",
    "conf", "meet", "chat", "im", "xmpp", "irc", "old", "new", "backup", "bak",
    "archive", "legacy", "temp", "tmp", "web", "web1", "web2", "server", "srv",
    "host", "cloud", "s3", "storage", "data", "analytics", "stats", "metrics",
    "dashboard", "panel", "console", "manage", "management", "office", "corp",
];

/// Read an optional cap from an environment variable. Accepts a positive
/// integer, or "all"/"0" meaning "no limit" (returns `usize::MAX`). Falls back
/// to `default` when the variable is unset, empty, or unparseable.
fn env_cap(var: &str, default: usize) -> usize {
    match std::env::var(var) {
        Ok(v) => {
            let v = v.trim();
            if v.is_empty() {
                default
            } else if v.eq_ignore_ascii_case("all") || v == "0" {
                usize::MAX
            } else {
                v.parse::<usize>().unwrap_or(default)
            }
        }
        Err(_) => default,
    }
}

/// Recognise generic CDN/cloud reverse-DNS names (auto-generated per IP) so we
/// can collapse them instead of flooding the output with a whole provider /24.
fn cdn_provider(host: &str) -> Option<&'static str> {
    const PROVIDERS: &[(&str, &str)] = &[
        ("akamaitechnologies.com", "Akamai"),
        ("akamaiedge.net", "Akamai"),
        ("akamai.net", "Akamai"),
        ("edgekey.net", "Akamai"),
        ("edgesuite.net", "Akamai"),
        ("cloudfront.net", "CloudFront"),
        ("amazonaws.com", "AWS"),
        ("cloudflare.com", "Cloudflare"),
        ("cloudflare.net", "Cloudflare"),
        ("googleusercontent.com", "Google"),
        ("1e100.net", "Google"),
        ("cloudapp.azure.com", "Azure"),
        ("cloudapp.net", "Azure"),
        ("fastly.net", "Fastly"),
        ("fastlylb.net", "Fastly"),
        ("incapdns.net", "Imperva"),
        ("stackpathdns.com", "StackPath"),
        ("cdn77.org", "CDN77"),
        ("llnwd.net", "Limelight"),
        ("footprint.net", "CenturyLink"),
        ("azureedge.net", "Azure"),
        ("azurefd.net", "Azure"),
        ("digitalocean.com", "DigitalOcean"),
        ("linode.com", "Linode"),
        ("hetzner.com", "Hetzner"),
        ("ovh.net", "OVH"),
    ];
    let h = host.to_ascii_lowercase();
    PROVIDERS
        .iter()
        .find(|(suf, _)| h.ends_with(suf))
        .map(|(_, name)| *name)
}

async fn resolve_a(server: SocketAddr, name: &str, timeout_ms: u64) -> BTreeSet<Ipv4Addr> {
    let qt = dns::type_to_num("A").unwrap();
    let mut out = BTreeSet::new();
    if let Ok(resp) = dns::query(server, name, qt, false, timeout_ms).await {
        for a in resp.answers {
            if let RData::A(ip) = a.data {
                out.insert(ip);
            }
        }
    }
    out
}

async fn reverse_ptr(server: SocketAddr, ip: Ipv4Addr, timeout_ms: u64) -> Option<String> {
    let name = dns::reverse_name(IpAddr::V4(ip));
    let qt = dns::type_to_num("PTR").unwrap();
    if let Ok(resp) = dns::query(server, &name, qt, false, timeout_ms).await {
        for a in resp.answers {
            if let RData::Name(n) = a.data {
                return Some(n.trim_end_matches('.').to_string());
            }
        }
    }
    None
}

pub async fn run(
    domain: &str,
    server: SocketAddr,
    timeout_ms: u64,
    color: bool,
    concurrency: usize,
) {
    let p = Painter::new(color);
    let domain = domain.trim_end_matches('.');
    // Keep DNS recon gentle: bursting hundreds of concurrent UDP queries at a
    // public resolver invites rate-limiting and packet loss (false negatives).
    let conc = concurrency.clamp(1, 32);

    println!();
    println!(
        "{} {} {}",
        p.bold("Kaisen neighbor recon for"),
        p.cyan(domain),
        p.dim(&format!("(via {})", server.ip()))
    );

    // 1) Apex.
    let apex = resolve_a(server, domain, timeout_ms).await;
    if apex.is_empty() {
        println!("{}", p.yellow("Apex has no A record (or could not resolve)."));
    } else {
        let ips = apex.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
        println!("{:<12}{} -> {}", p.bold("Apex:"), domain, ips);
    }

    // 2) Wildcard detection: does a random label resolve?
    let rnd = format!("kaisen-{}-wc.{}", std::process::id(), domain);
    let wildcard = resolve_a(server, &rnd, timeout_ms).await;
    if !wildcard.is_empty() {
        let ips = wildcard.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
        println!(
            "{} {}",
            p.yellow("[wildcard]"),
            p.dim(&format!("*.{domain} resolves to {ips} — results matching only these are filtered"))
        );
    }

    // 3) Brute-force subdomains.
    println!();
    println!("{}", p.bold(&format!("Probing {} subdomains...", SUBDOMAINS.len())));

    let found: Vec<(String, BTreeSet<Ipv4Addr>)> = stream::iter(SUBDOMAINS.iter())
        .map(|sub| {
            let fqdn = format!("{sub}.{domain}");
            async move {
                let ips = resolve_a(server, &fqdn, timeout_ms).await;
                (fqdn, ips)
            }
        })
        .buffer_unordered(conc)
        .filter_map(|(fqdn, ips)| async move {
            if ips.is_empty() {
                None
            } else {
                Some((fqdn, ips))
            }
        })
        .collect()
        .await;

    // Filter out pure-wildcard matches.
    let mut subs: Vec<(String, BTreeSet<Ipv4Addr>)> = found
        .into_iter()
        .filter(|(_, ips)| wildcard.is_empty() || !ips.is_subset(&wildcard))
        .collect();
    subs.sort_by(|a, b| a.0.cmp(&b.0));

    if subs.is_empty() {
        println!("{}", p.yellow("No subdomains discovered from the built-in list."));
    } else {
        println!("{}", p.bold(&format!("Subdomains found ({}):", subs.len())));
        for (fqdn, ips) in &subs {
            let ipss = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
            println!("  {:<34} -> {}", p.green(fqdn), ipss);
        }
    }

    // 4) Neighbourhood reverse DNS. Collect unique /24s from apex + subs.
    let mut subnets: BTreeSet<[u8; 3]> = BTreeSet::new();
    let mut all_ips: BTreeSet<Ipv4Addr> = apex.clone();
    for (_, ips) in &subs {
        all_ips.extend(ips.iter().copied());
    }
    for ip in &all_ips {
        let o = ip.octets();
        subnets.insert([o[0], o[1], o[2]]);
    }
    // Cap how many /24s we scan (e.g. CDN-spread records). Default 2; override
    // with KAISEN_NEIGH_SUBNETS (a number, or "all"/"0" for every discovered /24).
    let subnet_cap = env_cap("KAISEN_NEIGH_SUBNETS", 2);
    let capped: Vec<[u8; 3]> = subnets.into_iter().take(subnet_cap).collect();

    if !capped.is_empty() {
        println!();
        println!(
            "{}",
            p.bold(&format!(
                "Neighbours (reverse DNS of {} nearby /24 range(s)):",
                capped.len()
            ))
        );

        let targets: Vec<Ipv4Addr> = capped
            .iter()
            .flat_map(|s| (1u16..=254).map(move |h| Ipv4Addr::new(s[0], s[1], s[2], h as u8)))
            .collect();

        let neighbours: Vec<(Ipv4Addr, String)> = stream::iter(targets.into_iter())
            .map(|ip| async move { (ip, reverse_ptr(server, ip, timeout_ms).await) })
            .buffer_unordered(conc)
            .filter_map(|(ip, name)| async move { name.map(|n| (ip, n)) })
            .collect()
            .await;

        let mut sorted: BTreeMap<Ipv4Addr, String> = BTreeMap::new();
        for (ip, n) in neighbours {
            sorted.insert(ip, n);
        }

        if sorted.is_empty() {
            println!("{}", p.dim("  (no PTR records in the neighbouring range)"));
        } else {
            let root = domain.rsplitn(3, '.').take(2).collect::<Vec<_>>();
            let root_suffix = root.into_iter().rev().collect::<Vec<_>>().join(".");

            // Categorise: same-domain neighbours (gold), other notable hosts, and
            // generic CDN/cloud auto-PTRs (noise we collapse into a count).
            let mut related: Vec<(Ipv4Addr, String)> = Vec::new();
            let mut other: Vec<(Ipv4Addr, String)> = Vec::new();
            let mut cdn: BTreeMap<&'static str, usize> = BTreeMap::new();
            for (ip, name) in sorted {
                if name.ends_with(&root_suffix) {
                    related.push((ip, name));
                } else if let Some(prov) = cdn_provider(&name) {
                    *cdn.entry(prov).or_insert(0) += 1;
                } else {
                    other.push((ip, name));
                }
            }

            if related.is_empty() && other.is_empty() {
                println!("{}", p.dim("  (only generic CDN/cloud PTRs in range — see summary below)"));
            }
            for (ip, name) in &related {
                println!("  {:<16} {}", ip, p.cyan(name));
            }
            // How many "other" neighbours to print. Default 40; override with
            // KAISEN_NEIGH_MAX (a number, or "all"/"0" to print every one).
            let max_other = env_cap("KAISEN_NEIGH_MAX", 40);
            for (ip, name) in other.iter().take(max_other) {
                println!("  {:<16} {}", ip, name);
            }
            if other.len() > max_other {
                println!(
                    "{}",
                    p.dim(&format!(
                        "  ... and {} more (set KAISEN_NEIGH_MAX=all to show them)",
                        other.len() - max_other
                    ))
                );
            }
            if !cdn.is_empty() {
                let summary = cdn
                    .iter()
                    .map(|(prov, n)| format!("{prov} ({n})"))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "{}",
                    p.dim(&format!("  [hidden] {summary} — generic CDN/cloud auto-PTRs"))
                );
            }
        }
    }

    println!();
    println!(
        "{}",
        p.dim("Note: only passive DNS is used. Discovery is limited to the built-in wordlist and \
               PTR coverage of the neighbouring ranges.")
    );
}
