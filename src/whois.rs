//! A from-scratch WHOIS client (RFC 3912).
//!
//! WHOIS is a trivial line protocol: connect to a server on TCP/43, send the
//! query followed by CRLF, and read the plain-text answer until the server
//! closes the connection. The only real work is *finding the right server*:
//! we ask IANA (whois.iana.org) which registry is authoritative, follow its
//! `refer:` (domains) or `whois:` (IP allocations) pointer, and then follow the
//! registrar referral for the fullest record. No external crates.

use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::output::Painter;

const IANA: &str = "whois.iana.org";

/// Fallback WHOIS server for common TLDs, used when the IANA referral is
/// unavailable (e.g. TCP/43 to IANA is blocked or slow).
fn default_tld_server(tld: &str) -> Option<&'static str> {
    Some(match tld.to_ascii_lowercase().as_str() {
        "com" | "net" => "whois.verisign-grs.com",
        "org" => "whois.pir.org",
        "info" => "whois.afilias.net",
        "biz" => "whois.nic.biz",
        "io" => "whois.nic.io",
        "co" => "whois.nic.co",
        "me" => "whois.nic.me",
        "dev" | "app" | "page" => "whois.nic.google",
        "xyz" => "whois.nic.xyz",
        "ai" => "whois.nic.ai",
        "us" => "whois.nic.us",
        "uk" => "whois.nic.uk",
        "de" => "whois.denic.de",
        "fr" => "whois.nic.fr",
        "es" => "whois.nic.es",
        "eu" => "whois.eu",
        "ru" | "su" => "whois.tcinet.ru",
        "nl" => "whois.domain-registry.nl",
        "ca" => "whois.cira.ca",
        "au" => "whois.auda.org.au",
        "jp" => "whois.jprs.jp",
        "br" => "whois.registro.br",
        "it" => "whois.nic.it",
        "pl" => "whois.dns.pl",
        "tv" => "whois.nic.tv",
        "cc" => "whois.nic.cc",
        "in" => "whois.registry.in",
        "cn" => "whois.cnnic.cn",
        _ => return None,
    })
}

/// Send one WHOIS query to `server` (port 43) and return the full response.
async fn ask(server: &str, query: &str, timeout_ms: u64) -> Result<String, String> {
    let dur = Duration::from_millis(timeout_ms.max(3000));
    let mut stream = timeout(dur, TcpStream::connect((server, 43)))
        .await
        .map_err(|_| format!("connect to {server}:43 timed out"))?
        .map_err(|e| format!("connect to {server}:43 failed: {e}"))?;

    stream
        .write_all(format!("{query}\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match timeout(dur, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => out.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => break, // read timeout — return whatever we have
        }
        if out.len() > 1_000_000 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

/// First value for any of the given case-insensitive field keys.
fn field(text: &str, keys: &[&str]) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if !v.is_empty() && keys.iter().any(|key| key.eq_ignore_ascii_case(&k)) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// All values for any of the given field keys (e.g. multiple name servers).
fn fields(text: &str, keys: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if !v.is_empty() && keys.iter().any(|key| key.eq_ignore_ascii_case(&k)) {
                let val = v.to_string();
                if !out.contains(&val) {
                    out.push(val);
                }
            }
        }
    }
    out
}

/// Resolve and query WHOIS for a domain, following IANA → registry → registrar.
async fn query_domain(domain: &str, timeout_ms: u64) -> Result<String, String> {
    let tld = domain.rsplit('.').next().unwrap_or(domain);

    // 1) Ask IANA which registry owns the TLD, falling back to a built-in map.
    let registry = match ask(IANA, tld, timeout_ms).await {
        Ok(resp) => field(&resp, &["refer", "whois"]),
        Err(_) => None,
    }
    .or_else(|| default_tld_server(tld).map(String::from));

    // 2) Query the registry.
    let Some(registry) = registry else {
        return Err(format!("no WHOIS server found for .{tld}"));
    };
    let reg_resp = ask(&registry, domain, timeout_ms).await?;

    // 3) Follow the registrar referral for the richest record, if present.
    if let Some(rwhois) = field(&reg_resp, &["registrar whois server", "whois server"]) {
        if !rwhois.eq_ignore_ascii_case(&registry) {
            if let Ok(full) = ask(&rwhois, domain, timeout_ms).await {
                if full.len() > reg_resp.len() / 2 && full.contains(':') {
                    return Ok(full);
                }
            }
        }
    }
    Ok(reg_resp)
}

/// Resolve and query WHOIS for an IP address (IANA → RIR, ARIN as fallback).
async fn query_ip(ip: IpAddr, timeout_ms: u64) -> Result<String, String> {
    let q = ip.to_string();

    // Preferred: IANA tells us the responsible RIR.
    if let Ok(resp) = ask(IANA, &q, timeout_ms).await {
        if let Some(rir) = field(&resp, &["whois", "refer"]) {
            if let Ok(r) = ask(&rir, &q, timeout_ms).await {
                return Ok(follow_referral(r, &q, timeout_ms).await);
            }
        }
        if resp.contains(':') {
            return Ok(resp);
        }
    }

    // Fallback: ARIN, which returns a ReferralServer for non-ARIN space.
    let arin = ask("whois.arin.net", &q, timeout_ms).await?;
    Ok(follow_referral(arin, &q, timeout_ms).await)
}

/// If a WHOIS response points to another server (RIPE/APNIC/... via
/// `ReferralServer: whois://host`), query that server and return its record.
async fn follow_referral(resp: String, query: &str, timeout_ms: u64) -> String {
    if let Some(mut r) = field(&resp, &["referralserver"]) {
        r = r
            .trim_start_matches("whois://")
            .trim_start_matches("rwhois://")
            .split('/')
            .next()
            .unwrap_or(&r)
            .split(':')
            .next()
            .unwrap_or(&r)
            .to_string();
        if !r.is_empty() && r != "whois.arin.net" {
            if let Ok(better) = ask(&r, query, timeout_ms).await {
                if better.contains(':') {
                    return better;
                }
            }
        }
    }
    resp
}

/// Public entry point: run a WHOIS lookup for a domain or IP and print a summary
/// (plus the raw record with -v).
pub async fn run(target: &str, timeout_ms: u64, color: bool, verbosity: u8) -> bool {
    let p = Painter::new(color);
    let is_ip = target.parse::<IpAddr>().is_ok();

    println!();
    println!("{} {}", p.bold("Kaisen WHOIS for"), p.cyan(target));

    let result = if let Ok(ip) = target.parse::<IpAddr>() {
        query_ip(ip, timeout_ms).await
    } else {
        query_domain(target, timeout_ms).await
    };

    let text = match result {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", p.red(&format!("[!] {e}")));
            return false;
        }
    };

    println!();
    if is_ip {
        summarize_ip(&text, &p);
    } else {
        summarize_domain(&text, &p);
    }

    if verbosity >= 1 {
        println!();
        println!("{}", p.bold(";; RAW RECORD:"));
        for line in text.lines() {
            let l = line.trim_end();
            if l.starts_with('%') || l.starts_with('#') || l.is_empty() {
                println!("{}", p.dim(l));
            } else {
                println!("{l}");
            }
        }
    } else {
        println!("{}", p.dim("(use -v to show the full raw WHOIS record)"));
    }
    true
}

fn kv(p: &Painter, label: &str, value: &str) {
    if !value.is_empty() {
        println!("{:<20}{}", p.bold(label), value);
    }
}

fn summarize_domain(text: &str, p: &Painter) {
    kv(p, "Domain:", &field(text, &["domain name", "domain"]).unwrap_or_default());
    kv(p, "Registrar:", &field(text, &["registrar"]).unwrap_or_default());
    kv(p, "Registered:", &field(text, &["creation date", "created", "registered on", "registration time"]).unwrap_or_default());
    kv(p, "Updated:", &field(text, &["updated date", "last updated", "modified"]).unwrap_or_default());
    kv(p, "Expires:", &field(text, &["registry expiry date", "expiry date", "expires on", "paid-till", "expiration time"]).unwrap_or_default());
    kv(p, "Registrant:", &field(text, &["registrant organization", "registrant", "org", "organization"]).unwrap_or_default());
    kv(p, "Country:", &field(text, &["registrant country", "country"]).unwrap_or_default());

    let status = fields(text, &["domain status", "status"]);
    if !status.is_empty() {
        kv(p, "Status:", &status.join(", "));
    }
    let ns = fields(text, &["name server", "nserver"]);
    if !ns.is_empty() {
        println!("{}", p.bold("Name servers:"));
        for n in ns {
            println!("  - {}", n.split_whitespace().next().unwrap_or(&n).to_ascii_lowercase());
        }
    }
    let dnssec = field(text, &["dnssec"]).unwrap_or_default();
    kv(p, "DNSSEC:", &dnssec);
}

fn summarize_ip(text: &str, p: &Painter) {
    kv(p, "Range:", &field(text, &["inetnum", "netrange", "cidr", "inet6num"]).unwrap_or_default());
    kv(p, "Network:", &field(text, &["netname", "network-name"]).unwrap_or_default());
    kv(p, "Organization:", &field(text, &["org-name", "orgname", "organisation", "descr", "owner"]).unwrap_or_default());
    kv(p, "Country:", &field(text, &["country"]).unwrap_or_default());
    kv(p, "Abuse contact:", &field(text, &["abuse-mailbox", "orgabuseemail", "abusecontactemail"]).unwrap_or_default());
    kv(p, "Registry:", &field(text, &["source"]).unwrap_or_default());
    kv(p, "Assigned:", &field(text, &["regdate", "created"]).unwrap_or_default());
}
