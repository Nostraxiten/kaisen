//! `kaisen mail <domain>` — one-shot email posture audit.
//!
//! Queries the domain's mail-related DNS records (MX, SPF, DMARC, DKIM, CAA,
//! MTA-STS, TLS-RPT), interprets them, and prints a checklist with a verdict.
//! Everything is plain DNS, so it runs unprivileged anywhere.

use std::net::SocketAddr;

use crate::dns::{self, RData};
use crate::util::output::Painter;

/// DKIM selectors we can't enumerate from DNS, so we probe the common ones used
/// by popular mail providers.
const DKIM_SELECTORS: &[&str] = &[
    // Generic and self-hosted conventions.
    "default",
    "dkim",
    "mail",
    "smtp",
    "key1",
    "key2",
    "s1",
    "s2",
    "s1024",
    "s2048",
    "selector",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "k3",
    "dkim1",
    "dkim2",
    "mx",
    "email",
    "10",
    "20",
    "2020",
    "2021",
    "2022",
    "2023",
    "2024",
    "2025",
    // Google Workspace and Microsoft 365.
    "google",
    "20161025",
    "20210112",
    "20230601",
    // Common SaaS senders.
    "mandrill",
    "mailjet",
    "sendgrid",
    "s1._domainkey",
    "sparkpost",
    "scph0819",
    "amazonses",
    "ses",
    "postmark",
    "pm",
    "mailchimp",
    "mc1",
    "mc2",
    "cm",
    "sendinblue",
    "sib",
    "klaviyo",
    "hs1",
    "hs2",
    "hubspot",
    "zendesk1",
    "zendesk2",
    "freshdesk",
    "intercom",
    "mixmax",
    "front",
    "helpscout",
    // Mailbox providers.
    "protonmail",
    "protonmail2",
    "protonmail3",
    "fm1",
    "fm2",
    "fm3",
    "zoho",
    "zohomail",
    "yandex",
    "mail-ru",
    "titan1",
    "titan2",
    "migadu",
    "everlytickey1",
    "everlytickey2",
    "mxvault",
    "dyn",
    "ctct1",
    "ctct2",
];

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

/// Collect the concatenated TXT strings from a response's answer section.
async fn txt_lookup(server: SocketAddr, name: &str, timeout_ms: u64) -> Vec<String> {
    let qt = dns::type_to_num("TXT").unwrap();
    match dns::query(server, name, qt, false, timeout_ms).await {
        Ok(resp) => resp
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::Txt(parts) => Some(parts.concat()),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Count the DNS lookups an SPF record costs. RFC 7208 caps this at 10, and
/// exceeding it makes evaluation return PERMERROR — which in practice means
/// legitimate mail starts failing SPF, silently, once a provider grows its
/// own include chain. It is the single most common way a valid-looking SPF
/// record stops working, and nothing in the record itself shows it.
async fn spf_lookup_count(
    server: SocketAddr,
    record: &str,
    timeout_ms: u64,
    depth: u8,
    seen: &mut Vec<String>,
) -> (u32, Vec<String>) {
    let mut count = 0u32;
    let mut notes = Vec::new();
    if depth > 5 {
        return (count, notes);
    }

    for term in record.split_whitespace() {
        let term = term.trim_start_matches(['+', '~', '-', '?']);
        let lower = term.to_ascii_lowercase();
        // These mechanisms each cost one DNS lookup; ip4/ip6/all cost none.
        let target = if let Some(t) = lower.strip_prefix("include:") {
            count += 1;
            Some(t.to_string())
        } else if let Some(t) = lower.strip_prefix("redirect=") {
            count += 1;
            Some(t.to_string())
        } else if lower.starts_with("a:") || lower == "a" || lower.starts_with("a/") {
            count += 1;
            None
        } else if lower.starts_with("mx:") || lower == "mx" || lower.starts_with("mx/") {
            count += 1;
            None
        } else if lower.starts_with("exists:") {
            count += 1;
            None
        } else if lower == "ptr" || lower.starts_with("ptr:") {
            count += 1;
            notes.push("uses the deprecated 'ptr' mechanism".to_string());
            None
        } else {
            None
        };

        if let Some(domain) = target {
            if seen.contains(&domain) {
                continue;
            }
            seen.push(domain.clone());
            let nested = txt_lookup(server, &domain, timeout_ms).await;
            if let Some(rec) = nested
                .iter()
                .find(|t| t.to_ascii_lowercase().starts_with("v=spf1"))
            {
                let (sub, sub_notes) =
                    Box::pin(spf_lookup_count(server, rec, timeout_ms, depth + 1, seen)).await;
                count += sub;
                notes.extend(sub_notes);
            } else if !domain.contains('%') {
                notes.push(format!(
                    "include:{domain} has no SPF record (evaluates to PERMERROR)"
                ));
            }
        }
    }
    (count, notes)
}

/// Connect to a mail exchanger and find out what it actually offers: the
/// greeting names the software, and EHLO says whether the server is willing
/// to encrypt at all. DNS alone cannot answer either question.
async fn probe_mx(host: &str, timeout_ms: u64) -> Option<(String, bool, Vec<String>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dur = std::time::Duration::from_millis(timeout_ms.max(3000));
    let addr = tokio::net::lookup_host((host, 25)).await.ok()?.next()?;
    let mut stream = tokio::time::timeout(dur, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(dur, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    let banner = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(100)
        .collect::<String>();

    tokio::time::timeout(dur, stream.write_all(b"EHLO kaisen.probe\r\n"))
        .await
        .ok()?
        .ok()?;
    let mut ehlo = String::new();
    for _ in 0..4 {
        match tokio::time::timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                ehlo.push_str(&String::from_utf8_lossy(&buf[..n]));
                if ehlo.contains("250 ") {
                    break;
                }
            }
            _ => break,
        }
    }
    let _ = tokio::time::timeout(dur, stream.write_all(b"QUIT\r\n")).await;

    let upper = ehlo.to_ascii_uppercase();
    let starttls = upper.contains("STARTTLS");
    let mut caps = Vec::new();
    for cap in [
        "STARTTLS",
        "AUTH",
        "8BITMIME",
        "SMTPUTF8",
        "PIPELINING",
        "DSN",
        "CHUNKING",
    ] {
        if upper.contains(cap) {
            caps.push(cap.to_string());
        }
    }
    Some((banner, starttls, caps))
}

/// DANE: a TLSA record under _25._tcp.<mx> binds the mail server's
/// certificate, so a sending MTA can refuse a downgraded or substituted one.
async fn dane_for_mx(server: SocketAddr, mx: &str, timeout_ms: u64) -> usize {
    let qt = dns::type_to_num("TLSA").unwrap();
    let name = format!("_25._tcp.{}", mx.trim_end_matches('.'));
    match dns::query(server, &name, qt, false, timeout_ms).await {
        Ok(resp) => resp.answers.iter().filter(|r| r.rtype == 52).count(),
        Err(_) => 0,
    }
}

/// Run the audit. Returns true if at least one query succeeded (host reachable).
pub async fn audit(domain: &str, server: SocketAddr, timeout_ms: u64, color: bool, verbosity: u8) {
    let p = Painter::new(color);
    let domain = domain.trim_end_matches('.');
    let mut mx_hosts: Vec<String> = Vec::new();

    println!();
    println!(
        "{} {} {}",
        p.bold("Kaisen mail audit for"),
        p.cyan(domain),
        p.dim(&format!("(via {})", server.ip()))
    );
    println!();

    let mut passed = 0usize;
    let mut warnings = 0usize;
    let mut fails = 0usize;

    // ── MX ──────────────────────────────────────────────────────────────────
    let mx_qt = dns::type_to_num("MX").unwrap();
    let mx = dns::query(server, domain, mx_qt, false, timeout_ms).await;
    let mut has_mail = true;
    match &mx {
        Ok(resp) if !resp.answers.is_empty() => {
            let mut hosts: Vec<(u16, String)> = resp
                .answers
                .iter()
                .filter_map(|r| match &r.data {
                    RData::Mx { pref, exchange } => Some((*pref, exchange.clone())),
                    _ => None,
                })
                .collect();
            hosts.sort_by_key(|(pref, _)| *pref);

            // Null MX (RFC 7505): a single "." exchange means the domain sends
            // and receives no mail on purpose.
            if hosts.len() == 1 && (hosts[0].1 == "." || hosts[0].1.is_empty()) {
                has_mail = false;
                println!(
                    "{}{:<9} null MX (0 .) — domain accepts NO email by design (RFC 7505)",
                    mark(&p, Mark::Info),
                    "MX"
                );
            } else {
                let list = hosts
                    .iter()
                    .map(|(pref, h)| format!("{pref} {h}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("{}{:<9} {}", mark(&p, Mark::Ok), "MX", list);
                passed += 1;
                mx_hosts = resp
                    .answers
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::Mx { exchange, .. } if exchange != "." => {
                            Some(exchange.trim_end_matches('.').to_string())
                        }
                        _ => None,
                    })
                    .collect();
            }
        }
        _ => {
            has_mail = false;
            println!(
                "{}{:<9} no MX records (mail, if any, would fall back to the A record)",
                mark(&p, Mark::Warn),
                "MX"
            );
            warnings += 1;
        }
    }

    // ── SPF (TXT apex, v=spf1) ───────────────────────────────────────────────
    let txts = txt_lookup(server, domain, timeout_ms).await;
    let spf = txts
        .iter()
        .find(|t| t.to_ascii_lowercase().starts_with("v=spf1"));
    match spf {
        Some(rec) => {
            let low = rec.to_ascii_lowercase();
            let (m, note) = if low.contains("-all") {
                (Mark::Ok, "hardfail (-all): strict, recommended")
            } else if low.contains("~all") {
                (Mark::Ok, "softfail (~all): acceptable")
            } else if low.contains("?all") {
                (
                    Mark::Warn,
                    "neutral (?all): weak — spoofing not discouraged",
                )
            } else if low.contains("+all") {
                (
                    Mark::Bad,
                    "pass-all (+all): anyone may send as you — misconfigured",
                )
            } else {
                (Mark::Warn, "no explicit all mechanism")
            };
            println!("{}{:<9} {}", mark(&p, m), "SPF", rec);
            println!("{:<14}{}", "", p.dim(note));
            match m {
                Mark::Ok => passed += 1,
                Mark::Bad => fails += 1,
                _ => warnings += 1,
            }

            // The RFC 7208 ten-lookup budget. Nothing in the record shows when
            // it has been blown, but evaluation returns PERMERROR when it has.
            let mut seen = Vec::new();
            let (lookups, notes) = spf_lookup_count(server, rec, timeout_ms, 0, &mut seen).await;
            if lookups > 10 {
                println!(
                    "{}{:<9} {} DNS lookups — over the RFC 7208 limit of 10, so SPF returns PERMERROR",
                    mark(&p, Mark::Bad),
                    "SPF-LIMIT",
                    lookups
                );
                fails += 1;
            } else if lookups >= 8 {
                println!(
                    "{}{:<9} {}/10 DNS lookups — close to the limit; one more include will break it",
                    mark(&p, Mark::Warn),
                    "SPF-LIMIT",
                    lookups
                );
                warnings += 1;
            } else {
                println!(
                    "{}{:<9} {}/10 DNS lookups",
                    mark(&p, Mark::Ok),
                    "SPF-LIMIT",
                    lookups
                );
                passed += 1;
            }
            for n in notes.iter().take(4) {
                println!("{:<14}{}", "", p.yellow(n));
                warnings += 1;
            }
        }
        None if txts.is_empty() => {
            // No TXT came back at all — could be truncation needing TCP/53 that
            // was blocked, not necessarily a missing SPF record.
            println!(
                "{}{:<9} apex TXT query returned nothing (large SPF may need TCP/53 — retry with +tcp)",
                mark(&p, Mark::Warn),
                "SPF"
            );
            warnings += 1;
        }
        None => {
            let m = if has_mail { Mark::Bad } else { Mark::Info };
            println!(
                "{}{:<9} no SPF record{}",
                mark(&p, m),
                "SPF",
                if has_mail {
                    " — senders can't be validated"
                } else {
                    " (no mail expected)"
                }
            );
            if has_mail {
                fails += 1;
            }
        }
    }

    // ── DMARC (_dmarc TXT, v=DMARC1) ─────────────────────────────────────────
    let dmarc_txts = txt_lookup(server, &format!("_dmarc.{domain}"), timeout_ms).await;
    let dmarc = dmarc_txts
        .iter()
        .find(|t| t.to_ascii_lowercase().starts_with("v=dmarc1"));
    match dmarc {
        Some(rec) => {
            let policy = rec
                .split(';')
                .filter_map(|kv| {
                    let kv = kv.trim();
                    kv.strip_prefix("p=").map(|v| v.trim().to_ascii_lowercase())
                })
                .next()
                .unwrap_or_default();
            let (m, note) = match policy.as_str() {
                "reject" => (Mark::Ok, "p=reject: strongest protection"),
                "quarantine" => (Mark::Ok, "p=quarantine: good"),
                "none" => (Mark::Warn, "p=none: monitor only — no enforcement"),
                _ => (Mark::Warn, "policy tag missing"),
            };
            println!("{}{:<9} {}", mark(&p, m), "DMARC", rec);
            println!("{:<14}{}", "", p.dim(note));
            match m {
                Mark::Ok => passed += 1,
                _ => warnings += 1,
            }

            // The tags that decide whether the policy actually bites.
            let tag = |name: &str| -> Option<String> {
                rec.split(';').find_map(|kv| {
                    let kv = kv.trim();
                    kv.strip_prefix(&format!("{name}="))
                        .map(|v| v.trim().to_ascii_lowercase())
                })
            };
            let mut detail = Vec::new();
            if let Some(pct) = tag("pct") {
                if pct != "100" {
                    println!(
                        "{}{:<9} pct={} — the policy is only applied to {}% of failing mail",
                        mark(&p, Mark::Warn),
                        "DMARC-PCT",
                        pct,
                        pct
                    );
                    warnings += 1;
                }
            }
            if let Some(sp) = tag("sp") {
                detail.push(format!("subdomain policy sp={sp}"));
            }
            detail.push(format!(
                "alignment: dkim={}, spf={}",
                tag("adkim").unwrap_or_else(|| "r (relaxed)".into()),
                tag("aspf").unwrap_or_else(|| "r (relaxed)".into())
            ));
            if tag("rua").is_none() {
                println!(
                    "{}{:<9} no rua= address — you receive no aggregate reports, so you cannot see what is being spoofed",
                    mark(&p, Mark::Warn),
                    "DMARC-RUA"
                );
                warnings += 1;
            } else {
                detail.push("aggregate reporting configured".into());
            }
            if !detail.is_empty() {
                println!("{:<14}{}", "", p.dim(&detail.join("; ")));
            }
        }
        None => {
            let m = if has_mail { Mark::Bad } else { Mark::Info };
            println!(
                "{}{:<9} no DMARC record{}",
                mark(&p, m),
                "DMARC",
                if has_mail {
                    " — domain is spoofable"
                } else {
                    " (no mail expected)"
                }
            );
            if has_mail {
                fails += 1;
            }
        }
    }

    // ── DKIM (probe common selectors) ────────────────────────────────────────
    let mut found: Vec<String> = Vec::new();
    let mut revoked: Vec<String> = Vec::new();
    let probes = DKIM_SELECTORS.iter().map(|sel| {
        let name = format!("{sel}._domainkey.{domain}");
        async move {
            let txts = txt_lookup(server, &name, timeout_ms).await;
            let rec = txts
                .into_iter()
                .find(|t| t.to_ascii_lowercase().contains("v=dkim1") || t.contains("p="));
            (sel.to_string(), rec)
        }
    });
    let results = futures::future::join_all(probes).await;
    for (sel, rec) in results {
        if let Some(r) = rec {
            // "p=" with nothing after it means a revoked/empty key.
            let empty_key = r.replace(' ', "").contains("p=;") || r.trim_end().ends_with("p=");
            if empty_key {
                revoked.push(sel);
            } else {
                found.push(sel);
            }
        }
    }
    let cap = |list: &[String]| {
        if list.len() > 8 {
            format!("{}, +{} more", list[..8].join(", "), list.len() - 8)
        } else {
            list.join(", ")
        }
    };
    if !found.is_empty() {
        println!(
            "{}{:<9} selector(s) found: {}",
            mark(&p, Mark::Ok),
            "DKIM",
            cap(&found)
        );
        passed += 1;
    } else if revoked.len() >= DKIM_SELECTORS.len() / 2 {
        // Every probed selector resolves to an empty key -> a wildcard
        // "*._domainkey" record with p= (an explicit "no DKIM keys" policy).
        println!(
            "{}{:<9} wildcard/empty DKIM (v=DKIM1; p=) — no active signing keys",
            mark(&p, Mark::Info),
            "DKIM"
        );
    } else if !revoked.is_empty() {
        println!(
            "{}{:<9} only revoked/empty selector(s): {}",
            mark(&p, Mark::Warn),
            "DKIM",
            cap(&revoked)
        );
        warnings += 1;
    } else {
        println!(
            "{}{:<9} no DKIM found for common selectors (may use a custom one)",
            mark(&p, if has_mail { Mark::Warn } else { Mark::Info }),
            "DKIM"
        );
        if has_mail {
            warnings += 1;
        }
    }

    // ── MTA-STS & TLS-RPT ────────────────────────────────────────────────────
    let mta = txt_lookup(server, &format!("_mta-sts.{domain}"), timeout_ms).await;
    if mta
        .iter()
        .any(|t| t.to_ascii_lowercase().contains("v=stsv1"))
    {
        println!(
            "{}{:<9} enabled (enforces TLS for inbound mail)",
            mark(&p, Mark::Ok),
            "MTA-STS"
        );
        passed += 1;
    } else if has_mail {
        println!("{}{:<9} not configured", mark(&p, Mark::Warn), "MTA-STS");
        warnings += 1;
    }

    let tlsrpt = txt_lookup(server, &format!("_smtp._tls.{domain}"), timeout_ms).await;
    if tlsrpt
        .iter()
        .any(|t| t.to_ascii_lowercase().contains("v=tlsrptv1"))
    {
        println!(
            "{}{:<9} enabled (TLS failure reporting)",
            mark(&p, Mark::Ok),
            "TLS-RPT"
        );
        passed += 1;
    } else if has_mail && verbosity >= 1 {
        println!("{}{:<9} not configured", mark(&p, Mark::Info), "TLS-RPT");
    }

    // ── DANE / TLSA on each MX ───────────────────────────────────────────────
    if !mx_hosts.is_empty() {
        let checks = mx_hosts
            .iter()
            .take(4)
            .map(|mx| async move { (mx.clone(), dane_for_mx(server, mx, timeout_ms).await) });
        let results = futures::future::join_all(checks).await;
        let with_dane: Vec<&String> = results
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(m, _)| m)
            .collect();
        if with_dane.len() == results.len() {
            println!(
                "{}{:<9} TLSA records on every MX — senders can detect a downgraded or substituted certificate",
                mark(&p, Mark::Ok),
                "DANE"
            );
            passed += 1;
        } else if !with_dane.is_empty() {
            println!(
                "{}{:<9} TLSA on only some MX hosts ({}) — partial DANE is not enforced",
                mark(&p, Mark::Warn),
                "DANE",
                with_dane
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            warnings += 1;
        } else if verbosity >= 1 {
            println!(
                "{}{:<9} no TLSA records (DANE not deployed)",
                mark(&p, Mark::Info),
                "DANE"
            );
        }
    }

    // ── STARTTLS: what the mail servers actually offer ───────────────────────
    if !mx_hosts.is_empty() {
        let probes = mx_hosts
            .iter()
            .take(3)
            .map(|mx| async move { (mx.clone(), probe_mx(mx, timeout_ms).await) });
        let results = futures::future::join_all(probes).await;
        let mut reachable = 0;
        let mut cleartext_only = Vec::new();
        for (host, result) in &results {
            match result {
                Some((banner, starttls, caps)) => {
                    reachable += 1;
                    if *starttls {
                        println!(
                            "{}{:<9} {} offers STARTTLS ({})",
                            mark(&p, Mark::Ok),
                            "SMTP",
                            host,
                            caps.join(", ")
                        );
                    } else {
                        cleartext_only.push(host.clone());
                        println!(
                            "{}{:<9} {} does NOT offer STARTTLS — inbound mail crosses the internet in cleartext",
                            mark(&p, Mark::Bad),
                            "SMTP",
                            host
                        );
                    }
                    if verbosity >= 1 && !banner.is_empty() {
                        println!("{:<14}{}", "", p.dim(banner));
                    }
                }
                None if verbosity >= 1 => {
                    println!(
                        "{}{:<9} {} did not answer on port 25 (blocked outbound, or the host is down)",
                        mark(&p, Mark::Info),
                        "SMTP",
                        host
                    );
                }
                None => {}
            }
        }
        if reachable > 0 {
            if cleartext_only.is_empty() {
                passed += 1;
            } else {
                fails += 1;
            }
        }
    }

    // ── BIMI (brand indicators; requires DMARC enforcement) ──────────────────
    let bimi = txt_lookup(server, &format!("default._bimi.{domain}"), timeout_ms).await;
    if let Some(rec) = bimi
        .iter()
        .find(|t| t.to_ascii_lowercase().contains("v=bimi1"))
    {
        let has_vmc = rec.to_ascii_lowercase().contains("a=");
        println!(
            "{}{:<9} published{}",
            mark(&p, Mark::Ok),
            "BIMI",
            if has_vmc {
                " with a verified mark certificate"
            } else {
                " (logo only, no VMC)"
            }
        );
        passed += 1;
    } else if has_mail && verbosity >= 1 {
        println!("{}{:<9} not published", mark(&p, Mark::Info), "BIMI");
    }

    // ── MTA-STS policy host ──────────────────────────────────────────────────
    // The TXT record only announces a policy; the policy itself lives on
    // https://mta-sts.<domain>/. If that host does not resolve, the announced
    // policy cannot be fetched and senders fall back to opportunistic TLS.
    if has_mail {
        let a_qt = dns::type_to_num("A").unwrap();
        let policy_host = format!("mta-sts.{domain}");
        let resolves = matches!(
            dns::query(server, &policy_host, a_qt, false, timeout_ms).await,
            Ok(r) if !r.answers.is_empty()
        );
        if !resolves && verbosity >= 1 {
            println!(
                "{}{:<9} {} does not resolve — an announced MTA-STS policy could not be fetched",
                mark(&p, Mark::Info),
                "MTA-STS",
                policy_host
            );
        }
    }

    // ── CAA (cert issuance policy) ───────────────────────────────────────────
    let caa_qt = dns::type_to_num("CAA").unwrap();
    match dns::query(server, domain, caa_qt, false, timeout_ms).await {
        Ok(resp) if !resp.answers.is_empty() => {
            let issuers: Vec<String> = resp
                .answers
                .iter()
                .filter_map(|r| match &r.data {
                    RData::Caa { tag, value, .. } => Some(format!("{tag} {value}")),
                    _ => None,
                })
                .collect();
            println!("{}{:<9} {}", mark(&p, Mark::Ok), "CAA", issuers.join(", "));
            passed += 1;
        }
        _ => {
            println!(
                "{}{:<9} none — any CA may issue certificates for this domain",
                mark(&p, Mark::Warn),
                "CAA"
            );
            warnings += 1;
        }
    }

    // ── Verdict ──────────────────────────────────────────────────────────────
    println!();
    if !has_mail {
        println!(
            "{}",
            p.dim("This domain declares it handles no email (null MX / no SPF-sender). Mail checks are informational.")
        );
    }
    let summary = format!("{passed} passed, {warnings} warning(s), {fails} problem(s)");
    let colored = if fails > 0 {
        p.red(&summary)
    } else if warnings > 0 {
        p.yellow(&summary)
    } else {
        p.green(&summary)
    };
    println!("{} {}", p.bold("Summary:"), colored);
}
