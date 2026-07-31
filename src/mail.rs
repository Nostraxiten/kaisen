//! `kaisen mail <domain>` — one-shot email posture audit.
//!
//! Queries the domain's mail-related DNS records (MX, SPF, DMARC, DKIM, CAA,
//! MTA-STS, TLS-RPT), interprets them, and prints a checklist with a verdict.
//! Everything is plain DNS, so it runs unprivileged anywhere.

use std::net::SocketAddr;

use crate::dns::{self, RData};
use crate::output::Painter;

/// DKIM selectors we can't enumerate from DNS, so we probe the common ones used
/// by popular mail providers.
const DKIM_SELECTORS: &[&str] = &[
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail",
    "dkim", "smtp", "mandrill", "protonmail", "protonmail2", "protonmail3", "fm1",
    "fm2", "fm3", "zoho", "everlytickey1", "everlytickey2", "mxvault", "key1",
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

/// Run the audit. Returns true if at least one query succeeded (host reachable).
pub async fn audit(domain: &str, server: SocketAddr, timeout_ms: u64, color: bool, verbosity: u8) {
    let p = Painter::new(color);
    let domain = domain.trim_end_matches('.');

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
    let spf = txts.iter().find(|t| t.to_ascii_lowercase().starts_with("v=spf1"));
    match spf {
        Some(rec) => {
            let low = rec.to_ascii_lowercase();
            let (m, note) = if low.contains("-all") {
                (Mark::Ok, "hardfail (-all): strict, recommended")
            } else if low.contains("~all") {
                (Mark::Ok, "softfail (~all): acceptable")
            } else if low.contains("?all") {
                (Mark::Warn, "neutral (?all): weak — spoofing not discouraged")
            } else if low.contains("+all") {
                (Mark::Bad, "pass-all (+all): anyone may send as you — misconfigured")
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
                if has_mail { " — senders can't be validated" } else { " (no mail expected)" }
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
        }
        None => {
            let m = if has_mail { Mark::Bad } else { Mark::Info };
            println!(
                "{}{:<9} no DMARC record{}",
                mark(&p, m),
                "DMARC",
                if has_mail { " — domain is spoofable" } else { " (no mail expected)" }
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
    if mta.iter().any(|t| t.to_ascii_lowercase().contains("v=stsv1")) {
        println!("{}{:<9} enabled (enforces TLS for inbound mail)", mark(&p, Mark::Ok), "MTA-STS");
        passed += 1;
    } else if has_mail {
        println!("{}{:<9} not configured", mark(&p, Mark::Warn), "MTA-STS");
        warnings += 1;
    }

    let tlsrpt = txt_lookup(server, &format!("_smtp._tls.{domain}"), timeout_ms).await;
    if tlsrpt.iter().any(|t| t.to_ascii_lowercase().contains("v=tlsrptv1")) {
        println!("{}{:<9} enabled (TLS failure reporting)", mark(&p, Mark::Ok), "TLS-RPT");
        passed += 1;
    } else if has_mail && verbosity >= 1 {
        println!("{}{:<9} not configured", mark(&p, Mark::Info), "TLS-RPT");
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
