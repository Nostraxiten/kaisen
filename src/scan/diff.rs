//! `--diff <file>` — Compare a previous JSON scan report with the current scan.
//! Shows newly opened ports, closed ports, version changes, and new vulnerabilities.

use std::collections::{BTreeMap, BTreeSet};

use crate::util::output::Painter;

#[derive(Debug, Clone, Default)]
pub struct PortInfo {
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: String,
    pub product: String,
    pub version: String,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HostSnapshot {
    pub target: String,
    #[allow(dead_code)]
    pub ip: String,
    #[allow(dead_code)]
    pub os_guess: String,
    pub ports: BTreeMap<u16, PortInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct HostDiff {
    pub target: String,
    pub ip: String,
    pub new_open_ports: Vec<PortInfo>,
    pub closed_ports: Vec<PortInfo>,
    pub changed_services: Vec<(PortInfo, PortInfo)>, // (old, new)
    pub new_findings: Vec<(u16, String)>,
    pub resolved_findings: Vec<(u16, String)>,
}

impl HostDiff {
    pub fn is_empty(&self) -> bool {
        self.new_open_ports.is_empty()
            && self.closed_ports.is_empty()
            && self.changed_services.is_empty()
            && self.new_findings.is_empty()
            && self.resolved_findings.is_empty()
    }
}

/// Parse a Kaisen JSON scan report into a map of `ip -> HostSnapshot`.
pub fn parse_json_report(json: &str) -> Result<BTreeMap<String, HostSnapshot>, String> {
    let mut map = BTreeMap::new();
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(map);
    }

    // Handle JSON array `[...]` or newline-delimited objects
    let objects = split_json_objects(trimmed);
    for obj in objects {
        let ip = crate::service::probe::json_str(&obj, "ip").unwrap_or_default();
        if ip.is_empty() {
            continue;
        }
        let target = crate::service::probe::json_str(&obj, "target").unwrap_or_else(|| ip.clone());
        let os_guess = crate::service::probe::json_str(&obj, "os_guess").unwrap_or_default();

        let mut ports_map = BTreeMap::new();
        if let Some(ports_idx) = obj.find("\"ports\"") {
            let rest = &obj[ports_idx + 7..];
            if let Some(open_bracket) = rest.find('[') {
                if let Some(close_bracket) = rest.rfind(']') {
                    let ports_inner = &rest[open_bracket + 1..close_bracket];
                    let port_objs = split_json_objects(ports_inner);
                    for pobj in port_objs {
                        if let Some(port_num) = crate::service::probe::json_num(&pobj, "port") {
                            let port = port_num as u16;
                            let proto = crate::service::probe::json_str(&pobj, "protocol")
                                .unwrap_or_else(|| "tcp".into());
                            let state = crate::service::probe::json_str(&pobj, "state")
                                .unwrap_or_else(|| "open".into());
                            let service = crate::service::probe::json_str(&pobj, "service")
                                .unwrap_or_default();
                            let product = crate::service::probe::json_str(&pobj, "product")
                                .unwrap_or_default();
                            let version = crate::service::probe::json_str(&pobj, "version")
                                .unwrap_or_default();

                            let mut findings = Vec::new();
                            if let Some(f_idx) = pobj.find("\"findings\"") {
                                let f_rest = &pobj[f_idx + 10..];
                                if let Some(fb) = f_rest.find('[') {
                                    if let Some(fe) = f_rest.find(']') {
                                        let fin = &f_rest[fb + 1..fe];
                                        let fobjs = split_json_objects(fin);
                                        for fo in fobjs {
                                            if let Some(fid) =
                                                crate::service::probe::json_str(&fo, "id")
                                            {
                                                findings.push(fid);
                                            }
                                        }
                                    }
                                }
                            }

                            ports_map.insert(
                                port,
                                PortInfo {
                                    port,
                                    proto,
                                    state,
                                    service,
                                    product,
                                    version,
                                    findings,
                                },
                            );
                        }
                    }
                }
            }
        }

        map.insert(
            ip.clone(),
            HostSnapshot {
                target,
                ip,
                os_guess,
                ports: ports_map,
            },
        );
    }

    Ok(map)
}

/// Split a JSON string with multiple top-level objects `{ ... }`.
fn split_json_objects(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let mut in_str = false;
    let mut escape = false;

    for (i, c) in s.char_indices() {
        if in_str {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }

        match c {
            '"' => in_str = true,
            '{' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            '}' => {
                if depth > 0 {
                    depth -= 1;
                    if depth == 0 {
                        out.push(s[start..=i].to_string());
                    }
                }
            }
            _ => {}
        }
    }

    out
}

/// Compare two host snapshots and calculate differences.
pub fn diff_snapshots(
    prev: &BTreeMap<String, HostSnapshot>,
    curr: &BTreeMap<String, HostSnapshot>,
) -> Vec<HostDiff> {
    let mut diffs = Vec::new();
    let mut all_ips: BTreeSet<String> = prev.keys().cloned().collect();
    all_ips.extend(curr.keys().cloned());

    for ip in all_ips {
        let p_host = prev.get(&ip);
        let c_host = curr.get(&ip);

        let target = c_host
            .map(|h| h.target.clone())
            .or_else(|| p_host.map(|h| h.target.clone()))
            .unwrap_or_else(|| ip.clone());

        let mut diff = HostDiff {
            target,
            ip: ip.clone(),
            ..Default::default()
        };

        let empty_ports = BTreeMap::new();
        let p_ports = p_host.map(|h| &h.ports).unwrap_or(&empty_ports);
        let c_ports = c_host.map(|h| &h.ports).unwrap_or(&empty_ports);

        let mut all_ports: BTreeSet<u16> = p_ports.keys().copied().collect();
        all_ports.extend(c_ports.keys().copied());

        for port in all_ports {
            match (p_ports.get(&port), c_ports.get(&port)) {
                (None, Some(new_p)) => {
                    if new_p.state == "open" {
                        diff.new_open_ports.push(new_p.clone());
                        for f in &new_p.findings {
                            diff.new_findings.push((port, f.clone()));
                        }
                    }
                }
                (Some(old_p), None) => {
                    if old_p.state == "open" {
                        diff.closed_ports.push(old_p.clone());
                        for f in &old_p.findings {
                            diff.resolved_findings.push((port, f.clone()));
                        }
                    }
                }
                (Some(old_p), Some(new_p)) => {
                    if old_p.state != "open" && new_p.state == "open" {
                        diff.new_open_ports.push(new_p.clone());
                    } else if old_p.state == "open" && new_p.state != "open" {
                        diff.closed_ports.push(old_p.clone());
                    } else if old_p.state == "open" && new_p.state == "open" {
                        // Check for service/version drift
                        if old_p.product != new_p.product || old_p.version != new_p.version {
                            diff.changed_services.push((old_p.clone(), new_p.clone()));
                        }
                        // Check findings
                        let old_f: BTreeSet<&String> = old_p.findings.iter().collect();
                        let new_f: BTreeSet<&String> = new_p.findings.iter().collect();
                        for f in new_f.difference(&old_f) {
                            diff.new_findings.push((port, (*f).clone()));
                        }
                        for f in old_f.difference(&new_f) {
                            diff.resolved_findings.push((port, (*f).clone()));
                        }
                    }
                }
                (None, None) => {}
            }
        }

        diffs.push(diff);
    }

    diffs
}

/// Print scan diff to terminal.
pub fn print_diff_report(diffs: &[HostDiff], color: bool) {
    let p = Painter::new(color);
    println!();
    println!("{}", p.bold("=== KAISEN SCAN DIFF REPORT ==="));

    let mut any_change = false;
    for d in diffs {
        if d.is_empty() {
            continue;
        }
        any_change = true;
        println!();
        println!("{} {} ({})", p.bold("Host:"), p.cyan(&d.target), d.ip);

        for open in &d.new_open_ports {
            println!(
                "  {} {:<6} {} {}",
                p.green("[+] NEW OPEN:"),
                format!("{}/{}", open.port, open.proto),
                p.bold(&open.service),
                p.dim(&format!("{} {}", open.product, open.version))
            );
        }

        for closed in &d.closed_ports {
            println!(
                "  {} {:<6} {}",
                p.red("[-] CLOSED:  "),
                format!("{}/{}", closed.port, closed.proto),
                closed.service
            );
        }

        for (old_p, new_p) in &d.changed_services {
            println!(
                "  {} {:<6} {} {} -> {} {}",
                p.yellow("[~] CHANGED: "),
                format!("{}/{}", new_p.port, new_p.proto),
                old_p.product,
                old_p.version,
                p.bold(&new_p.product),
                p.bold(&new_p.version)
            );
        }

        for (port, vuln) in &d.new_findings {
            println!(
                "  {} {:<6} {}",
                p.bold(&p.red("[!] NEW VULN:")),
                port,
                p.red(vuln)
            );
        }

        for (port, vuln) in &d.resolved_findings {
            println!("  {} {:<6} {}", p.green("[v] RESOLVED:"), port, p.dim(vuln));
        }
    }

    if !any_change {
        println!("{}", p.green("No changes detected between scans."));
    }
}
