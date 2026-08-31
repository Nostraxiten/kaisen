//! OS fingerprinting signals that work without root.
//!
//! Root-free OS detection can't use raw TCP/IP fingerprinting (that needs
//! CAP_NET_RAW). Instead Kaisen gathers several unprivileged signals and
//! combines them:
//!   * TTL of an ICMP echo reply, obtained via the system `ping` (unprivileged
//!     on Linux/Kali/Termux/macOS). Initial TTL reveals the OS family.
//!   * SNMP sysDescr (UDP/161, community "public") — the exact OS string when
//!     the device exposes SNMP.
//! Banner-based hints (SSH/HTTP/FTP-SYST/SMTP) are collected in `service.rs`.

use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Result of the network-level probes.
pub struct Probes {
    pub ttl: Option<u8>,
    pub ttl_family: Option<&'static str>,
    pub ttl_hops: Option<u8>,
    pub snmp_os: Option<String>,
}

/// Run the TTL and SNMP probes concurrently.
pub async fn probe(ip: IpAddr) -> Probes {
    let (ttl, snmp_os) = tokio::join!(ttl_via_ping(ip), snmp_sysdescr(ip));
    let (ttl_family, ttl_hops) = match ttl {
        Some(t) => {
            let (fam, initial) = ttl_family(t);
            (Some(fam), Some(initial.saturating_sub(t)))
        }
        None => (None, None),
    };
    Probes {
        ttl,
        ttl_family,
        ttl_hops,
        snmp_os,
    }
}

/// Map an observed TTL to the most likely initial TTL and OS family.
/// Common initial TTLs: 64 (Linux/Unix/macOS/Android), 128 (Windows),
/// 255 (routers/switches, some BSD/Solaris).
pub fn ttl_family(ttl: u8) -> (&'static str, u8) {
    if ttl <= 64 {
        ("Linux / Unix / macOS / Android", 64)
    } else if ttl <= 128 {
        ("Windows", 128)
    } else {
        ("Network device / Solaris / BSD", 255)
    }
}

/// Get the reply TTL by shelling out to the unprivileged `ping` utility.
/// Handles Linux/Termux (`-W`) and macOS/BSD (`-t`) flag differences, plus the
/// Windows `TTL=` spelling. Also used as the unprivileged host-discovery probe
/// (`Some(_)` means the host answered ICMP echo, i.e. it's up).
pub async fn ttl_via_ping(ip: IpAddr) -> Option<u8> {
    let ip_s = ip.to_string();
    let arg_sets: [&[&str]; 3] = [
        &["-c", "1", "-W", "1"],    // Linux / Termux
        &["-c", "1", "-t", "1"],    // macOS / BSD
        &["-n", "1", "-w", "1000"], // Windows
    ];
    // Bounding process execution: Android/Termux aggressively kills apps
    // (signal 9) that fork too many subprocesses simultaneously (max 32 globally).
    // This limits concurrent forks across all target IPs to 8 to stay well under
    // the Phantom Process Killer threshold.
    let sem = SUBPROCESS_SEM.get_or_init(|| tokio::sync::Semaphore::new(8));
    let _permit = sem.acquire().await.ok();

    for args in arg_sets {
        let mut full_args: Vec<&str> = args.to_vec();
        full_args.push(&ip_s);
        let fut = tokio::process::Command::new("ping")
            .args(&full_args)
            .kill_on_drop(true)
            .output();
        if let Ok(Ok(out)) = timeout(Duration::from_secs(3), fut).await {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if let Some(ttl) = parse_ttl(&text) {
                return Some(ttl);
            }
        }
    }
    None
}

static SUBPROCESS_SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();

/// Single-attempt, ~1s ICMP ping for the fast discovery sweep that runs
/// concurrently across every target before the real port scan. Unlike
/// `ttl_via_ping` (used for one host's detailed `-OS` probe), this tries
/// only the current platform's flag convention and doesn't retry across
/// conventions — it's meant to run hundreds-wide in parallel, not tuned for
/// a single host.
pub async fn ping_quick(ip: IpAddr) -> bool {
    let ip_s = ip.to_string();
    #[cfg(target_os = "windows")]
    let args: [&str; 4] = ["-n", "1", "-w", "800"];
    #[cfg(target_os = "macos")]
    let args: [&str; 4] = ["-c", "1", "-t", "1"];
    #[cfg(all(unix, not(target_os = "macos")))]
    let args: [&str; 4] = ["-c", "1", "-W", "1"];

    let mut full_args: Vec<&str> = args.to_vec();
    full_args.push(&ip_s);

    // Bounding process execution: Android/Termux aggressively kills apps
    // (signal 9) that fork too many subprocesses simultaneously (max 32 globally).
    // This limits concurrent forks across all target IPs to 8 to stay well under
    // the Phantom Process Killer threshold.
    let sem = SUBPROCESS_SEM.get_or_init(|| tokio::sync::Semaphore::new(8));
    let _permit = sem.acquire().await.ok();

    let fut = tokio::process::Command::new("ping")
        .args(&full_args)
        .kill_on_drop(true)
        .output();
    matches!(timeout(Duration::from_millis(1500), fut).await, Ok(Ok(out)) if out.status.success())
}

/// Extract "ttl=NN" (any case; Windows uses "TTL=") from ping output.
fn parse_ttl(s: &str) -> Option<u8> {
    let lower = s.to_ascii_lowercase();
    let idx = lower.find("ttl=")?;
    let rest = &lower[idx + 4..];
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

// ── ARP/neighbor-cache liveness (local-subnet fallback) ────────────────────
//
// On a LAN, a host can drop every ICMP echo and every TCP probe at the OS
// firewall level and still be "up" — because ARP resolution happens in the
// kernel below any of that filtering, the same reason `nmap` prefers ARP
// over ping for local targets. We can't send raw ARP requests without root,
// but we don't have to: probing the host's TCP ports already forces the
// kernel to resolve its MAC address as a side effect, so afterwards we just
// read back that resolution from the OS's own neighbor/ARP cache.

/// Ask the OS whether it holds a *resolved* (not just attempted) ARP/neighbor
/// entry for `ip`, meaning the device answered at layer 2 regardless of
/// whether anything above that responded.
pub async fn arp_alive(ip: IpAddr) -> bool {
    arp_lookup(ip).await.is_some()
}

/// Look up the resolved MAC address for `ip` in the OS's own ARP/neighbor
/// cache (used by `-MC` and as the `arp_alive` liveness fallback). Only
/// meaningful for a directly-connected local subnet — always `None` for a
/// routed/remote target, since there's no ARP entry to find.
pub async fn arp_lookup(ip: IpAddr) -> Option<String> {
    let IpAddr::V4(_) = ip else { return None };
    #[cfg(target_os = "linux")]
    {
        arp_lookup_linux(ip).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        arp_lookup_via_command(ip).await
    }
}

/// Linux: read `/proc/net/arp` directly (no subprocess, no root needed).
/// Format: `IP address  HW type  Flags  HW address  Mask  Device`, where
/// the ATF_COM (0x2) bit in Flags means the entry is actually resolved.
/// Note: Android locks this file down with SELinux even for the shell's own
/// "root"-looking prompt in apps like Termux — a read failure there is a
/// platform restriction, not a bug, and just yields `None`.
#[cfg(target_os = "linux")]
async fn arp_lookup_linux(ip: IpAddr) -> Option<String> {
    let target = ip.to_string();
    let contents = std::fs::read_to_string("/proc/net/arp").ok()?;
    contents.lines().skip(1).find_map(|line| {
        let mut cols = line.split_whitespace();
        let entry_ip = cols.next()?;
        let _hw_type = cols.next();
        let flags = cols.next();
        let mac = cols.next()?;
        if entry_ip != target {
            return None;
        }
        let flags_val = flags
            .and_then(|f| i64::from_str_radix(f.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        if flags_val & 0x2 != 0 && mac != "00:00:00:00:00:00" {
            Some(mac.to_ascii_lowercase())
        } else {
            None
        }
    })
}

/// macOS/BSD fallback: shell out to `arp -n <ip>` and pull the MAC out of
/// `? (192.168.1.4) at aa:bb:cc:dd:ee:ff on en0 ...`.
#[cfg(not(target_os = "linux"))]
async fn arp_lookup_via_command(ip: IpAddr) -> Option<String> {
    let target = ip.to_string();

    // Bounding process execution: Android/Termux aggressively kills apps
    // (signal 9) that fork too many subprocesses simultaneously (max 32 globally).
    // This limits concurrent forks across all target IPs to 8 to stay well under
    // the Phantom Process Killer threshold.
    let sem = SUBPROCESS_SEM.get_or_init(|| tokio::sync::Semaphore::new(8));
    let _permit = sem.acquire().await.ok();

    let fut = tokio::process::Command::new("arp")
        .arg("-n")
        .arg(&target)
        .kill_on_drop(true)
        .output();
    let out = timeout(Duration::from_millis(800), fut).await.ok()?.ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().find_map(|line| {
        let idx = line.find(" at ")?;
        let mac = line[idx + 4..].split_whitespace().next()?;
        if mac.contains(':') && !mac.eq_ignore_ascii_case("incomplete") {
            Some(mac.to_ascii_lowercase())
        } else {
            None
        }
    })
}

// ── SNMP v1 sysDescr.0 probe ────────────────────────────────────────────────

/// The BER-encoded OID for 1.3.6.1.2.1.1.1.0 (sysDescr.0), value bytes only.
const SYSDESCR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    // Short-form length only (all our fields are < 128 bytes).
    let mut out = Vec::with_capacity(value.len() + 2);
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
    out
}

/// Build an SNMPv1 GET request for sysDescr.0 with community "public".
fn build_snmp_get() -> Vec<u8> {
    let oid = tlv(0x06, SYSDESCR_OID);
    let null = vec![0x05u8, 0x00];
    let mut varbind = oid;
    varbind.extend_from_slice(&null);
    let varbind = tlv(0x30, &varbind); // SEQUENCE

    let varbind_list = tlv(0x30, &varbind); // SEQUENCE OF

    let mut pdu = Vec::new();
    pdu.extend_from_slice(&tlv(0x02, &[0x00, 0x00, 0x00, 0x01])); // request-id
    pdu.extend_from_slice(&tlv(0x02, &[0x00])); // error-status
    pdu.extend_from_slice(&tlv(0x02, &[0x00])); // error-index
    pdu.extend_from_slice(&varbind_list);
    let pdu = tlv(0xA0, &pdu); // GET-request PDU (context tag 0xA0)

    let mut msg = Vec::new();
    msg.extend_from_slice(&tlv(0x02, &[0x00])); // version = 0 (v1)
    msg.extend_from_slice(&tlv(0x04, b"public")); // community
    msg.extend_from_slice(&pdu);
    tlv(0x30, &msg) // top-level SEQUENCE
}

/// Query SNMP sysDescr.0 over UDP/161. Best-effort: most hosts won't answer,
/// but when they do it yields the exact OS description string.
async fn snmp_sysdescr(ip: IpAddr) -> Option<String> {
    let bind = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect((ip, 161)).await.ok()?;
    let packet = build_snmp_get();
    sock.send(&packet).await.ok()?;

    let mut buf = vec![0u8; 2048];
    let n = timeout(Duration::from_millis(1500), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_snmp_sysdescr(&buf[..n])
}

/// Find the sysDescr OID in the response and read the OCTET STRING value that
/// follows it in the varbind.
fn parse_snmp_sysdescr(resp: &[u8]) -> Option<String> {
    // Locate the OID byte sequence, then the value TLV right after it.
    let needle = {
        let mut v = vec![0x06u8, SYSDESCR_OID.len() as u8];
        v.extend_from_slice(SYSDESCR_OID);
        v
    };
    let pos = resp
        .windows(needle.len())
        .position(|w| w == needle.as_slice())?;
    let mut i = pos + needle.len();
    if i + 2 > resp.len() {
        return None;
    }
    let tag = resp[i];
    let len = resp[i + 1] as usize;
    i += 2;
    if tag != 0x04 || i + len > resp.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&resp[i..i + len])
        .trim()
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
