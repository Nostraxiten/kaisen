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
    Probes { ttl, ttl_family, ttl_hops, snmp_os }
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
        &["-c", "1", "-W", "1"],  // Linux / Termux
        &["-c", "1", "-t", "1"],  // macOS / BSD
        &["-n", "1", "-w", "1000"], // Windows
    ];
    for base in arg_sets {
        let mut args: Vec<&str> = base.to_vec();
        args.push(&ip_s);
        let fut = tokio::process::Command::new("ping")
            .args(&args)
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

/// Extract "ttl=NN" (any case; Windows uses "TTL=") from ping output.
fn parse_ttl(s: &str) -> Option<u8> {
    let lower = s.to_ascii_lowercase();
    let idx = lower.find("ttl=")?;
    let rest = &lower[idx + 4..];
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
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
    let pos = resp.windows(needle.len()).position(|w| w == needle.as_slice())?;
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
    let s = String::from_utf8_lossy(&resp[i..i + len]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
