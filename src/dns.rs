//! A dependency-free DNS resolver — Kaisen's `dig` half.
//!
//! Implements DNS message encoding/decoding (RFC 1035 + compression pointers)
//! over UDP with automatic TCP fallback on truncation. Supports the common
//! record types and querying arbitrary servers, all unprivileged.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

pub fn type_to_num(t: &str) -> Option<u16> {
    Some(match t.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "CAA" => 257,
        "ANY" => 255,
        _ => return None,
    })
}

pub fn num_to_type(n: u16) -> String {
    match n {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        257 => "CAA",
        255 => "ANY",
        other => return format!("TYPE{other}"),
    }
    .to_string()
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Name(String),
    Mx { pref: u16, exchange: String },
    Txt(Vec<String>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
    #[allow(dead_code)]
    Other(u16, Vec<u8>),
}

impl RData {
    pub fn render(&self) -> String {
        match self {
            RData::A(ip) => ip.to_string(),
            RData::Aaaa(ip) => ip.to_string(),
            RData::Name(n) => n.clone(),
            RData::Mx { pref, exchange } => format!("{pref} {exchange}"),
            RData::Txt(parts) => parts
                .iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(" "),
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
                format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}")
            }
            RData::Srv { priority, weight, port, target } => {
                format!("{priority} {weight} {port} {target}")
            }
            RData::Caa { flags, tag, value } => format!("{flags} {tag} \"{value}\""),
            RData::Other(_, bytes) => format!("<{} bytes>", bytes.len()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub rcode: u8,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub elapsed_ms: u128,
    pub server: SocketAddr,
    pub via_tcp: bool,
}

pub fn rcode_str(code: u8) -> &'static str {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0);
}

fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut buf, name);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    buf
}

/// Parse a (possibly compressed) domain name starting at `pos`.
/// Returns the name and the position *after* the name in the flat stream
/// (following any compression pointer means we return the post-pointer offset).
fn parse_name(msg: &[u8], mut pos: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut next_pos = pos;
    let mut guard = 0;

    loop {
        guard += 1;
        if guard > 128 {
            return Err("name compression loop".into());
        }
        if pos >= msg.len() {
            return Err("truncated name".into());
        }
        let len = msg[pos];
        if len & 0xC0 == 0xC0 {
            // pointer
            if pos + 1 >= msg.len() {
                return Err("truncated pointer".into());
            }
            let ptr = (((len & 0x3F) as usize) << 8) | msg[pos + 1] as usize;
            if !jumped {
                next_pos = pos + 2;
            }
            jumped = true;
            pos = ptr;
        } else if len == 0 {
            pos += 1;
            if !jumped {
                next_pos = pos;
            }
            break;
        } else {
            let start = pos + 1;
            let end = start + len as usize;
            if end > msg.len() {
                return Err("truncated label".into());
            }
            labels.push(String::from_utf8_lossy(&msg[start..end]).to_string());
            pos = end;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Ok((name, next_pos))
}

fn read_u16(msg: &[u8], pos: usize) -> Result<u16, String> {
    if pos + 2 > msg.len() {
        return Err("truncated u16".into());
    }
    Ok(u16::from_be_bytes([msg[pos], msg[pos + 1]]))
}

fn read_u32(msg: &[u8], pos: usize) -> Result<u32, String> {
    if pos + 4 > msg.len() {
        return Err("truncated u32".into());
    }
    Ok(u32::from_be_bytes([msg[pos], msg[pos + 1], msg[pos + 2], msg[pos + 3]]))
}

fn parse_rdata(msg: &[u8], rtype: u16, rdstart: usize, rdlen: usize) -> Result<RData, String> {
    let end = rdstart + rdlen;
    if end > msg.len() {
        return Err("truncated rdata".into());
    }
    Ok(match rtype {
        1 => {
            if rdlen != 4 {
                return Err("bad A rdata".into());
            }
            RData::A(Ipv4Addr::new(msg[rdstart], msg[rdstart + 1], msg[rdstart + 2], msg[rdstart + 3]))
        }
        28 => {
            if rdlen != 16 {
                return Err("bad AAAA rdata".into());
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&msg[rdstart..rdstart + 16]);
            RData::Aaaa(Ipv6Addr::from(o))
        }
        2 | 5 | 12 => {
            let (name, _) = parse_name(msg, rdstart)?;
            RData::Name(name)
        }
        15 => {
            let pref = read_u16(msg, rdstart)?;
            let (exchange, _) = parse_name(msg, rdstart + 2)?;
            RData::Mx { pref, exchange }
        }
        16 => {
            let mut parts = Vec::new();
            let mut p = rdstart;
            while p < end {
                let l = msg[p] as usize;
                p += 1;
                if p + l > end {
                    break;
                }
                parts.push(String::from_utf8_lossy(&msg[p..p + l]).to_string());
                p += l;
            }
            RData::Txt(parts)
        }
        6 => {
            let (mname, p1) = parse_name(msg, rdstart)?;
            let (rname, p2) = parse_name(msg, p1)?;
            RData::Soa {
                mname,
                rname,
                serial: read_u32(msg, p2)?,
                refresh: read_u32(msg, p2 + 4)?,
                retry: read_u32(msg, p2 + 8)?,
                expire: read_u32(msg, p2 + 12)?,
                minimum: read_u32(msg, p2 + 16)?,
            }
        }
        33 => {
            let priority = read_u16(msg, rdstart)?;
            let weight = read_u16(msg, rdstart + 2)?;
            let port = read_u16(msg, rdstart + 4)?;
            let (target, _) = parse_name(msg, rdstart + 6)?;
            RData::Srv { priority, weight, port, target }
        }
        257 => {
            let flags = msg[rdstart];
            let taglen = msg[rdstart + 1] as usize;
            let tstart = rdstart + 2;
            let tag = String::from_utf8_lossy(&msg[tstart..tstart + taglen]).to_string();
            let value = String::from_utf8_lossy(&msg[tstart + taglen..end]).to_string();
            RData::Caa { flags, tag, value }
        }
        other => RData::Other(other, msg[rdstart..end].to_vec()),
    })
}

fn parse_response(msg: &[u8]) -> Result<(u8, Vec<Record>, Vec<Record>, Vec<Record>), String> {
    if msg.len() < 12 {
        return Err("short response".into());
    }
    let flags = read_u16(msg, 2)?;
    let rcode = (flags & 0x000F) as u8;
    let qd = read_u16(msg, 4)?;
    let an = read_u16(msg, 6)?;
    let ns = read_u16(msg, 8)?;
    let ar = read_u16(msg, 10)?;

    let mut pos = 12;
    // Skip questions.
    for _ in 0..qd {
        let (_, p) = parse_name(msg, pos)?;
        pos = p + 4; // qtype + qclass
    }

    let read_section = |count: u16, pos: &mut usize| -> Result<Vec<Record>, String> {
        let mut out = Vec::new();
        for _ in 0..count {
            let (name, p) = parse_name(msg, *pos)?;
            let rtype = read_u16(msg, p)?;
            let ttl = read_u32(msg, p + 4)?;
            let rdlen = read_u16(msg, p + 8)? as usize;
            let rdstart = p + 10;
            let data = parse_rdata(msg, rtype, rdstart, rdlen)?;
            out.push(Record { name, rtype, ttl, data });
            *pos = rdstart + rdlen;
        }
        Ok(out)
    };

    let answers = read_section(an, &mut pos)?;
    let authorities = read_section(ns, &mut pos)?;
    let additionals = read_section(ar, &mut pos)?;
    Ok((rcode, answers, authorities, additionals))
}

fn rand_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16) ^ (std::process::id() as u16)
}

/// Query `server` for `name`/`qtype`. Uses UDP first, retries over TCP if the
/// response is truncated (TC bit) or if `force_tcp` is set.
pub async fn query(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    force_tcp: bool,
    timeout_ms: u64,
) -> Result<Response, String> {
    let id = rand_id();
    let packet = build_query(id, name, qtype);
    let start = std::time::Instant::now();
    let dur = Duration::from_millis(timeout_ms.max(500));

    if !force_tcp {
        let bind: SocketAddr = if server.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
        sock.connect(server).await.map_err(|e| e.to_string())?;

        // UDP is lossy — especially over mobile links and against rate-limited
        // public resolvers under bursts. Retransmit up to 3 times on timeout
        // before giving up on UDP (a per-attempt window keeps latency bounded).
        let per_try = Duration::from_millis((dur.as_millis() as u64 / 2).max(700));
        let mut buf = vec![0u8; 4096];
        let mut received: Option<usize> = None;
        for _ in 0..3 {
            if sock.send(&packet).await.is_err() {
                break;
            }
            match timeout(per_try, sock.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    received = Some(n);
                    break;
                }
                Ok(Err(e)) => return Err(e.to_string()),
                Err(_) => continue, // timed out — retransmit
            }
        }

        if let Some(n) = received {
            let msg = &buf[..n];
            // Check TC (truncation) bit.
            let tc = n >= 4 && (msg[2] & 0x02) != 0;
            if !tc {
                let (rcode, answers, authorities, additionals) = parse_response(msg)?;
                return Ok(Response {
                    rcode,
                    answers,
                    authorities,
                    additionals,
                    elapsed_ms: start.elapsed().as_millis(),
                    server,
                    via_tcp: false,
                });
            }
            // truncated -> fall through to TCP
        }
        // If every UDP attempt timed out, fall through to a TCP retry below.
    }

    // TCP path (length-prefixed).
    let mut stream = timeout(dur, TcpStream::connect(server))
        .await
        .map_err(|_| "TCP connect timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let len = (packet.len() as u16).to_be_bytes();
    stream.write_all(&len).await.map_err(|e| e.to_string())?;
    stream.write_all(&packet).await.map_err(|e| e.to_string())?;

    let mut lenbuf = [0u8; 2];
    timeout(dur, stream.read_exact(&mut lenbuf))
        .await
        .map_err(|_| "TCP read timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let rlen = u16::from_be_bytes(lenbuf) as usize;
    let mut msg = vec![0u8; rlen];
    timeout(dur, stream.read_exact(&mut msg))
        .await
        .map_err(|_| "TCP read timed out".to_string())?
        .map_err(|e| e.to_string())?;

    let (rcode, answers, authorities, additionals) = parse_response(&msg)?;
    Ok(Response {
        rcode,
        answers,
        authorities,
        additionals,
        elapsed_ms: start.elapsed().as_millis(),
        server,
        via_tcp: true,
    })
}

/// Build the reverse-lookup (PTR) name for an IP address.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::new();
            for byte in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// Discover the system's default DNS server from /etc/resolv.conf, falling
/// back to a public resolver so Kaisen works even on minimal systems (Termux).
pub fn default_server() -> IpAddr {
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    // Public fallback.
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
}
