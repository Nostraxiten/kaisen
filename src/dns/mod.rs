//! A dependency-free DNS resolver — Kaisen's `dig` half.
//!
//! Implements DNS message encoding/decoding (RFC 1035 + compression pointers)
//! over UDP with automatic TCP fallback on truncation. Supports the common
//! record types and querying arbitrary servers, all unprivileged.

pub mod nsaudit;
pub mod whois;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

pub fn type_to_num(t: &str) -> Option<u16> {
    Some(match t.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "WKS" => 11,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "SIG" => 24,
        "KEY" => 25,
        "AAAA" => 28,
        "LOC" => 29,
        "SRV" => 33,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "DNAME" => 39,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC3" => 50,
        "NSEC3PARAM" => 51,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "HIP" => 55,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "EUI48" => 108,
        "EUI64" => 109,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "ANY" | "*" => 255,
        "URI" => 256,
        "CAA" => 257,
        "AVC" => 258,
        "DOA" => 259,
        "TA" => 32768,
        "DLV" => 32769,
        other => {
            // dig-style TYPE### escape hatch for anything not named above.
            let rest = other.strip_prefix("TYPE")?;
            return rest.parse::<u16>().ok();
        }
    })
}

pub fn num_to_type(n: u16) -> String {
    match n {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        10 => "NULL",
        11 => "WKS",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        24 => "SIG",
        25 => "KEY",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        39 => "DNAME",
        41 => "OPT",
        42 => "APL",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        108 => "EUI48",
        109 => "EUI64",
        250 => "TSIG",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        258 => "AVC",
        32768 => "TA",
        32769 => "DLV",
        other => return format!("TYPE{other}"),
    }
    .to_string()
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Name(String),
    Mx {
        pref: u16,
        exchange: String,
    },
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
    /// DS and CDS: the delegation signer digest that links a child zone to its parent.
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    /// DNSKEY and CDNSKEY.
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        key: Vec<u8>,
    },
    Rrsig {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: String,
    },
    Nsec {
        next: String,
        types: Vec<u16>,
    },
    Nsec3 {
        hash_alg: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed: Vec<u8>,
        types: Vec<u16>,
    },
    /// TLSA and SMIMEA: the DANE certificate association.
    Tlsa {
        usage: u8,
        selector: u8,
        matching: u8,
        data: Vec<u8>,
    },
    Sshfp {
        algorithm: u8,
        fp_type: u8,
        fingerprint: Vec<u8>,
    },
    Naptr {
        order: u16,
        preference: u16,
        flags: String,
        service: String,
        regexp: String,
        replacement: String,
    },
    /// SVCB and HTTPS: service binding, where ALPN and ECH now live.
    Svcb {
        priority: u16,
        target: String,
        params: Vec<(u16, Vec<u8>)>,
    },
    Uri {
        priority: u16,
        weight: u16,
        target: String,
    },
    Hinfo {
        cpu: String,
        os: String,
    },
    Eui(Vec<u8>),
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
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}")
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                format!("{priority} {weight} {port} {target}")
            }
            RData::Caa { flags, tag, value } => format!("{flags} {tag} \"{value}\""),
            RData::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => format!(
                "{key_tag} {algorithm} ({}) {digest_type} ({}) {}",
                dnssec_alg(*algorithm),
                digest_alg(*digest_type),
                hex(digest)
            ),
            RData::Dnskey {
                flags,
                protocol,
                algorithm,
                key,
            } => {
                let role = if flags & 0x0001 != 0 {
                    if flags & 0x0100 != 0 {
                        "KSK"
                    } else {
                        "secure entry point"
                    }
                } else if flags & 0x0100 != 0 {
                    "ZSK"
                } else {
                    "non-signing"
                };
                format!(
                    "{flags} ({role}) {protocol} {algorithm} ({}) {} bits, tag {}",
                    dnssec_alg(*algorithm),
                    key.len() * 8,
                    dnskey_tag(*flags, *protocol, *algorithm, key)
                )
            }
            RData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
            } => format!(
                "{} {} ({}) {labels} {original_ttl} exp {} inc {} tag {key_tag} {signer}",
                num_to_type(*type_covered),
                algorithm,
                dnssec_alg(*algorithm),
                fmt_time(*expiration),
                fmt_time(*inception)
            ),
            RData::Nsec { next, types } => {
                format!(
                    "{next} {}",
                    types
                        .iter()
                        .map(|t| num_to_type(*t))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            RData::Nsec3 {
                hash_alg,
                flags,
                iterations,
                salt,
                next_hashed,
                types,
            } => format!(
                "{hash_alg} {flags} {iterations} {} {} {}",
                if salt.is_empty() {
                    "-".to_string()
                } else {
                    hex(salt)
                },
                base32hex(next_hashed),
                types
                    .iter()
                    .map(|t| num_to_type(*t))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            RData::Tlsa {
                usage,
                selector,
                matching,
                data,
            } => format!(
                "{usage} ({}) {selector} ({}) {matching} ({}) {}",
                tlsa_usage(*usage),
                tlsa_selector(*selector),
                tlsa_matching(*matching),
                hex(data)
            ),
            RData::Sshfp {
                algorithm,
                fp_type,
                fingerprint,
            } => format!(
                "{algorithm} ({}) {fp_type} ({}) {}",
                sshfp_alg(*algorithm),
                sshfp_fptype(*fp_type),
                hex(fingerprint)
            ),
            RData::Naptr {
                order,
                preference,
                flags,
                service,
                regexp,
                replacement,
            } => {
                format!("{order} {preference} \"{flags}\" \"{service}\" \"{regexp}\" {replacement}")
            }
            RData::Svcb {
                priority,
                target,
                params,
            } => {
                let target = if target.is_empty() {
                    "."
                } else {
                    target.as_str()
                };
                let mut s = format!("{priority} {target}");
                for (key, value) in params {
                    s.push(' ');
                    s.push_str(&svcb_param(*key, value));
                }
                s
            }
            RData::Uri {
                priority,
                weight,
                target,
            } => format!("{priority} {weight} \"{target}\""),
            RData::Hinfo { cpu, os } => format!("\"{cpu}\" \"{os}\""),
            RData::Eui(bytes) => bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("-"),
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
    /// Authoritative Answer: this server owns the zone rather than caching it.
    pub aa: bool,
    /// Authentic Data: the resolver validated DNSSEC for this answer.
    pub ad: bool,
    /// Recursion Available.
    pub ra: bool,
    /// The response was truncated over UDP (and we retried over TCP).
    pub tc: bool,
    /// NSID, when requested: identifies which anycast node answered.
    pub nsid: Option<String>,
    /// EDNS Client Subnet scope returned by the server, when +subnet was sent.
    pub ecs_scope: Option<u8>,
}

impl Response {
    /// The flag letters dig prints, e.g. "qr rd ra ad".
    pub fn flag_str(&self) -> String {
        let mut f = vec!["qr"];
        if self.aa {
            f.push("aa");
        }
        if self.tc {
            f.push("tc");
        }
        if self.ra {
            f.push("ra");
        }
        if self.ad {
            f.push("ad");
        }
        f.join(" ")
    }
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

/// Knobs the caller can turn on a single query. Defaults mirror `dig` with no
/// `+` options: recursion on, no EDNS record, UDP first.
#[derive(Debug, Clone, Copy)]
pub struct QueryOpts {
    pub force_tcp: bool,
    pub timeout_ms: u64,
    /// Set the EDNS0 DO bit, asking the server for DNSSEC records.
    pub dnssec: bool,
    /// Request NSID (RFC 5001), which names the specific anycast node that answered.
    pub nsid: bool,
    /// Clear the RD bit — how you ask an authoritative server for its own data
    /// rather than making it recurse, and how iterative resolution works.
    pub no_recurse: bool,
    /// Advertised EDNS0 UDP payload size. 0 means send no OPT record at all.
    pub udp_size: u16,
    /// EDNS Client Subnet (RFC 7871): the network to claim to be asking from,
    /// as (address, source prefix length). Only the prefix is sent — the host
    /// bits are stripped before transmission.
    pub client_subnet: Option<(IpAddr, u8)>,
}

impl Default for QueryOpts {
    fn default() -> Self {
        QueryOpts {
            force_tcp: false,
            timeout_ms: 2000,
            dnssec: false,
            nsid: false,
            no_recurse: false,
            // Advertise EDNS0 by default, as every modern resolver does: without
            // it a large TXT or DNSKEY answer comes back truncated and forces a
            // TCP retry, which is slower and is blocked on many networks. 1232
            // is the size the DNS Flag Day 2020 guidance settled on, chosen to
            // stay under the common 1280-byte IPv6 MTU.
            udp_size: 1232,
            client_subnet: None,
        }
    }
}

/// Parse a `+subnet` argument: `203.0.113.0/24`, a bare address (which takes
/// dig's defaults of /24 for IPv4 and /56 for IPv6), or `0` for the explicit
/// "reveal nothing" form of the option.
pub fn parse_client_subnet(s: &str) -> Result<(IpAddr, u8), String> {
    if s == "0" || s == "0/0" {
        return Ok((IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0));
    }
    let (addr_s, prefix_s) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let addr: IpAddr = addr_s
        .parse()
        .map_err(|_| format!("+subnet: '{addr_s}' is not an IP address"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix: u8 = match prefix_s {
        Some(p) => p
            .parse()
            .map_err(|_| format!("+subnet: '{p}' is not a prefix length"))?,
        None => {
            if addr.is_ipv4() {
                24
            } else {
                56
            }
        }
    };
    if prefix > max {
        return Err(format!(
            "+subnet: /{prefix} is out of range for this address"
        ));
    }
    Ok((addr, prefix))
}

/// The address bytes an ECS option carries: the leading `ceil(prefix/8)` bytes
/// with every bit past the prefix cleared, as RFC 7871 §6 requires.
fn ecs_address_bytes(addr: IpAddr, prefix: u8) -> Vec<u8> {
    let full: Vec<u8> = match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    let len = prefix.div_ceil(8) as usize;
    let mut out = full[..len.min(full.len())].to_vec();
    // Zero the bits beyond the prefix inside the final byte.
    let rem = prefix % 8;
    if rem != 0 {
        if let Some(last) = out.last_mut() {
            *last &= 0xFFu8 << (8 - rem);
        }
    }
    out
}

fn build_query_opts(id: u16, name: &str, qtype: u16, o: &QueryOpts) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = if o.no_recurse { 0x0000 } else { 0x0100 };
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    let needs_opt = o.dnssec || o.nsid || o.client_subnet.is_some() || o.udp_size > 0;
    buf.extend_from_slice(&(if needs_opt { 1u16 } else { 0u16 }).to_be_bytes()); // arcount
    encode_name(&mut buf, name);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // class IN

    if needs_opt {
        // EDNS0 pseudo-record: root name, type OPT, class = UDP payload size,
        // and the DO bit lives in the high byte of the "TTL" field.
        buf.push(0x00);
        buf.extend_from_slice(&41u16.to_be_bytes());
        let size = if o.udp_size == 0 { 4096 } else { o.udp_size };
        buf.extend_from_slice(&size.to_be_bytes());
        buf.push(0x00); // extended rcode
        buf.push(0x00); // EDNS version 0
        buf.extend_from_slice(&(if o.dnssec { 0x8000u16 } else { 0u16 }).to_be_bytes());
        let mut rdata = Vec::new();
        if o.nsid {
            rdata.extend_from_slice(&3u16.to_be_bytes()); // option code NSID
            rdata.extend_from_slice(&0u16.to_be_bytes()); // zero-length request
        }
        if let Some((addr, prefix)) = o.client_subnet {
            // EDNS Client Subnet (RFC 7871): family, the prefix length we are
            // asserting, a scope of 0 (only the *response* carries a scope),
            // and the truncated address.
            let bytes = ecs_address_bytes(addr, prefix);
            rdata.extend_from_slice(&8u16.to_be_bytes()); // option code
            rdata.extend_from_slice(&((4 + bytes.len()) as u16).to_be_bytes());
            rdata.extend_from_slice(&(if addr.is_ipv4() { 1u16 } else { 2u16 }).to_be_bytes());
            rdata.push(prefix);
            rdata.push(0); // scope prefix, always 0 in a query
            rdata.extend_from_slice(&bytes);
        }
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
    }
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
    Ok(u32::from_be_bytes([
        msg[pos],
        msg[pos + 1],
        msg[pos + 2],
        msg[pos + 3],
    ]))
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
            RData::A(Ipv4Addr::new(
                msg[rdstart],
                msg[rdstart + 1],
                msg[rdstart + 2],
                msg[rdstart + 3],
            ))
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
            RData::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
        257 => {
            let flags = msg[rdstart];
            let taglen = msg[rdstart + 1] as usize;
            let tstart = rdstart + 2;
            let tag = String::from_utf8_lossy(&msg[tstart..tstart + taglen]).to_string();
            let value = String::from_utf8_lossy(&msg[tstart + taglen..end]).to_string();
            RData::Caa { flags, tag, value }
        }
        // DS / CDS / DLV: key tag, algorithm, digest type, digest.
        43 | 59 | 32769 if rdlen >= 4 => RData::Ds {
            key_tag: read_u16(msg, rdstart)?,
            algorithm: msg[rdstart + 2],
            digest_type: msg[rdstart + 3],
            digest: msg[rdstart + 4..end].to_vec(),
        },
        // DNSKEY / CDNSKEY.
        48 | 60 if rdlen >= 4 => RData::Dnskey {
            flags: read_u16(msg, rdstart)?,
            protocol: msg[rdstart + 2],
            algorithm: msg[rdstart + 3],
            key: msg[rdstart + 4..end].to_vec(),
        },
        46 if rdlen >= 18 => {
            let (signer, _) = parse_name(msg, rdstart + 18)?;
            RData::Rrsig {
                type_covered: read_u16(msg, rdstart)?,
                algorithm: msg[rdstart + 2],
                labels: msg[rdstart + 3],
                original_ttl: read_u32(msg, rdstart + 4)?,
                expiration: read_u32(msg, rdstart + 8)?,
                inception: read_u32(msg, rdstart + 12)?,
                key_tag: read_u16(msg, rdstart + 16)?,
                signer,
            }
        }
        47 => {
            let (next, p) = parse_name(msg, rdstart)?;
            RData::Nsec {
                next,
                types: parse_type_bitmap(msg, p, end),
            }
        }
        50 if rdlen >= 5 => {
            let salt_len = msg[rdstart + 4] as usize;
            let salt_start = rdstart + 5;
            if salt_start + salt_len + 1 > end {
                return Err("truncated NSEC3".into());
            }
            let hash_len = msg[salt_start + salt_len] as usize;
            let hash_start = salt_start + salt_len + 1;
            if hash_start + hash_len > end {
                return Err("truncated NSEC3 hash".into());
            }
            RData::Nsec3 {
                hash_alg: msg[rdstart],
                flags: msg[rdstart + 1],
                iterations: read_u16(msg, rdstart + 2)?,
                salt: msg[salt_start..salt_start + salt_len].to_vec(),
                next_hashed: msg[hash_start..hash_start + hash_len].to_vec(),
                types: parse_type_bitmap(msg, hash_start + hash_len, end),
            }
        }
        // TLSA / SMIMEA: the DANE association.
        52 | 53 if rdlen >= 3 => RData::Tlsa {
            usage: msg[rdstart],
            selector: msg[rdstart + 1],
            matching: msg[rdstart + 2],
            data: msg[rdstart + 3..end].to_vec(),
        },
        44 if rdlen >= 2 => RData::Sshfp {
            algorithm: msg[rdstart],
            fp_type: msg[rdstart + 1],
            fingerprint: msg[rdstart + 2..end].to_vec(),
        },
        35 if rdlen >= 4 => {
            let mut p = rdstart + 4;
            let flags = read_char_string(msg, &mut p, end);
            let service = read_char_string(msg, &mut p, end);
            let regexp = read_char_string(msg, &mut p, end);
            let (replacement, _) = parse_name(msg, p)?;
            RData::Naptr {
                order: read_u16(msg, rdstart)?,
                preference: read_u16(msg, rdstart + 2)?,
                flags,
                service,
                regexp,
                replacement,
            }
        }
        // SVCB / HTTPS: priority, target, then a list of key/value parameters.
        64 | 65 if rdlen >= 2 => {
            let (target, p) = parse_name(msg, rdstart + 2)?;
            let mut params = Vec::new();
            let mut i = p;
            while i + 4 <= end {
                let key = read_u16(msg, i)?;
                let len = read_u16(msg, i + 2)? as usize;
                i += 4;
                if i + len > end {
                    break;
                }
                params.push((key, msg[i..i + len].to_vec()));
                i += len;
            }
            RData::Svcb {
                priority: read_u16(msg, rdstart)?,
                target,
                params,
            }
        }
        256 if rdlen >= 4 => RData::Uri {
            priority: read_u16(msg, rdstart)?,
            weight: read_u16(msg, rdstart + 2)?,
            target: String::from_utf8_lossy(&msg[rdstart + 4..end]).to_string(),
        },
        13 => {
            let mut p = rdstart;
            let cpu = read_char_string(msg, &mut p, end);
            let os = read_char_string(msg, &mut p, end);
            RData::Hinfo { cpu, os }
        }
        // DNAME behaves like CNAME for rendering purposes.
        39 => {
            let (name, _) = parse_name(msg, rdstart)?;
            RData::Name(name)
        }
        108 | 109 => RData::Eui(msg[rdstart..end].to_vec()),
        // SPF (obsolete) shares TXT's wire format.
        99 => {
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
        other => RData::Other(other, msg[rdstart..end].to_vec()),
    })
}

/// Read a length-prefixed character-string, advancing `pos`.
fn read_char_string(msg: &[u8], pos: &mut usize, end: usize) -> String {
    if *pos >= end {
        return String::new();
    }
    let len = msg[*pos] as usize;
    *pos += 1;
    if *pos + len > end {
        *pos = end;
        return String::new();
    }
    let s = String::from_utf8_lossy(&msg[*pos..*pos + len]).to_string();
    *pos += len;
    s
}

/// NSEC/NSEC3 type bitmaps: a series of (window, length, bits) blocks where
/// each set bit names a record type present at the name.
fn parse_type_bitmap(msg: &[u8], mut pos: usize, end: usize) -> Vec<u16> {
    let mut out = Vec::new();
    while pos + 2 <= end {
        let window = msg[pos] as u16;
        let len = msg[pos + 1] as usize;
        pos += 2;
        if pos + len > end || len > 32 {
            break;
        }
        for (i, byte) in msg[pos..pos + len].iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    out.push(window * 256 + (i as u16) * 8 + bit as u16);
                }
            }
        }
        pos += len;
    }
    out
}

/// Header flags worth surfacing: authoritative, truncated, recursion
/// available, authentic data.
fn header_flags(msg: &[u8]) -> (bool, bool, bool, bool) {
    if msg.len() < 4 {
        return (false, false, false, false);
    }
    let flags = ((msg[2] as u16) << 8) | msg[3] as u16;
    (
        flags & 0x0400 != 0, // AA
        flags & 0x0200 != 0, // TC
        flags & 0x0080 != 0, // RA
        flags & 0x0020 != 0, // AD
    )
}

/// Pull one EDNS0 option out of the OPT record in the additional section.
/// The OPT rdata is a flat sequence of (code, length, value) triples.
fn edns_option(additionals: &[Record], want: u16) -> Option<Vec<u8>> {
    for r in additionals {
        if r.rtype == 41 {
            if let RData::Other(_, bytes) = &r.data {
                let mut i = 0usize;
                while i + 4 <= bytes.len() {
                    let code = ((bytes[i] as u16) << 8) | bytes[i + 1] as u16;
                    let len = ((bytes[i + 2] as usize) << 8) | bytes[i + 3] as usize;
                    i += 4;
                    if i + len > bytes.len() {
                        break;
                    }
                    if code == want {
                        return Some(bytes[i..i + len].to_vec());
                    }
                    i += len;
                }
            }
        }
    }
    None
}

/// Pull the NSID option out of an OPT record in the additional section.
fn extract_nsid(additionals: &[Record]) -> Option<String> {
    let raw = edns_option(additionals, 3)?;
    if raw.is_empty() {
        return None;
    }
    // NSID is opaque bytes; most servers put ASCII in it.
    Some(
        raw.iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect(),
    )
}

/// The scope prefix a server returns for EDNS Client Subnet: how much of the
/// subnet it actually used to pick the answer. 0 means "this answer does not
/// depend on where you are"; anything larger means the reply is tailored to
/// that many bits of the network you claimed.
fn extract_ecs_scope(additionals: &[Record]) -> Option<u8> {
    let raw = edns_option(additionals, 8)?;
    // family(2) + source prefix(1) + scope prefix(1)
    if raw.len() < 4 {
        return None;
    }
    Some(raw[3])
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
            out.push(Record {
                name,
                rtype,
                ttl,
                data,
            });
            *pos = rdstart + rdlen;
        }
        Ok(out)
    };

    let answers = read_section(an, &mut pos)?;
    let authorities = read_section(ns, &mut pos)?;
    let additionals = read_section(ar, &mut pos)?;
    Ok((rcode, answers, authorities, additionals))
}

// ── naming and formatting helpers for the richer record types ──────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// base32hex with no padding — the encoding NSEC3 uses for hashed names.
fn base32hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::new();
    let mut buffer: u16 = 0;
    let mut bits = 0u8;
    for &b in bytes {
        buffer = (buffer << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            let idx = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// RRSIG timestamps are seconds since the epoch, rendered as dig does.
fn fmt_time(secs: u32) -> String {
    let days = secs as i64 / 86_400;
    let rem = secs as i64 % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}{m:02}{d:02}{:02}{:02}{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// The DNSSEC key tag (RFC 4034 appendix B) — the value a DS record points at,
/// so printing it lets you match a DNSKEY to its delegation by eye.
fn dnskey_tag(flags: u16, protocol: u8, algorithm: u8, key: &[u8]) -> u32 {
    let mut rdata = Vec::with_capacity(key.len() + 4);
    rdata.extend_from_slice(&flags.to_be_bytes());
    rdata.push(protocol);
    rdata.push(algorithm);
    rdata.extend_from_slice(key);
    let mut acc: u32 = 0;
    for (i, b) in rdata.iter().enumerate() {
        acc += if i % 2 == 0 {
            (*b as u32) << 8
        } else {
            *b as u32
        };
    }
    acc += (acc >> 16) & 0xffff;
    acc & 0xffff
}

pub fn dnssec_alg(a: u8) -> &'static str {
    match a {
        1 => "RSAMD5",
        3 => "DSA-SHA1",
        5 => "RSASHA1",
        6 => "DSA-NSEC3-SHA1",
        7 => "RSASHA1-NSEC3-SHA1",
        8 => "RSASHA256",
        10 => "RSASHA512",
        12 => "ECC-GOST",
        13 => "ECDSAP256SHA256",
        14 => "ECDSAP384SHA384",
        15 => "ED25519",
        16 => "ED448",
        _ => "unknown",
    }
}

fn digest_alg(d: u8) -> &'static str {
    match d {
        1 => "SHA-1",
        2 => "SHA-256",
        3 => "GOST R 34.11-94",
        4 => "SHA-384",
        _ => "unknown",
    }
}

fn tlsa_usage(u: u8) -> &'static str {
    match u {
        0 => "PKIX-TA",
        1 => "PKIX-EE",
        2 => "DANE-TA",
        3 => "DANE-EE",
        _ => "unknown",
    }
}

fn tlsa_selector(s: u8) -> &'static str {
    match s {
        0 => "full certificate",
        1 => "SubjectPublicKeyInfo",
        _ => "unknown",
    }
}

fn tlsa_matching(m: u8) -> &'static str {
    match m {
        0 => "exact match",
        1 => "SHA-256",
        2 => "SHA-512",
        _ => "unknown",
    }
}

fn sshfp_alg(a: u8) -> &'static str {
    match a {
        1 => "RSA",
        2 => "DSA",
        3 => "ECDSA",
        4 => "Ed25519",
        6 => "Ed448",
        _ => "unknown",
    }
}

fn sshfp_fptype(t: u8) -> &'static str {
    match t {
        1 => "SHA-1",
        2 => "SHA-256",
        _ => "unknown",
    }
}

/// SVCB/HTTPS parameters. `alpn` says whether the name serves HTTP/2 or /3,
/// and `ech` means Encrypted Client Hello is published for it.
fn svcb_param(key: u16, value: &[u8]) -> String {
    match key {
        0 => {
            let keys: Vec<String> = value
                .chunks_exact(2)
                .map(|c| ((c[0] as u16) << 8 | c[1] as u16).to_string())
                .collect();
            format!("mandatory={}", keys.join(","))
        }
        1 => {
            // A list of length-prefixed protocol names.
            let mut protos = Vec::new();
            let mut i = 0usize;
            while i < value.len() {
                let l = value[i] as usize;
                i += 1;
                if i + l > value.len() {
                    break;
                }
                protos.push(String::from_utf8_lossy(&value[i..i + l]).to_string());
                i += l;
            }
            format!("alpn=\"{}\"", protos.join(","))
        }
        2 => "no-default-alpn".to_string(),
        3 => format!(
            "port={}",
            value
                .first()
                .map(|_| ((value[0] as u16) << 8) | *value.get(1).unwrap_or(&0) as u16)
                .unwrap_or(0)
        ),
        4 => {
            let ips: Vec<String> = value
                .chunks_exact(4)
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string())
                .collect();
            format!("ipv4hint={}", ips.join(","))
        }
        5 => format!("ech={} bytes", value.len()),
        6 => {
            let ips: Vec<String> = value
                .chunks_exact(16)
                .map(|c| Ipv6Addr::from(<[u8; 16]>::try_from(c).unwrap()).to_string())
                .collect();
            format!("ipv6hint={}", ips.join(","))
        }
        7 => format!("dohpath={}", String::from_utf8_lossy(value)),
        other => format!("key{other}={}", hex(value)),
    }
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
    query_opts(
        server,
        name,
        qtype,
        &QueryOpts {
            force_tcp,
            timeout_ms,
            ..Default::default()
        },
    )
    .await
}

/// The full-control query used by `+dnssec`, `+nsid`, `+norec` and `+trace`.
pub async fn query_opts(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    o: &QueryOpts,
) -> Result<Response, String> {
    let start = std::time::Instant::now();
    let mut plain_opts: Option<QueryOpts> = None;

    loop {
        let cur = plain_opts.as_ref().unwrap_or(o);
        let (force_tcp, timeout_ms) = (cur.force_tcp, cur.timeout_ms);
        let needs_edns = cur.dnssec || cur.nsid || cur.client_subnet.is_some() || cur.udp_size > 0;
        let packet = build_query_opts(rand_id(), name, qtype, cur);
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
                // A server too old for EDNS0 answers FORMERR or NOTIMP to the OPT
                // record rather than to the question. Retry once without it before
                // concluding the name does not resolve.
                let rcode_early = if n >= 4 { msg[3] & 0x0f } else { 0 };
                if (rcode_early == 1 || rcode_early == 4) && needs_edns {
                    let plain = QueryOpts {
                        udp_size: 0,
                        dnssec: false,
                        nsid: false,
                        client_subnet: None,
                        ..*cur
                    };
                    plain_opts = Some(plain);
                    continue;
                }
                // Check TC (truncation) bit.
                let tc = n >= 4 && (msg[2] & 0x02) != 0;
                if !tc {
                    let (rcode, answers, authorities, additionals) = parse_response(msg)?;
                    let (aa, tc_flag, ra, ad) = header_flags(msg);
                    let nsid = extract_nsid(&additionals);
                    let ecs_scope = extract_ecs_scope(&additionals);
                    return Ok(Response {
                        rcode,
                        answers,
                        authorities,
                        additionals,
                        elapsed_ms: start.elapsed().as_millis(),
                        server,
                        via_tcp: false,
                        aa,
                        ad,
                        ra,
                        tc: tc_flag,
                        nsid,
                        ecs_scope,
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
        let ecs_scope = extract_ecs_scope(&additionals);
        let (aa, tc_flag, ra, ad) = header_flags(&msg);
        let nsid = extract_nsid(&additionals);
        return Ok(Response {
            rcode,
            answers,
            authorities,
            additionals,
            elapsed_ms: start.elapsed().as_millis(),
            server,
            via_tcp: true,
            aa,
            ad,
            ra,
            tc: tc_flag,
            nsid,
            ecs_scope,
        });
    }
}

// ── encrypted transports ───────────────────────────────────────────────────

/// Details of how an encrypted query travelled, for printing alongside the
/// answer. The trust note is deliberately part of the result: a caller should
/// not be able to report "encrypted" without also being handed the caveat.
#[derive(Debug, Clone)]
pub struct SecureInfo {
    pub transport: &'static str,
    pub suite: &'static str,
    /// The protocol the server agreed to over ALPN, when it named one.
    pub alpn: Option<String>,
    pub certificate: String,
    pub note: &'static str,
}

/// The default resolvers for `+dot` and `--doh` when none is named. Both are
/// stated in --help, because sending your queries somewhere by default is the
/// kind of thing a user has a right to know without reading the source.
pub const DEFAULT_DOT_HOST: &str = "one.one.one.one";
pub const DEFAULT_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";

/// DNS over TLS (RFC 7858). The framing is exactly DNS-over-TCP's two-byte
/// length prefix; the only difference is the socket it travels down, so this
/// reuses the same query builder and response parser as everything else.
pub async fn query_dot(
    server: SocketAddr,
    tls_name: &str,
    name: &str,
    qtype: u16,
    o: &QueryOpts,
) -> Result<(Response, SecureInfo), String> {
    let start = std::time::Instant::now();
    let packet = build_query_opts(rand_id(), name, qtype, o);
    let dur = Duration::from_millis(o.timeout_ms.max(3000));

    let stream = timeout(dur, TcpStream::connect(server))
        .await
        .map_err(|_| "DoT connect timed out".to_string())?
        .map_err(|e| format!("DoT connect failed: {e}"))?;

    let mut tls =
        crate::tls::tls13::handshake(stream, tls_name, &["dot"], o.timeout_ms.max(3000)).await?;

    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    framed.extend_from_slice(&packet);
    tls.write(&framed, o.timeout_ms.max(3000)).await?;

    // Read until at least the length prefix and the message it announces are in.
    let mut buf = tls.read(2, o.timeout_ms.max(3000)).await?;
    if buf.len() < 2 {
        return Err("DoT reply was truncated".into());
    }
    let want = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    while buf.len() < 2 + want {
        let more = tls.read(0, o.timeout_ms.max(3000)).await?;
        if more.is_empty() {
            break;
        }
        buf.extend_from_slice(&more);
    }
    if buf.len() < 2 + want {
        return Err("DoT reply was truncated".into());
    }
    let msg = &buf[2..2 + want];

    let info = SecureInfo {
        transport: "DoT (TLS 1.3, port 853)",
        suite: tls.suite_name(),
        alpn: tls.alpn_name().map(|s| s.to_string()),
        certificate: tls.cert_summary.clone(),
        note: tls.trust_note(),
    };
    Ok((response_from(msg, server, true, start)?, info))
}

/// DNS over HTTPS (RFC 8484): the same wire-format query, POSTed as
/// `application/dns-message`. HTTP/1.1 is requested through ALPN so the reply
/// is a plain response rather than a multiplexed HTTP/2 stream.
pub async fn query_doh(
    url: &str,
    name: &str,
    qtype: u16,
    o: &QueryOpts,
) -> Result<(Response, SecureInfo), String> {
    let start = std::time::Instant::now();
    let (host, port, path) = split_https_url(url)?;
    let packet = build_query_opts(rand_id(), name, qtype, o);
    let dur = Duration::from_millis(o.timeout_ms.max(3000));

    let addr = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("cannot resolve {host}"))?;

    let stream = timeout(dur, TcpStream::connect(addr))
        .await
        .map_err(|_| "DoH connect timed out".to_string())?
        .map_err(|e| format!("DoH connect failed: {e}"))?;

    let mut tls =
        crate::tls::tls13::handshake(stream, &host, &["http/1.1"], o.timeout_ms.max(3000)).await?;

    let mut req = Vec::new();
    req.extend_from_slice(
        format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-message\r\n\
             Content-Type: application/dns-message\r\nContent-Length: {}\r\n\
             User-Agent: kaisen/{}\r\nConnection: close\r\n\r\n",
            packet.len(),
            crate::cli::VERSION
        )
        .as_bytes(),
    );
    req.extend_from_slice(&packet);
    tls.write(&req, o.timeout_ms.max(3000)).await?;

    let mut raw = Vec::new();
    loop {
        let chunk = tls.read(0, o.timeout_ms.max(3000)).await?;
        if chunk.is_empty() {
            break;
        }
        raw.extend_from_slice(&chunk);
        if let Some(body) = http_body(&raw) {
            if !body.is_empty() {
                break;
            }
        }
        if raw.len() > 65536 {
            break;
        }
    }

    let status = http_status(&raw).ok_or("DoH: no HTTP status line")?;
    if status != 200 {
        return Err(format!("DoH server answered HTTP {status}"));
    }
    let body = http_body(&raw).ok_or("DoH: incomplete HTTP response")?;
    if body.is_empty() {
        return Err("DoH: empty response body".into());
    }

    let info = SecureInfo {
        transport: "DoH (TLS 1.3, HTTP/1.1)",
        suite: tls.suite_name(),
        alpn: tls.alpn_name().map(|s| s.to_string()),
        certificate: tls.cert_summary.clone(),
        note: tls.trust_note(),
    };
    Ok((response_from(&body, addr, true, start)?, info))
}

/// Turn a raw DNS message into a Response, shared by both encrypted transports.
fn response_from(
    msg: &[u8],
    server: SocketAddr,
    via_tcp: bool,
    start: std::time::Instant,
) -> Result<Response, String> {
    let (rcode, answers, authorities, additionals) = parse_response(msg)?;
    let (aa, tc, ra, ad) = header_flags(msg);
    let nsid = extract_nsid(&additionals);
    let ecs_scope = extract_ecs_scope(&additionals);
    Ok(Response {
        rcode,
        answers,
        authorities,
        additionals,
        elapsed_ms: start.elapsed().as_millis(),
        server,
        via_tcp,
        aa,
        ad,
        ra,
        tc,
        nsid,
        ecs_scope,
    })
}

/// A parsed https:// endpoint: host, port and path.
type HttpsEndpoint = (String, u16, String);

/// Split an https:// URL into its parts. Only https is accepted — the whole
/// point of the option is that the query is encrypted.
pub fn split_https_url(url: &str) -> Result<HttpsEndpoint, String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("--doh needs an https:// URL, got '{url}'"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/dns-query"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        // Guard against an IPv6 literal, where the colon is not a port marker.
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| "invalid port in --doh URL")?,
        ),
        _ => (authority.to_string(), 443),
    };
    if host.is_empty() {
        return Err("--doh URL has no host".into());
    }
    Ok((host, port, path.to_string()))
}

fn http_status(raw: &[u8]) -> Option<u16> {
    let head = raw.split(|&b| b == b'\n').next()?;
    let text = String::from_utf8_lossy(head);
    text.split_whitespace().nth(1)?.parse().ok()
}

/// Extract the body of an HTTP/1.1 response, handling both Content-Length and
/// chunked transfer coding. Returns None while the response is still partial.
fn http_body(raw: &[u8]) -> Option<Vec<u8>> {
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..sep]).to_ascii_lowercase();
    let body = &raw[sep + 4..];

    if head.contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        let mut i = 0usize;
        loop {
            let nl = body[i..].windows(2).position(|w| w == b"\r\n")? + i;
            let size_txt = String::from_utf8_lossy(&body[i..nl]);
            let size = usize::from_str_radix(size_txt.trim().split(';').next()?.trim(), 16).ok()?;
            i = nl + 2;
            if size == 0 {
                return Some(out);
            }
            if i + size > body.len() {
                return None;
            }
            out.extend_from_slice(&body[i..i + size]);
            i += size + 2;
        }
    }

    if let Some(pos) = head.find("content-length:") {
        let len: usize = head[pos + 15..].lines().next()?.trim().parse().ok()?;
        if body.len() < len {
            return None;
        }
        return Some(body[..len].to_vec());
    }

    // No framing headers: the server said Connection: close, so the body runs
    // to the end of what we read.
    Some(body.to_vec())
}

// ── zone transfer ──────────────────────────────────────────────────────────

/// Attempt a full zone transfer (AXFR). A server that allows this to a stranger
/// hands over every name in the zone — hosts, internal addresses, staging
/// systems — which is why it is one of the first things worth checking against
/// a name server you are authorised to test.
///
/// AXFR is TCP-only and streams: the zone arrives as a series of
/// length-prefixed messages that begin and end with the zone's SOA.
pub async fn axfr(server: SocketAddr, zone: &str, timeout_ms: u64) -> Result<Vec<Record>, String> {
    let dur = Duration::from_millis(timeout_ms.max(3000));
    let packet = build_query_opts(rand_id(), zone, 252, &QueryOpts::default());

    let mut stream = timeout(dur, TcpStream::connect(server))
        .await
        .map_err(|_| "AXFR: TCP connect timed out".to_string())?
        .map_err(|e| format!("AXFR: {e}"))?;
    stream
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(&packet).await.map_err(|e| e.to_string())?;

    let mut records: Vec<Record> = Vec::new();
    let mut soa_seen = 0usize;

    // Read message after message until the closing SOA, the peer hangs up, or
    // we hit a sanity cap — a hostile or enormous zone shouldn't run us out of
    // memory.
    for _ in 0..4096 {
        let mut lenbuf = [0u8; 2];
        match timeout(dur, stream.read_exact(&mut lenbuf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let rlen = u16::from_be_bytes(lenbuf) as usize;
        if rlen == 0 {
            break;
        }
        let mut msg = vec![0u8; rlen];
        if timeout(dur, stream.read_exact(&mut msg)).await.is_err() {
            break;
        }
        let (rcode, answers, _, _) = parse_response(&msg)?;
        if rcode != 0 {
            return Err(format!("AXFR refused: {}", rcode_str(rcode)));
        }
        for r in answers {
            if r.rtype == 6 {
                soa_seen += 1;
            }
            records.push(r);
            if records.len() >= 100_000 {
                return Ok(records);
            }
        }
        // The transfer is framed by SOA records: one to open, one to close.
        if soa_seen >= 2 {
            break;
        }
    }

    if records.is_empty() {
        return Err("AXFR returned no records (transfer refused)".into());
    }
    Ok(records)
}

// ── iterative resolution (+trace) ──────────────────────────────────────────

/// The root name servers, as of the current root hints. Used as the starting
/// point for `+trace`.
pub const ROOT_SERVERS: &[(&str, &str)] = &[
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "170.247.170.2"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
];

/// One hop of an iterative resolution.
pub struct TraceStep {
    pub server_name: String,
    pub server: SocketAddr,
    pub response: Response,
    /// The zone this server was asked about, for display.
    pub zone: String,
}

/// Walk the delegation chain from the root down to the authoritative answer,
/// exactly as a resolver does — which is what makes `+trace` useful for
/// diagnosing a broken delegation rather than a broken record.
pub async fn trace(name: &str, qtype: u16, timeout_ms: u64) -> Vec<TraceStep> {
    let mut steps = Vec::new();
    let mut current: Vec<(String, IpAddr)> = ROOT_SERVERS
        .iter()
        .filter_map(|(n, ip)| ip.parse().ok().map(|ip| (n.to_string(), ip)))
        .collect();
    let mut zone = ".".to_string();

    for _hop in 0..12 {
        let Some((server_name, server_ip)) = current.first().cloned() else {
            break;
        };
        let server = SocketAddr::new(server_ip, 53);
        let opts = QueryOpts {
            timeout_ms,
            // Iterative resolution means asking each server for what it knows,
            // never asking it to do the walking for us.
            no_recurse: true,
            udp_size: 4096,
            ..Default::default()
        };
        let Ok(resp) = query_opts(server, name, qtype, &opts).await else {
            // This server didn't answer; try the next one at this level.
            current.remove(0);
            if current.is_empty() {
                break;
            }
            continue;
        };

        let answered = !resp.answers.is_empty();
        let delegation: Vec<String> = resp
            .authorities
            .iter()
            .filter(|r| r.rtype == 2)
            .filter_map(|r| match &r.data {
                RData::Name(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        let next_zone = resp
            .authorities
            .iter()
            .find(|r| r.rtype == 2)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| zone.clone());

        // Glue from the additional section saves a round trip; without it we
        // would have to resolve the nameserver's own name first.
        let mut next: Vec<(String, IpAddr)> = Vec::new();
        for ns in &delegation {
            if let Some(glue) = resp
                .additionals
                .iter()
                .find(|a| a.name.eq_ignore_ascii_case(ns) && matches!(a.data, RData::A(_)))
            {
                if let RData::A(ip) = glue.data {
                    next.push((ns.clone(), IpAddr::V4(ip)));
                }
            }
        }

        steps.push(TraceStep {
            server_name,
            server,
            response: resp,
            zone: zone.clone(),
        });

        if answered {
            break;
        }
        if next.is_empty() {
            // Delegation without glue: resolve one nameserver name normally and
            // carry on, otherwise the trace dead-ends where dig would continue.
            let mut resolved = Vec::new();
            for ns in delegation.iter().take(2) {
                if let Ok(mut addrs) = tokio::net::lookup_host((ns.as_str(), 53)).await {
                    if let Some(sa) = addrs.next() {
                        resolved.push((ns.clone(), sa.ip()));
                        break;
                    }
                }
            }
            if resolved.is_empty() {
                break;
            }
            next = resolved;
        }
        current = next;
        zone = next_zone;
    }

    steps
}

/// Query in the CHAOS class rather than IN. Only used for the `version.bind`
/// and `hostname.bind` pseudo-records that name servers publish about
/// themselves.
pub async fn query_chaos(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    o: &QueryOpts,
) -> Result<Response, String> {
    let id = rand_id();
    let mut packet = build_query_opts(id, name, qtype, o);
    // Rewrite QCLASS from IN (1) to CHAOS (3). It sits immediately after the
    // QNAME and QTYPE, which is 12 header bytes + the encoded name + 2.
    let mut pos = 12;
    while pos < packet.len() && packet[pos] != 0 {
        pos += packet[pos] as usize + 1;
    }
    let qclass_at = pos + 1 + 2;
    if qclass_at + 2 <= packet.len() {
        packet[qclass_at] = 0;
        packet[qclass_at + 1] = 3;
    }

    let dur = Duration::from_millis(o.timeout_ms.max(500));
    let bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let start = std::time::Instant::now();
    let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.connect(server).await.map_err(|e| e.to_string())?;
    sock.send(&packet).await.map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(dur, sock.recv(&mut buf))
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let msg = &buf[..n];
    let (rcode, answers, authorities, additionals) = parse_response(msg)?;
    let (aa, tc, ra, ad) = header_flags(msg);
    let ecs_scope = extract_ecs_scope(&additionals);
    Ok(Response {
        rcode,
        answers,
        authorities,
        additionals,
        elapsed_ms: start.elapsed().as_millis(),
        server,
        via_tcp: false,
        aa,
        ad,
        ra,
        tc,
        nsid: None,
        ecs_scope,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_subnet_masks_the_host_bits() {
        // RFC 7871 s6: only the prefix travels, and the trailing bits are zero.
        let (a, p) = parse_client_subnet("203.0.113.77/24").unwrap();
        assert_eq!(ecs_address_bytes(a, p), vec![203, 0, 113]);
        let (a, p) = parse_client_subnet("203.0.113.77/20").unwrap();
        assert_eq!(ecs_address_bytes(a, p), vec![203, 0, 112]);
        // A bare address takes dig's defaults.
        assert_eq!(parse_client_subnet("203.0.113.77").unwrap().1, 24);
        assert_eq!(parse_client_subnet("2001:db8::1").unwrap().1, 56);
        // The explicit "say nothing" form.
        assert_eq!(parse_client_subnet("0").unwrap().1, 0);
        assert!(parse_client_subnet("203.0.113.0/33").is_err());
        assert!(parse_client_subnet("nonsense").is_err());
    }

    #[test]
    fn doh_urls_split_into_host_port_path() {
        assert_eq!(
            split_https_url("https://dns.google/dns-query").unwrap(),
            ("dns.google".into(), 443, "/dns-query".into())
        );
        assert_eq!(
            split_https_url("https://example.test:8443/q").unwrap(),
            ("example.test".into(), 8443, "/q".into())
        );
        // No path given: the RFC 8484 well-known one.
        assert_eq!(
            split_https_url("https://example.test").unwrap(),
            ("example.test".into(), 443, "/dns-query".into())
        );
        // Plain HTTP defeats the purpose, so it is refused rather than upgraded.
        assert!(split_https_url("http://example.test/dns-query").is_err());
    }

    #[test]
    fn http_bodies_parse_both_framings() {
        let cl = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd".to_vec();
        assert_eq!(http_status(&cl), Some(200));
        assert_eq!(http_body(&cl), Some(b"abcd".to_vec()));
        // Still short of Content-Length: not an answer yet.
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabcd".to_vec();
        assert_eq!(http_body(&partial), None);

        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
                .to_vec();
        assert_eq!(http_body(&chunked), Some(b"abcde".to_vec()));
    }
}
