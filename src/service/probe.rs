//! Protocol-specific probes for services that don't hand out a text banner.
//!
//! A plain banner grab only works for the handful of protocols where the server
//! speaks first in ASCII (SSH, SMTP, FTP…). Everything else — SMB, RDP, MSSQL,
//! MongoDB, Oracle, Kafka, Minecraft — stays silent until the client says the
//! right thing in the right binary shape. Each function here speaks just enough
//! of one protocol to make the server identify itself, then stops: no auth, no
//! writes, no exploitation. All of it is unprivileged.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// What a probe managed to learn. Empty fields are simply left alone by the
/// caller, so a probe that only confirms "yes, this is protocol X" is still useful.
#[derive(Debug, Clone, Default)]
pub struct Probed {
    pub name: &'static str,
    pub product: String,
    pub version: String,
    pub extra: String,
    pub os_hint: String,
    pub banner: String,
}

impl Probed {
    fn named(name: &'static str, product: &str) -> Self {
        Probed {
            name,
            product: product.to_string(),
            ..Default::default()
        }
    }
}

// ── low-level helpers ───────────────────────────────────────────────────────

async fn send(stream: &mut TcpStream, data: &[u8], dur: Duration) -> Option<()> {
    timeout(dur, stream.write_all(data)).await.ok()?.ok()
}

/// Read whatever arrives, up to `cap` bytes, stopping at the first quiet moment.
/// The first read waits the full timeout; later ones only wait long enough to
/// pick up the rest of a response split across segments.
async fn read_any(stream: &mut TcpStream, dur: Duration, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
    let tail = Duration::from_millis(250);
    for round in 0..6 {
        let wait = if round == 0 { dur } else { tail };
        match timeout(wait, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                out.extend_from_slice(&buf[..n]);
                if out.len() >= cap {
                    break;
                }
            }
            _ => break,
        }
    }
    out
}

/// Read at least `n` bytes (or give up), for length-prefixed protocols.
async fn read_at_least(stream: &mut TcpStream, n: usize, dur: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 8192];
    while out.len() < n {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(k)) if k > 0 => out.extend_from_slice(&buf[..k]),
            _ => break,
        }
        if out.len() > 1_048_576 {
            break;
        }
    }
    out
}

fn be16(b: &[u8], i: usize) -> u16 {
    if i + 2 <= b.len() {
        ((b[i] as u16) << 8) | b[i + 1] as u16
    } else {
        0
    }
}

// ── active vulnerability confirmation probes ─────────────────────────────────
// These only run under `-vuln`, and each speaks exactly one request: enough to
// prove a service answers without authentication, never to change its state.

/// Split an HTTP response into (status code, body).
fn parse_http(raw: &[u8]) -> Option<(u16, String)> {
    let text = String::from_utf8_lossy(raw);
    let code: u16 = text
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Some((code, body))
}

fn http_get_request(host: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: kaisen/{}\r\nAccept: */*\r\n\
         Connection: close\r\n\r\n",
        crate::cli::VERSION
    )
}

/// Cleartext HTTP GET, returning (status, body) when the response parses.
pub async fn http_get(
    addr: SocketAddr,
    host: &str,
    path: &str,
    dur: Duration,
) -> Option<(u16, String)> {
    let mut s = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    crate::util::netutil::reset_on_close(&s);
    send(&mut s, http_get_request(host, path).as_bytes(), dur).await?;
    parse_http(&read_any(&mut s, dur, 65536).await)
}

/// HTTPS GET over the from-scratch TLS 1.3 client, for confirming services that
/// only speak TLS (e.g. a Kubernetes API server's `/version`).
pub async fn https_get(
    addr: SocketAddr,
    sni: &str,
    path: &str,
    dur: Duration,
) -> Option<(u16, String)> {
    let ms = (dur.as_millis() as u64).max(3000);
    let stream = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
    crate::util::netutil::reset_on_close(&stream);
    let mut tls = crate::tls::tls13::handshake(stream, sni, &["http/1.1"], ms)
        .await
        .ok()?;
    tls.write(http_get_request(sni, path).as_bytes(), ms)
        .await
        .ok()?;
    let mut raw = Vec::new();
    for _ in 0..8 {
        match tls.read(0, ms).await {
            Ok(chunk) if !chunk.is_empty() => raw.extend_from_slice(&chunk),
            _ => break,
        }
        if raw.len() > 65536 {
            break;
        }
    }
    parse_http(&raw)
}

/// Does Redis answer `PING` with `+PONG` and no authentication? An unauthed
/// server replies `+PONG`; one that requires a password replies
/// `-NOAUTH Authentication required.`
pub async fn redis_unauth(addr: SocketAddr, dur: Duration) -> bool {
    let Ok(Ok(mut s)) = timeout(dur, TcpStream::connect(addr)).await else {
        return false;
    };
    crate::util::netutil::reset_on_close(&s);
    if send(&mut s, b"*1\r\n$4\r\nPING\r\n", dur).await.is_none() {
        return false;
    }
    let resp = read_at_least(&mut s, 5, dur).await;
    resp.starts_with(b"+PONG")
}

/// Does the Ezviz command port process a cleartext request? On a device whose
/// certificate already identified it as Ezviz, a non-empty reply to an
/// unencrypted probe on 9010 means the AES pre-shared-key is not enforced
/// (CVE-2023-48121 class). Deliberately minimal: one small write, one read.
pub async fn ezviz_cleartext(addr: SocketAddr, dur: Duration) -> bool {
    let Ok(Ok(mut s)) = timeout(dur, TcpStream::connect(addr)).await else {
        return false;
    };
    crate::util::netutil::reset_on_close(&s);
    // A short, benign framing byte plus padding — enough to see whether the
    // device answers in the clear at all.
    if send(&mut s, &[0x00, 0x00, 0x00, 0x00], dur).await.is_none() {
        return false;
    }
    !read_any(&mut s, dur, 256).await.is_empty()
}

fn le16(b: &[u8], i: usize) -> u16 {
    if i + 2 <= b.len() {
        ((b[i + 1] as u16) << 8) | b[i] as u16
    } else {
        0
    }
}

fn be32(b: &[u8], i: usize) -> u32 {
    if i + 4 <= b.len() {
        ((b[i] as u32) << 24)
            | ((b[i + 1] as u32) << 16)
            | ((b[i + 2] as u32) << 8)
            | b[i + 3] as u32
    } else {
        0
    }
}

fn le32(b: &[u8], i: usize) -> u32 {
    if i + 4 <= b.len() {
        ((b[i + 3] as u32) << 24)
            | ((b[i + 2] as u32) << 16)
            | ((b[i + 1] as u32) << 8)
            | b[i] as u32
    } else {
        0
    }
}

/// Printable-ASCII view of a binary blob, for loose keyword scans.
fn ascii(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                ' '
            }
        })
        .collect()
}

// ── SMB2 ────────────────────────────────────────────────────────────────────

/// SMB2 NEGOTIATE. The dialect the server picks pins down a Windows generation
/// (or tells you it's Samba, once combined with the banner-free ports around it).
pub async fn smb(stream: &mut TcpStream, port: u16, dur: Duration) -> Option<Probed> {
    // On 139 the SMB session rides on NetBIOS, which wants a session request
    // naming the server before it will pass anything through.
    if port == 139 {
        let mut req = vec![0x81, 0x00, 0x00, 0x44];
        req.extend_from_slice(&netbios_name(b"*SMBSERVER", 0x20));
        req.extend_from_slice(&netbios_name(b"KAISEN", 0x00));
        send(stream, &req, dur).await?;
        let resp = read_at_least(stream, 4, dur).await;
        // Nothing came back at all. The port accepted the connection and then
        // said nothing, which is exactly what a middlebox completing
        // handshakes on a host's behalf looks like — so claim nothing. Naming
        // it from the port number alone would manufacture the one piece of
        // evidence that distinguishes a real service from a phantom.
        if resp.is_empty() {
            return None;
        }
        // 0x82 = positive session response; anything else and SMB2 won't flow,
        // but the peer did answer, so NetBIOS on 139 is a fair reading.
        if resp.first() != Some(&0x82) {
            return Some(Probed::named("netbios-ssn", "NetBIOS session service"));
        }
    }

    let dialects: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];
    let mut body = Vec::new();
    body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&[0x6b; 16]); // ClientGuid
    body.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
    for d in dialects {
        body.extend_from_slice(&d.to_le_bytes());
    }

    let mut header = Vec::with_capacity(64);
    header.extend_from_slice(&[0xfe, b'S', b'M', b'B']);
    header.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    header.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    header.extend_from_slice(&0u32.to_le_bytes()); // Status
    header.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
    header.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    header.extend_from_slice(&0u32.to_le_bytes()); // Flags
    header.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    header.extend_from_slice(&1u64.to_le_bytes()); // MessageId
    header.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    header.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    header.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    header.extend_from_slice(&[0u8; 16]); // Signature

    let smb_len = header.len() + body.len();
    let mut packet = vec![
        0x00,
        ((smb_len >> 16) & 0xff) as u8,
        ((smb_len >> 8) & 0xff) as u8,
        (smb_len & 0xff) as u8,
    ];
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&body);

    send(stream, &packet, dur).await?;
    let resp = read_at_least(stream, 76, dur).await;
    if resp.len() < 8 {
        return None;
    }

    // Legacy servers answer an SMB2 negotiate with an SMB1 response.
    if resp.len() > 8 && &resp[4..8] == b"\xffSMB" {
        return Some(Probed {
            name: "netbios-ssn",
            product: "SMB".into(),
            version: "1.0".into(),
            extra: "SMB1 only (legacy dialect)".into(),
            ..Default::default()
        });
    }
    if &resp[4..8.min(resp.len())] != b"\xfeSMB" {
        return None;
    }

    let dialect = le16(&resp, 4 + 64 + 4);
    let (ver, os) = smb_dialect(dialect);
    let mut p = Probed {
        name: if port == 445 {
            "microsoft-ds"
        } else {
            "netbios-ssn"
        },
        product: "SMB".into(),
        version: ver.to_string(),
        os_hint: os.to_string(),
        ..Default::default()
    };
    let security_mode = le16(&resp, 4 + 64 + 2);
    if security_mode & 0x0002 != 0 {
        p.extra = "signing required".into();
    }
    Some(p)
}

fn smb_dialect(d: u16) -> (&'static str, &'static str) {
    match d {
        0x0202 => ("2.0.2", "Windows Vista / Server 2008 (or Samba)"),
        0x0210 => ("2.1", "Windows 7 / Server 2008 R2 (or Samba)"),
        0x0300 => ("3.0", "Windows 8 / Server 2012 (or Samba)"),
        0x0302 => ("3.0.2", "Windows 8.1 / Server 2012 R2 (or Samba)"),
        0x0311 => ("3.1.1", "Windows 10+ / Server 2016+ (or Samba)"),
        0x02ff => ("2.???", ""),
        _ => ("", ""),
    }
}

/// NetBIOS level-1 encoded name: each nibble becomes a letter from 'A'.
fn netbios_name(name: &[u8], suffix: u8) -> Vec<u8> {
    let mut padded = [b' '; 16];
    for (i, &c) in name.iter().take(15).enumerate() {
        padded[i] = c.to_ascii_uppercase();
    }
    padded[15] = suffix;
    let mut out = Vec::with_capacity(34);
    out.push(32);
    for c in padded {
        out.push(b'A' + (c >> 4));
        out.push(b'A' + (c & 0x0f));
    }
    out.push(0x00);
    out
}

// ── Microsoft SQL Server (TDS pre-login) ────────────────────────────────────

/// TDS PRELOGIN hands back the exact server build before any login attempt,
/// which maps cleanly onto a marketing release ("15.0.2000" → SQL Server 2019).
pub async fn mssql(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    // Option tokens: VERSION(0), ENCRYPTION(1), then the 0xFF terminator.
    let payload_offset = 5 + 5 + 1; // two option records plus terminator
    let mut opts = Vec::new();
    opts.extend_from_slice(&[0x00]);
    opts.extend_from_slice(&(payload_offset as u16).to_be_bytes());
    opts.extend_from_slice(&6u16.to_be_bytes());
    opts.extend_from_slice(&[0x01]);
    opts.extend_from_slice(&((payload_offset + 6) as u16).to_be_bytes());
    opts.extend_from_slice(&1u16.to_be_bytes());
    opts.push(0xff);
    opts.extend_from_slice(&[0u8; 6]); // our (irrelevant) version
    opts.push(0x00); // encryption: off

    let total = 8 + opts.len();
    let mut pkt = vec![0x12, 0x01];
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    pkt.extend_from_slice(&opts);

    send(stream, &pkt, dur).await?;
    let resp = read_at_least(stream, 16, dur).await;
    if resp.len() < 14 || resp[0] != 0x04 {
        return None;
    }
    let body = &resp[8..];

    // Walk the option records looking for VERSION (token 0).
    let mut i = 0usize;
    let mut version = String::new();
    let mut encryption = "";
    while i + 5 <= body.len() && body[i] != 0xff {
        let token = body[i];
        let off = be16(body, i + 1) as usize;
        let len = be16(body, i + 3) as usize;
        if off + len <= body.len() {
            let data = &body[off..off + len];
            match token {
                0 if len >= 6 => {
                    version = format!(
                        "{}.{}.{}",
                        data[0],
                        data[1],
                        ((data[2] as u16) << 8) | data[3] as u16
                    );
                }
                1 if len >= 1 => {
                    encryption = match data[0] {
                        0x00 => "encryption off",
                        0x01 => "encryption on",
                        0x02 => "encryption not supported",
                        0x03 => "encryption required",
                        _ => "",
                    };
                }
                _ => {}
            }
        }
        i += 5;
    }
    if version.is_empty() {
        return Some(Probed::named("ms-sql-s", "Microsoft SQL Server"));
    }
    let major: u32 = version
        .split('.')
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let minor: u32 = version
        .split('.')
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let release = mssql_release(major, minor);
    let mut extra = String::new();
    if !release.is_empty() {
        extra.push_str(release);
    }
    if !encryption.is_empty() {
        if !extra.is_empty() {
            extra.push_str("; ");
        }
        extra.push_str(encryption);
    }
    Some(Probed {
        name: "ms-sql-s",
        product: "Microsoft SQL Server".into(),
        version,
        extra,
        os_hint: "Windows".into(),
        ..Default::default()
    })
}

fn mssql_release(major: u32, minor: u32) -> &'static str {
    match (major, minor) {
        (7, _) => "SQL Server 7.0",
        (8, _) => "SQL Server 2000",
        (9, _) => "SQL Server 2005",
        (10, 0) => "SQL Server 2008",
        (10, 50) => "SQL Server 2008 R2",
        (11, _) => "SQL Server 2012",
        (12, _) => "SQL Server 2014",
        (13, _) => "SQL Server 2016",
        (14, _) => "SQL Server 2017",
        (15, _) => "SQL Server 2019",
        (16, _) => "SQL Server 2022",
        (17, _) => "SQL Server 2025",
        _ => "",
    }
}

// ── MongoDB ─────────────────────────────────────────────────────────────────

/// `isMaster` is the one command MongoDB still answers over the legacy OP_QUERY
/// opcode without auth, and its `maxWireVersion` maps 1:1 onto a release line.
/// If the deployment is unauthenticated, `buildInfo` then gives the exact build.
pub async fn mongodb(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    let query = op_query("admin.$cmd", &bson_int32_doc("isMaster", 1));
    send(stream, &query, dur).await?;
    let resp = read_at_least(stream, 36, dur).await;
    // The header's opCode is little-endian; 1 == OP_REPLY.
    if resp.len() < 36 || le32(&resp, 12) != 1 {
        return None;
    }
    let doc = &resp[36..];
    let mut p = Probed::named("mongodb", "MongoDB");

    if let Some(wire) = bson_i32(doc, "maxWireVersion") {
        p.version = mongo_wire_release(wire).to_string();
        if p.version.is_empty() {
            p.extra = format!("maxWireVersion {wire}");
        }
    }
    let mut flags = Vec::new();
    if bson_bool(doc, "ismaster") == Some(true) || bson_bool(doc, "isWritablePrimary") == Some(true)
    {
        flags.push("primary".to_string());
    }
    if let Some(set) = bson_str(doc, "setName") {
        flags.push(format!("replica set {set}"));
    }

    // buildInfo is richer but privileged on secured deployments; a refusal here
    // is itself informative (it means auth is actually enforced).
    let build = op_query("admin.$cmd", &bson_int32_doc("buildInfo", 1));
    if send(stream, &build, dur).await.is_some() {
        let r2 = read_at_least(stream, 36, dur).await;
        if r2.len() > 36 {
            let d2 = &r2[36..];
            if let Some(v) = bson_str(d2, "version") {
                p.version = v;
            }
            if let Some(err) = bson_str(d2, "errmsg") {
                if err.to_ascii_lowercase().contains("unauthorized")
                    || err.to_ascii_lowercase().contains("auth")
                {
                    flags.push("auth enforced".to_string());
                }
            } else if !p.version.is_empty() {
                flags.push("UNAUTHENTICATED buildInfo".to_string());
            }
        }
    }
    if !flags.is_empty() {
        if !p.extra.is_empty() {
            p.extra.push_str("; ");
        }
        p.extra.push_str(&flags.join("; "));
    }
    Some(p)
}

/// MongoDB's wire protocol version is bumped once per release line, so it is a
/// reliable stand-in for the server version even when `buildInfo` is locked down.
fn mongo_wire_release(w: i32) -> &'static str {
    match w {
        0 => "2.4 or older",
        1 => "2.6",
        2 => "3.0",
        3 => "3.2",
        4 => "3.4",
        5 => "3.4",
        6 => "3.6",
        7 => "4.0",
        8 => "4.2",
        9 => "4.4",
        12 => "4.9",
        13 => "5.0",
        14 => "5.1",
        15 => "5.2",
        16 => "5.3",
        17 => "6.0",
        18..=20 => "6.x",
        21 => "7.0",
        22..=24 => "7.x",
        25 => "8.0",
        _ => "",
    }
}

fn op_query(collection: &str, doc: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // flags
    body.extend_from_slice(collection.as_bytes());
    body.push(0);
    body.extend_from_slice(&0u32.to_le_bytes()); // numberToSkip
    body.extend_from_slice(&1u32.to_le_bytes()); // numberToReturn
    body.extend_from_slice(doc);

    let total = 16 + body.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // requestID
    out.extend_from_slice(&0u32.to_le_bytes()); // responseTo
    out.extend_from_slice(&2004u32.to_le_bytes()); // OP_QUERY
    out.extend_from_slice(&body);
    out
}

fn bson_int32_doc(key: &str, value: i32) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x10); // int32
    body.extend_from_slice(key.as_bytes());
    body.push(0);
    body.extend_from_slice(&value.to_le_bytes());
    body.push(0x00); // end of document

    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Walk a BSON document's top-level elements, calling `f` with (type, key, value start).
fn bson_walk<T>(doc: &[u8], mut f: impl FnMut(u8, &str, usize) -> Option<T>) -> Option<T> {
    if doc.len() < 5 {
        return None;
    }
    let end = (le32(doc, 0) as usize).min(doc.len());
    let mut i = 4usize;
    while i < end && doc[i] != 0x00 {
        let ty = doc[i];
        i += 1;
        let key_start = i;
        while i < end && doc[i] != 0x00 {
            i += 1;
        }
        if i >= end {
            return None;
        }
        let key = String::from_utf8_lossy(&doc[key_start..i]).to_string();
        i += 1; // NUL
        if let Some(v) = f(ty, &key, i) {
            return Some(v);
        }
        // Skip the value.
        let size = match ty {
            0x01 | 0x09 | 0x11 | 0x12 => 8,
            0x10 => 4,
            0x08 => 1,
            0x07 => 12,
            0x0a | 0x06 | 0xff | 0x7f => 0,
            0x02 | 0x0d | 0x0e => 4 + le32(doc, i) as usize,
            0x03 | 0x04 => le32(doc, i) as usize,
            0x05 => 5 + le32(doc, i) as usize,
            _ => return None, // unknown type: we can no longer walk safely
        };
        i = i.checked_add(size)?;
        if i > end {
            return None;
        }
    }
    None
}

fn bson_i32(doc: &[u8], key: &str) -> Option<i32> {
    bson_walk(doc, |ty, k, at| {
        if ty == 0x10 && k.eq_ignore_ascii_case(key) {
            Some(le32(doc, at) as i32)
        } else {
            None
        }
    })
}

fn bson_bool(doc: &[u8], key: &str) -> Option<bool> {
    bson_walk(doc, |ty, k, at| {
        if ty == 0x08 && k.eq_ignore_ascii_case(key) {
            doc.get(at).map(|&b| b != 0)
        } else {
            None
        }
    })
}

fn bson_str(doc: &[u8], key: &str) -> Option<String> {
    bson_walk(doc, |ty, k, at| {
        if ty == 0x02 && k.eq_ignore_ascii_case(key) {
            let len = le32(doc, at) as usize;
            let start = at + 4;
            if len >= 1 && start + len <= doc.len() {
                let s = String::from_utf8_lossy(&doc[start..start + len - 1])
                    .trim()
                    .to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
            None
        } else {
            None
        }
    })
}

// ── PostgreSQL ──────────────────────────────────────────────────────────────

/// PostgreSQL never volunteers its version pre-auth, but the SSLRequest reply
/// identifies the protocol unambiguously and tells you whether TLS is offered,
/// and a deliberately bogus startup packet returns a server-formatted error.
pub async fn postgres(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    let mut ssl_req = Vec::new();
    ssl_req.extend_from_slice(&8u32.to_be_bytes());
    ssl_req.extend_from_slice(&80877103u32.to_be_bytes()); // 1234.5679
    send(stream, &ssl_req, dur).await?;
    let resp = read_at_least(stream, 1, dur).await;
    let tls = match resp.first() {
        Some(b'S') => "TLS supported",
        Some(b'N') => "TLS not supported",
        Some(b'E') => "TLS rejected",
        _ => return None,
    };

    let mut p = Probed::named("postgresql", "PostgreSQL");
    p.extra = tls.to_string();

    // Only meaningful when the server declined TLS: otherwise the socket is now
    // waiting for a ClientHello we have no reason to send here.
    if resp.first() == Some(&b'N') {
        let mut startup = Vec::new();
        let params = b"user\0kaisen\0database\0kaisen\0application_name\0kaisen\0\0";
        startup.extend_from_slice(&((params.len() + 8) as u32).to_be_bytes());
        startup.extend_from_slice(&196608u32.to_be_bytes()); // protocol 3.0
        startup.extend_from_slice(params);
        if send(stream, &startup, dur).await.is_some() {
            let err = read_any(stream, dur, 4096).await;
            let text = ascii(&err);
            // The error fields name the auth method the cluster demands, which
            // is the one thing worth knowing about an exposed PostgreSQL port.
            for marker in ["scram", "md5", "password", "trust", "pg_hba.conf", "ident"] {
                if text.to_ascii_lowercase().contains(marker) {
                    p.extra.push_str("; auth: ");
                    p.extra.push_str(marker);
                    break;
                }
            }
        }
    }
    Some(p)
}

// ── MQTT ────────────────────────────────────────────────────────────────────

pub async fn mqtt(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    let client_id = b"kaisen";
    let mut var = Vec::new();
    var.extend_from_slice(&4u16.to_be_bytes());
    var.extend_from_slice(b"MQTT");
    var.push(0x04); // protocol level 4 = MQTT 3.1.1
    var.push(0x02); // clean session
    var.extend_from_slice(&60u16.to_be_bytes()); // keepalive
    var.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    var.extend_from_slice(client_id);

    let mut pkt = vec![0x10];
    let mut remaining = var.len();
    loop {
        let mut byte = (remaining % 128) as u8;
        remaining /= 128;
        if remaining > 0 {
            byte |= 0x80;
        }
        pkt.push(byte);
        if remaining == 0 {
            break;
        }
    }
    pkt.extend_from_slice(&var);

    send(stream, &pkt, dur).await?;
    let resp = read_at_least(stream, 4, dur).await;
    if resp.len() < 4 || resp[0] != 0x20 {
        return None;
    }
    let rc = resp[3];
    let status = match rc {
        0x00 => "anonymous connect ACCEPTED",
        0x01 => "protocol version refused",
        0x02 => "client id rejected",
        0x03 => "service unavailable",
        0x04 => "bad credentials",
        0x05 => "not authorized",
        _ => "connect refused",
    };
    Some(Probed {
        name: "mqtt",
        product: "MQTT broker".into(),
        version: "3.1.1".into(),
        extra: status.into(),
        ..Default::default()
    })
}

// ── AMQP 0-9-1 ──────────────────────────────────────────────────────────────

/// The very first frame an AMQP broker sends (connection.start) carries a
/// server-properties field table with the product name and exact version —
/// RabbitMQ, Qpid and friends all fill it in.
pub async fn amqp(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    send(stream, b"AMQP\x00\x00\x09\x01", dur).await?;
    let resp = read_at_least(stream, 64, dur).await;
    if resp.is_empty() {
        return None;
    }
    // A version mismatch makes the broker reply with its own protocol header.
    if resp.starts_with(b"AMQP") && resp.len() >= 8 {
        return Some(Probed {
            name: "amqp",
            product: "AMQP broker".into(),
            version: format!("{}.{}.{}", resp[5], resp[6], resp[7]),
            ..Default::default()
        });
    }
    if resp[0] != 0x01 {
        return None;
    }
    let mut p = Probed::named("amqp", "AMQP broker");
    if let Some(product) = amqp_field(&resp, b"product") {
        p.product = product;
    }
    if let Some(version) = amqp_field(&resp, b"version") {
        p.version = version;
    }
    let mut extras = Vec::new();
    if let Some(platform) = amqp_field(&resp, b"platform") {
        extras.push(platform);
    }
    if let Some(cluster) = amqp_field(&resp, b"cluster_name") {
        extras.push(cluster);
    }
    p.extra = extras.join("; ");
    Some(p)
}

/// Pull one long-string field out of an AMQP field table: `<len>key S <u32 len> value`.
fn amqp_field(buf: &[u8], key: &[u8]) -> Option<String> {
    let mut needle = Vec::with_capacity(key.len() + 1);
    needle.push(key.len() as u8);
    needle.extend_from_slice(key);
    let pos = buf
        .windows(needle.len())
        .position(|w| w == needle.as_slice())?;
    let i = pos + needle.len();
    if buf.get(i) != Some(&b'S') {
        return None;
    }
    let len = be32(buf, i + 1) as usize;
    let start = i + 5;
    if len == 0 || len > 256 || start + len > buf.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[start..start + len])
        .trim()
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// ── DNS (version.bind) ──────────────────────────────────────────────────────

/// The classic `dig @host version.bind chaos txt`, over TCP so it works on the
/// same socket the port scan already proved open. BIND, PowerDNS, NSD and
/// Knot all answer it unless the operator deliberately hid the string.
pub async fn dns_version(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice(&0x6b61u16.to_be_bytes()); // transaction id
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD
    msg.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    msg.extend_from_slice(&[0u8; 6]); // an/ns/ar counts
    for label in ["version", "bind"] {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&16u16.to_be_bytes()); // TXT
    msg.extend_from_slice(&3u16.to_be_bytes()); // CHAOS

    let mut framed = Vec::with_capacity(msg.len() + 2);
    framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(&msg);
    send(stream, &framed, dur).await?;

    let resp = read_at_least(stream, 14, dur).await;
    if resp.len() < 14 {
        return None;
    }
    let body = &resp[2..];
    // Confirm it's a response to our query before trusting anything else.
    if be16(body, 0) != 0x6b61 || body[2] & 0x80 == 0 {
        return None;
    }
    let mut p = Probed::named("domain", "DNS server");
    let ancount = be16(body, 6);
    if ancount == 0 {
        p.extra = "version.bind hidden or refused".into();
        return Some(p);
    }

    // Skip the header and the echoed question, then read the first TXT rdata.
    let mut i = 12usize;
    while i < body.len() && body[i] != 0 {
        let l = body[i] as usize;
        if l & 0xc0 == 0xc0 {
            i += 2;
            break;
        }
        i += l + 1;
    }
    i += 5; // root label + qtype + qclass
            // Answer: name, type, class, ttl, rdlength, rdata.
    if i + 2 <= body.len() && body[i] & 0xc0 == 0xc0 {
        i += 2;
    } else {
        while i < body.len() && body[i] != 0 {
            i += body[i] as usize + 1;
        }
        i += 1;
    }
    i += 8; // type + class + ttl
    if i + 2 > body.len() {
        return Some(p);
    }
    let rdlen = be16(body, i) as usize;
    i += 2;
    if i + rdlen > body.len() || rdlen == 0 {
        return Some(p);
    }
    let txt_len = body[i] as usize;
    let start = i + 1;
    if start + txt_len > body.len() {
        return Some(p);
    }
    let text = String::from_utf8_lossy(&body[start..start + txt_len])
        .trim()
        .to_string();
    p.banner.clone_from(&text);
    let lower = text.to_ascii_lowercase();
    let product = if lower.contains("dnsmasq") {
        "dnsmasq"
    } else if lower.contains("powerdns") || lower.contains("pdns") {
        "PowerDNS"
    } else if lower.contains("unbound") {
        "Unbound"
    } else if lower.contains("knot") {
        "Knot DNS"
    } else if lower.contains("nsd") {
        "NSD"
    } else if lower.contains("coredns") {
        "CoreDNS"
    } else if lower.contains("microsoft") {
        "Microsoft DNS"
    } else {
        "BIND"
    };
    p.product = product.to_string();
    p.version = first_version(&text);
    if p.version.is_empty() {
        p.extra = text;
    } else if let Some(rest) = text
        .split_once(&p.version)
        .map(|(_, r)| r.trim().to_string())
    {
        if !rest.is_empty() {
            p.extra = rest;
        }
    }
    Some(p)
}

// ── Minecraft (Server List Ping) ────────────────────────────────────────────

pub async fn minecraft(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    dur: Duration,
) -> Option<Probed> {
    let mut payload = vec![0x00]; // handshake packet id
    write_varint(&mut payload, 765); // protocol version (any recent value works)
    write_varint(&mut payload, host.len() as i32);
    payload.extend_from_slice(host.as_bytes());
    payload.extend_from_slice(&port.to_be_bytes());
    write_varint(&mut payload, 1); // next state: status

    let mut pkt = Vec::new();
    write_varint(&mut pkt, payload.len() as i32);
    pkt.extend_from_slice(&payload);
    pkt.extend_from_slice(&[0x01, 0x00]); // status request

    send(stream, &pkt, dur).await?;
    let resp = read_at_least(stream, 16, dur).await;
    if resp.len() < 5 {
        return None;
    }
    let (_len, mut i) = read_varint(&resp, 0)?;
    let (id, ni) = read_varint(&resp, i)?;
    if id != 0 {
        return None;
    }
    i = ni;
    let (slen, si) = read_varint(&resp, i)?;
    let start = si;
    let end = (start + slen.max(0) as usize).min(resp.len());
    let json = String::from_utf8_lossy(&resp[start..end]).to_string();

    let mut p = Probed::named("minecraft", "Minecraft server");
    if let Some(name) = json_str(&json, "name") {
        p.version = name;
    }
    let mut bits = Vec::new();
    if let Some(proto) = json_num(&json, "protocol") {
        bits.push(format!("protocol {proto}"));
    }
    if let (Some(online), Some(max)) = (json_num(&json, "online"), json_num(&json, "max")) {
        bits.push(format!("{online}/{max} players"));
    }
    p.extra = bits.join("; ");
    Some(p)
}

fn write_varint(out: &mut Vec<u8>, mut v: i32) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v = ((v as u32) >> 7) as i32;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn read_varint(buf: &[u8], mut i: usize) -> Option<(i32, usize)> {
    let mut result: i32 = 0;
    for shift in 0..5 {
        let b = *buf.get(i)?;
        i += 1;
        result |= ((b & 0x7f) as i32) << (7 * shift);
        if b & 0x80 == 0 {
            return Some((result, i));
        }
    }
    None
}

/// Tiny "good enough" JSON scalar readers — we only ever look at flat,
/// well-known keys in responses we just asked for.
pub fn json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut from = 0usize;
    while let Some(pos) = json[from..].find(&needle) {
        let after = from + pos + needle.len();
        let rest = json[after..].trim_start();
        if let Some(rest) = rest.strip_prefix(':') {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('"') {
                let mut out = String::new();
                let mut chars = rest.chars();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some(n) = chars.next() {
                                out.push(n);
                            }
                        }
                        '"' => break,
                        _ => out.push(c),
                    }
                }
                let out = out.trim().to_string();
                if !out.is_empty() {
                    return Some(out);
                }
            }
        }
        from = after;
    }
    None
}

pub fn json_num(json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let rest = json[pos + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    digits.parse().ok()
}

// ── Erlang port mapper (epmd) ───────────────────────────────────────────────

/// epmd lists every Erlang node registered on the host, which is how you find
/// RabbitMQ / CouchDB / Ejabberd clusters (and their distribution ports).
pub async fn epmd(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    send(stream, &[0x00, 0x01, 0x6e], dur).await?; // NAMES_REQ
    let resp = read_any(stream, dur, 8192).await;
    if resp.len() < 4 {
        return None;
    }
    let text = ascii(&resp[4..]);
    let nodes: Vec<String> = text
        .lines()
        .filter(|l| l.contains("at port"))
        .map(|l| l.trim().to_string())
        .take(6)
        .collect();
    // The product stays "Erlang Port Mapper Daemon" whatever is registered:
    // naming RabbitMQ here would make this port match broker signatures that
    // are about the broker's own port, not the port mapper's.
    let mut p = Probed::named("epmd", "Erlang Port Mapper Daemon");
    if !nodes.is_empty() {
        let lower = nodes.join(" ").to_ascii_lowercase();
        let flavour = if lower.contains("rabbit") {
            "RabbitMQ node; "
        } else if lower.contains("couchdb") {
            "CouchDB node; "
        } else if lower.contains("ejabberd") {
            "ejabberd node; "
        } else {
            ""
        };
        p.extra = format!("{flavour}{}", nodes.join(", "));
    }
    Some(p)
}

// ── Cassandra (CQL native protocol) ─────────────────────────────────────────

pub async fn cassandra(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    // OPTIONS on protocol v4; servers that only speak v3 answer with an ERROR
    // frame that still identifies them.
    send(
        stream,
        &[0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00],
        dur,
    )
    .await?;
    let resp = read_at_least(stream, 9, dur).await;
    if resp.len() < 9 || resp[0] & 0x80 == 0 {
        return None;
    }
    let mut p = Probed::named("cassandra", "Apache Cassandra");
    let body = &resp[9..];
    let text = ascii(body);
    if let Some(pos) = text.find("CQL_VERSION") {
        let after = &body[(pos + "CQL_VERSION".len()).min(body.len())..];
        let v = first_version(&ascii(after));
        if !v.is_empty() {
            p.extra = format!("CQL {v}");
        }
    }
    if text.contains("dse") || text.contains("DSE") {
        p.product = "DataStax Enterprise".into();
    }
    Some(p)
}

// ── Kafka ───────────────────────────────────────────────────────────────────

/// ApiVersions is the one request a Kafka broker answers before anything else.
/// The highest API key it knows about brackets the broker's release.
pub async fn kafka(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    let client_id = b"kaisen";
    let mut body = Vec::new();
    body.extend_from_slice(&18u16.to_be_bytes()); // ApiVersions
    body.extend_from_slice(&0u16.to_be_bytes()); // version 0
    body.extend_from_slice(&1u32.to_be_bytes()); // correlation id
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id);

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&(body.len() as u32).to_be_bytes());
    pkt.extend_from_slice(&body);
    send(stream, &pkt, dur).await?;

    let resp = read_at_least(stream, 14, dur).await;
    if resp.len() < 14 || be32(&resp, 4) != 1 {
        return None;
    }
    let error = be16(&resp, 8);
    let count = be32(&resp, 10) as usize;
    if count == 0 || count > 512 {
        return Some(Probed::named("kafka", "Apache Kafka"));
    }
    let mut max_key = 0u16;
    for k in 0..count {
        let at = 14 + k * 6;
        if at + 2 > resp.len() {
            break;
        }
        max_key = max_key.max(be16(&resp, at));
    }
    let mut p = Probed::named("kafka", "Apache Kafka");
    p.version = kafka_release(max_key).to_string();
    p.extra = format!("{count} APIs, max api key {max_key}");
    if error != 0 {
        p.extra.push_str(&format!("; error {error}"));
    }
    Some(p)
}

/// Approximate — Kafka has no version in the protocol, but each release adds
/// API keys, so the highest key advertised puts a floor under the version.
fn kafka_release(max_key: u16) -> &'static str {
    match max_key {
        0..=20 => "0.9 or older",
        21..=31 => "0.10.x",
        32..=36 => "0.11.x",
        37..=41 => "1.0.x",
        42..=43 => "1.1.x",
        44 => "2.3.x",
        45..=47 => "2.4.x",
        48..=49 => "2.6.x",
        50..=56 => "2.7.x",
        57..=63 => "2.8.x",
        64..=67 => "3.0-3.6",
        68 => "3.7.x",
        _ => "3.8 or newer",
    }
}

// ── RDP ─────────────────────────────────────────────────────────────────────

/// X.224 connection request with an RDP negotiation payload. The reply says
/// which security layer the server insists on — the single most useful fact
/// about an exposed RDP port, since "standard RDP security" means no NLA.
pub async fn rdp(stream: &mut TcpStream, host: Option<&str>, dur: Duration) -> Option<Probed> {
    let mut x224 = vec![
        0xe0, // CR
        0x00, 0x00, // dst-ref
        0x00, 0x00, // src-ref
        0x00, // class
    ];
    // RDP_NEG_REQ: request TLS + CredSSP so the server reveals its best option.
    x224.extend_from_slice(&[0x01, 0x00, 0x08, 0x00]);
    x224.extend_from_slice(&3u32.to_le_bytes());

    let mut pkt = vec![0x03, 0x00];
    let total = 4 + 1 + x224.len();
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.push(x224.len() as u8);
    pkt.extend_from_slice(&x224);

    send(stream, &pkt, dur).await?;
    let resp = read_at_least(stream, 11, dur).await;
    if resp.len() < 11 || resp[0] != 0x03 {
        return None;
    }

    let mut p = Probed::named("ms-wbt-server", "Microsoft Terminal Services");
    p.os_hint = "Windows".into();
    let neg_type = resp[11.min(resp.len() - 1)];
    let mut wants_tls = false;
    match neg_type {
        0x02 if resp.len() >= 19 => {
            let selected = le32(&resp, 15);
            p.extra = match selected {
                0 => "standard RDP security (no NLA)".into(),
                1 => {
                    wants_tls = true;
                    "TLS".to_string()
                }
                2 => {
                    wants_tls = true;
                    "CredSSP / NLA required".to_string()
                }
                4 => {
                    wants_tls = true;
                    "RDSTLS".to_string()
                }
                8 => {
                    wants_tls = true;
                    "CredSSP with early user auth".to_string()
                }
                other => format!("protocol {other}"),
            };
        }
        0x03 if resp.len() >= 19 => {
            let code = le32(&resp, 15);
            p.extra = match code {
                1 => "SSL required by server".into(),
                2 => "SSL not allowed by server".into(),
                3 => "SSL certificate not on server".into(),
                5 => "hybrid (NLA) required by server".into(),
                _ => format!("negotiation failure {code}"),
            };
            wants_tls = code == 1 || code == 5;
        }
        _ => {
            p.extra = "standard RDP security (no NLA)".into();
        }
    }

    // When the server switched to TLS, the certificate it presents is normally
    // self-signed with CN = the machine's own hostname. That's free host naming.
    if wants_tls {
        if let Some(t) = crate::tls::probe_stream(stream, host, dur, false).await {
            if !t.subject_cn.is_empty() {
                p.extra.push_str(&format!("; hostname {}", t.subject_cn));
            }
            if !t.version.is_empty() {
                p.extra.push_str(&format!("; {}", t.version));
            }
        }
    }
    Some(p)
}

// ── X11 ─────────────────────────────────────────────────────────────────────

/// An X server answers the connection setup even when it refuses us, and the
/// refusal still carries the protocol version — plus, if it *doesn't* refuse,
/// the display is wide open to anyone on the network.
pub async fn x11(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    let mut req = vec![0x6c, 0x00]; // little-endian, pad
    req.extend_from_slice(&11u16.to_le_bytes()); // protocol major
    req.extend_from_slice(&0u16.to_le_bytes()); // protocol minor
    req.extend_from_slice(&0u16.to_le_bytes()); // auth proto name length
    req.extend_from_slice(&0u16.to_le_bytes()); // auth proto data length
    req.extend_from_slice(&0u16.to_le_bytes()); // pad
    send(stream, &req, dur).await?;

    let resp = read_at_least(stream, 8, dur).await;
    if resp.len() < 8 {
        return None;
    }
    let mut p = Probed::named("x11", "X11 server");
    p.version = format!("{}.{}", le16(&resp, 2), le16(&resp, 4));
    match resp[0] {
        1 => {
            p.extra = "ACCESS GRANTED (no authentication)".into();
            if resp.len() > 40 {
                let vendor_len = le16(&resp, 24) as usize;
                let start = 40;
                if start + vendor_len <= resp.len() && vendor_len > 0 && vendor_len < 128 {
                    let vendor = String::from_utf8_lossy(&resp[start..start + vendor_len])
                        .trim()
                        .to_string();
                    if !vendor.is_empty() {
                        p.product = vendor;
                    }
                }
                let release = le32(&resp, 8);
                if release > 0 {
                    p.extra.push_str(&format!("; release {release}"));
                }
            }
        }
        0 => {
            let reason_len = resp[1] as usize;
            if 8 + reason_len <= resp.len() {
                let reason = String::from_utf8_lossy(&resp[8..8 + reason_len])
                    .trim()
                    .to_string();
                p.extra = reason;
            } else {
                p.extra = "access denied".into();
            }
        }
        _ => p.extra = "further authentication required".into(),
    }
    Some(p)
}

// ── LDAP ────────────────────────────────────────────────────────────────────

/// An anonymous rootDSE search. Active Directory answers with the domain and
/// forest naming contexts and the DC's own DNS name; OpenLDAP answers with its
/// naming contexts and, when configured, vendorName / vendorVersion.
pub async fn ldap(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    fn ber(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    let attrs: [&str; 6] = [
        "vendorName",
        "vendorVersion",
        "namingContexts",
        "dnsHostName",
        "supportedLDAPVersion",
        "objectClass",
    ];
    let mut attr_seq = Vec::new();
    for a in attrs {
        attr_seq.extend_from_slice(&ber(0x04, a.as_bytes()));
    }

    let mut search = Vec::new();
    search.extend_from_slice(&ber(0x04, b"")); // baseObject: rootDSE
    search.extend_from_slice(&ber(0x0a, &[0x00])); // scope: baseObject
    search.extend_from_slice(&ber(0x0a, &[0x00])); // derefAliases: never
    search.extend_from_slice(&ber(0x02, &[0x00])); // sizeLimit
    search.extend_from_slice(&ber(0x02, &[0x0a])); // timeLimit
    search.extend_from_slice(&ber(0x01, &[0x00])); // typesOnly: false
    search.extend_from_slice(&ber(0x87, b"objectClass")); // filter: (objectClass=*)
    search.extend_from_slice(&ber(0x30, &attr_seq));

    let mut msg = Vec::new();
    msg.extend_from_slice(&ber(0x02, &[0x01])); // messageID
    msg.extend_from_slice(&ber(0x63, &search)); // [APPLICATION 3] searchRequest
    let packet = ber(0x30, &msg);

    send(stream, &packet, dur).await?;
    let resp = read_any(stream, dur, 16384).await;
    if resp.is_empty() || resp[0] != 0x30 {
        return None;
    }

    let text = ascii(&resp);
    let mut p = Probed::named("ldap", "LDAP server");
    let lower = text.to_ascii_lowercase();
    if lower.contains("microsoft")
        || lower.contains("configuration,dc=")
        || lower.contains("forestdns")
    {
        p.product = "Microsoft Active Directory LDAP".into();
        p.os_hint = "Windows".into();
    } else if lower.contains("openldap") {
        p.product = "OpenLDAP".into();
    } else if lower.contains("389") && lower.contains("directory") {
        p.product = "389 Directory Server".into();
    } else if lower.contains("opendj") {
        p.product = "OpenDJ".into();
    }

    let mut bits = Vec::new();
    if let Some(dc) = extract_after(&text, "dnsHostName") {
        bits.push(dc);
    }
    for token in text.split_whitespace() {
        if token.to_ascii_uppercase().starts_with("DC=") && bits.len() < 3 {
            let t = token
                .trim_matches(|c: char| !c.is_ascii_graphic())
                .to_string();
            if !bits.contains(&t) {
                bits.push(t);
            }
        }
    }
    // Deliberately no version guess here: an LDAP response is full of dotted
    // OIDs that look exactly like version numbers and aren't.
    p.extra = bits.join("; ");
    Some(p)
}

/// Pull the readable run that follows a marker word out of an ASCII-ised blob.
fn extract_after(text: &str, marker: &str) -> Option<String> {
    let pos = text.find(marker)?;
    let rest = text[pos + marker.len()..].trim_start();
    let value: String = rest
        .chars()
        .skip_while(|c| !c.is_ascii_alphanumeric())
        .take_while(|c| c.is_ascii_graphic() && *c != ',')
        .collect();
    if value.len() > 2 {
        Some(value)
    } else {
        None
    }
}

// ── Oracle TNS ──────────────────────────────────────────────────────────────

/// A TNS connect packet for a service that doesn't exist. The listener refuses
/// it — and the refusal carries VSNNUM, an encoded build number that decodes
/// straight to something like 11.2.0.4.
pub async fn oracle_tns(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    let connect_data = b"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=)(CID=(PROGRAM=)(HOST=kaisen)(USER=kaisen)))(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)))";
    let len = 58 + connect_data.len();
    let mut pkt = Vec::with_capacity(len);
    pkt.extend_from_slice(&(len as u16).to_be_bytes()); // packet length
    pkt.extend_from_slice(&0u16.to_be_bytes()); // packet checksum
    pkt.push(0x01); // type: CONNECT
    pkt.push(0x00); // reserved
    pkt.extend_from_slice(&0u16.to_be_bytes()); // header checksum
    pkt.extend_from_slice(&0x013au16.to_be_bytes()); // version 314
    pkt.extend_from_slice(&0x012cu16.to_be_bytes()); // compatible version 300
    pkt.extend_from_slice(&0x0c41u16.to_be_bytes()); // service options
    pkt.extend_from_slice(&0x2000u16.to_be_bytes()); // SDU
    pkt.extend_from_slice(&0x7fffu16.to_be_bytes()); // TDU
    pkt.extend_from_slice(&0x7f08u16.to_be_bytes()); // protocol characteristics
    pkt.extend_from_slice(&0u16.to_be_bytes()); // max packets before ack
    pkt.extend_from_slice(&1u16.to_be_bytes()); // byte order marker
    pkt.extend_from_slice(&(connect_data.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&58u16.to_be_bytes()); // connect data offset
    pkt.extend_from_slice(&0u32.to_be_bytes()); // max receivable data
    pkt.extend_from_slice(&[0x01, 0x01]); // flags
    pkt.extend_from_slice(&[0u8; 20]); // cross-facility and connect flags
    pkt.extend_from_slice(connect_data);

    send(stream, &pkt, dur).await?;
    let resp = read_any(stream, dur, 8192).await;
    if resp.len() < 8 {
        return None;
    }
    let ptype = resp[4];
    // 1=connect, 2=accept, 4=refuse, 5=redirect, 11=resend — anything else and
    // this almost certainly isn't a TNS listener.
    if !matches!(ptype, 2 | 4 | 5 | 11 | 12) {
        return None;
    }
    let mut p = Probed::named("oracle-tns", "Oracle TNS Listener");
    let text = ascii(&resp);
    if let Some(pos) = text.find("VSNNUM=") {
        let digits: String = text[pos + 7..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(v) = digits.parse::<u32>() {
            p.version = oracle_version(v);
        }
    }
    if p.version.is_empty() && ptype == 2 {
        p.version = match be16(&resp, 8) {
            v if v >= 318 => "19c or newer".into(),
            316..=317 => "12c".into(),
            314..=315 => "11g".into(),
            313 => "10g".into(),
            312 => "9i".into(),
            310..=311 => "8i".into(),
            _ => String::new(),
        };
    }
    if let Some(pos) = text.find("ERR=") {
        let code: String = text[pos + 4..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !code.is_empty() {
            p.extra = format!("TNS-{code}");
        }
    }
    Some(p)
}

/// VSNNUM packs the five-part Oracle version into one 32-bit integer.
fn oracle_version(v: u32) -> String {
    let major = (v >> 24) & 0xff;
    let minor = (v >> 20) & 0x0f;
    let update = (v >> 12) & 0xff;
    let port_release = (v >> 8) & 0x0f;
    let port_update = v & 0xff;
    if major == 0 {
        return String::new();
    }
    format!("{major}.{minor}.{update}.{port_release}.{port_update}")
}

// ── AJP13 (Tomcat) ──────────────────────────────────────────────────────────

/// A CPing/CPong exchange: cheap, and a positive CPong on 8009 means the AJP
/// connector is reachable, which is the precondition for Ghostcat.
pub async fn ajp(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    send(stream, &[0x12, 0x34, 0x00, 0x01, 0x0a], dur).await?;
    let resp = read_at_least(stream, 5, dur).await;
    if resp.len() < 5 || &resp[0..2] != b"AB" {
        return None;
    }
    let mut p = Probed::named("ajp13", "Apache JServ Protocol");
    p.version = "1.3".into();
    p.extra = match resp[4] {
        0x09 => "CPong (connector reachable)".into(),
        0x05 => "End response".to_string(),
        code => format!("prefix code {code}"),
    };
    Some(p)
}

// ── SOCKS ───────────────────────────────────────────────────────────────────

pub async fn socks(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    send(stream, &[0x05, 0x02, 0x00, 0x02], dur).await?; // v5, no-auth or user/pass
    let resp = read_at_least(stream, 2, dur).await;
    if resp.len() < 2 || resp[0] != 0x05 {
        return None;
    }
    let mut p = Probed::named("socks", "SOCKS proxy");
    p.version = "5".into();
    p.extra = match resp[1] {
        0x00 => "NO AUTHENTICATION REQUIRED (open proxy)".into(),
        0x02 => "username/password auth".into(),
        0xff => "no acceptable auth method".into(),
        m => format!("auth method {m}"),
    };
    Some(p)
}

// ── Git daemon ──────────────────────────────────────────────────────────────

pub async fn git_daemon(stream: &mut TcpStream, dur: Duration) -> Option<Probed> {
    let payload = b"git-upload-pack /\0host=kaisen\0";
    let line = format!("{:04x}", payload.len() + 4);
    let mut pkt = line.into_bytes();
    pkt.extend_from_slice(payload);
    send(stream, &pkt, dur).await?;
    let resp = read_any(stream, dur, 4096).await;
    if resp.len() < 4 {
        return None;
    }
    let text = ascii(&resp);
    let mut p = Probed::named("git", "Git daemon");
    if text.contains("ERR ") {
        p.extra = text
            .split("ERR ")
            .nth(1)
            .unwrap_or("")
            .trim()
            .chars()
            .take(80)
            .collect();
    } else if text.contains("agent=") {
        if let Some(v) = extract_after(&text, "agent=git/") {
            p.version = v;
        }
        p.extra = "repository exported".into();
    }
    Some(p)
}

// ── shared little helpers ───────────────────────────────────────────────────

/// First token in `s` that looks like a dotted version number.
pub fn first_version(s: &str) -> String {
    for tok in s.split(|c: char| c.is_whitespace() || "(),;:[]<>\"'".contains(c)) {
        let t = tok.trim_end_matches(['.', ',']);
        if looks_like_version(t) {
            return t.to_string();
        }
    }
    String::new()
}

/// Whether a token is plausibly a version rather than something that merely
/// starts with a digit. Requires at least two dot-separated components with a
/// purely numeric first one, which rejects the likes of an SMTP greeting's
/// "250-mail.example.com" while still accepting "8.0.35-0ubuntu0.22.04.1".
pub fn looks_like_version(t: &str) -> bool {
    if t.len() > 40 || !t.contains('.') {
        return false;
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '+')
    {
        return false;
    }
    let mut parts = t.split('.');
    let first = parts.next().unwrap_or("");
    let second = parts.next().unwrap_or("");
    !first.is_empty()
        && first.chars().all(|c| c.is_ascii_digit())
        && second
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
}
