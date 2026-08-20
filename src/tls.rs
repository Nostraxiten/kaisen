//! A tiny, dependency-free TLS prober.
//!
//! Kaisen has no TLS library, and it doesn't need one to *identify* a TLS
//! service: the negotiated version, the cipher suite, the ALPN protocol and —
//! for TLS 1.2 and below — the whole certificate chain all travel in the clear
//! before any key schedule kicks in. So we hand-roll a ClientHello, read the
//! server's answer, and parse the interesting bits out of it.
//!
//! This turns a previously blind port (443 and friends used to receive a
//! cleartext `GET /`, which every TLS server rejects) into one of the richest
//! sources of version data we have: the certificate names the host, the issuer
//! names the CA, and the negotiated protocol tells you whether the box still
//! speaks obsolete crypto.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default)]
pub struct TlsInfo {
    pub version: String,     // "TLS 1.2", "SSL 3.0", ...
    pub cipher: String,      // negotiated cipher suite name
    pub alpn: String,        // "h2", "http/1.1", ...
    pub subject_cn: String,  // certificate subject CN
    pub subject_o: String,   // certificate subject Organization (O), e.g. "Ezviz"
    pub issuer_cn: String,   // certificate issuer CN
    pub not_after: String,   // "2026-01-31"
    pub expired: bool,
    pub self_signed: bool,
    pub sans: Vec<String>,   // subject alternative DNS names (capped)
}

impl TlsInfo {
    /// A compact one-line summary for the VERSION column.
    pub fn summary(&self) -> String {
        let mut bits = Vec::new();
        if !self.subject_cn.is_empty() {
            bits.push(format!("CN={}", self.subject_cn));
        }
        if !self.issuer_cn.is_empty() && !self.self_signed {
            bits.push(format!("issuer={}", self.issuer_cn));
        }
        if self.self_signed {
            bits.push("self-signed".to_string());
        }
        if !self.not_after.is_empty() {
            bits.push(if self.expired {
                format!("EXPIRED {}", self.not_after)
            } else {
                format!("expires {}", self.not_after)
            });
        }
        if !self.alpn.is_empty() {
            bits.push(format!("ALPN={}", self.alpn));
        }
        if !self.cipher.is_empty() {
            bits.push(self.cipher.clone());
        }
        bits.join("; ")
    }
}

/// Connect-free probe: run a handshake over an already-open stream. Used both
/// for plain TLS ports and for protocols that negotiate STARTTLS-style upgrades
/// mid-stream (RDP does exactly this after its X.224 exchange).
pub async fn probe_stream(
    stream: &mut TcpStream,
    host: Option<&str>,
    dur: Duration,
    offer_tls13: bool,
) -> Option<TlsInfo> {
    let hello = client_hello(host, offer_tls13);
    timeout(dur, stream.write_all(&hello)).await.ok()?.ok()?;

    let mut raw: Vec<u8> = Vec::with_capacity(8192);
    let mut handshake: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 8192];
    let mut info = TlsInfo::default();
    let mut saw_hello = false;
    let mut saw_cert = false;

    // Read until we have both the ServerHello and the Certificate, the server
    // stops talking, or we hit a hard cap. A TLS 1.3 server never sends a
    // cleartext certificate, so `saw_hello` alone ends the loop there.
    for _ in 0..16 {
        let n = match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };
        raw.extend_from_slice(&buf[..n]);

        let (records, consumed) = split_records(&raw);
        raw.drain(..consumed);
        for (ctype, payload) in records {
            match ctype {
                0x16 => handshake.extend_from_slice(&payload),
                0x15 => {
                    // Alert before we learned anything: not (this dialect of) TLS.
                    if !saw_hello {
                        return None;
                    }
                }
                _ => {}
            }
        }

        for (mtype, body) in split_handshake(&handshake) {
            match mtype {
                2 => {
                    if parse_server_hello(&body, &mut info) {
                        saw_hello = true;
                    }
                }
                11 => {
                    parse_certificates(&body, &mut info);
                    saw_cert = true;
                }
                _ => {}
            }
        }

        if saw_hello && (saw_cert || info.version == "TLS 1.3") {
            break;
        }
        if raw.len() + handshake.len() > 262_144 {
            break;
        }
    }

    if saw_hello {
        Some(info)
    } else {
        None
    }
}

/// Full probe against an address: try a TLS 1.2-style hello first (it keeps the
/// certificate in the clear), and only if the server refuses outright retry
/// offering TLS 1.3. Modern 1.3-only servers answer the second attempt.
pub async fn probe(addr: std::net::SocketAddr, host: Option<&str>, dur: Duration) -> Option<TlsInfo> {
    if let Ok(Ok(mut s)) = timeout(dur, TcpStream::connect(addr)).await {
        crate::netutil::reset_on_close(&s);
        if let Some(i) = probe_stream(&mut s, host, dur, false).await {
            return Some(i);
        }
    }
    if let Ok(Ok(mut s)) = timeout(dur, TcpStream::connect(addr)).await {
        crate::netutil::reset_on_close(&s);
        if let Some(i) = probe_stream(&mut s, host, dur, true).await {
            return Some(i);
        }
    }
    None
}

// ── ClientHello construction ────────────────────────────────────────────────

/// Cipher suites we offer, strongest-first, spanning TLS 1.3 down to the legacy
/// suites that only ancient servers still speak (so those get identified too
/// rather than silently failing the handshake).
const CIPHERS: &[u16] = &[
    0x1302, 0x1303, 0x1301, // TLS 1.3
    0xc02c, 0xc030, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xccaa,
    0xc024, 0xc028, 0xc023, 0xc027, 0xc00a, 0xc014, 0xc009, 0xc013,
    0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a, 0x0005, 0x0004,
];

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 33) as u8
        })
        .collect()
}

fn u16b(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn ext(id: u16, body: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&u16b(id));
    out.extend_from_slice(&u16b(body.len() as u16));
    out.extend_from_slice(body);
}

/// `host` is only used for SNI, and only when it is a real DNS name — sending
/// an IP literal in SNI is illegal and some servers drop the connection for it.
fn client_hello(host: Option<&str>, offer_tls13: bool) -> Vec<u8> {
    let mut exts: Vec<u8> = Vec::new();

    if let Some(h) = host {
        if is_dns_name(h) {
            let name = h.as_bytes();
            let mut sni = Vec::new();
            sni.extend_from_slice(&u16b(name.len() as u16 + 3)); // server_name_list length
            sni.push(0x00); // host_name
            sni.extend_from_slice(&u16b(name.len() as u16));
            sni.extend_from_slice(name);
            ext(0x0000, &sni, &mut exts);
        }
    }

    ext(0x0017, &[], &mut exts); // extended_master_secret
    ext(0x0023, &[], &mut exts); // session_ticket
    ext(0x000b, &[0x01, 0x00], &mut exts); // ec_point_formats: uncompressed

    let groups: [u16; 5] = [0x001d, 0x0017, 0x0018, 0x0019, 0x001e];
    let mut g = Vec::new();
    g.extend_from_slice(&u16b((groups.len() * 2) as u16));
    for x in groups {
        g.extend_from_slice(&u16b(x));
    }
    ext(0x000a, &g, &mut exts); // supported_groups

    let sigalgs: [u16; 12] = [
        0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
        0x0201,
    ];
    let mut sa = Vec::new();
    sa.extend_from_slice(&u16b((sigalgs.len() * 2) as u16));
    for x in sigalgs {
        sa.extend_from_slice(&u16b(x));
    }
    ext(0x000d, &sa, &mut exts); // signature_algorithms

    // ALPN: knowing whether a server speaks HTTP/2 is itself a version signal.
    let mut alpn = Vec::new();
    let protos: [&[u8]; 2] = [b"h2", b"http/1.1"];
    let list_len: usize = protos.iter().map(|p| p.len() + 1).sum();
    alpn.extend_from_slice(&u16b(list_len as u16));
    for p in protos {
        alpn.push(p.len() as u8);
        alpn.extend_from_slice(p);
    }
    ext(0x0010, &alpn, &mut exts);

    if offer_tls13 {
        ext(0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03], &mut exts); // supported_versions: 1.3, 1.2
        ext(0x002d, &[0x01, 0x01], &mut exts); // psk_key_exchange_modes: psk_dhe_ke

        // A key_share the server can consume: any 32 bytes is a syntactically
        // valid x25519 public key. We never finish the handshake, so it not
        // being a real key pair costs us nothing.
        let mut ks = Vec::new();
        let key = rand_bytes(32);
        ks.extend_from_slice(&u16b(36)); // client_shares length
        ks.extend_from_slice(&u16b(0x001d)); // x25519
        ks.extend_from_slice(&u16b(32));
        ks.extend_from_slice(&key);
        ext(0x0033, &ks, &mut exts);
    }

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
    body.extend_from_slice(&rand_bytes(32)); // random
    let sid = rand_bytes(32);
    body.push(sid.len() as u8); // legacy_session_id (compat mode)
    body.extend_from_slice(&sid);
    body.extend_from_slice(&u16b((CIPHERS.len() * 2) as u16));
    for c in CIPHERS {
        body.extend_from_slice(&u16b(*c));
    }
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    body.extend_from_slice(&u16b(exts.len() as u16));
    body.extend_from_slice(&exts);

    let mut hs: Vec<u8> = Vec::with_capacity(body.len() + 4);
    hs.push(0x01); // ClientHello
    hs.push(((body.len() >> 16) & 0xff) as u8);
    hs.push(((body.len() >> 8) & 0xff) as u8);
    hs.push((body.len() & 0xff) as u8);
    hs.extend_from_slice(&body);

    let mut rec: Vec<u8> = Vec::with_capacity(hs.len() + 5);
    rec.push(0x16); // handshake
    rec.extend_from_slice(&[0x03, 0x01]); // record version TLS 1.0 for maximum compatibility
    rec.extend_from_slice(&u16b(hs.len() as u16));
    rec.extend_from_slice(&hs);
    rec
}

fn is_dns_name(h: &str) -> bool {
    !h.is_empty()
        && h.parse::<std::net::IpAddr>().is_err()
        && h.contains('.')
        && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

// ── Record / handshake framing ──────────────────────────────────────────────

/// Split whole TLS records out of `buf`, returning them plus how many bytes
/// were consumed (a trailing partial record stays in the buffer).
fn split_records(buf: &[u8]) -> (Vec<(u8, Vec<u8>)>, usize) {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 5 <= buf.len() {
        let ctype = buf[i];
        let len = ((buf[i + 3] as usize) << 8) | buf[i + 4] as usize;
        if len > 18432 {
            // Nonsense length: this isn't TLS, stop consuming.
            return (out, buf.len());
        }
        if i + 5 + len > buf.len() {
            break;
        }
        out.push((ctype, buf[i + 5..i + 5 + len].to_vec()));
        i += 5 + len;
    }
    (out, i)
}

/// Split complete handshake messages out of the reassembled handshake stream.
fn split_handshake(buf: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        let mtype = buf[i];
        let len = ((buf[i + 1] as usize) << 16) | ((buf[i + 2] as usize) << 8) | buf[i + 3] as usize;
        if i + 4 + len > buf.len() {
            break;
        }
        out.push((mtype, buf[i + 4..i + 4 + len].to_vec()));
        i += 4 + len;
    }
    out
}

fn parse_server_hello(body: &[u8], info: &mut TlsInfo) -> bool {
    if body.len() < 38 {
        return false;
    }
    let legacy = ((body[0] as u16) << 8) | body[1] as u16;
    let sid_len = body[34] as usize;
    let mut i = 35 + sid_len;
    if i + 3 > body.len() {
        return false;
    }
    let cipher = ((body[i] as u16) << 8) | body[i + 1] as u16;
    i += 3; // cipher suite + compression method

    let mut negotiated = legacy;
    if i + 2 <= body.len() {
        let ext_len = ((body[i] as usize) << 8) | body[i + 1] as usize;
        i += 2;
        let end = (i + ext_len).min(body.len());
        while i + 4 <= end {
            let id = ((body[i] as u16) << 8) | body[i + 1] as u16;
            let l = ((body[i + 2] as usize) << 8) | body[i + 3] as usize;
            i += 4;
            if i + l > end {
                break;
            }
            let data = &body[i..i + l];
            match id {
                // supported_versions in a ServerHello overrides legacy_version.
                0x002b if l >= 2 => negotiated = ((data[0] as u16) << 8) | data[1] as u16,
                0x0010 if l >= 3 => {
                    let plen = data[2] as usize;
                    if 3 + plen <= l {
                        info.alpn = String::from_utf8_lossy(&data[3..3 + plen]).to_string();
                    }
                }
                _ => {}
            }
            i += l;
        }
    }

    info.version = version_name(negotiated).to_string();
    info.cipher = cipher_name(cipher).to_string();
    true
}

fn version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        0xfefd => "DTLS 1.2",
        _ => "TLS (unknown version)",
    }
}

fn cipher_name(c: u16) -> &'static str {
    match c {
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xccaa => "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        _ => "",
    }
}

// ── Certificate parsing (just enough DER to be useful) ──────────────────────

fn parse_certificates(body: &[u8], info: &mut TlsInfo) {
    // Certificate: 3-byte list length, then (3-byte length, DER) entries.
    if body.len() < 6 {
        return;
    }
    let list_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
    let end = (3 + list_len).min(body.len());
    let mut i = 3usize;
    if i + 3 > end {
        return;
    }
    let cert_len = ((body[i] as usize) << 16) | ((body[i + 1] as usize) << 8) | body[i + 2] as usize;
    i += 3;
    if i + cert_len > end {
        return;
    }
    let cert = &body[i..i + cert_len];

    let cns = der_common_names(cert);
    // Within a certificate the issuer RDN precedes the subject RDN, so the
    // first CN we meet is the issuer's and the last is the subject's.
    if let Some(first) = cns.first() {
        info.issuer_cn = first.clone();
    }
    if let Some(last) = cns.last() {
        info.subject_cn = last.clone();
    }
    info.self_signed = cns.len() >= 1 && info.issuer_cn == info.subject_cn;

    // The subject Organization (O) names appliances that leave the CN generic
    // — an Ezviz camera ships CN=Device but O=Ezviz. Same encounter-order rule
    // as the CN: the subject's O is the last one in the certificate.
    let orgs = der_organizations(cert);
    if let Some(last) = orgs.last() {
        info.subject_o = last.clone();
    }

    info.sans = der_dns_sans(cert);

    if let Some((not_after, expired)) = der_not_after(cert) {
        info.not_after = not_after;
        info.expired = expired;
    }
}

/// Read a DER tag/length at `i`, returning (value start, value length).
fn der_tlv(b: &[u8], i: usize) -> Option<(usize, usize)> {
    if i + 2 > b.len() {
        return None;
    }
    let first = b[i + 1] as usize;
    if first < 0x80 {
        Some((i + 2, first))
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 || i + 2 + n > b.len() {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | b[i + 2 + k] as usize;
        }
        Some((i + 2 + n, len))
    }
}

fn der_string(b: &[u8], i: usize) -> Option<String> {
    let tag = *b.get(i)?;
    // PrintableString / UTF8String / IA5String / T61String / BMPString
    if !matches!(tag, 0x0c | 0x13 | 0x16 | 0x14 | 0x1e) {
        return None;
    }
    let (start, len) = der_tlv(b, i)?;
    let end = start.checked_add(len)?;
    if end > b.len() || len > 512 {
        return None;
    }
    let s: String = if tag == 0x1e {
        // BMPString: UTF-16BE.
        b[start..end]
            .chunks_exact(2)
            .map(|c| ((c[0] as u16) << 8) | c[1] as u16)
            .filter_map(|u| char::from_u32(u as u32))
            .collect()
    } else {
        String::from_utf8_lossy(&b[start..end]).to_string()
    };
    let s = s.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Every commonName (OID 2.5.4.3) value in the certificate, in encounter order.
pub fn der_common_names(cert: &[u8]) -> Vec<String> {
    const CN_OID: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + CN_OID.len() < cert.len() {
        if &cert[i..i + CN_OID.len()] == CN_OID {
            if let Some(s) = der_string(cert, i + CN_OID.len()) {
                out.push(s);
            }
            i += CN_OID.len();
        } else {
            i += 1;
        }
    }
    out
}

/// Every organizationName (OID 2.5.4.10) value in the certificate, in
/// encounter order — the issuer's precede the subject's, exactly like the CN.
pub fn der_organizations(cert: &[u8]) -> Vec<String> {
    const O_OID: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x0a];
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + O_OID.len() < cert.len() {
        if &cert[i..i + O_OID.len()] == O_OID {
            if let Some(s) = der_string(cert, i + O_OID.len()) {
                out.push(s);
            }
            i += O_OID.len();
        } else {
            i += 1;
        }
    }
    out
}

/// dNSName entries from the subjectAltName extension (OID 2.5.29.17).
pub fn der_dns_sans(cert: &[u8]) -> Vec<String> {
    const SAN_OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
    let mut out: Vec<String> = Vec::new();
    let Some(pos) = cert
        .windows(SAN_OID.len())
        .position(|w| w == SAN_OID)
    else {
        return out;
    };
    let mut i = pos + SAN_OID.len();
    // An optional `critical` BOOLEAN may sit between the OID and the value.
    if cert.get(i) == Some(&0x01) {
        if let Some((s, l)) = der_tlv(cert, i) {
            i = s + l;
        }
    }
    // extnValue is an OCTET STRING wrapping the GeneralNames SEQUENCE.
    if cert.get(i) != Some(&0x04) {
        return out;
    }
    let Some((s, l)) = der_tlv(cert, i) else { return out };
    let inner = match cert.get(s..s + l) {
        Some(v) => v,
        None => return out,
    };
    if inner.first() != Some(&0x30) {
        return out;
    }
    let Some((gs, gl)) = der_tlv(inner, 0) else { return out };
    let end = (gs + gl).min(inner.len());
    let mut j = gs;
    while j + 2 <= end && out.len() < 8 {
        let tag = inner[j];
        let Some((vs, vl)) = der_tlv(inner, j) else { break };
        if vs + vl > inner.len() {
            break;
        }
        if tag == 0x82 {
            // [2] dNSName, an implicitly-tagged IA5String.
            let name = String::from_utf8_lossy(&inner[vs..vs + vl]).trim().to_string();
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        }
        j = vs + vl;
    }
    out
}

/// The certificate's notAfter, as "YYYY-MM-DD", plus whether it is in the past.
///
/// Rather than walking the whole tbsCertificate we look for the Validity
/// SEQUENCE by shape: a SEQUENCE whose first element is a UTCTime (13 bytes,
/// "YYMMDDHHMMSSZ") or GeneralizedTime (15 bytes) — an encoding essentially
/// every real certificate uses.
pub fn der_not_after(cert: &[u8]) -> Option<(String, bool)> {
    let mut i = 0usize;
    while i + 4 < cert.len() {
        if cert[i] == 0x30 && matches!(cert[i + 2], 0x17 | 0x18) && matches!(cert[i + 3], 0x0d | 0x0f)
        {
            let (first_start, first_len) = der_tlv(cert, i + 2)?;
            let second = first_start + first_len;
            if second + 2 <= cert.len() && matches!(cert[second], 0x17 | 0x18) {
                let (s, l) = der_tlv(cert, second)?;
                if s + l <= cert.len() {
                    let raw = String::from_utf8_lossy(&cert[s..s + l]).to_string();
                    return parse_asn1_time(&raw).map(|(y, m, d)| {
                        let (cy, cm, cd) = today_utc();
                        let expired = (y, m, d) < (cy, cm, cd);
                        (format!("{y:04}-{m:02}-{d:02}"), expired)
                    });
                }
            }
        }
        i += 1;
    }
    None
}

/// "260131120000Z" (UTCTime) or "20260131120000Z" (GeneralizedTime).
fn parse_asn1_time(s: &str) -> Option<(i64, u32, u32)> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    let (year, rest) = if digits.len() >= 14 {
        (digits[0..4].parse::<i64>().ok()?, &digits[4..])
    } else if digits.len() >= 12 {
        let yy = digits[0..2].parse::<i64>().ok()?;
        // RFC 5280: two-digit years >= 50 mean 19xx.
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
    } else {
        return None;
    };
    let month = rest.get(0..2)?.parse::<u32>().ok()?;
    let day = rest.get(2..4)?.parse::<u32>().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

/// Today's UTC date, derived from the epoch with Howard Hinnant's civil-from-days.
fn today_utc() -> (i64, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
