//! UDP scanning and UDP service detection, without root.
//!
//! UDP is where most scanners give up, because "is this port open?" has no
//! handshake to lean on. Kaisen gets a real answer two ways, both unprivileged:
//!
//!   * **A reply means open.** So every port worth scanning gets a payload the
//!     service on it will actually answer — an NTP client packet, an SNMP GET,
//!     a NetBIOS node-status query, a Steam A2S_INFO. A generic empty datagram
//!     tells you nothing; a protocol-shaped one tells you everything.
//!   * **An ICMP port-unreachable means closed.** We never see the ICMP packet
//!     itself (that needs CAP_NET_RAW), but a *connected* UDP socket surfaces it
//!     as `ConnectionRefused` on the next receive. That is how we distinguish
//!     closed from filtered without any privileges at all.
//!
//! Silence stays honest: it is reported as `open|filtered`, exactly as nmap
//! does, because a firewall drop and a service that simply had nothing to say
//! are genuinely indistinguishable from here.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::service::probe::Probed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpState {
    /// Something answered. Unambiguous.
    Open,
    /// ICMP port-unreachable came back (seen as a socket error).
    Closed,
    /// Silence — a drop, or a service with nothing to say to our probe.
    OpenFiltered,
}

pub struct UdpReport {
    pub port: u16,
    pub state: UdpState,
    pub service: Option<Probed>,
    pub reason: &'static str,
}

/// Probe one UDP port: send the best payload we have for it, then interpret
/// whatever comes back (or doesn't).
pub async fn probe(ip: IpAddr, port: u16, timeout_ms: u64, retries: u32) -> UdpReport {
    let addr = SocketAddr::new(ip, port);
    let dur = Duration::from_millis(timeout_ms.max(700));
    let payloads = payloads_for(port, ip);

    let mut state = UdpState::OpenFiltered;
    let mut reason = "no-response";
    let mut best: Option<Probed> = None;

    for payload in &payloads {
        for _attempt in 0..=retries.min(2) {
            match send_recv(addr, payload, dur).await {
                Recv::Data(data) => {
                    state = UdpState::Open;
                    reason = "udp-response";
                    let parsed = parse(port, &data, ip);
                    // Keep the most informative answer across payload variants.
                    if best
                        .as_ref()
                        .map(|b| score(&parsed) > score(b))
                        .unwrap_or(true)
                    {
                        best = Some(parsed);
                    }
                    break;
                }
                Recv::Refused => {
                    // ICMP port unreachable: definitive, stop immediately.
                    return UdpReport {
                        port,
                        state: UdpState::Closed,
                        service: None,
                        reason: "port-unreach",
                    };
                }
                Recv::Timeout => continue,
                Recv::Error => break,
            }
        }
        if state == UdpState::Open && best.as_ref().map(|b| score(b) >= 2).unwrap_or(false) {
            break; // already have a solid identification
        }
    }

    UdpReport {
        port,
        state,
        service: best,
        reason,
    }
}

/// How much a parsed result actually tells us, used to pick between the
/// answers of several probe variants for the same port.
fn score(p: &Probed) -> u8 {
    let mut s = 0;
    if !p.product.is_empty() {
        s += 1;
    }
    if !p.version.is_empty() {
        s += 2;
    }
    if !p.extra.is_empty() {
        s += 1;
    }
    s
}

enum Recv {
    Data(Vec<u8>),
    /// ICMP port unreachable, surfaced by the connected socket.
    Refused,
    Timeout,
    Error,
}

async fn send_recv(addr: SocketAddr, payload: &[u8], dur: Duration) -> Recv {
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(sock) = UdpSocket::bind(bind).await else {
        return Recv::Error;
    };
    // Connecting matters: only a connected socket reports the ICMP error back
    // to us, which is the whole basis of unprivileged closed-port detection.
    if sock.connect(addr).await.is_err() {
        return Recv::Error;
    }
    if let Err(e) = sock.send(payload).await {
        return if e.kind() == std::io::ErrorKind::ConnectionRefused {
            Recv::Refused
        } else {
            Recv::Error
        };
    }
    let mut buf = vec![0u8; 8192];
    match timeout(dur, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Recv::Data(buf[..n].to_vec()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Recv::Refused,
        Ok(Err(_)) => Recv::Error,
        Err(_) => Recv::Timeout,
    }
}

// ── payload table ───────────────────────────────────────────────────────────

/// The payloads to try for a port, most informative first. Several ports get
/// more than one: NTP is asked as a client, then for its version string, then
/// for the monitor list, because each answers a different question.
fn payloads_for(port: u16, ip: IpAddr) -> Vec<Vec<u8>> {
    match port {
        53 => vec![dns_version_query(), dns_a_query()],
        67 | 68 => vec![dhcp_inform()],
        69 => vec![tftp_rrq()],
        7 => vec![b"kaisen\n".to_vec()],
        13 | 17 | 19 | 37 => vec![b"\r\n".to_vec()],
        111 => vec![rpc_dump()],
        123 => vec![ntp_client(), ntp_readvar(), ntp_monlist()],
        137 => vec![netbios_node_status()],
        161 | 162 | 6161 => vec![
            snmp_get(b"public", SYSDESCR_OID),
            snmp_get(b"private", SYSDESCR_OID),
            snmp_v3_discovery(),
        ],
        177 => vec![xdmcp_query()],
        427 => vec![slp_request()],
        500 | 4500 => vec![isakmp_sa()],
        520 => vec![rip_request()],
        623 | 664 => vec![ipmi_channel_auth()],
        1194 => vec![openvpn_reset()],
        1434 => vec![vec![0x02], vec![0x03]],
        1604 => vec![citrix_ica_browse()],
        1900 | 5000 => vec![ssdp_msearch()],
        3283 => vec![ard_probe()],
        3478 | 3479 | 19302 => vec![stun_binding()],
        3702 => vec![wsd_probe()],
        5060 | 5061 => vec![sip_options(ip)],
        5093 => vec![sentinel_probe()],
        5353 => vec![mdns_services_query()],
        5355 => vec![llmnr_query()],
        5683 => vec![coap_wellknown()],
        10001 => vec![ubnt_discover()],
        11211 => vec![memcached_udp_stats()],
        17185 => vec![vec![0u8; 8]],
        19132 | 19133 => vec![raknet_ping()],
        20000 => vec![vec![0u8; 8]],
        27015..=27020 | 27960 | 26000 => vec![a2s_info(), quake_getstatus()],
        30718 => vec![vec![0x00, 0x00, 0x00, 0xf8]],
        44818 => vec![enip_list_identity()],
        47808 => vec![bacnet_whois()],
        64738 => vec![mumble_ping()],
        // Unknown port: an empty datagram still triggers ICMP port-unreachable
        // from a closed port, which is the useful half of the answer.
        _ => vec![Vec::new(), b"\r\n\r\n".to_vec()],
    }
}

// ── individual probe payloads ───────────────────────────────────────────────

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// `version.bind` CHAOS TXT — the same question the TCP path asks.
fn dns_version_query() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&be16(0x6b61));
    m.extend_from_slice(&be16(0x0100));
    m.extend_from_slice(&be16(1));
    m.extend_from_slice(&[0u8; 6]);
    for label in ["version", "bind"] {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&be16(16)); // TXT
    m.extend_from_slice(&be16(3)); // CHAOS
    m
}

/// A plain recursive A query, which also reveals whether this is an open resolver.
fn dns_a_query() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&be16(0x6b62));
    m.extend_from_slice(&be16(0x0100)); // RD set
    m.extend_from_slice(&be16(1));
    m.extend_from_slice(&[0u8; 6]);
    for label in ["www", "example", "com"] {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&be16(1)); // A
    m.extend_from_slice(&be16(1)); // IN
    m
}

// ── NTP ─────────────────────────────────────────────────────────────────────

/// A normal NTPv4 client request (mode 3). The reply carries stratum, the
/// reference clock, precision and the server's idea of the time.
fn ntp_client() -> Vec<u8> {
    let mut p = vec![0u8; 48];
    p[0] = 0x23; // LI=0, VN=4, Mode=3 (client)
    p[1] = 0; // stratum
    p[2] = 4; // poll
    p[3] = 0xec; // precision
    p
}

/// NTP control (mode 6) READVAR with no association: `ntpd` answers with a
/// text variable list containing `version=`, `processor=` and `system=` —
/// the exact daemon build and the host OS, pre-auth.
fn ntp_readvar() -> Vec<u8> {
    vec![
        0x16, // LI=0, VN=2, Mode=6 (control)
        0x02, // op = readvar, response=0, more=0
        0x00, 0x01, // sequence
        0x00, 0x00, // status
        0x00, 0x00, // association id = 0 (system variables)
        0x00, 0x00, // offset
        0x00, 0x00, // count
    ]
}

/// NTP private mode 7 MON_GETLIST_1 — the classic `monlist`. A reply means the
/// daemon is old enough to be a DDoS amplifier (CVE-2013-5211).
fn ntp_monlist() -> Vec<u8> {
    let mut p = vec![0u8; 48];
    p[0] = 0x17; // response=0, more=0, VN=2, Mode=7
    p[1] = 0x00; // auth=0, sequence=0
    p[2] = 0x03; // implementation = XNTPD
    p[3] = 0x2a; // request code 42 = MON_GETLIST_1
    p
}

// ── SNMP ────────────────────────────────────────────────────────────────────

const SYSDESCR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(tag);
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(value);
    out
}

fn snmp_get(community: &[u8], oid: &[u8]) -> Vec<u8> {
    let mut varbind = tlv(0x06, oid);
    varbind.extend_from_slice(&[0x05, 0x00]); // NULL value
    let varbind = tlv(0x30, &varbind);
    let varbind_list = tlv(0x30, &varbind);

    let mut pdu = Vec::new();
    pdu.extend_from_slice(&tlv(0x02, &[0x00, 0x00, 0x00, 0x01])); // request-id
    pdu.extend_from_slice(&tlv(0x02, &[0x00])); // error-status
    pdu.extend_from_slice(&tlv(0x02, &[0x00])); // error-index
    pdu.extend_from_slice(&varbind_list);
    let pdu = tlv(0xA0, &pdu);

    let mut msg = Vec::new();
    msg.extend_from_slice(&tlv(0x02, &[0x01])); // version 1 => SNMPv2c
    msg.extend_from_slice(&tlv(0x04, community));
    msg.extend_from_slice(&pdu);
    tlv(0x30, &msg)
}

/// An SNMPv3 engine discovery: agents that refuse v1/v2c still answer this,
/// and the engine ID encodes the vendor's IANA enterprise number.
fn snmp_v3_discovery() -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&tlv(0x02, &[0x00, 0x00, 0x00, 0x01])); // msgID
    header.extend_from_slice(&tlv(0x02, &[0x00, 0x00, 0xff, 0xe3])); // max size
    header.extend_from_slice(&tlv(0x04, &[0x04])); // flags: reportable
    header.extend_from_slice(&tlv(0x02, &[0x03])); // security model = USM
    let header = tlv(0x30, &header);

    let mut usm = Vec::new();
    usm.extend_from_slice(&tlv(0x04, &[])); // engine id (empty = discovery)
    usm.extend_from_slice(&tlv(0x02, &[0x00])); // engine boots
    usm.extend_from_slice(&tlv(0x02, &[0x00])); // engine time
    usm.extend_from_slice(&tlv(0x04, &[])); // user name
    usm.extend_from_slice(&tlv(0x04, &[])); // auth params
    usm.extend_from_slice(&tlv(0x04, &[])); // priv params
    let usm = tlv(0x30, &usm);
    let security = tlv(0x04, &usm);

    let mut scoped = Vec::new();
    scoped.extend_from_slice(&tlv(0x04, &[])); // context engine id
    scoped.extend_from_slice(&tlv(0x04, &[])); // context name
    let mut pdu = Vec::new();
    pdu.extend_from_slice(&tlv(0x02, &[0x01]));
    pdu.extend_from_slice(&tlv(0x02, &[0x00]));
    pdu.extend_from_slice(&tlv(0x02, &[0x00]));
    pdu.extend_from_slice(&tlv(0x30, &[]));
    scoped.extend_from_slice(&tlv(0xA0, &pdu));
    let scoped = tlv(0x30, &scoped);

    let mut msg = Vec::new();
    msg.extend_from_slice(&tlv(0x02, &[0x03])); // version 3
    msg.extend_from_slice(&header);
    msg.extend_from_slice(&security);
    msg.extend_from_slice(&scoped);
    tlv(0x30, &msg)
}

// ── NetBIOS ─────────────────────────────────────────────────────────────────

/// NBSTAT query for the wildcard name. The reply lists the machine's NetBIOS
/// names (hostname, workgroup, logged-on user) *and* its MAC address — on a
/// Windows host this is the richest unprivileged identification there is.
fn netbios_node_status() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&be16(0x6b61));
    m.extend_from_slice(&be16(0x0000));
    m.extend_from_slice(&be16(1)); // qdcount
    m.extend_from_slice(&[0u8; 6]);
    // The wildcard name "*" padded with NULs, level-1 encoded.
    let mut name = [0u8; 16];
    name[0] = b'*';
    m.push(32);
    for c in name {
        m.push(b'A' + (c >> 4));
        m.push(b'A' + (c & 0x0f));
    }
    m.push(0);
    m.extend_from_slice(&be16(0x0021)); // NBSTAT
    m.extend_from_slice(&be16(0x0001)); // IN
    m
}

// ── the rest ────────────────────────────────────────────────────────────────

fn tftp_rrq() -> Vec<u8> {
    let mut p = vec![0x00, 0x01];
    p.extend_from_slice(b"kaisen.probe\0octet\0");
    p
}

/// ONC RPC portmap DUMP: lists every registered RPC program (NFS, NIS, mountd).
fn rpc_dump() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x6b616973u32.to_be_bytes()); // xid
    p.extend_from_slice(&0u32.to_be_bytes()); // CALL
    p.extend_from_slice(&2u32.to_be_bytes()); // RPC version
    p.extend_from_slice(&100000u32.to_be_bytes()); // portmapper
    p.extend_from_slice(&2u32.to_be_bytes()); // version 2
    p.extend_from_slice(&4u32.to_be_bytes()); // PMAPPROC_DUMP
    p.extend_from_slice(&0u32.to_be_bytes()); // cred: AUTH_NULL
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes()); // verf: AUTH_NULL
    p.extend_from_slice(&0u32.to_be_bytes());
    p
}

fn xdmcp_query() -> Vec<u8> {
    vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00]
}

fn slp_request() -> Vec<u8> {
    let mut p = vec![0x02, 0x01, 0x00, 0x00, 0x00];
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    p.extend_from_slice(b"\x00\x02en\x00\x00\x00\x0eservice:service-agent\x00\x00\x00\x00\x00\x00");
    let len = p.len() as u32;
    p[2] = ((len >> 16) & 0xff) as u8;
    p[3] = ((len >> 8) & 0xff) as u8;
    p[4] = (len & 0xff) as u8;
    p
}

/// An IKEv1 main-mode SA proposal. VPN gateways answer with vendor IDs that
/// name the product (Cisco, Fortinet, strongSwan, Windows).
fn isakmp_sa() -> Vec<u8> {
    let mut transform = Vec::new();
    transform.extend_from_slice(&[0x00, 0x00, 0x00, 0x24]); // next=none, len=36
    transform.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // transform 1, KEY_IKE
                                                            // Attributes: 3DES / SHA1 / preshared / group 2 / lifetime 28800s
    transform.extend_from_slice(&[0x80, 0x01, 0x00, 0x05]);
    transform.extend_from_slice(&[0x80, 0x02, 0x00, 0x02]);
    transform.extend_from_slice(&[0x80, 0x03, 0x00, 0x01]);
    transform.extend_from_slice(&[0x80, 0x04, 0x00, 0x02]);
    transform.extend_from_slice(&[0x80, 0x0b, 0x00, 0x01]);
    transform.extend_from_slice(&[0x00, 0x0c, 0x00, 0x04, 0x00, 0x00, 0x70, 0x80]);

    let mut proposal = Vec::new();
    proposal.extend_from_slice(&[0x00, 0x00]); // next payload none
    proposal.extend_from_slice(&be16((8 + transform.len()) as u16));
    proposal.extend_from_slice(&[0x01, 0x01, 0x00, 0x01]); // proposal 1, ISAKMP, 1 transform
    proposal.extend_from_slice(&transform);

    let mut sa = Vec::new();
    sa.extend_from_slice(&[0x00, 0x00]); // next payload none
    sa.extend_from_slice(&be16((4 + 8 + proposal.len()) as u16));
    sa.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // DOI = IPsec
    sa.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // situation = identity only
    sa.extend_from_slice(&proposal);

    let mut p = Vec::new();
    p.extend_from_slice(&[0x6b, 0x61, 0x69, 0x73, 0x65, 0x6e, 0x21, 0x21]); // initiator cookie
    p.extend_from_slice(&[0u8; 8]); // responder cookie
    p.push(0x01); // next payload = SA
    p.push(0x10); // version 1.0
    p.push(0x02); // exchange type = identity protection (main mode)
    p.push(0x00); // flags
    p.extend_from_slice(&[0u8; 4]); // message id
    p.extend_from_slice(&((28 + sa.len()) as u32).to_be_bytes());
    p.extend_from_slice(&sa);
    p
}

fn rip_request() -> Vec<u8> {
    let mut p = vec![0x01, 0x02, 0x00, 0x00]; // request, version 2
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // AF=0, tag
    p.extend_from_slice(&[0u8; 12]);
    p.extend_from_slice(&16u32.to_be_bytes()); // metric 16 = "send me everything"
    p
}

/// IPMI Get Channel Authentication Capabilities — answered before any login,
/// and the answer says whether null-auth and anonymous login are permitted.
fn ipmi_channel_auth() -> Vec<u8> {
    let mut ipmi = vec![0x20, 0x18, 0xc8, 0x81, 0x04, 0x38, 0x0e, 0x04];
    // Two's-complement checksum over the request bytes.
    let sum: u8 = ipmi[3..].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    ipmi.push((!sum).wrapping_add(1));

    let mut p = vec![0x06, 0x00, 0xff, 0x07]; // RMCP: version 6, class IPMI
    p.push(0x00); // auth type = none
    p.extend_from_slice(&[0u8; 4]); // session sequence
    p.extend_from_slice(&[0u8; 4]); // session id
    p.push(ipmi.len() as u8);
    p.extend_from_slice(&ipmi);
    p
}

fn openvpn_reset() -> Vec<u8> {
    let mut p = vec![0x38]; // P_CONTROL_HARD_RESET_CLIENT_V2 << 3
    p.extend_from_slice(&[0x6b, 0x61, 0x69, 0x73, 0x65, 0x6e, 0x00, 0x01]); // session id
    p.push(0x00); // no packet-id acks
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // message packet id
    p
}

fn citrix_ica_browse() -> Vec<u8> {
    vec![
        0x1e, 0x00, 0x01, 0x30, 0x02, 0xfd, 0xa8, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

/// SSDP M-SEARCH. UPnP devices answer with a SERVER header naming the OS and
/// the product — routers, TVs, printers, consoles and NAS boxes all do it.
fn ssdp_msearch() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n\
      MX: 1\r\nST: ssdp:all\r\nUSER-AGENT: Kaisen\r\n\r\n"
        .to_vec()
}

fn ard_probe() -> Vec<u8> {
    vec![0x00, 0x14, 0x00, 0x00]
}

/// A STUN binding request: identifies STUN/TURN servers, and the reply tells
/// you the public address the server sees you coming from.
fn stun_binding() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&be16(0x0001)); // Binding Request
    p.extend_from_slice(&be16(0x0000)); // length
    p.extend_from_slice(&0x2112A442u32.to_be_bytes()); // magic cookie
    p.extend_from_slice(b"kaisen-probe"); // 12-byte transaction id
    p
}

fn wsd_probe() -> Vec<u8> {
    b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\
      <soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" \
      xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
      xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\">\
      <soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>\
      <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>\
      <wsa:MessageID>urn:uuid:6b616973-656e-0000-0000-000000000001</wsa:MessageID>\
      </soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>"
        .to_vec()
}

fn sip_options(ip: IpAddr) -> Vec<u8> {
    format!(
        "OPTIONS sip:{ip} SIP/2.0\r\nVia: SIP/2.0/UDP kaisen:5060;branch=z9hG4bKkaisen\r\n\
         From: <sip:kaisen@kaisen>;tag=1\r\nTo: <sip:{ip}>\r\nCall-ID: kaisen@kaisen\r\n\
         CSeq: 1 OPTIONS\r\nContact: <sip:kaisen@kaisen>\r\nMax-Forwards: 70\r\n\
         User-Agent: Kaisen\r\nContent-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

fn sentinel_probe() -> Vec<u8> {
    vec![0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
}

/// mDNS: ask for the service-enumeration record. Apple, Linux (Avahi) and IoT
/// devices answer with their hostname and the services they publish.
fn mdns_services_query() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&be16(0x0000)); // mDNS uses id 0
    m.extend_from_slice(&be16(0x0000));
    m.extend_from_slice(&be16(1));
    m.extend_from_slice(&[0u8; 6]);
    for label in ["_services", "_dns-sd", "_udp", "local"] {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&be16(12)); // PTR
    m.extend_from_slice(&be16(1)); // IN
    m
}

fn llmnr_query() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&be16(0x6b61));
    m.extend_from_slice(&be16(0x0000));
    m.extend_from_slice(&be16(1));
    m.extend_from_slice(&[0u8; 6]);
    for label in ["wpad"] {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&be16(1));
    m.extend_from_slice(&be16(1));
    m
}

/// Append one CoAP option. Deltas and lengths below 13 go straight into the
/// nibbles; 13..268 use the one-byte extended form. Getting this wrong is easy
/// and silent, so it lives in one place rather than inline per option.
fn coap_option(out: &mut Vec<u8>, delta: u16, value: &[u8]) {
    let nibble = |v: usize| -> (u8, Option<u8>) {
        if v < 13 {
            (v as u8, None)
        } else {
            (13, Some((v - 13) as u8))
        }
    };
    let (d, d_ext) = nibble(delta as usize);
    let (l, l_ext) = nibble(value.len());
    out.push((d << 4) | l);
    if let Some(e) = d_ext {
        out.push(e);
    }
    if let Some(e) = l_ext {
        out.push(e);
    }
    out.extend_from_slice(value);
}

fn coap_wellknown() -> Vec<u8> {
    let mut p = vec![0x40, 0x01, 0x6b, 0x61]; // ver 1, CON, no token, GET, message id
    coap_option(&mut p, 11, b".well-known"); // Uri-Path
    coap_option(&mut p, 0, b"core"); // Uri-Path (same option number)
    p
}

fn ubnt_discover() -> Vec<u8> {
    vec![0x01, 0x00, 0x00, 0x00]
}

fn memcached_udp_stats() -> Vec<u8> {
    let mut p = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]; // UDP frame header
    p.extend_from_slice(b"stats\r\n");
    p
}

/// RakNet unconnected ping — Minecraft Bedrock and other RakNet servers answer
/// with a semicolon-delimited MOTD containing the exact version.
fn raknet_ping() -> Vec<u8> {
    let mut p = vec![0x01];
    p.extend_from_slice(&0u64.to_be_bytes()); // time
    p.extend_from_slice(&[
        0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56,
        0x78,
    ]); // RakNet magic
    p.extend_from_slice(&0x6b616973656u64.to_be_bytes()); // client GUID
    p
}

/// Valve A2S_INFO — name, map, game, player counts and version.
fn a2s_info() -> Vec<u8> {
    let mut p = vec![0xff, 0xff, 0xff, 0xff, 0x54];
    p.extend_from_slice(b"Source Engine Query\0");
    p
}

fn quake_getstatus() -> Vec<u8> {
    let mut p = vec![0xff, 0xff, 0xff, 0xff];
    p.extend_from_slice(b"getstatus\n");
    p
}

/// EtherNet/IP List Identity: industrial controllers answer with vendor,
/// product code, firmware revision, serial number and product name.
fn enip_list_identity() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x0063u16.to_le_bytes()); // ListIdentity
    p.extend_from_slice(&0u16.to_le_bytes()); // length
    p.extend_from_slice(&0u32.to_le_bytes()); // session handle
    p.extend_from_slice(&0u32.to_le_bytes()); // status
    p.extend_from_slice(&[0u8; 8]); // sender context
    p.extend_from_slice(&0u32.to_le_bytes()); // options
    p
}

/// BACnet Who-Is. Building controllers answer I-Am with their device instance
/// and vendor identifier.
fn bacnet_whois() -> Vec<u8> {
    vec![
        0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08,
    ]
}

/// Mumble/Murmur ping: version, user count and bandwidth, no auth.
fn mumble_ping() -> Vec<u8> {
    let mut p = vec![0u8; 12];
    p[0..4].copy_from_slice(&0u32.to_be_bytes()); // type 0 = ping
    p[4..12].copy_from_slice(&0x6b616973656u64.to_be_bytes()); // ident echoed back
    p
}

fn dhcp_inform() -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 0x01; // BOOTREQUEST
    p[1] = 0x01; // ethernet
    p[2] = 0x06; // hardware address length
    p[4..8].copy_from_slice(&0x6b616973u32.to_be_bytes()); // xid
    p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
    p.extend_from_slice(&[53, 1, 8]); // DHCP message type = INFORM
    p.extend_from_slice(&[55, 3, 1, 3, 6]); // parameter request list
    p.push(0xff);
    p
}

// ── response parsing ────────────────────────────────────────────────────────

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

fn clean(s: &str, max: usize) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max)
        .collect()
}

fn named(name: &'static str, product: &str) -> Probed {
    Probed {
        name,
        product: product.to_string(),
        ..Default::default()
    }
}

/// Turn a response into a service identification. Every branch here is reached
/// only because the matching payload above got an answer, so the port really
/// is running the protocol we asked about.
fn parse(port: u16, data: &[u8], _ip: IpAddr) -> Probed {
    match port {
        123 => parse_ntp(data),
        161 | 162 | 6161 => parse_snmp(data),
        137 => parse_netbios(data),
        53 => parse_dns(data),
        1434 => parse_mssql_browser(data),
        623 | 664 => parse_ipmi(data),
        1900 | 5000 | 3702 => parse_ssdp(data),
        5353 => parse_mdns(data),
        111 => parse_rpc(data),
        69 => named("tftp", "TFTP server"),
        27015..=27020 | 27960 | 26000 => parse_a2s(data),
        19132 | 19133 => parse_raknet(data),
        64738 => parse_mumble(data),
        44818 => parse_enip(data),
        47808 => parse_bacnet(data),
        11211 => parse_memcached(data),
        500 | 4500 => parse_isakmp(data),
        3478 | 3479 | 19302 => named("stun", "STUN/TURN server"),
        5683 => parse_coap(data),
        1194 => named("openvpn", "OpenVPN server"),
        520 => named("rip", "RIP router"),
        177 => named("xdmcp", "XDMCP display manager"),
        427 => named("svrloc", "Service Location Protocol"),
        10001 => parse_ubnt(data),
        5060 | 5061 => parse_sip(data),
        19 => Probed {
            name: "chargen",
            product: "Chargen".into(),
            extra: "UDP amplification vector".into(),
            ..Default::default()
        },
        7 => named("echo", "Echo service"),
        13 => named("daytime", clean(&ascii(data), 60).as_str()),
        _ => {
            let text = clean(&ascii(data), 60);
            if text.len() >= 4 {
                Probed {
                    name: "unknown",
                    banner: text,
                    ..Default::default()
                }
            } else {
                Probed {
                    name: "unknown",
                    extra: format!("{} byte reply", data.len()),
                    ..Default::default()
                }
            }
        }
    }
}

fn parse_ntp(data: &[u8]) -> Probed {
    let mut p = named("ntp", "NTP server");
    if data.is_empty() {
        return p;
    }
    let mode = data[0] & 0x07;
    let version = (data[0] >> 3) & 0x07;

    // Mode 6 control response: a text variable list with the daemon's version.
    if mode == 6 {
        let text = ascii(&data[12.min(data.len())..]);
        let mut bits = Vec::new();
        for key in ["version", "processor", "system", "leap", "stratum"] {
            if let Some(v) = kv_lookup(&text, key) {
                if key == "version" {
                    p.product = v
                        .split(&['@', ' '][..])
                        .next()
                        .unwrap_or("ntpd")
                        .to_string();
                    p.version = crate::service::probe::first_version(&v);
                    if p.version.is_empty() {
                        p.version = v.clone();
                    }
                } else if key == "system" {
                    p.os_hint = v.clone();
                    bits.push(v);
                } else {
                    bits.push(format!("{key}={v}"));
                }
            }
        }
        p.extra = bits.join("; ");
        if p.extra.is_empty() {
            p.extra = "mode 6 control queries allowed".into();
        } else {
            p.extra.push_str("; mode 6 control queries allowed");
        }
        return p;
    }

    // Mode 7 private response: monlist answered => a known amplifier.
    if mode == 7 {
        p.extra = "MONLIST ENABLED (CVE-2013-5211 amplification)".into();
        return p;
    }

    // Mode 4 server response: stratum and reference clock.
    if data.len() >= 48 {
        let stratum = data[1];
        let refid = &data[12..16];
        let refid_str = if stratum <= 1 {
            clean(&ascii(refid), 8)
        } else {
            format!("{}.{}.{}.{}", refid[0], refid[1], refid[2], refid[3])
        };
        let mut bits = vec![format!("NTPv{version}"), format!("stratum {stratum}")];
        if !refid_str.trim().is_empty() {
            bits.push(format!("refid {}", refid_str.trim()));
        }
        if stratum == 0 {
            bits.push("kiss-of-death / unsynchronised".into());
        }
        p.version = format!("v{version}");
        p.extra = bits.join("; ");
    }
    p
}

/// Pull `key=value` out of an NTP control variable list.
fn kv_lookup(text: &str, key: &str) -> Option<String> {
    let pos = text.find(&format!("{key}="))?;
    let rest = &text[pos + key.len() + 1..];
    let rest = rest.trim_start();
    let value = if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next().unwrap_or("")
    } else {
        rest.split(',').next().unwrap_or("")
    };
    let v = value.trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn parse_snmp(data: &[u8]) -> Probed {
    let mut p = named("snmp", "SNMP agent");
    // SNMPv3 report: no community needed, but the engine ID identifies the vendor.
    if data.len() > 4 && data.windows(3).any(|w| w == [0x02, 0x01, 0x03]) {
        p.version = "v3".into();
        p.extra = "SNMPv3 (authentication required)".into();
        return p;
    }
    let needle = {
        let mut v = vec![0x06u8, SYSDESCR_OID.len() as u8];
        v.extend_from_slice(SYSDESCR_OID);
        v
    };
    if let Some(pos) = data
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
    {
        let i = pos + needle.len();
        if i + 2 <= data.len() && data[i] == 0x04 {
            let len = data[i + 1] as usize;
            let start = i + 2;
            if start + len <= data.len() {
                let descr = clean(&String::from_utf8_lossy(&data[start..start + len]), 140);
                if !descr.is_empty() {
                    p.product = "SNMP agent".into();
                    p.extra = descr.clone();
                    p.banner = descr.clone();
                    p.version = crate::service::probe::first_version(&descr);
                    p.os_hint = descr;
                    return p;
                }
            }
        }
    }
    p.extra = "responded to community \"public\"".into();
    p
}

fn parse_netbios(data: &[u8]) -> Probed {
    let mut p = named("netbios-ns", "NetBIOS Name Service");
    p.os_hint = "Windows".into();
    if data.len() < 57 {
        return p;
    }
    // A node-status reply normally sets QDCOUNT=0 and leads straight with the
    // answer, so trust the header rather than assuming the question is echoed.
    let qdcount = ((data[4] as u16) << 8) | data[5] as u16;
    let mut idx = 12;
    for _ in 0..qdcount {
        while idx < data.len() && data[idx] != 0 {
            if data[idx] & 0xc0 == 0xc0 {
                idx += 1;
                break;
            }
            idx += data[idx] as usize + 1;
        }
        idx += 1 + 4; // root label + qtype + qclass
    }
    if idx + 12 > data.len() {
        return p;
    }
    // Answer RR: name (pointer or labels), type, class, ttl, rdlength.
    let mut a = idx;
    if data[a] & 0xc0 == 0xc0 {
        a += 2;
    } else {
        while a < data.len() && data[a] != 0 {
            a += data[a] as usize + 1;
        }
        a += 1;
    }
    a += 8; // type + class + ttl
    if a + 2 > data.len() {
        return p;
    }
    a += 2; // rdlength
    if a >= data.len() {
        return p;
    }
    let count = data[a] as usize;
    a += 1;

    let mut names = Vec::new();
    let mut workgroup = String::new();
    let mut hostname = String::new();
    for _ in 0..count.min(32) {
        if a + 18 > data.len() {
            break;
        }
        let raw = String::from_utf8_lossy(&data[a..a + 15]).trim().to_string();
        let suffix = data[a + 15];
        let flags = ((data[a + 16] as u16) << 8) | data[a + 17] as u16;
        let group = flags & 0x8000 != 0;
        if group && workgroup.is_empty() {
            workgroup = raw.clone();
        } else if !group && hostname.is_empty() && suffix == 0x00 {
            hostname = raw.clone();
        }
        let role = match suffix {
            0x00 => "workstation",
            0x03 => "messenger",
            0x1b => "domain master browser",
            0x1c => "domain controllers",
            0x1d => "master browser",
            0x1e => "browser elections",
            0x20 => "file server",
            _ => "",
        };
        if !raw.is_empty() {
            names.push(if role.is_empty() {
                raw
            } else {
                format!("{raw}<{suffix:02x}> {role}")
            });
        }
        a += 18;
    }
    // The adapter's MAC address follows the name list.
    if a + 6 <= data.len() {
        let mac = data[a..a + 6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        if mac != "00:00:00:00:00:00" {
            names.push(format!("MAC {mac}"));
        }
    }
    if !hostname.is_empty() {
        p.product = format!("NetBIOS: {hostname}");
    }
    if !workgroup.is_empty() {
        names.insert(0, format!("workgroup {workgroup}"));
    }
    p.extra = names.join("; ");
    p
}

fn parse_dns(data: &[u8]) -> Probed {
    let mut p = named("domain", "DNS server");
    if data.len() < 12 {
        return p;
    }
    let ancount = ((data[6] as u16) << 8) | data[7] as u16;
    let flags = ((data[2] as u16) << 8) | data[3] as u16;
    let rcode = flags & 0x000f;
    let ra = flags & 0x0080 != 0;

    let text = ascii(&data[12..]);
    for (needle, product) in [
        ("dnsmasq", "dnsmasq"),
        ("PowerDNS", "PowerDNS"),
        ("unbound", "Unbound"),
        ("Knot", "Knot DNS"),
        ("NSD", "NSD"),
        ("CoreDNS", "CoreDNS"),
        ("BIND", "BIND"),
        ("Microsoft", "Microsoft DNS"),
    ] {
        if text.contains(needle) {
            p.product = product.to_string();
            p.version = crate::service::probe::first_version(&text);
            break;
        }
    }
    let mut bits = Vec::new();
    if ra {
        bits.push(if ancount > 0 && rcode == 0 {
            "OPEN RESOLVER (recursion available and answered)".to_string()
        } else {
            "recursion available".to_string()
        });
    }
    if p.version.is_empty() && ancount > 0 {
        let v = crate::service::probe::first_version(&text);
        if !v.is_empty() {
            p.version = v;
        }
    }
    p.extra = bits.join("; ");
    p
}

/// The SQL Server Browser answers with every instance on the host, each with
/// its own name, TCP port and exact version — before any authentication.
fn parse_mssql_browser(data: &[u8]) -> Probed {
    let mut p = named("ms-sql-m", "Microsoft SQL Server Browser");
    p.os_hint = "Windows".into();
    if data.len() < 3 {
        return p;
    }
    let text = String::from_utf8_lossy(&data[3..]).to_string();
    let mut instances = Vec::new();
    for chunk in text.split(";;") {
        let fields: Vec<&str> = chunk.split(';').collect();
        let mut name = String::new();
        let mut version = String::new();
        let mut tcp = String::new();
        let mut i = 0;
        while i + 1 < fields.len() {
            match fields[i] {
                "InstanceName" => name = fields[i + 1].to_string(),
                "Version" => version = fields[i + 1].to_string(),
                "tcp" => tcp = fields[i + 1].to_string(),
                _ => {}
            }
            i += 2;
        }
        if !name.is_empty() {
            let mut s = name;
            if !version.is_empty() {
                s.push_str(&format!(" {version}"));
                if p.version.is_empty() {
                    p.version = version;
                }
            }
            if !tcp.is_empty() {
                s.push_str(&format!(" on tcp/{tcp}"));
            }
            instances.push(s);
        }
    }
    p.extra = instances.join(", ");
    p
}

fn parse_ipmi(data: &[u8]) -> Probed {
    let mut p = named("ipmi", "IPMI / BMC");
    // RMCP(4) + session(9) + IPMI response header(7) then the payload.
    if data.len() < 22 {
        return p;
    }
    let body = &data[20..];
    let mut bits = Vec::new();
    if !body.is_empty() {
        let auth_support = body.get(2).copied().unwrap_or(0);
        let auth_status = body.get(3).copied().unwrap_or(0);
        p.version = if auth_support & 0x80 != 0 {
            "2.0".into()
        } else {
            "1.5".into()
        };
        if auth_support & 0x01 != 0 {
            bits.push("NULL authentication permitted".to_string());
        }
        if auth_support & 0x02 != 0 {
            bits.push("MD2".to_string());
        }
        if auth_support & 0x04 != 0 {
            bits.push("MD5".to_string());
        }
        if auth_support & 0x10 != 0 {
            bits.push("straight password".to_string());
        }
        if auth_status & 0x01 != 0 {
            bits.push("ANONYMOUS LOGIN ENABLED".to_string());
        }
        if auth_status & 0x20 != 0 {
            bits.push("per-message auth disabled".to_string());
        }
    }
    p.extra = bits.join("; ");
    p
}

fn parse_ssdp(data: &[u8]) -> Probed {
    let text = String::from_utf8_lossy(data).to_string();
    let mut p = named("upnp", "UPnP device");
    let mut bits = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("server:") {
            let server = line[line.len() - v.len()..].trim().to_string();
            p.product = server.clone();
            // "Linux/3.14 UPnP/1.0 Sonos/57.6" — the last token is the product.
            if let Some(last) = server.split_whitespace().last() {
                if let Some((prod, ver)) = last.split_once('/') {
                    p.product = prod.to_string();
                    p.version = ver.to_string();
                }
            }
            p.os_hint = server.clone();
            p.banner = server;
        } else if lower.starts_with("st:") || lower.starts_with("nt:") {
            bits.push(
                line.split_once(':')
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default(),
            );
        } else if lower.starts_with("location:") {
            bits.push(line.trim().to_string());
        }
    }
    if text.contains("wsd:ProbeMatch") || text.contains("Device") && text.contains("soap") {
        p.name = "ws-discovery";
        p.product = "WS-Discovery device".into();
    }
    p.extra = clean(&bits.join("; "), 160);
    p
}

fn parse_mdns(data: &[u8]) -> Probed {
    let mut p = named("mdns", "mDNS / Bonjour");
    let text = ascii(data);
    let mut services: Vec<String> = Vec::new();
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')) {
        if token.starts_with('_') && token.len() > 2 && !services.contains(&token.to_string()) {
            services.push(token.to_string());
        }
    }
    services.truncate(12);
    // Well-known service names double as a device-type hint.
    for (needle, label) in [
        ("_airplay", "Apple AirPlay receiver"),
        ("_raop", "AirPlay audio receiver"),
        ("_companion-link", "Apple device"),
        ("_homekit", "HomeKit accessory"),
        ("_googlecast", "Google Cast device"),
        ("_spotify-connect", "Spotify Connect device"),
        ("_ipp", "Network printer"),
        ("_pdl-datastream", "Network printer"),
        ("_smb", "File server"),
        ("_afpovertcp", "Apple file server"),
        ("_sftp-ssh", "SSH/SFTP host"),
        ("_workstation", "Workstation"),
        ("_hap", "HomeKit accessory"),
        ("_esphomelib", "ESPHome device"),
        ("_octoprint", "OctoPrint host"),
        ("_plexmediasvr", "Plex Media Server"),
    ] {
        if text.contains(needle) {
            p.product = label.to_string();
            break;
        }
    }
    p.extra = services.join(" ");
    p
}

fn parse_rpc(data: &[u8]) -> Probed {
    let mut p = named("rpcbind", "ONC RPC portmapper");
    // Walk the DUMP linked list: each entry is program, version, protocol, port.
    let mut programs: Vec<String> = Vec::new();
    let mut i = 28usize; // RPC reply header
    while i + 20 <= data.len() {
        let follows = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if follows == 0 {
            break;
        }
        let prog = u32::from_be_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);
        let vers = u32::from_be_bytes([data[i + 8], data[i + 9], data[i + 10], data[i + 11]]);
        let proto = u32::from_be_bytes([data[i + 12], data[i + 13], data[i + 14], data[i + 15]]);
        let port = u32::from_be_bytes([data[i + 16], data[i + 17], data[i + 18], data[i + 19]]);
        let name = rpc_program_name(prog);
        let entry = format!(
            "{} v{} {}/{}",
            name,
            vers,
            if proto == 6 { "tcp" } else { "udp" },
            port
        );
        if !programs.contains(&entry) {
            programs.push(entry);
        }
        if programs.len() >= 12 {
            break;
        }
        i += 20;
    }
    p.extra = programs.join(", ");
    p
}

fn rpc_program_name(prog: u32) -> String {
    match prog {
        100000 => "portmapper".into(),
        100003 => "nfs".into(),
        100005 => "mountd".into(),
        100021 => "nlockmgr".into(),
        100024 => "status".into(),
        100011 => "rquotad".into(),
        100004 => "ypserv".into(),
        100007 => "ypbind".into(),
        100009 => "yppasswdd".into(),
        391002 => "sgi_fam".into(),
        1073741824 => "fedfs_admin".into(),
        other => format!("program {other}"),
    }
}

fn parse_a2s(data: &[u8]) -> Probed {
    let mut p = named("steam", "Game server");
    if data.len() < 6 {
        return p;
    }
    // Quake III / idTech: plain text key/value blob.
    let text = ascii(data);
    if text.contains("statusResponse") || text.contains("\\gamename\\") {
        p.product = "Quake/idTech server".into();
        for key in [
            "gamename",
            "sv_hostname",
            "mapname",
            "version",
            "shortversion",
        ] {
            if let Some(pos) = text.find(&format!("\\{key}\\")) {
                let v: String = text[pos + key.len() + 2..]
                    .chars()
                    .take_while(|c| *c != '\\')
                    .collect();
                if key == "version" || key == "shortversion" {
                    p.version = clean(&v, 32);
                } else if key == "sv_hostname" {
                    p.extra = clean(&v, 48);
                }
            }
        }
        return p;
    }
    if data[4] != 0x49 {
        return p;
    }
    // A2S_INFO: header, protocol, then NUL-terminated name/map/folder/game.
    let mut i = 6usize;
    let mut fields = Vec::new();
    for _ in 0..4 {
        let start = i;
        while i < data.len() && data[i] != 0 {
            i += 1;
        }
        fields.push(String::from_utf8_lossy(&data[start..i]).to_string());
        i += 1;
    }
    let (name, map, _folder, game) = (
        fields.first().cloned().unwrap_or_default(),
        fields.get(1).cloned().unwrap_or_default(),
        fields.get(2).cloned().unwrap_or_default(),
        fields.get(3).cloned().unwrap_or_default(),
    );
    p.product = if game.is_empty() {
        "Source game server".into()
    } else {
        game
    };
    if i + 4 <= data.len() {
        let players = data[i + 2];
        let max = data[i + 3];
        p.extra = format!(
            "\"{}\"; map {}; {}/{} players",
            clean(&name, 40),
            clean(&map, 24),
            players,
            max
        );
    } else {
        p.extra = clean(&name, 40);
    }
    p
}

fn parse_raknet(data: &[u8]) -> Probed {
    let mut p = named("minecraft", "Minecraft Bedrock server");
    if data.len() < 35 {
        return p;
    }
    // MOTD: "MCPE;name;protocol;version;online;max;serverId;..."
    let text = String::from_utf8_lossy(&data[35..]).to_string();
    let fields: Vec<&str> = text.split(';').collect();
    if fields.len() >= 6 {
        p.version = fields[3].to_string();
        p.extra = format!(
            "\"{}\"; protocol {}; {}/{} players",
            clean(fields[1], 40),
            fields[2],
            fields[4],
            fields[5]
        );
    } else {
        p.extra = clean(&text, 60);
    }
    p
}

fn parse_mumble(data: &[u8]) -> Probed {
    let mut p = named("mumble", "Mumble (Murmur) server");
    if data.len() >= 24 {
        p.version = format!("{}.{}.{}", data[1], data[2], data[3]);
        let users = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let max = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        p.extra = format!("{users}/{max} users");
    }
    p
}

fn parse_enip(data: &[u8]) -> Probed {
    let mut p = named("ethernet-ip", "EtherNet/IP device");
    // 24-byte encapsulation header, item count (2), then each item as
    // type_id (2) + length (2) + data. The CIP identity object lives in the
    // first item, and its fields are all little-endian.
    if data.len() < 63 {
        return p;
    }
    let id = 24 + 2 + 2 + 2; // header + item count + item type + item length
                             // Identity: encap_version(2) socket(16) vendor(2) device_type(2)
                             // product_code(2) revision(2) status(2) serial(4) name_len(1) name
    let base = id + 2 + 16;
    if data.len() < base + 15 {
        return p;
    }
    let vendor = u16::from_le_bytes([data[base], data[base + 1]]);
    let device_type = u16::from_le_bytes([data[base + 2], data[base + 3]]);
    let product_code = u16::from_le_bytes([data[base + 4], data[base + 5]]);
    let revision = format!("{}.{}", data[base + 6], data[base + 7]);
    let serial = u32::from_le_bytes([
        data[base + 10],
        data[base + 11],
        data[base + 12],
        data[base + 13],
    ]);
    let name_len = data[base + 14] as usize;
    let name_start = base + 15;
    if name_len > 0 && name_start + name_len <= data.len() {
        p.product = clean(
            &String::from_utf8_lossy(&data[name_start..name_start + name_len]),
            48,
        );
    }
    p.version = revision;
    p.extra = format!(
        "vendor {vendor} ({}); device type {device_type}; product code {product_code}; serial {serial:08x}",
        enip_vendor(vendor)
    );
    p
}

fn enip_vendor(id: u16) -> &'static str {
    match id {
        1 => "Rockwell/Allen-Bradley",
        5 => "Schneider Electric",
        26 => "Festo",
        40 => "WAGO",
        47 => "Phoenix Contact",
        108 => "Beckhoff",
        283 => "HMS/Anybus",
        356 => "Omron",
        678 => "Siemens",
        _ => "unknown",
    }
}

fn parse_bacnet(data: &[u8]) -> Probed {
    let mut p = named("bacnet", "BACnet device");
    let text = ascii(data);
    if data.len() >= 12 {
        p.extra = format!("I-Am response, {} bytes", data.len());
    }
    if text.contains("Vendor") {
        p.extra = clean(&text, 80);
    }
    p
}

fn parse_memcached(data: &[u8]) -> Probed {
    let mut p = named("memcached", "Memcached");
    let text = ascii(data);
    for line in text.split("STAT ") {
        if let Some(rest) = line.strip_prefix("version ") {
            p.version = rest.split_whitespace().next().unwrap_or("").to_string();
        }
    }
    p.extra = format!(
        "UDP enabled ({} byte reply — amplification vector)",
        data.len()
    );
    p
}

fn parse_isakmp(data: &[u8]) -> Probed {
    let mut p = named("isakmp", "IKE / IPsec VPN");
    if data.len() < 28 {
        return p;
    }
    p.version = format!("v{}.{}", data[17] >> 4, data[17] & 0x0f);
    let exchange = data[18];
    let mut bits = vec![match exchange {
        2 => "identity protection (main mode)".to_string(),
        4 => "aggressive mode".to_string(),
        5 => "informational".to_string(),
        other => format!("exchange type {other}"),
    }];
    if exchange == 4 {
        bits.push("AGGRESSIVE MODE ACCEPTED (PSK hash disclosure)".to_string());
    }
    // Vendor ID payloads name the gateway product.
    let text = ascii(data);
    for (needle, vendor) in [
        ("Cisco", "Cisco"),
        ("strongSwan", "strongSwan"),
        ("Openswan", "Openswan"),
        ("libreswan", "Libreswan"),
        ("FortiGate", "Fortinet"),
        ("Windows", "Microsoft"),
        ("draft-ietf", "IKE draft NAT-T"),
    ] {
        if text.contains(needle) {
            p.product = format!("IKE / {vendor}");
            break;
        }
    }
    p.extra = bits.join("; ");
    p
}

fn parse_coap(data: &[u8]) -> Probed {
    let mut p = named("coap", "CoAP server");
    let text = ascii(data);
    if let Some(pos) = text.find("</") {
        p.extra = clean(&text[pos..], 120);
    }
    if text.contains("rt=") {
        p.product = "CoAP server (resource directory)".into();
    }
    p
}

fn parse_ubnt(data: &[u8]) -> Probed {
    let mut p = named("ubnt-discovery", "Ubiquiti device");
    let text = clean(&ascii(data), 100);
    p.extra = text;
    p.os_hint = "Linux (Ubiquiti)".into();
    p
}

fn parse_sip(data: &[u8]) -> Probed {
    let text = String::from_utf8_lossy(data).to_string();
    let mut p = named("sip", "SIP server");
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("server:") || lower.starts_with("user-agent:") {
            let v = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
            p.product = v.split('/').next().unwrap_or(v).trim().to_string();
            p.version = crate::service::probe::first_version(v);
            p.banner = v.to_string();
        } else if lower.starts_with("allow:") {
            p.extra = clean(line.split_once(':').map(|(_, v)| v).unwrap_or(""), 80);
        }
    }
    if p.product.is_empty() {
        p.product = "SIP server".into();
    }
    p
}

/// UDP ports worth scanning by default — the ones that actually answer and
/// identify something. A blind UDP sweep of 65535 ports is mostly waiting.
pub const TOP_UDP_PORTS: &[u16] = &[
    53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 177, 445, 500, 514, 520, 623, 631, 1434,
    1604, 1701, 1900, 2049, 3283, 3478, 3702, 4500, 5060, 5353, 5355, 5683, 10001, 11211, 17185,
    19132, 20000, 27015, 30718, 44818, 47808, 49152, 64738, 5093, 427, 111, 7, 13, 17, 19, 37, 88,
    389, 464, 546, 547, 593, 749, 996, 997, 998, 999, 1025, 1026, 1027, 1028, 1029, 1030, 1194,
    1645, 1646, 1812, 1813, 2000, 2222, 3456, 4045, 5000, 5001, 5432, 6346, 9200, 27016, 27017,
    27960, 26000, 32768, 32769, 33281, 65024,
];

pub fn top_udp_ports(n: usize) -> Vec<u16> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(n);
    for &p in TOP_UDP_PORTS {
        if out.len() >= n {
            break;
        }
        if seen.insert(p) {
            out.push(p);
        }
    }
    out
}

/// Friendly names for UDP ports, which don't always match their TCP twin.
pub fn udp_service_name(port: u16) -> &'static str {
    match port {
        7 => "echo",
        13 => "daytime",
        17 => "qotd",
        19 => "chargen",
        37 => "time",
        53 => "domain",
        67 => "dhcps",
        68 => "dhcpc",
        69 => "tftp",
        88 => "kerberos-sec",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        161 => "snmp",
        162 => "snmptrap",
        177 => "xdmcp",
        389 => "ldap",
        427 => "svrloc",
        445 => "microsoft-ds",
        464 => "kpasswd",
        500 => "isakmp",
        514 => "syslog",
        520 => "route",
        546 => "dhcpv6-client",
        547 => "dhcpv6-server",
        623 => "ipmi-rmcp",
        631 => "ipp",
        749 => "kerberos-adm",
        1194 => "openvpn",
        1434 => "ms-sql-m",
        1604 => "citrix-ica",
        1645 | 1812 => "radius",
        1646 | 1813 => "radacct",
        1701 => "l2tp",
        1900 => "upnp",
        2049 => "nfs",
        3283 => "apple-remote-desktop",
        3478 | 3479 => "stun",
        3702 => "ws-discovery",
        4045 => "lockd",
        4500 => "ipsec-nat-t",
        5060 => "sip",
        5093 => "sentinel-lm",
        5353 => "mdns",
        5355 => "llmnr",
        5683 => "coap",
        10001 => "ubnt-discovery",
        11211 => "memcached",
        17185 => "vxworks-wdb",
        19132 => "minecraft-bedrock",
        20000 => "dnp3",
        26000 => "quake",
        27015 | 27016 => "steam",
        27960 => "quake3",
        30718 => "lantronix",
        44818 => "ethernet-ip",
        47808 => "bacnet",
        64738 => "mumble",
        _ => crate::ports::service_name(port),
    }
}
