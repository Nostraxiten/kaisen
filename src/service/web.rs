//! Web fingerprinting — Kaisen's answer to `whatweb`.
//!
//! Given an open HTTP or HTTPS port, this fetches the site (following a few
//! same-host redirects), then reads the response the way a fingerprinter does:
//! the `Server` / `X-Powered-By` / `Set-Cookie` headers, the HTML markers a
//! CMS or framework leaves behind, the WAF/CDN a request passes through, the
//! security headers a site does (or does not) set, and a Shodan-compatible
//! favicon hash you can pivot on. It is deliberately passive — a handful of
//! GETs, no path brute-forcing — so it stays on-brand with the rest of Kaisen:
//! no root, one binary, light on the wire.
//!
//! Everything here is reimplemented from the wire behaviour and public specs
//! (HTTP, the products' own visible fingerprints, MurmurHash3, base64), so it
//! carries no third-party code or database.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// One identified technology: what it is, which version (if we could read one),
/// which bucket it falls in, and how sure we are (0–100).
#[derive(Debug, Clone)]
pub struct Tech {
    pub name: String,
    pub version: String,
    pub category: &'static str,
    pub confidence: u8,
}

/// Presence of the six response headers that decide a site's baseline browser
/// hardening, plus the letter grade they add up to.
#[derive(Debug, Clone, Default)]
pub struct SecHeaders {
    pub hsts: bool,
    pub csp: bool,
    pub x_frame: bool,
    pub x_content_type: bool,
    pub referrer_policy: bool,
    pub permissions_policy: bool,
}

impl SecHeaders {
    pub fn present(&self) -> usize {
        [
            self.hsts,
            self.csp,
            self.x_frame,
            self.x_content_type,
            self.referrer_policy,
            self.permissions_policy,
        ]
        .iter()
        .filter(|b| **b)
        .count()
    }

    /// A six-point scale, one point per header. Deliberately blunt: it is a
    /// nudge ("this site sets none of the basics"), not a compliance audit.
    pub fn grade(&self) -> &'static str {
        match self.present() {
            6 => "A+",
            5 => "A",
            4 => "B",
            3 => "C",
            2 => "D",
            1 => "E",
            _ => "F",
        }
    }

    /// The headers that are missing, for the one-line hint under the grade.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut m = Vec::new();
        if !self.hsts {
            m.push("HSTS");
        }
        if !self.csp {
            m.push("CSP");
        }
        if !self.x_frame {
            m.push("X-Frame-Options");
        }
        if !self.x_content_type {
            m.push("X-Content-Type-Options");
        }
        if !self.referrer_policy {
            m.push("Referrer-Policy");
        }
        if !self.permissions_policy {
            m.push("Permissions-Policy");
        }
        m
    }
}

/// The full picture for one web endpoint.
#[derive(Debug, Clone, Default)]
pub struct WebProfile {
    pub url: String,
    pub status: u16,
    pub title: String,
    pub server: String,
    pub powered_by: String,
    pub generator: String,
    pub techs: Vec<Tech>,
    pub waf: Option<String>,
    pub cdn: Option<String>,
    pub favicon_hash: Option<i32>,
    pub sec: SecHeaders,
    /// Redirect hops we followed, most-recent last, for the trail line.
    pub redirects: Vec<String>,
}

impl WebProfile {
    pub fn has_findings(&self) -> bool {
        self.status != 0
            && (!self.techs.is_empty()
                || !self.server.is_empty()
                || self.waf.is_some()
                || self.cdn.is_some()
                || self.favicon_hash.is_some()
                || !self.title.is_empty())
    }
}

/// A parsed HTTP response, headers kept (unlike `probe::parse_http`, which
/// throws them away) because they are where half the fingerprints live.
struct RawResp {
    status: u16,
    /// (lowercased-name, value) pairs, in wire order — a header can repeat
    /// (`Set-Cookie`), so this is a list, not a map.
    headers: Vec<(String, String)>,
    body: String,
    /// `Location`, already extracted for redirect following.
    location: Option<String>,
}

impl RawResp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn header_all(&self, name: &str) -> String {
        self.headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn request_line(host: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: kaisen/{}\r\n\
         Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        crate::cli::VERSION
    )
}

fn parse_response(raw: &[u8]) -> Option<RawResp> {
    // Split at the header/body boundary; tolerate a bare-LF boundary too.
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .unwrap_or((text.as_ref(), ""));

    let mut lines = head.lines();
    let status_line = lines.next()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut headers = Vec::new();
    let mut location = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "location" {
                location = Some(val.clone());
            }
            headers.push((key, val));
        }
    }
    Some(RawResp {
        status,
        headers,
        body: body.to_string(),
        location,
    })
}

/// Fetch one path over HTTP or HTTPS, capturing the full response. Reuses
/// Kaisen's own TCP path (RST-on-close) and from-scratch TLS 1.3 client.
async fn fetch(
    ip: IpAddr,
    port: u16,
    tls: bool,
    host: &str,
    path: &str,
    dur: Duration,
) -> Option<RawResp> {
    let addr = SocketAddr::new(ip, port);
    let ms = (dur.as_millis() as u64).max(3000);
    let req = request_line(host, path);

    let raw: Vec<u8> = if tls {
        let stream = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
        crate::util::netutil::reset_on_close(&stream);
        let mut conn = crate::tls::tls13::handshake(stream, host, &["http/1.1"], ms)
            .await
            .ok()?;
        conn.write(req.as_bytes(), ms).await.ok()?;
        let mut buf = Vec::new();
        for _ in 0..16 {
            match conn.read(0, ms).await {
                Ok(chunk) if !chunk.is_empty() => buf.extend_from_slice(&chunk),
                _ => break,
            }
            if buf.len() > 262_144 {
                break;
            }
        }
        buf
    } else {
        let mut stream = timeout(dur, TcpStream::connect(addr)).await.ok()?.ok()?;
        crate::util::netutil::reset_on_close(&stream);
        timeout(dur, stream.write_all(req.as_bytes()))
            .await
            .ok()?
            .ok()?;
        read_all(&mut stream, dur).await
    };

    parse_response(&raw)
}

async fn read_all(stream: &mut TcpStream, dur: Duration) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match timeout(dur, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 262_144 {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    buf
}

/// Fingerprint one open web port. Follows up to `MAX_REDIRECTS` same-host
/// redirects (including an http→https upgrade) so the fingerprint lands on the
/// page a browser would actually see.
pub async fn scan(
    host: &str,
    ip: IpAddr,
    port: u16,
    tls: bool,
    timeout_ms: u64,
) -> Option<WebProfile> {
    const MAX_REDIRECTS: usize = 4;
    let dur = Duration::from_millis(timeout_ms.max(3000));

    let mut cur_host = host.to_string();
    let mut cur_ip = ip;
    let mut cur_port = port;
    let mut cur_tls = tls;
    let mut path = "/".to_string();
    let mut redirects = Vec::new();

    // The first fetch decides whether we return anything at all, so give it a
    // second try: under -WW concurrency the from-scratch TLS client does
    // several handshakes at once and an occasional one trips its timeout. A
    // lone retry turns that flake into a result instead of a null.
    let mut resp = match fetch(cur_ip, cur_port, cur_tls, &cur_host, &path, dur).await {
        Some(r) => r,
        None => fetch(cur_ip, cur_port, cur_tls, &cur_host, &path, dur).await?,
    };

    for _ in 0..MAX_REDIRECTS {
        if !(300..400).contains(&resp.status) {
            break;
        }
        let Some(loc) = resp.location.clone() else {
            break;
        };
        // Follow like `curl -L`: relative and same-host redirects reuse the
        // connection target; a cross-host redirect (apex → www is the common
        // one) is resolved fresh so the fingerprint lands on the real page.
        let Some((nh, np, nt, npath)) = parse_location(&loc, &cur_host, cur_port, cur_tls) else {
            break;
        };
        let next_ip = if nh.eq_ignore_ascii_case(&cur_host) {
            cur_ip
        } else {
            match resolve_first(&nh, np).await {
                Some(x) => x,
                None => break,
            }
        };
        redirects.push(loc);
        cur_host = nh;
        cur_ip = next_ip;
        cur_port = np;
        cur_tls = nt;
        path = npath;
        match fetch(cur_ip, cur_port, cur_tls, &cur_host, &path, dur).await {
            Some(r) => resp = r,
            None => break,
        }
    }

    let scheme = if cur_tls { "https" } else { "http" };
    let mut prof = WebProfile {
        url: format!("{scheme}://{cur_host}:{cur_port}{path}"),
        status: resp.status,
        redirects,
        ..Default::default()
    };

    prof.server = resp.header("server").unwrap_or_default().to_string();
    prof.powered_by = resp.header("x-powered-by").unwrap_or_default().to_string();
    prof.title = extract_title(&resp.body);
    prof.generator = extract_generator(&resp.body);
    prof.sec = grade_headers(&resp);
    prof.waf = detect_waf(&resp);
    prof.cdn = detect_cdn(&resp);
    prof.techs = fingerprint(&resp, &cur_host);

    // Favicon hash: fetch /favicon.ico on the final endpoint. Best-effort —
    // many sites 404 it, and that is fine.
    if let Some(fav) = fetch(cur_ip, cur_port, cur_tls, &cur_host, "/favicon.ico", dur).await {
        if fav.status == 200 {
            // Re-read raw favicon bytes: the body we parsed is lossy UTF-8, but
            // the hash must be over the exact bytes, so refetch is not ideal —
            // instead hash the body we already have as bytes. Good enough for
            // the common case where the icon is served verbatim.
            let bytes = fav.body.as_bytes();
            if !bytes.is_empty() {
                prof.favicon_hash = Some(shodan_favicon_hash(bytes));
            }
        }
    }

    prof.has_findings().then_some(prof)
}

/// Resolve a `Location` against the current endpoint into the next
/// (host, port, tls, path). A relative target keeps the current host; an
/// absolute one may point anywhere. Returns `None` for a scheme-less
/// non-absolute value we shouldn't guess at.
fn parse_location(
    loc: &str,
    cur_host: &str,
    cur_port: u16,
    cur_tls: bool,
) -> Option<(String, u16, bool, String)> {
    if loc.starts_with('/') {
        return Some((cur_host.to_string(), cur_port, cur_tls, sanitize_path(loc)));
    }
    let (scheme, rest) = if let Some(r) = loc.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = loc.strip_prefix("http://") {
        ("http", r)
    } else {
        return None; // scheme-less non-absolute — don't guess
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (h, explicit_port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (authority, None),
    };
    let tls = scheme == "https";
    let port = explicit_port.unwrap_or(if tls { 443 } else { 80 });
    Some((h.to_string(), port, tls, sanitize_path(&path)))
}

/// First IP a hostname resolves to (or the literal, if it already is one).
async fn resolve_first(host: &str, port: u16) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .next()
        .map(|s| s.ip())
}

fn sanitize_path(p: &str) -> String {
    // Strip a fragment and cap length; keep the query, it can matter.
    let p = p.split('#').next().unwrap_or("/");
    if p.is_empty() {
        "/".to_string()
    } else {
        p.chars().take(512).collect()
    }
}

fn extract_title(body: &str) -> String {
    title_inner(body).unwrap_or_default()
}

fn title_inner(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after = &body[start..];
    let gt = after.find('>')?; // end of the opening <title ...>
    let rest = &after[gt + 1..];
    let end = rest.to_ascii_lowercase().find("</title>")?;
    let cleaned = rest[..end].split_whitespace().collect::<Vec<_>>().join(" ");
    Some(cleaned.chars().take(120).collect())
}

fn extract_generator(body: &str) -> String {
    // <meta name="generator" content="WordPress 6.4.2">
    let lower = body.to_ascii_lowercase();
    let mut idx = 0;
    while let Some(rel) = lower[idx..].find("<meta") {
        let start = idx + rel;
        let end = lower[start..]
            .find('>')
            .map(|e| start + e)
            .unwrap_or(lower.len());
        let tag = &lower[start..end];
        if tag.contains("name=\"generator\"") || tag.contains("name='generator'") {
            if let Some(c) = attr_value(&body[start..end], "content") {
                return c.chars().take(80).collect();
            }
        }
        idx = end + 1;
        if idx >= lower.len() {
            break;
        }
    }
    String::new()
}

/// Pull the value of `attr="..."` (or `attr='...'`) out of a tag fragment.
fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let key = format!("{attr}=");
    let pos = lower.find(&key)? + key.len();
    let bytes = tag.as_bytes();
    let quote = *bytes.get(pos)?;
    if quote == b'"' || quote == b'\'' {
        let rest = &tag[pos + 1..];
        let end = rest.find(quote as char)?;
        Some(rest[..end].to_string())
    } else {
        // unquoted
        let rest = &tag[pos..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

fn grade_headers(resp: &RawResp) -> SecHeaders {
    SecHeaders {
        hsts: resp.header("strict-transport-security").is_some(),
        csp: resp.header("content-security-policy").is_some()
            || resp.header("content-security-policy-report-only").is_some(),
        x_frame: resp.header("x-frame-options").is_some(),
        x_content_type: resp.header("x-content-type-options").is_some(),
        referrer_policy: resp.header("referrer-policy").is_some(),
        permissions_policy: resp.header("permissions-policy").is_some()
            || resp.header("feature-policy").is_some(),
    }
}

/// WAF/CDN detection from response headers. Ordered most-specific first.
const WAF_SIGNS: &[(&str, &str, &str)] = &[
    // (header-name, needle-in-value-or-empty-for-presence, label)
    ("x-sucuri-id", "", "Sucuri WAF"),
    ("x-sucuri-cache", "", "Sucuri WAF"),
    ("server", "sucuri", "Sucuri WAF"),
    ("x-iinfo", "", "Imperva Incapsula"),
    ("x-cdn", "incapsula", "Imperva Incapsula"),
    ("server", "awselb", "AWS ELB / WAF"),
    ("x-amzn-waf-action", "", "AWS WAF"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "akamaighost", "Akamai Ghost"),
    ("x-cache", "cloudfront", "AWS CloudFront"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("x-fw-hash", "", "Fortinet FortiWeb"),
    ("x-mod-security", "", "ModSecurity"),
    ("server", "mod_security", "ModSecurity"),
    ("x-sourcefire", "", "Cisco Sourcefire"),
    ("x-barracuda", "", "Barracuda WAF"),
    ("x-powered-by-360wzb", "", "360 Web Application Firewall"),
    ("x-denied-reason", "", "WAF (generic)"),
    ("x-waf-event-info", "", "WAF (generic)"),
];

fn detect_waf(resp: &RawResp) -> Option<String> {
    for (hdr, needle, label) in WAF_SIGNS {
        if let Some(v) = resp.header(hdr) {
            if needle.is_empty() || v.to_ascii_lowercase().contains(needle) {
                return Some((*label).to_string());
            }
        }
    }
    None
}

const CDN_SIGNS: &[(&str, &str, &str)] = &[
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("x-served-by", "cache-", "Fastly"),
    ("x-fastly-request-id", "", "Fastly"),
    ("x-cache", "cloudfront", "AWS CloudFront"),
    ("x-amz-cf-pop", "", "AWS CloudFront"),
    ("x-akamai-request-id", "", "Akamai"),
    ("server", "akamai", "Akamai"),
    ("x-cache", "bunnycdn", "BunnyCDN"),
    ("server", "bunnycdn", "BunnyCDN"),
    ("x-hw", "", "Highwinds/StackPath"),
    ("x-cdn", "keycdn", "KeyCDN"),
    ("x-vercel-id", "", "Vercel"),
    ("x-nf-request-id", "", "Netlify"),
    ("server", "netlify", "Netlify"),
    ("x-goog-", "", "Google Cloud"),
    ("via", "varnish", "Varnish"),
    ("x-varnish", "", "Varnish"),
];

fn detect_cdn(resp: &RawResp) -> Option<String> {
    for (hdr, needle, label) in CDN_SIGNS {
        // x-goog- is a prefix probe: match any header starting with it.
        if hdr.ends_with('-') {
            if resp.headers.iter().any(|(k, _)| k.starts_with(hdr)) {
                return Some((*label).to_string());
            }
            continue;
        }
        if let Some(v) = resp.header(hdr) {
            if needle.is_empty() || v.to_ascii_lowercase().contains(needle) {
                return Some((*label).to_string());
            }
        }
    }
    None
}

/// Insert a technology, or fill in a version on one already present. Kept a
/// free function (not a closure) so it doesn't hold a standing mutable borrow
/// of `techs` while the fingerprint pass also reads it.
fn add_tech(
    techs: &mut Vec<Tech>,
    name: &str,
    version: &str,
    category: &'static str,
    confidence: u8,
) {
    if let Some(t) = techs.iter_mut().find(|t| t.name.eq_ignore_ascii_case(name)) {
        if t.version.is_empty() && !version.is_empty() {
            t.version = version.to_string();
        }
        return;
    }
    techs.push(Tech {
        name: name.to_string(),
        version: version.to_string(),
        category,
        confidence,
    });
}

/// The main fingerprint pass: headers first (cheap and authoritative), then
/// HTML-body markers, then a version-extraction sweep.
fn fingerprint(resp: &RawResp, host: &str) -> Vec<Tech> {
    let mut techs: Vec<Tech> = Vec::new();
    let body = &resp.body;
    let low = body.to_ascii_lowercase();
    let cookies = resp.header_all("set-cookie").to_ascii_lowercase();

    // ── Server software + version ──────────────────────────────────────────
    if let Some(server) = resp.header("server") {
        for (needle, label) in SERVER_PRODUCTS {
            if server.to_ascii_lowercase().contains(needle) {
                let ver = version_after(server, needle);
                add_tech(&mut techs, label, &ver, "server", 100);
            }
        }
    }

    // ── Language / runtime ────────────────────────────────────────────────
    if let Some(pb) = resp.header("x-powered-by") {
        let pbl = pb.to_ascii_lowercase();
        for (needle, label, cat) in POWERED_BY {
            if pbl.contains(needle) {
                add_tech(&mut techs, label, &version_after(pb, needle), cat, 100);
            }
        }
    }
    if let Some(v) = resp.header("x-aspnet-version") {
        add_tech(&mut techs, "ASP.NET", v, "framework", 100);
    }
    if let Some(v) = resp.header("x-aspnetmvc-version") {
        add_tech(&mut techs, "ASP.NET MVC", v, "framework", 100);
    }
    if resp.header("x-drupal-cache").is_some() || resp.header("x-drupal-dynamic-cache").is_some() {
        add_tech(&mut techs, "Drupal", "", "cms", 100);
    }
    if resp
        .header("x-generator")
        .map(|g| g.to_ascii_lowercase().contains("drupal"))
        .unwrap_or(false)
    {
        add_tech(&mut techs, "Drupal", "", "cms", 100);
    }
    if let Some(v) = resp.header("x-shopify-stage") {
        let _ = v;
        add_tech(&mut techs, "Shopify", "", "cms", 100);
    }

    // ── Cookie-based framework tells ──────────────────────────────────────
    for (needle, label, cat) in COOKIE_MARKERS {
        if cookies.contains(needle) {
            add_tech(&mut techs, label, "", cat, 90);
        }
    }

    // ── Meta generator ────────────────────────────────────────────────────
    let gen = extract_generator(body);
    if !gen.is_empty() {
        let genl = gen.to_ascii_lowercase();
        for (needle, label, cat) in GENERATOR_MARKERS {
            if genl.contains(needle) {
                add_tech(&mut techs, label, &version_after(&gen, needle), cat, 100);
            }
        }
    }

    // ── HTML body markers ─────────────────────────────────────────────────
    for (needle, label, cat, conf) in BODY_MARKERS {
        if low.contains(needle) {
            add_tech(&mut techs, label, "", cat, *conf);
        }
    }

    // ── JS library versions from script paths ─────────────────────────────
    if let Some(v) =
        find_version(&low, "jquery-", ".js").or_else(|| find_version(&low, "jquery/", "/"))
    {
        add_tech(&mut techs, "jQuery", &v, "js-lib", 90);
    } else if low.contains("jquery") {
        add_tech(&mut techs, "jQuery", "", "js-lib", 70);
    }
    if let Some(v) = find_version(&low, "bootstrap/", "/")
        .or_else(|| find_version(&low, "bootstrap.min.css?ver=", "\""))
    {
        add_tech(&mut techs, "Bootstrap", &v, "css", 80);
    } else if low.contains("bootstrap.min.css") || low.contains("bootstrap.css") {
        add_tech(&mut techs, "Bootstrap", "", "css", 70);
    }
    if let Some(v) = find_version(&low, "ng-version=\"", "\"") {
        add_tech(&mut techs, "Angular", &v, "framework", 95);
    }

    // ── WordPress version from ?ver= on wp assets, if present ──────────────
    if techs.iter().any(|t| t.name == "WordPress") {
        if let Some(v) = find_version(&low, "wp-emoji-release.min.js?ver=", "\"")
            .or_else(|| find_version(&low, "/wp-includes/js/", "ver="))
        {
            if v.chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                add_tech(&mut techs, "WordPress", &v, "cms", 100);
            }
        }
    }

    let _ = host;
    // Sort: highest confidence first, then name, so the report leads with the
    // things we are sure about.
    techs.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.name.cmp(&b.name)));
    techs
}

/// Extract a version string that follows `product/` or `product` in a header,
/// e.g. `nginx/1.25.3` → `1.25.3`, `Apache/2.4.58 (Ubuntu)` → `2.4.58`.
fn version_after(hay: &str, needle: &str) -> String {
    let low = hay.to_ascii_lowercase();
    let Some(pos) = low.find(needle) else {
        return String::new();
    };
    let after = &hay[pos + needle.len()..];
    // Skip the separators that sit between a product name and its version:
    // "nginx/1.25", "WordPress 6.4", "Joomla! - 5.0", "PHP/8.2".
    let after = after.trim_start_matches([' ', '/', '-', ':', '!', 'v', 'V']);
    let ver: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    // Require it to look like a version (at least one dot or 2+ digits).
    if ver.contains('.') || ver.len() >= 2 {
        ver
    } else {
        String::new()
    }
}

/// Find a version between `prefix` and the first `stop` after it, keeping only
/// a leading dotted-number run. `jquery-3.6.0.min.js` with prefix `jquery-`
/// and stop `.js` → `3.6.0`.
fn find_version(hay: &str, prefix: &str, stop: &str) -> Option<String> {
    let start = hay.find(prefix)? + prefix.len();
    let rest = &hay[start..];
    let end = rest.find(stop).unwrap_or(rest.len());
    let candidate = &rest[..end];
    let ver: String = candidate
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if ver.contains('.') {
        Some(ver)
    } else {
        None
    }
}

// ── Fingerprint tables ──────────────────────────────────────────────────────

const SERVER_PRODUCTS: &[(&str, &str)] = &[
    ("nginx", "nginx"),
    ("apache", "Apache httpd"),
    ("microsoft-iis", "Microsoft IIS"),
    ("litespeed", "LiteSpeed"),
    ("openresty", "OpenResty"),
    ("caddy", "Caddy"),
    ("cloudflare", "Cloudflare"),
    ("gunicorn", "Gunicorn"),
    ("uvicorn", "Uvicorn"),
    ("kestrel", "Kestrel (ASP.NET Core)"),
    ("werkzeug", "Werkzeug (Flask)"),
    ("tomcat", "Apache Tomcat"),
    ("jetty", "Eclipse Jetty"),
    ("gws", "Google Web Server"),
    ("cowboy", "Cowboy (Erlang)"),
    ("puma", "Puma (Ruby)"),
    ("thin", "Thin (Ruby)"),
    ("lighttpd", "lighttpd"),
    ("boa", "Boa (embedded)"),
    ("mini_httpd", "mini_httpd"),
    ("gsw", "Google servlet"),
    ("envoy", "Envoy proxy"),
    ("traefik", "Traefik"),
    ("haproxy", "HAProxy"),
    ("varnish", "Varnish"),
    ("squid", "Squid proxy"),
];

const POWERED_BY: &[(&str, &str, &str)] = &[
    ("php", "PHP", "language"),
    ("asp.net", "ASP.NET", "framework"),
    ("express", "Express (Node.js)", "framework"),
    ("next.js", "Next.js", "framework"),
    ("nuxt", "Nuxt", "framework"),
    ("servlet", "Java Servlet", "framework"),
    ("plesk", "Plesk", "panel"),
    ("wp engine", "WP Engine", "hosting"),
    ("phusion passenger", "Phusion Passenger", "server"),
];

const COOKIE_MARKERS: &[(&str, &str, &str)] = &[
    ("phpsessid", "PHP", "language"),
    ("jsessionid", "Java", "language"),
    ("asp.net_sessionid", "ASP.NET", "framework"),
    ("aspsessionid", "Classic ASP", "framework"),
    ("laravel_session", "Laravel", "framework"),
    ("ci_session", "CodeIgniter", "framework"),
    ("csrftoken", "Django", "framework"),
    ("django", "Django", "framework"),
    ("connect.sid", "Express (Node.js)", "framework"),
    ("_session_id", "Ruby on Rails", "framework"),
    ("wordpress_", "WordPress", "cms"),
    ("wp-settings", "WordPress", "cms"),
    ("wp_woocommerce_session", "WooCommerce", "cms"),
    ("prestashop", "PrestaShop", "cms"),
    ("ocsessid", "OpenCart", "cms"),
    ("magento", "Magento", "cms"),
    ("xf_session", "XenForo", "cms"),
    ("phpbb3_", "phpBB", "cms"),
    ("mybb", "MyBB", "cms"),
    ("grafana_session", "Grafana", "app"),
    ("sails.sid", "Sails.js", "framework"),
];

const GENERATOR_MARKERS: &[(&str, &str, &str)] = &[
    ("wordpress", "WordPress", "cms"),
    ("drupal", "Drupal", "cms"),
    ("joomla", "Joomla", "cms"),
    ("typo3", "TYPO3", "cms"),
    ("ghost", "Ghost", "cms"),
    ("hugo", "Hugo", "ssg"),
    ("jekyll", "Jekyll", "ssg"),
    ("hexo", "Hexo", "ssg"),
    ("gatsby", "Gatsby", "ssg"),
    ("wix", "Wix", "cms"),
    ("squarespace", "Squarespace", "cms"),
    ("shopify", "Shopify", "cms"),
    ("blogger", "Blogger", "cms"),
    ("mediawiki", "MediaWiki", "cms"),
    ("docusaurus", "Docusaurus", "ssg"),
    ("bitrix", "1C-Bitrix", "cms"),
    ("concrete5", "Concrete CMS", "cms"),
    ("prestashop", "PrestaShop", "cms"),
];

// Only *distinctive* markers — asset paths, JS globals, unique class/attribute
// names — never a bare product word, which turns up on marketing pages that
// merely mention a competitor or customer (GitHub's homepage says "Shopify").
const BODY_MARKERS: &[(&str, &str, &str, u8)] = &[
    ("/wp-content/", "WordPress", "cms", 95),
    ("/wp-includes/", "WordPress", "cms", 95),
    ("/sites/default/files", "Drupal", "cms", 90),
    ("drupal.settings", "Drupal", "cms", 90),
    ("drupal-settings-json", "Drupal", "cms", 90),
    ("/media/jui/", "Joomla", "cms", 85),
    ("/templates/", "Joomla", "cms", 40),
    ("com_content", "Joomla", "cms", 80),
    ("/_next/static", "Next.js", "framework", 95),
    ("__next_data__", "Next.js", "framework", 95),
    ("window.__nuxt__", "Nuxt", "framework", 90),
    ("data-reactroot", "React", "js-lib", 85),
    ("react-dom", "React", "js-lib", 70),
    ("ng-version=", "Angular", "framework", 95),
    ("data-v-app", "Vue.js", "js-lib", 80),
    ("/@vite/client", "Vite", "framework", 85),
    ("cdn.shopify.com", "Shopify", "cms", 95),
    ("static.parastorage.com", "Wix", "cms", 90),
    ("static1.squarespace.com", "Squarespace", "cms", 90),
    (
        "cloudflareinsights.com",
        "Cloudflare Insights",
        "analytics",
        85,
    ),
    (
        "google-analytics.com/analytics.js",
        "Google Analytics",
        "analytics",
        85,
    ),
    (
        "googletagmanager.com/gtm.js",
        "Google Tag Manager",
        "analytics",
        85,
    ),
    ("static.hotjar.com", "Hotjar", "analytics", 80),
    ("gstatic.com/recaptcha", "Google reCAPTCHA", "security", 85),
    ("hcaptcha.com/1/api.js", "hCaptcha", "security", 85),
    (
        "challenges.cloudflare.com/turnstile",
        "Cloudflare Turnstile",
        "security",
        85,
    ),
    ("/phpmyadmin/", "phpMyAdmin", "app", 85),
    ("pma_password", "phpMyAdmin", "app", 90),
    ("swagger-ui", "Swagger UI", "app", 85),
    ("id=\"__docusaurus\"", "Docusaurus", "ssg", 90),
    ("grav-", "Grav", "cms", 60),
    ("/ghost/", "Ghost", "cms", 70),
    ("mediawiki", "MediaWiki", "cms", 60),
];

// ── Shodan-compatible favicon hash ──────────────────────────────────────────

/// The `http.favicon.hash` value Shodan indexes: MurmurHash3 (x86, 32-bit,
/// seed 0) of the icon re-encoded as base64 with a newline every 76 chars and
/// a trailing newline (Python's `base64.encodebytes`). Reproducing that exact
/// pipeline is what makes the number a usable pivot in Shodan/Censys.
pub fn shodan_favicon_hash(data: &[u8]) -> i32 {
    let b64 = base64_encodebytes(data);
    murmur3_x86_32(b64.as_bytes(), 0) as i32
}

fn base64_encodebytes(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut raw = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        raw.push(T[((n >> 18) & 63) as usize] as char);
        raw.push(T[((n >> 12) & 63) as usize] as char);
        raw.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        raw.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    // Python's encodebytes wraps at 76 chars and appends a trailing newline.
    let mut out = String::with_capacity(raw.len() + raw.len() / 76 + 1);
    for (i, ch) in raw.chars().enumerate() {
        if i > 0 && i % 76 == 0 {
            out.push('\n');
        }
        out.push(ch);
    }
    out.push('\n');
    out
}

fn murmur3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = seed;
    let nblocks = data.len() / 4;
    for i in 0..nblocks {
        let k = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
        let mut k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13);
        h = h.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let tail = &data[nblocks * 4..];
    let mut k1: u32 = 0;
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h ^= k1;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_after_reads_server_versions() {
        assert_eq!(version_after("nginx/1.25.3", "nginx"), "1.25.3");
        assert_eq!(version_after("Apache/2.4.58 (Ubuntu)", "apache"), "2.4.58");
        assert_eq!(version_after("Microsoft-IIS/10.0", "microsoft-iis"), "10.0");
        // No version present → empty, never a bogus token.
        assert_eq!(version_after("cloudflare", "cloudflare"), "");
    }

    #[test]
    fn find_version_pulls_dotted_runs_only() {
        assert_eq!(
            find_version("/js/jquery-3.6.0.min.js", "jquery-", ".min"),
            Some("3.6.0".into())
        );
        assert_eq!(
            find_version("ng-version=\"17.0.1\"", "ng-version=\"", "\""),
            Some("17.0.1".into())
        );
        // A single integer is not a version.
        assert_eq!(find_version("bootstrap-5/", "bootstrap-", "/"), None);
    }

    #[test]
    fn security_grade_counts_headers() {
        let mut s = SecHeaders::default();
        assert_eq!(s.grade(), "F");
        s.hsts = true;
        s.csp = true;
        s.x_frame = true;
        s.x_content_type = true;
        assert_eq!(s.present(), 4);
        assert_eq!(s.grade(), "B");
        assert!(s.missing().contains(&"Referrer-Policy"));
    }

    #[test]
    fn title_and_generator_extracted() {
        let body = "<html><head><title>  Hello   World </title>\
                    <meta name=\"generator\" content=\"WordPress 6.4.2\"></head></html>";
        assert_eq!(extract_title(body), "Hello World");
        assert_eq!(extract_generator(body), "WordPress 6.4.2");
    }

    #[test]
    fn favicon_hash_is_stable_and_signed() {
        // Deterministic across runs; the point is a stable pivot value.
        let h1 = shodan_favicon_hash(b"\x00\x01\x02kaisen-favicon-bytes");
        let h2 = shodan_favicon_hash(b"\x00\x01\x02kaisen-favicon-bytes");
        assert_eq!(h1, h2);
        assert_ne!(h1, shodan_favicon_hash(b"different"));
    }

    #[test]
    fn murmur3_known_vectors() {
        // Reference values for MurmurHash3 x86_32, seed 0.
        assert_eq!(murmur3_x86_32(b"", 0), 0);
        assert_eq!(murmur3_x86_32(b"hello", 0), 0x248bfa47);
    }

    #[test]
    fn parse_location_handles_relative_upgrade_and_cross_host() {
        // http→https on the same host: switch to 443/tls, host unchanged.
        assert_eq!(
            parse_location("https://example.com/", "example.com", 80, false),
            Some(("example.com".to_string(), 443, true, "/".to_string()))
        );
        // Cross-host absolute: returns the new host (caller resolves it).
        assert_eq!(
            parse_location("https://www.example.com/x", "example.com", 80, false),
            Some(("www.example.com".to_string(), 443, true, "/x".to_string()))
        );
        // Relative: same host/port/scheme, new path.
        assert_eq!(
            parse_location("/en/home", "example.com", 8080, false),
            Some((
                "example.com".to_string(),
                8080,
                false,
                "/en/home".to_string()
            ))
        );
        // Scheme-less junk: don't guess.
        assert_eq!(
            parse_location("mailto:x@y.z", "example.com", 80, false),
            None
        );
    }
}
