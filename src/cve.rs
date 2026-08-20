//! Offline CVE correlation.
//!
//! `vuln::assess` matches a service against config heuristics and exact-version
//! signatures. This module adds the missing middle: a detected product and
//! version correlated against a curated, embedded table of CVEs whose affected
//! range the version actually falls in — the same idea as Nmap's `vulners.nse`,
//! but with the database compiled into the binary so a scan never has to touch
//! the network or tell a third party which hosts it is looking at.
//!
//! It is deliberately small and honest: an entry fires only when the detected
//! version lands inside a documented affected range, so a patched host comes
//! back clean rather than being tarred by a product name alone. The public
//! surface is a single `correlate(&ServiceInfo) -> Vec<Finding>`, so a future
//! swap to a full NVD/SQLite mirror is a drop-in behind the same call.

use crate::service::ServiceInfo;
use crate::vuln::{Finding, Severity};

/// A version reduced to up to four numeric components, so ranges compare the
/// way a human reads them (`1.6.9 < 1.6.18`, not the string order that puts
/// "18" before "9"). Non-numeric tails — `p1`, `-ubuntu`, `build 201719` — are
/// dropped: they never decide an affected range and only confuse a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version([u32; 4]);

impl Version {
    /// Parse the leading dotted-numeric run. `8.2p1` → `8.2`, `5.3.0 build
    /// 201719` → `5.3.0`, so the IoT "build" tail never lands in a component.
    pub fn parse(s: &str) -> Version {
        let lead: String = s
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let mut parts = [0u32; 4];
        for (i, p) in lead.split('.').take(4).enumerate() {
            parts[i] = p.parse().unwrap_or(0);
        }
        Version(parts)
    }

    /// A version we could not read at all. An unknown version must never
    /// satisfy a `< x` range, or every unversioned banner would match.
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }
}

/// One CVE (or tightly-related cluster sharing an affected range), keyed by a
/// product substring and gated on a version predicate.
pub struct CveEntry {
    /// Matched case-insensitively as a substring of everything the probe
    /// reported — product, banner and extra — so a product named only in a
    /// `Server:` header still correlates.
    pub match_product: &'static str,
    /// CPE 2.3 identifier, surfaced in the finding so the lead is traceable.
    pub cpe: &'static str,
    pub cve: &'static str,
    pub cvss: f32,
    pub severity: Severity,
    pub title: &'static str,
    pub summary: &'static str,
    pub reference: &'static str,
    /// True when this parsed version is inside the affected range.
    pub affected: fn(Version) -> bool,
}

pub const CVE_DB: &[CveEntry] = &[
    // ── libupnp / "Portable SDK for UPnP devices" ───────────────────────────
    // The SSDP parser in pupnp before 1.6.18 had a family of stack buffer
    // overflows reachable unauthenticated over UDP (the "unique_service_name"
    // set), fixed together. Millions of embedded devices shipped the affected
    // code.
    CveEntry {
        match_product: "Portable SDK for UPnP devices",
        cpe: "cpe:2.3:a:libupnp_project:libupnp",
        cve: "CVE-2012-5958",
        cvss: 10.0,
        severity: Severity::Critical,
        title: "libupnp SSDP stack buffer overflows (unauthenticated RCE)",
        summary: "pupnp/libupnp before 1.6.18 has remotely exploitable stack overflows in \
                  the SSDP unique_service_name parser (the CVE-2012-5958..5965 and \
                  CVE-2013-0229/0230 cluster). Reachable pre-auth over UDP/1900.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2012-5958",
        affected: |v| !v.is_zero() && v < Version::parse("1.6.18"),
    },
    // CallStranger: the SUBSCRIBE callback is not validated, so the device can
    // be steered to send traffic to an arbitrary target (data exfiltration,
    // DDoS amplification, internal port scanning). Mitigated in pupnp 1.14.0.
    CveEntry {
        match_product: "Portable SDK for UPnP devices",
        cpe: "cpe:2.3:a:libupnp_project:libupnp",
        cve: "CVE-2020-12695",
        cvss: 7.5,
        severity: Severity::High,
        title: "CallStranger (UPnP SUBSCRIBE callback abuse)",
        summary: "The UPnP SUBSCRIBE Callback header is honoured without validation, letting \
                  an attacker use the device for amplified DDoS, data exfiltration, or \
                  reaching internal hosts. Mitigated in libupnp 1.14.0.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2020-12695",
        affected: |v| !v.is_zero() && v < Version::parse("1.14.0"),
    },
    // ── OpenSSH ─────────────────────────────────────────────────────────────
    // regreSSHion: a signal-handler race in sshd giving unauthenticated RCE on
    // glibc Linux. Reintroduced in 8.5p1 and fixed in 9.8p1; the original bug
    // (CVE-2006-5051) also affects releases before 4.4p1.
    CveEntry {
        match_product: "OpenSSH",
        cpe: "cpe:2.3:a:openbsd:openssh",
        cve: "CVE-2024-6387",
        cvss: 8.1,
        severity: Severity::High,
        title: "OpenSSH regreSSHion (unauthenticated RCE in sshd)",
        summary: "A race in sshd's SIGALRM handler allows unauthenticated remote code \
                  execution as root on glibc-based Linux. Present in < 4.4p1 and again in \
                  8.5p1 through 9.7p1; fixed in 9.8p1.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        affected: |v| {
            !v.is_zero()
                && (v < Version::parse("4.4")
                    || (v >= Version::parse("8.5") && v < Version::parse("9.8")))
        },
    },
    // ════════════════════════════════════════════════════════════════════════
    // The Nmap NSE set: CVEs that ship as scripts with nmap and that this table
    // did not cover. Three shapes appear below, and which one an entry gets is
    // decided by what a scan can honestly see:
    //
    //   * a version range, when the product states its version (Apache, BIND,
    //     Exim, or an OpenSSL that rides along in a `Server:` header). This is
    //     the default, and the only shape that can clear a patched host.
    //   * a protocol-state predicate, when the "version" Kaisen holds is a
    //     negotiated dialect rather than a release — SMB and TLS both work this
    //     way, so "SMB1 is still offered" is what the predicate can say.
    //   * `|_v| true`, only where the flaw is a configuration or an entire
    //     product line rather than a release. Those summaries name the builds
    //     NVD actually lists, so the reader can finish the job by hand.
    //
    // Where the fix is distinguished only by a letter or a -P suffix (OpenSSL
    // 1.0.1f against 1.0.1g, BIND 9.9.7 against 9.9.7-P3) `Version` cannot see
    // it — it reads the dotted-numeric run and stops. Those entries say so in
    // the summary instead of claiming a precision they do not have.
    //
    // Several entries key on a string that lives in the banner or in `extra`
    // rather than in `product`, which is what `match_product`'s substring match
    // over product+banner+extra is for: "OpenSSL" inside an httpd `Server:`
    // line, the BSD ftpd greeting, the RDP negotiation result.
    // ════════════════════════════════════════════════════════════════════════

    // ── FTP ─────────────────────────────────────────────────────────────────
    // The BSD ftpd greets with "220 host FTP server (Version 6.00LS) ready.",
    // and that parenthesis is the only thing that separates it from every other
    // daemon whose banner also contains the word FTP. Both of its entries key
    // on the greeting rather than on the product name for exactly that reason.
    CveEntry {
        match_product: "FTP server (Version 6.",
        cpe: "cpe:2.3:a:david_madore:ftpd-bsd",
        cve: "CVE-2001-0053",
        cvss: 10.0,
        severity: Severity::Critical,
        title: "BSD ftpd replydirname one-byte overflow (root)",
        summary: "El ftpd de las BSD desborda en un byte el buffer de replydirname, lo que \
                  entrega root al atacante. Afecta a ftpd-bsd 0.2.3, OpenBSD 2.4-2.8 y NetBSD \
                  1.4-1.5; el saludo no publica la versión del sistema base, así que confírmala.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2001-0053",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "FTP server (Version 6.",
        cpe: "cpe:2.3:a:nrl:opie",
        cve: "CVE-2010-1938",
        cvss: 9.3,
        severity: Severity::Critical,
        title: "OPIE libopie off-by-one via a long USER (FreeBSD ftpd)",
        summary: "__opiereadrec() en libopie (OPIE 2.4.1-test1 y anteriores), tal como lo usa el \
                  ftpd de FreeBSD 6.4 a 8.1-PRERELEASE, tiene un off-by-one: un USER largo tumba \
                  el demonio y puede llegar a ejecución de código, todo antes de autenticar.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-1938",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "ProFTPD",
        cpe: "cpe:2.3:a:proftpd:proftpd",
        cve: "CVE-2010-4221",
        cvss: 10.0,
        severity: Severity::Critical,
        title: "ProFTPD Telnet IAC stack overflow (pre-auth RCE)",
        summary: "pr_netio_telnet_gets() en ProFTPD anterior a 1.3.3c desborda la pila al procesar \
                  el carácter de escape IAC de Telnet, sin autenticación previa y tanto en FTP \
                  como en FTPS. El rango no distingue la letra: un 1.3.3c ya corregido cae dentro, \
                  así que comprueba el sufijo antes de dar el hallazgo por bueno.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-4221",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("1.3.2") && v <= Version::parse("1.3.3")
        },
    },

    // ── DNS ─────────────────────────────────────────────────────────────────
    // BIND is the one product here that reliably states its version: the CHAOS
    // TXT version.bind record is what `probe::dns_version` reads, so these are
    // real ranges. A -P patch suffix is invisible to `Version`, which is why the
    // ranges below are written against the base release.
    CveEntry {
        match_product: "BIND",
        cpe: "cpe:2.3:a:isc:bind",
        cve: "CVE-2002-0029",
        cvss: 7.5,
        severity: Severity::High,
        title: "BIND stub resolver buffer overrun (LIBRESOLV)",
        summary: "La biblioteca resolvedora de BIND 4.9.2 a 4.9.10 —y las libc derivadas de ella— \
                  desborda el buffer en getnetbyname() y getnetbyaddr() con respuestas DNS \
                  manipuladas, lo que permite ejecutar código en el cliente que consulta.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2002-0029",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("4.9.2") && v <= Version::parse("4.9.10")
        },
    },
    CveEntry {
        match_product: "BIND",
        cpe: "cpe:2.3:a:isc:bind",
        cve: "CVE-2002-0651",
        cvss: 7.5,
        severity: Severity::High,
        title: "BIND resolver buffer overflow (libbind / libc)",
        summary: "El código resolvedor derivado de BIND que usan libbind, libc y glibc desborda \
                  un buffer con respuestas de un servidor DNS malicioso, con denegación de \
                  servicio y posible ejecución de código. Corregido en las ramas 4.9.11 y 8.3.4.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2002-0651",
        affected: |v| v >= Version::parse("4.0") && v < Version::parse("8.3.4"),
    },
    CveEntry {
        match_product: "BIND",
        cpe: "cpe:2.3:a:isc:bind",
        cve: "CVE-2006-0987",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "BIND recurses for anyone by default",
        summary: "La configuración por defecto de BIND anterior a 9.4.1-P1 como servidor caché \
                  acepta consultas recursivas de cualquier dirección, lo que lo convierte en \
                  amplificador de DDoS y en objetivo de envenenamiento de caché. Limita la \
                  recursión con allow-recursion a los clientes que de verdad la necesitan.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2006-0987",
        affected: |v| v >= Version::parse("9.0") && v < Version::parse("9.4.1"),
    },
    CveEntry {
        match_product: "BIND",
        cpe: "cpe:2.3:a:isc:bind",
        cve: "CVE-2008-1447",
        cvss: 6.8,
        severity: Severity::Medium,
        title: "DNS cache poisoning (the Kaminsky bug)",
        summary: "BIND 8 y 9 anteriores a 9.5.0-P1 / 9.4.2-P1 / 9.3.5-P1 no aleatorizan lo \
                  suficiente el puerto de origen ni el identificador de transacción, así que un \
                  atacante puede ganar la carrera con referencias in-bailiwick y envenenar la \
                  caché del resolvedor. El sufijo -P no es visible en el banner.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2008-1447",
        affected: |v| v >= Version::parse("8.0") && v < Version::parse("9.5.0"),
    },
    CveEntry {
        match_product: "BIND",
        cpe: "cpe:2.3:a:isc:bind",
        cve: "CVE-2010-3615",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "BIND allow-query ACLs not checked everywhere",
        summary: "named en BIND 9.7.2-P2 no comprueba las ACL allow-query en todas las rutas \
                  previstas, de modo que un cliente no autorizado puede leer registros DNS \
                  privados con una consulta normal.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-3615",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("9.7.2") && v < Version::parse("9.7.3")
        },
    },
    CveEntry {
        match_product: "BIND",
        cpe: "cpe:2.3:a:isc:bind",
        cve: "CVE-2012-1667",
        cvss: 8.5,
        severity: Severity::High,
        title: "BIND zero-length RDATA handling",
        summary: "BIND anterior a 9.7.6-P1 / 9.8.3-P1 / 9.9.1-P1 gestiona mal los registros con \
                  RDATA de longitud cero: el demonio cae, los datos de la caché se corrompen o se \
                  filtra memoria del proceso en las respuestas.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2012-1667",
        affected: |v| {
            !v.is_zero()
                && ((v >= Version::parse("9.0") && v < Version::parse("9.7.6"))
                    || (v >= Version::parse("9.8.0") && v < Version::parse("9.8.3"))
                    || (v >= Version::parse("9.9.0") && v < Version::parse("9.9.1")))
        },
    },
    CveEntry {
        match_product: "BIND",
        cpe: "cpe:2.3:a:isc:bind",
        cve: "CVE-2014-3214",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "BIND 9.10.0 prefetch assertion failure",
        summary: "Con la recursión activada, la implementación de prefetch de BIND 9.10.0 falla \
                  una aserción REQUIRE y el demonio termina, así que una sola consulta cuya \
                  respuesta tenga ciertos atributos deja el resolvedor fuera de servicio.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-3214",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("9.10.0") && v < Version::parse("9.10.1")
        },
    },
    CveEntry {
        match_product: "BIND",
        cpe: "cpe:2.3:a:isc:bind",
        cve: "CVE-2015-4620",
        cvss: 7.8,
        severity: Severity::High,
        title: "BIND DNSSEC validation assertion failure",
        summary: "Como resolvedor recursivo con validación DNSSEC, BIND 9.7.x-9.9.x anterior a \
                  9.9.7-P1 y 9.10.x anterior a 9.10.2-P2 puede ser tumbado por una zona \
                  construida a medida más una consulta a un nombre de esa zona.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2015-4620",
        affected: |v| {
            !v.is_zero()
                && ((v >= Version::parse("9.7.0") && v <= Version::parse("9.9.7"))
                    || (v >= Version::parse("9.10.0") && v <= Version::parse("9.10.2")))
        },
    },
    CveEntry {
        match_product: "BIND",
        cpe: "cpe:2.3:a:isc:bind",
        cve: "CVE-2015-5986",
        cvss: 7.1,
        severity: Severity::High,
        title: "BIND OPENPGPKEY assertion failure",
        summary: "openpgpkey_61.c en BIND 9.9.7 anterior a 9.9.7-P3 y en 9.10.x anterior a \
                  9.10.2-P4 falla una aserción REQUIRE ante una respuesta DNS manipulada y el \
                  demonio termina. El sufijo -P no aparece en version.bind.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2015-5986",
        affected: |v| {
            !v.is_zero()
                && ((v >= Version::parse("9.9.7") && v < Version::parse("9.9.8"))
                    || (v >= Version::parse("9.10.0") && v <= Version::parse("9.10.2")))
        },
    },
    CveEntry {
        match_product: "Microsoft DNS",
        cpe: "cpe:2.3:o:microsoft:windows_server_2003",
        cve: "CVE-2007-1748",
        cvss: 10.0,
        severity: Severity::Critical,
        title: "Windows DNS Server RPC stack overflow (MS07-029)",
        summary: "La interfaz RPC de gestión del servidor DNS de Windows 2000 Server SP4 y Server \
                  2003 SP1/SP2 desborda la pila con un nombre de zona largo, sin autenticación. \
                  El servidor no publica su build: si esta máquina es de esa generación, trátala \
                  como vulnerable y cierra la interfaz RPC de administración.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2007-1748",
        affected: |_v| true,
    },

    // ── Mail ────────────────────────────────────────────────────────────────
    CveEntry {
        match_product: "Exim",
        cpe: "cpe:2.3:a:exim:exim",
        cve: "CVE-2010-4344",
        cvss: 9.8,
        severity: Severity::Critical,
        title: "Exim string_vformat heap overflow (remote RCE)",
        summary: "Exim anterior a 4.70 desborda el montículo en string_vformat() al registrar el \
                  rechazo de un mensaje grande con cabeceras manipuladas, lo que da ejecución \
                  remota de código sin autenticar. Encadenado con CVE-2010-4345 termina en root.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-4344",
        affected: |v| v >= Version::parse("3.0") && v < Version::parse("4.70"),
    },
    CveEntry {
        match_product: "Exim",
        cpe: "cpe:2.3:a:exim:exim",
        cve: "CVE-2010-4345",
        cvss: 7.8,
        severity: Severity::High,
        title: "Exim alternate-configuration privilege escalation",
        summary: "En Exim 4.72 y anteriores, el usuario exim puede indicar un fichero de \
                  configuración alternativo con directivas que ejecutan órdenes, así que quien \
                  llegue a ese usuario —por ejemplo a través de CVE-2010-4344— pasa a root.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-4345",
        affected: |v| v >= Version::parse("3.0") && v <= Version::parse("4.72"),
    },
    CveEntry {
        match_product: "Exim",
        cpe: "cpe:2.3:a:exim:exim",
        cve: "CVE-2011-1764",
        cvss: 7.5,
        severity: Severity::High,
        title: "Exim DKIM format-string vulnerability",
        summary: "dkim_exim_verify_finish() en Exim anterior a 4.76 pasa datos del mensaje como \
                  cadena de formato al registrar la verificación DKIM: un campo identity con un \
                  '%' tumba el demonio y puede llegar a ejecución de código.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-1764",
        affected: |v| v >= Version::parse("3.0") && v < Version::parse("4.76"),
    },
    CveEntry {
        match_product: "Postfix",
        cpe: "cpe:2.3:a:postfix:postfix",
        cve: "CVE-2011-1720",
        cvss: 6.8,
        severity: Severity::Medium,
        title: "Postfix Cyrus SASL memory corruption",
        summary: "Con ciertos mecanismos de Cyrus SASL activados, Postfix anterior a 2.5.13 / \
                  2.6.10 / 2.7.4 / 2.8.3 reutiliza el manejador del servidor tras un AUTH \
                  fallido: dos AUTH con mecanismos distintos corrompen el montículo y tumban el \
                  demonio, con posible ejecución de código.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-1720",
        affected: |v| {
            !v.is_zero()
                && ((v >= Version::parse("2.0") && v < Version::parse("2.5.13"))
                    || (v >= Version::parse("2.6.0") && v < Version::parse("2.6.10"))
                    || (v >= Version::parse("2.7.0") && v < Version::parse("2.7.4"))
                    || (v >= Version::parse("2.8.0") && v < Version::parse("2.8.3")))
        },
    },
    CveEntry {
        match_product: "Domino",
        cpe: "cpe:2.3:a:ibm:lotus_domino",
        cve: "CVE-2006-5835",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "Lotus Domino NRPC unauthenticated user lookup",
        summary: "El protocolo NRPC de Lotus Domino anterior a 6.5.5 FP2 y 7.x anterior a 7.0.2 \
                  no exige autenticación para resolver usuarios, de modo que cualquiera puede \
                  descargar el fichero de ID de un usuario y atacar su contraseña sin conexión. \
                  El nivel de fixpack no aparece en el saludo SMTP: confírmalo.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2006-5835",
        affected: |v| v >= Version::parse("4.0") && v < Version::parse("7.0.2"),
    },

    // ── Web servers ─────────────────────────────────────────────────────────
    CveEntry {
        match_product: "Apache",
        cpe: "cpe:2.3:a:apache:http_server",
        cve: "CVE-2001-1013",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "Apache UserDir username enumeration",
        summary: "Con UserDir activado, Apache devuelve códigos de error distintos según exista o \
                  no el usuario, lo que permite enumerar cuentas locales del servidor. El rango \
                  cubre la rama 1.3, que es la que NVD asocia al problema; en versiones modernas \
                  sigue siendo un riesgo de configuración si UserDir está activo.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2001-1013",
        affected: |v| v >= Version::parse("1.3") && v < Version::parse("2.0"),
    },
    CveEntry {
        match_product: "Apache",
        cpe: "cpe:2.3:a:apache:http_server",
        cve: "CVE-2007-6750",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "Apache Slowloris (partial-request denial of service)",
        summary: "Apache 1.x y 2.x hasta 2.2.14 mantienen abiertas las peticiones incompletas \
                  hasta agotar los procesos disponibles: un solo cliente lento deja el servidor \
                  sin servicio. La defensa es mod_reqtimeout, que llegó en 2.2.15.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2007-6750",
        affected: |v| v >= Version::parse("1.3") && v < Version::parse("2.2.15"),
    },
    CveEntry {
        match_product: "Apache",
        cpe: "cpe:2.3:a:apache:http_server",
        cve: "CVE-2011-3192",
        cvss: 7.8,
        severity: Severity::High,
        title: "Apache Range header denial of service (killapache)",
        summary: "El filtro byterange de Apache 1.3.x, 2.0.x hasta 2.0.64 y 2.2.x hasta 2.2.19 \
                  consume memoria y CPU sin límite ante una cabecera Range con muchos rangos \
                  solapados. Explotado de forma masiva en agosto de 2011; corregido en 2.2.20.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-3192",
        affected: |v| v >= Version::parse("1.3") && v < Version::parse("2.2.20"),
    },
    CveEntry {
        match_product: "Apache",
        cpe: "cpe:2.3:a:apache:http_server",
        cve: "CVE-2011-3368",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "Apache mod_proxy reverse-proxy bypass",
        summary: "Con RewriteRule o ProxyPassMatch configurando un proxy inverso, Apache 1.3.x \
                  hasta 1.3.42, 2.0.x hasta 2.0.64 y 2.2.x hasta 2.2.21 aceptan un URI que \
                  empieza por '@' y reenvían la petición a un servidor interno elegido por el \
                  atacante. Corregido en 2.2.22.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-3368",
        affected: |v| v >= Version::parse("1.3") && v < Version::parse("2.2.22"),
    },
    // Shellshock is a bash bug, not an httpd bug: what a scan sees is an httpd
    // old enough to be sitting on a 2014-era base system, with mod_cgi as the
    // classic remote path into the shell. So the predicate is deliberately a
    // date proxy — 2.4.10 is the release that predates the disclosure — and the
    // summary says plainly that bash is what has to be checked.
    CveEntry {
        match_product: "Apache",
        cpe: "cpe:2.3:a:gnu:bash",
        cve: "CVE-2014-6271",
        cvss: 9.8,
        severity: Severity::Critical,
        title: "Shellshock — check bash behind mod_cgi",
        summary: "bash hasta 4.3 ejecuta lo que venga detrás de una definición de función en una \
                  variable de entorno, y mod_cgi/mod_cgid pasan cabeceras HTTP como entorno: es \
                  ejecución remota de código sin autenticar. Este httpd es anterior a la \
                  divulgación (2.4.10), así que su sistema base es de esa época: comprueba bash \
                  con env x='() { :;}; echo vuln' bash -c true.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
        affected: |v| v >= Version::parse("1.3") && v < Version::parse("2.4.10"),
    },
    CveEntry {
        match_product: "Apache",
        cpe: "cpe:2.3:a:gnu:bash",
        cve: "CVE-2014-7169",
        cvss: 9.8,
        severity: Severity::Critical,
        title: "Shellshock incomplete fix (bash43-025)",
        summary: "El primer parche de CVE-2014-6271 quedó incompleto: bash hasta bash43-025 sigue \
                  procesando cadenas tras ciertas definiciones de función malformadas y permite \
                  escribir ficheros por la misma vía CGI. Un sistema parcheado a medias sigue \
                  siendo vulnerable; verifica que bash lleve las dos correcciones.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-7169",
        affected: |v| v >= Version::parse("1.3") && v < Version::parse("2.4.10"),
    },
    CveEntry {
        match_product: "LiteSpeed",
        cpe: "cpe:2.3:a:litespeedtech:litespeed_web_server",
        cve: "CVE-2010-2333",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "LiteSpeed null-byte source disclosure",
        summary: "LiteSpeed Web Server 4.0.x anterior a 4.0.15 devuelve el código fuente de los \
                  scripts cuando la petición lleva un byte nulo seguido de la extensión .txt, lo \
                  que expone credenciales de base de datos y claves de la aplicación.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-2333",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("4.0") && v < Version::parse("4.0.15")
        },
    },
    // Allegro's RomPager names itself in the `Server:` header of a very large
    // number of DSL routers ("Server: RomPager/4.07 UPnP/1.0"), so both of its
    // entries get a real version range.
    CveEntry {
        match_product: "RomPager",
        cpe: "cpe:2.3:a:allegrosoft:rompager",
        cve: "CVE-2014-9222",
        cvss: 10.0,
        severity: Severity::Critical,
        title: "Misfortune Cookie (RomPager memory corruption)",
        summary: "RomPager 4.34 y anteriores corrompen memoria al procesar una cookie manipulada, \
                  lo que permite tomar el control administrativo del router sin credenciales. \
                  Millones de equipos de operador quedaron expuestos; el arreglo es firmware del \
                  fabricante, no una opción de configuración.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-9222",
        affected: |v| v >= Version::parse("2.0") && v <= Version::parse("4.34"),
    },
    CveEntry {
        match_product: "RomPager",
        cpe: "cpe:2.3:a:allegrosoft:rompager",
        cve: "CVE-2013-6786",
        cvss: 4.3,
        severity: Severity::Medium,
        title: "RomPager cross-site scripting via 404 page",
        summary: "RomPager anterior a 4.51 refleja la cabecera Referer en la página de error 404 \
                  sin escaparla, lo que permite inyectar script en el navegador del \
                  administrador —y desde ahí reconfigurar el equipo— en modelos de ZyXEL, Huawei, \
                  TP-Link, D-Link y Sitecom.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2013-6786",
        affected: |v| v >= Version::parse("2.0") && v < Version::parse("4.51"),
    },
    // Webmin's own httpd answers "Server: MiniServ/1.890", and that version is
    // Webmin's version — the only place an unauthenticated request can read it.
    CveEntry {
        match_product: "MiniServ",
        cpe: "cpe:2.3:a:webmin:webmin",
        cve: "CVE-2006-3392",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "Webmin arbitrary file disclosure (miniserv.pl)",
        summary: "Webmin anterior a 1.290 y Usermin anterior a 1.220 simplifican la ruta antes de \
                  decodificar el HTML, así que secuencias como '..%01' sobreviven al filtro y \
                  permiten leer cualquier fichero del servidor —incluido /etc/shadow— sin \
                  autenticarse.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2006-3392",
        affected: |v| v >= Version::parse("0.9") && v < Version::parse("1.290"),
    },

    // ── Web applications ────────────────────────────────────────────────────
    CveEntry {
        match_product: "phpMyAdmin",
        cpe: "cpe:2.3:a:phpmyadmin:phpmyadmin",
        cve: "CVE-2005-3299",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "phpMyAdmin grab_globals.lib.php file inclusion",
        summary: "phpMyAdmin 2.6.4 y 2.6.4-pl1 incluyen ficheros locales a través del parámetro \
                  $__redirect de grab_globals.lib.php, lo que expone configuración y credenciales \
                  de la base de datos.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2005-3299",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("2.6.4") && v < Version::parse("2.6.5")
        },
    },
    CveEntry {
        match_product: "AWStats Totals",
        cpe: "cpe:2.3:a:telartis_bv:awstats_totals",
        cve: "CVE-2008-3922",
        cvss: 9.3,
        severity: Severity::Critical,
        title: "AWStats Totals unauthenticated PHP code execution",
        summary: "awstatstotals.php en AWStats Totals 1.0 a 1.14 pasa el parámetro sort a \
                  create_function(), de modo que cualquiera puede ejecutar PHP en el servidor sin \
                  autenticarse. El add-on no publica su versión: si está instalado, actualízalo o \
                  retíralo.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2008-3922",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "Majordomo",
        cpe: "cpe:2.3:a:mj2:majordomo_2",
        cve: "CVE-2011-0049",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "Majordomo 2 directory traversal (help command)",
        summary: "_list_file_get() en Majordomo 2 anterior a 20110131 acepta '..' en la orden \
                  help, tanto por correo como por cgi-bin/mj_wwwusr, y devuelve cualquier fichero \
                  legible por el proceso. La versión es una fecha que la interfaz no publica.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-0049",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "CM Download Manager",
        cpe: "cpe:2.3:a:creative_minds:cm_download_manager",
        cve: "CVE-2014-8877",
        cvss: 10.0,
        severity: Severity::Critical,
        title: "WordPress CM Download Manager code injection",
        summary: "El plugin CreativeMinds CM Downloads Manager anterior a 2.0.4 pasa el parámetro \
                  CMDsearch a create_function(), lo que da ejecución de PHP sin autenticar en \
                  cualquier WordPress que lo tenga instalado.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-8877",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "WordPress",
        cpe: "cpe:2.3:a:wordpress:wordpress",
        cve: "CVE-2017-1001000",
        cvss: 7.5,
        severity: Severity::High,
        title: "WordPress REST API content injection",
        summary: "register_routes() en la REST API de WordPress 4.7.0 y 4.7.1 no exige un \
                  identificador entero, así que cualquiera puede modificar entradas ajenas \
                  mediante wp-json/wp/v2/posts. Se usó para desfigurar más de un millón de sitios \
                  en los días siguientes al parche 4.7.2.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2017-1001000",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("4.7") && v < Version::parse("4.7.2")
        },
    },
    CveEntry {
        match_product: "Drupal",
        cpe: "cpe:2.3:a:drupal:drupal",
        cve: "CVE-2014-3704",
        cvss: 7.5,
        severity: Severity::High,
        title: "Drupalgeddon SQL injection (expandArguments)",
        summary: "expandArguments() en la capa de base de datos de Drupal 7.x anterior a 7.32 \
                  construye mal las consultas preparadas cuando las claves del array vienen \
                  manipuladas, lo que da inyección SQL sin autenticar y, en la práctica, control \
                  del sitio. Un Drupal 7 sin actualizar en 2014 debe considerarse comprometido.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-3704",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("7.0") && v < Version::parse("7.32")
        },
    },
    CveEntry {
        match_product: "Joomla",
        cpe: "cpe:2.3:a:joomla:joomla",
        cve: "CVE-2017-8917",
        cvss: 9.8,
        severity: Severity::Critical,
        title: "Joomla! 3.7.0 SQL injection",
        summary: "Joomla! 3.7.0 expone una inyección SQL sin autenticar en el componente de \
                  campos, con la que se leen los hashes y tokens de sesión de los administradores. \
                  Corregido en 3.7.1.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2017-8917",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("3.7.0") && v < Version::parse("3.7.1")
        },
    },
    CveEntry {
        match_product: "Ruby on Rails",
        cpe: "cpe:2.3:a:rubyonrails:ruby_on_rails",
        cve: "CVE-2013-0156",
        cvss: 7.5,
        severity: Severity::High,
        title: "Rails XML parameter object injection (RCE)",
        summary: "La conversión de tipos YAML y Symbol al parsear XML en Rails anterior a 2.3.15, \
                  3.0.19, 3.1.10 y 3.2.11 permite instanciar objetos arbitrarios desde la petición \
                  y ejecutar código. Afecta a cualquier acción que acepte XML, incluida la \
                  autenticación.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2013-0156",
        affected: |v| {
            !v.is_zero()
                && ((v >= Version::parse("1.0") && v < Version::parse("2.3.15"))
                    || (v >= Version::parse("3.0.0") && v < Version::parse("3.0.19"))
                    || (v >= Version::parse("3.1.0") && v < Version::parse("3.1.10"))
                    || (v >= Version::parse("3.2.0") && v < Version::parse("3.2.11")))
        },
    },
    CveEntry {
        match_product: "Zimbra",
        cpe: "cpe:2.3:a:synacor:zimbra_collaboration_suite",
        cve: "CVE-2013-7091",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "Zimbra skin parameter directory traversal",
        summary: "El recurso /res/…js.zgz de Zimbra 7.2.2 y 8.0.2 acepta '..' en el parámetro \
                  skin y devuelve cualquier fichero legible, incluido localconfig.xml con las \
                  credenciales LDAP — que a su vez abren la API de administración y llevan a \
                  ejecución de código.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2013-7091",
        affected: |v| v >= Version::parse("6.0") && v < Version::parse("8.0.3"),
    },
    CveEntry {
        match_product: "JBoss",
        cpe: "cpe:2.3:a:redhat:jboss_enterprise_application_platform",
        cve: "CVE-2010-0738",
        cvss: 5.3,
        severity: Severity::Medium,
        title: "JBoss JMX console verb-based authentication bypass",
        summary: "La consola JMX de JBoss AS aplica el control de acceso solo a GET y POST, así \
                  que basta con usar otro verbo HTTP (HEAD) para llegar al manejador y desplegar \
                  una aplicación — es decir, ejecución de código. La consola JMX no debería estar \
                  publicada aunque el servidor esté parcheado.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-0738",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "ColdFusion",
        cpe: "cpe:2.3:a:adobe:coldfusion",
        cve: "CVE-2010-2861",
        cvss: 9.8,
        severity: Severity::Critical,
        title: "ColdFusion administrator console directory traversal",
        summary: "La consola de administración de Adobe ColdFusion 9.0.1 y anteriores acepta '..' \
                  en el parámetro locale de varias páginas de CFIDE/administrator/, lo que permite \
                  leer el fichero con el hash de la contraseña de administrador y, desde ahí, \
                  desplegar código.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-2861",
        affected: |v| v >= Version::parse("6.0") && v <= Version::parse("9.0.1"),
    },
    CveEntry {
        match_product: "ColdFusion",
        cpe: "cpe:2.3:a:adobe:blazeds",
        cve: "CVE-2009-3960",
        cvss: 6.5,
        severity: Severity::Medium,
        title: "Adobe BlazeDS XML external entity injection",
        summary: "BlazeDS 3.2 y anteriores —el canal AMF que incorporan ColdFusion 7.0.2 a 9.0, \
                  LiveCycle y LiveCycle Data Services— resuelven entidades externas en los \
                  documentos XML que reciben, así que una petición puede leer ficheros locales y \
                  alcanzar servicios internos.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2009-3960",
        affected: |v| v >= Version::parse("6.0") && v <= Version::parse("9.0"),
    },

    // ── SMB / Windows ───────────────────────────────────────────────────────
    // `probe::smb` reports the negotiated dialect as the version — 1.0, 2.0.2,
    // 2.1, 3.1.1 — so these predicates read as "this host still speaks the
    // dialect that the affected Windows generation spoke". That is a genuine
    // narrowing: a host that negotiates SMB 3.1.1 is Windows 10/2016 or later
    // and is out of scope for every entry below.
    CveEntry {
        match_product: "SMB",
        cpe: "cpe:2.3:o:microsoft:windows_2003_server",
        cve: "CVE-2006-2370",
        cvss: 7.5,
        severity: Severity::High,
        title: "Windows RRAS memory corruption (MS06-025)",
        summary: "El servicio de enrutamiento y acceso remoto de Windows 2000 SP4, XP SP1/SP2 y \
                  Server 2003 SP1 desborda un buffer con peticiones RPC manipuladas, en algunos \
                  casos sin autenticación. Este host solo negocia SMB1, el perfil de esa \
                  generación de Windows.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2006-2370",
        affected: |v| !v.is_zero() && v < Version::parse("2.0"),
    },
    CveEntry {
        match_product: "SMB",
        cpe: "cpe:2.3:o:microsoft:windows_server_2003",
        cve: "CVE-2008-4250",
        cvss: 9.8,
        severity: Severity::Critical,
        title: "Windows Server service RPC overflow (MS08-067, Conficker)",
        summary: "El servicio Server de Windows 2000 a Server 2008 desborda la pila al canonizar \
                  una ruta recibida por RPC, lo que da ejecución de código sin autenticar sobre \
                  el puerto 445. Es el fallo que usó Conficker y sigue apareciendo en redes \
                  industriales.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2008-4250",
        affected: |v| !v.is_zero() && v < Version::parse("2.1"),
    },
    CveEntry {
        match_product: "SMB",
        cpe: "cpe:2.3:o:microsoft:windows_vista",
        cve: "CVE-2009-3103",
        cvss: 10.0,
        severity: Severity::Critical,
        title: "SMBv2 negotiation array-index error (MS09-050)",
        summary: "srv2.sys en Windows Vista y Server 2008 cae —o ejecuta código— ante un '&' en el \
                  campo Process ID High de una NEGOTIATE PROTOCOL REQUEST. Se dispara antes de \
                  autenticar y este host negocia el dialecto 2.0.2 de esa generación.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2009-3103",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("2.0") && v < Version::parse("2.1")
        },
    },
    CveEntry {
        match_product: "SMB",
        cpe: "cpe:2.3:o:microsoft:windows_7",
        cve: "CVE-2010-2550",
        cvss: 10.0,
        severity: Severity::Critical,
        title: "Windows SMB pool overflow (MS10-054)",
        summary: "El servidor SMB de Windows XP a 7 y Server 2003 a 2008 R2 no valida algunos \
                  campos de la petición y desborda el pool del núcleo, lo que da ejecución de \
                  código en anillo 0 desde la red.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-2550",
        affected: |v| !v.is_zero() && v < Version::parse("3.0"),
    },
    CveEntry {
        match_product: "SMB",
        cpe: "cpe:2.3:o:microsoft:windows_7",
        cve: "CVE-2010-2729",
        cvss: 9.3,
        severity: Severity::Critical,
        title: "Windows Print Spooler impersonation (MS10-061, Stuxnet)",
        summary: "Con la compartición de impresoras activada, el spooler de Windows XP a 7 no \
                  valida los permisos de la petición de impresión y deja escribir ficheros en un \
                  directorio del sistema, lo que termina en ejecución de código. Explotado por \
                  Stuxnet.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-2729",
        affected: |v| !v.is_zero() && v < Version::parse("3.0"),
    },
    CveEntry {
        match_product: "SMB",
        cpe: "cpe:2.3:a:microsoft:server_message_block",
        cve: "CVE-2017-0143",
        cvss: 8.8,
        severity: Severity::High,
        title: "EternalBlue — SMBv1 remote code execution (MS17-010)",
        summary: "El servidor SMBv1 de Windows Vista a Server 2016 ejecuta código con paquetes \
                  manipulados. Es la base de WannaCry y NotPetya, y este host sigue ofreciendo el \
                  dialecto SMB1: aplica MS17-010 y desactiva SMB1, que no tiene uso legítimo.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2017-0143",
        affected: |v| !v.is_zero() && v < Version::parse("2.0"),
    },

    // ── RDP ─────────────────────────────────────────────────────────────────
    // `probe::rdp` writes the negotiation result into `extra`, and "standard RDP
    // security (no NLA)" is the fingerprint of the Windows generation these two
    // bulletins cover: current Windows requires CredSSP/NLA by default, so a
    // server that still settles for standard RDP security is the population at
    // risk. The version is never published, so the negotiation is the gate.
    CveEntry {
        match_product: "standard RDP security",
        cpe: "cpe:2.3:o:microsoft:windows_server_2008",
        cve: "CVE-2012-0002",
        cvss: 9.3,
        severity: Severity::Critical,
        title: "RDP pre-auth remote code execution (MS12-020)",
        summary: "La implementación de RDP de Windows XP a 7 y Server 2003 a 2008 R2 accede a un \
                  objeto sin inicializar o ya liberado al procesar ciertos paquetes, lo que da \
                  ejecución de código antes de autenticar. Este servidor aceptó seguridad RDP \
                  estándar sin NLA, que es el perfil de esos sistemas: confirma el parche.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2012-0002",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "standard RDP security",
        cpe: "cpe:2.3:o:microsoft:windows_server_2008",
        cve: "CVE-2012-0152",
        cvss: 4.3,
        severity: Severity::Medium,
        title: "Terminal Server denial of service (MS12-020)",
        summary: "El servicio RDP de Windows 7 y Server 2008 R2 se cuelga ante una secuencia de \
                  paquetes manipulados, sin necesidad de credenciales. Es el segundo CVE del \
                  boletín MS12-020, junto con CVE-2012-0002.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2012-0152",
        affected: |_v| true,
    },

    // ── TLS and OpenSSL ─────────────────────────────────────────────────────
    // POODLE is a property of the negotiated protocol, so it keys on the
    // handshake result rather than on a version number. The version Kaisen holds
    // for a TLS service is the protocol itself, and SSL 3.0 arrives as the
    // string "3.0" — numerically *above* TLS 1.2, so a numeric predicate reads
    // backwards and, worse, a `>= 3.0` one also matches the "GnuTLS/3.7.9" that
    // an httpd prints in its own `Server:` header. `tls_version` says exactly
    // what was negotiated and nothing else does, which is why it is in the
    // haystack.
    //
    // For OpenSSL the version comes from that same module list ("Apache/2.4.7
    // (Ubuntu) OpenSSL/1.0.1f"), where the fix is usually a letter — and
    // `Version` stops at the first non-numeric character. Every OpenSSL entry
    // below therefore matches the whole letter series and says so: a
    // distribution that backports patches keeps the old letter.
    CveEntry {
        match_product: "SSL 3.0",
        cpe: "cpe:2.3:a:openssl:openssl",
        cve: "CVE-2014-3566",
        cvss: 3.4,
        severity: Severity::Low,
        title: "POODLE — SSL 3.0 negotiated",
        summary: "El servidor negoció SSL 3.0, cuyo relleno CBC no está autenticado: un atacante \
                  interpuesto que pueda repetir la petición descifra byte a byte datos como una \
                  cookie de sesión. SSL 3.0 no tiene arreglo posible; desactívalo.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-3566",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "OpenSSL",
        cpe: "cpe:2.3:a:openssl:openssl",
        cve: "CVE-2014-0160",
        cvss: 7.5,
        severity: Severity::High,
        title: "Heartbleed (OpenSSL heartbeat over-read)",
        summary: "OpenSSL 1.0.1 hasta 1.0.1f devuelve hasta 64 KB de memoria del proceso por cada \
                  latido manipulado, incluidas claves privadas y credenciales, sin dejar rastro. \
                  El banner no distingue la letra ni los parches retroportados —Ubuntu 14.04 \
                  mantiene el sello '1.0.1f' ya corregido—, así que confírmalo con una prueba de \
                  heartbeat antes de darlo por explotable.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("1.0.1") && v < Version::parse("1.0.2")
        },
    },
    CveEntry {
        match_product: "OpenSSL",
        cpe: "cpe:2.3:a:openssl:openssl",
        cve: "CVE-2014-0224",
        cvss: 7.4,
        severity: Severity::High,
        title: "OpenSSL CCS injection (session hijacking)",
        summary: "OpenSSL anterior a 0.9.8za, 1.0.0m y 1.0.1h acepta un ChangeCipherSpec fuera de \
                  orden y acaba usando una clave maestra de longitud cero, lo que permite a un \
                  atacante interpuesto descifrar y modificar la sesión cuando ambos extremos son \
                  OpenSSL.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-0224",
        affected: |v| v >= Version::parse("0.9") && v <= Version::parse("1.0.1"),
    },
    CveEntry {
        match_product: "OpenSSL",
        cpe: "cpe:2.3:a:openssl:openssl",
        cve: "CVE-2015-3197",
        cvss: 5.9,
        severity: Severity::Medium,
        title: "OpenSSL SSLv2 accepts disabled ciphers",
        summary: "s2_srvr.c en OpenSSL 1.0.1 anterior a 1.0.1r y 1.0.2 anterior a 1.0.2f negocia \
                  cifrados SSLv2 que el administrador había desactivado, lo que devuelve al \
                  servidor a criptografía rota y habilita ataques del tipo DROWN.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2015-3197",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("1.0.1") && v <= Version::parse("1.0.2")
        },
    },
    CveEntry {
        match_product: "OpenSSL",
        cpe: "cpe:2.3:a:openssl:openssl",
        cve: "CVE-2015-4000",
        cvss: 3.7,
        severity: Severity::Low,
        title: "Logjam (DHE_EXPORT downgrade)",
        summary: "TLS 1.2 y anteriores no atan la elección de suite a la negociación, así que un \
                  atacante interpuesto puede degradar un intercambio DHE a DHE_EXPORT de 512 bits \
                  y romperlo. OpenSSL hasta 1.0.1m y 1.0.2a mantiene esas suites y grupos \
                  pequeños; desactiva los cifrados EXPORT y usa un grupo DH de 2048 bits propio.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2015-4000",
        affected: |v| v >= Version::parse("0.9") && v <= Version::parse("1.0.2"),
    },
    CveEntry {
        match_product: "OpenSSL",
        cpe: "cpe:2.3:a:openssl:openssl",
        cve: "CVE-2016-0703",
        cvss: 5.9,
        severity: Severity::Medium,
        title: "OpenSSL SSLv2 CLEAR-KEY oracle (DROWN special)",
        summary: "get_client_master_key() en OpenSSL anterior a 0.9.8zf, 1.0.0r, 1.0.1m y 1.0.2a \
                  acepta una CLEAR-KEY-LENGTH no nula para cualquier cifrado, lo que revela la \
                  MASTER-KEY y permite descifrar sesiones TLS grabadas en minutos.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2016-0703",
        affected: |v| v >= Version::parse("0.9") && v <= Version::parse("1.0.2"),
    },
    CveEntry {
        match_product: "OpenSSL",
        cpe: "cpe:2.3:a:openssl:openssl",
        cve: "CVE-2016-0800",
        cvss: 5.9,
        severity: Severity::Medium,
        title: "DROWN — SSLv2 Bleichenbacher oracle",
        summary: "Mientras el servidor —o cualquier otro que comparta su clave RSA— siga \
                  aceptando SSLv2, ese protocolo actúa como oráculo de relleno y permite \
                  descifrar sesiones TLS modernas. Corregido en OpenSSL 1.0.1s y 1.0.2g, que \
                  desactivan SSLv2; comprueba también los servidores que reutilizan el mismo \
                  certificado.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2016-0800",
        affected: |v| {
            !v.is_zero() && v >= Version::parse("1.0.1") && v <= Version::parse("1.0.2")
        },
    },
    CveEntry {
        match_product: "BIG-IP",
        cpe: "cpe:2.3:a:f5:big-ip_local_traffic_manager",
        cve: "CVE-2016-9244",
        cvss: 7.5,
        severity: Severity::High,
        title: "Ticketbleed (F5 BIG-IP session ticket memory leak)",
        summary: "Un virtual server de BIG-IP con la opción Session Tickets activada devuelve \
                  hasta 31 bytes de memoria sin inicializar en cada handshake, lo que filtra \
                  identificadores de sesión y restos de otras conexiones. Verifica la build y la \
                  opción en el perfil Client SSL.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2016-9244",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "Infineon",
        cpe: "cpe:2.3:a:infineon:rsa_library",
        cve: "CVE-2017-15361",
        cvss: 5.9,
        severity: Severity::Medium,
        title: "ROCA — Infineon RSA key generation is factorable",
        summary: "La biblioteca RSA 1.02.013 de los TPM de Infineon genera claves con una \
                  estructura que permite factorizarlas: una clave de 2048 bits se rompe con unos \
                  cientos de horas de CPU. Afecta a claves creadas en el TPM antes del firmware \
                  4.34 / 6.43 / 133.33; hay que regenerarlas, no basta con actualizar.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2017-15361",
        affected: |_v| true,
    },

    // ── Databases ───────────────────────────────────────────────────────────
    CveEntry {
        match_product: "Oracle TNS",
        cpe: "cpe:2.3:a:oracle:database_server",
        cve: "CVE-2012-3137",
        cvss: 6.4,
        severity: Severity::Medium,
        title: "Oracle stealth password cracking (O5LOGIN)",
        summary: "El protocolo de autenticación de Oracle Database 10.2.0.3 a 11.2.0.3 entrega la \
                  clave de sesión y la sal antes de validar la contraseña, así que un atacante \
                  obtiene material para romper la contraseña sin conexión y sin dejar intentos \
                  fallidos en los registros. El listener publica el VSNNUM que se ve aquí.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2012-3137",
        affected: |v| {
            !v.is_zero()
                && ((v >= Version::parse("10.2.0.3") && v <= Version::parse("10.2.0.5"))
                    || (v >= Version::parse("11.1") && v <= Version::parse("11.2.0.3")))
        },
    },

    // ── Appliances, hypervisors and endpoints ───────────────────────────────
    // A Cisco ASA publishes no version on an unauthenticated request — the
    // WebVPN portal only gives away that it is an ASA — so these four are
    // product-level leads with the affected trains named in the summary, which
    // is the same posture the appliance signatures in vuln.rs take.
    CveEntry {
        match_product: "Cisco ASA",
        cpe: "cpe:2.3:a:cisco:adaptive_security_appliance_software",
        cve: "CVE-2014-2126",
        cvss: 8.5,
        severity: Severity::High,
        title: "Cisco ASA ASDM privilege escalation",
        summary: "Un usuario con acceso ASDM de nivel 0 puede elevar privilegios en ASA 8.2 \
                  anterior a 8.2(5.47), 8.4 anterior a 8.4(7.5), 8.7 anterior a 8.7(1.11), 9.0 \
                  anterior a 9.0(3.10) y 9.1 anterior a 9.1(3.4). Comprueba la build del equipo.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-2126",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "Cisco ASA",
        cpe: "cpe:2.3:a:cisco:adaptive_security_appliance_software",
        cve: "CVE-2014-2127",
        cvss: 8.5,
        severity: Severity::High,
        title: "Cisco ASA clientless SSL VPN privilege escalation",
        summary: "ASA 8.x anterior a 8.2(5.48), 8.3(2.40), 8.4(7.9), 8.6(1.13), 9.0(4.1) y \
                  9.1(4.3) no valida bien la sesión de gestión durante una conexión SSL VPN sin \
                  cliente, de modo que un usuario VPN cualquiera pasa a administrador.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-2127",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "Cisco ASA",
        cpe: "cpe:2.3:a:cisco:adaptive_security_appliance_software",
        cve: "CVE-2014-2128",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "Cisco ASA SSL VPN authentication bypass",
        summary: "La implementación SSL VPN de ASA 8.2 anterior a 8.2(5.47), 8.3(2.40), \
                  8.4(7.3), 8.6(1.13), 9.0(3.8) y 9.1(3.2) acepta una cookie manipulada en el \
                  POST o una URL preparada y salta la autenticación del portal.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-2128",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "Cisco ASA",
        cpe: "cpe:2.3:a:cisco:adaptive_security_appliance_software",
        cve: "CVE-2014-2129",
        cvss: 7.1,
        severity: Severity::High,
        title: "Cisco ASA SIP inspection denial of service",
        summary: "El motor de inspección SIP de ASA 8.2 anterior a 8.2(5.48), 8.4(6.5), 9.0(3.1) \
                  y 9.1(2.5) agota la memoria o reinicia el equipo ante paquetes SIP manipulados, \
                  lo que tumba el cortafuegos entero desde la red.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-2129",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "Cisco Webex",
        cpe: "cpe:2.3:a:cisco:webex_meetings_desktop",
        cve: "CVE-2018-15442",
        cvss: 7.8,
        severity: Severity::High,
        title: "WebExec — Cisco Webex update service command execution",
        summary: "El servicio de actualización de Cisco Webex Meetings Desktop App anterior a \
                  33.6.4 no valida los parámetros de la orden, de modo que quien pueda invocarlo \
                  —también de forma remota a través del canal SMB con credenciales de dominio— \
                  ejecuta código como SYSTEM.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2018-15442",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "ESXi",
        cpe: "cpe:2.3:o:vmware:esxi",
        cve: "CVE-2009-3733",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "VMware directory traversal (ESX/ESXi 3.5, Server 1.x/2.x)",
        summary: "La interfaz web de VMware Server anterior a 1.0.10 y 2.0.2, ESXi 3.5 y ESX \
                  3.0.3/3.5 deja leer ficheros arbitrarios del host, incluidos los de \
                  configuración de las máquinas virtuales y sus credenciales.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2009-3733",
        affected: |v| v >= Version::parse("3.0") && v < Version::parse("4.0"),
    },
    CveEntry {
        match_product: "RealVNC",
        cpe: "cpe:2.3:a:vnc:realvnc",
        cve: "CVE-2006-2369",
        cvss: 7.5,
        severity: Severity::High,
        title: "RealVNC 4.1.1 authentication bypass",
        summary: "RealVNC 4.1.1 —y los productos que lo incorporan, como AdderLink IP o Cisco \
                  CallManager— acepta el tipo de seguridad «1 - None» que elige el cliente aunque \
                  el servidor no lo ofrezca, así que cualquiera entra al escritorio sin \
                  contraseña. El saludo RFB solo publica la versión de protocolo, no la del \
                  producto: confirma la build.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2006-2369",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "Samba",
        cpe: "cpe:2.3:a:samba:samba",
        cve: "CVE-2012-1182",
        cvss: 10.0,
        severity: Severity::Critical,
        title: "Samba PIDL-generated RPC code execution (root)",
        summary: "El generador de código RPC de Samba 3.x anterior a 3.4.16, 3.5.14 y 3.6.4 \
                  valida la longitud del array de forma distinta a como reserva la memoria, lo que \
                  da ejecución de código como root sin autenticar mediante una llamada RPC \
                  manipulada.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2012-1182",
        affected: |v| {
            !v.is_zero()
                && ((v >= Version::parse("3.0") && v < Version::parse("3.4.16"))
                    || (v >= Version::parse("3.5") && v < Version::parse("3.5.14"))
                    || (v >= Version::parse("3.6") && v < Version::parse("3.6.4")))
        },
    },
    CveEntry {
        match_product: "PHP",
        cpe: "cpe:2.3:a:php:php",
        cve: "CVE-2012-1823",
        cvss: 9.8,
        severity: Severity::Critical,
        title: "PHP-CGI query-string argument injection (RCE)",
        summary: "php-cgi anterior a 5.3.12 y 5.4.2 trata una cadena de consulta sin '=' como \
                  opciones de línea de órdenes, así que ?-s muestra el código fuente y ?-d \
                  permite ejecutar código. Sigue siendo una de las vías de entrada más buscadas \
                  en instalaciones antiguas en modo CGI.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2012-1823",
        affected: |v| {
            !v.is_zero()
                && ((v >= Version::parse("5.0") && v < Version::parse("5.3.12"))
                    || (v >= Version::parse("5.4.0") && v < Version::parse("5.4.2")))
        },
    },
    CveEntry {
        match_product: "distcc",
        cpe: "cpe:2.3:a:distcc:distcc",
        cve: "CVE-2004-2687",
        cvss: 9.3,
        severity: Severity::Critical,
        title: "distccd unauthenticated command execution",
        summary: "distcc 2.x sin restricción de acceso ejecuta los trabajos de compilación que le \
                  llegan sin comprobar quién los envía, lo que es ejecución remota de código por \
                  diseño. No hay versión que lo arregle: hay que limitar el puerto con --allow o \
                  con el cortafuegos.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2004-2687",
        affected: |_v| true,
    },
    CveEntry {
        match_product: "Avahi",
        cpe: "cpe:2.3:a:avahi:avahi",
        cve: "CVE-2011-1002",
        cvss: 5.0,
        severity: Severity::Medium,
        title: "Avahi mDNS empty-packet infinite loop",
        summary: "avahi-core/socket.c en avahi-daemon anterior a 0.6.29 entra en un bucle infinito \
                  al recibir un paquete mDNS vacío en el puerto 5353, y basta uno para dejar el \
                  descubrimiento de servicios fuera de juego en toda la red local.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-1002",
        affected: |v| v >= Version::parse("0.1") && v < Version::parse("0.6.29"),
    },
    CveEntry {
        match_product: "AFP file sharing",
        cpe: "cpe:2.3:o:apple:mac_os_x",
        cve: "CVE-2010-0533",
        cvss: 7.5,
        severity: Severity::High,
        title: "Mac OS X AFP server directory traversal",
        summary: "El servidor AFP de Mac OS X anterior a 10.6.3 permite listar el directorio \
                  padre de la raíz del recurso compartido y leer y modificar sus ficheros, es \
                  decir, salir del recurso que el administrador quiso publicar.",
        reference: "https://nvd.nist.gov/vuln/detail/CVE-2010-0533",
        affected: |_v| true,
    },
];

/// Best-effort version for `product` in this service: the structured
/// `svc.version` when it names the matched product, otherwise the token right
/// after `product/…` in the banner (how `Portable SDK for UPnP devices/1.14.12`
/// carries its version inside a `Server:` header).
fn version_for(svc: &ServiceInfo, match_product: &str) -> String {
    // The structured version belongs to whatever `product`/`Server:` head the
    // parser latched onto. Trust it only when that product *is* the match —
    // otherwise a device's "Linux/4.1" version would be read as libupnp's.
    if !svc.version.is_empty()
        && svc
            .product
            .to_ascii_lowercase()
            .contains(&match_product.to_ascii_lowercase())
    {
        return svc.version.clone();
    }
    // Fall back to "<match_product>/<version>" anywhere in the banner or extra.
    let needle = format!("{}/", match_product.to_ascii_lowercase());
    for hay in [&svc.banner, &svc.extra] {
        let low = hay.to_ascii_lowercase();
        if let Some(pos) = low.find(&needle) {
            let after = &hay[pos + needle.len()..];
            let ver: String = after
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !ver.is_empty() {
                return ver;
            }
        }
    }
    String::new()
}

/// Correlate a detected service against the embedded CVE table. Empty when
/// nothing matches — a patched or unversioned host is not flagged.
pub fn correlate(svc: &ServiceInfo) -> Vec<Finding> {
    // `tls_version` joins the haystack because the negotiated protocol is a fact
    // about the service that nothing else records — it is how POODLE can key on
    // "SSL 3.0" itself instead of on a version number that means something else
    // in every other row of the table.
    let hay = format!(
        "{} {} {} {}",
        svc.product, svc.banner, svc.extra, svc.tls_version
    )
    .to_ascii_lowercase();
    let mut out = Vec::new();
    for e in CVE_DB {
        if !hay.contains(&e.match_product.to_ascii_lowercase()) {
            continue;
        }
        let ver = version_for(svc, e.match_product);
        let parsed = Version::parse(&ver);
        if !(e.affected)(parsed) {
            continue;
        }
        out.push(Finding {
            id: e.cve.to_string(),
            severity: e.severity,
            title: e.title.to_string(),
            detail: format!(
                "{} Detected {} {}. CVSS {:.1}. {} — {}",
                e.summary, e.match_product, ver, e.cvss, e.cpe, e.reference
            ),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upnp(version_in_banner: &str) -> ServiceInfo {
        ServiceInfo {
            name: "upnp".into(),
            banner: format!(
                "Server: Linux/4.1.52 UPnP/1.0 Portable SDK for UPnP devices/{version_in_banner}"
            ),
            extra: format!("UPnP/1.0 Portable SDK for UPnP devices/{version_in_banner}"),
            ..Default::default()
        }
    }
    fn openssh(v: &str) -> ServiceInfo {
        ServiceInfo { product: "OpenSSH".into(), version: v.into(), ..Default::default() }
    }
    fn ids(f: &[Finding]) -> Vec<String> {
        f.iter().map(|x| x.id.clone()).collect()
    }

    #[test]
    fn version_orders_numerically_not_lexically() {
        assert!(Version::parse("1.6.9") < Version::parse("1.6.18"));
        assert!(Version::parse("1.14.12") > Version::parse("1.6.18"));
        assert!(Version::parse("9.10") > Version::parse("9.8"));
    }

    #[test]
    fn version_ignores_non_numeric_tails() {
        assert_eq!(Version::parse("8.2p1"), Version::parse("8.2"));
        assert_eq!(Version::parse("5.3.0 build 201719"), Version::parse("5.3.0"));
        assert_eq!(Version::parse("1.6.18-ubuntu3"), Version::parse("1.6.18"));
    }

    #[test]
    fn unknown_version_never_matches_a_range() {
        assert!(Version::parse("").is_zero());
        assert!(!(CVE_DB[0].affected)(Version::parse("")));
    }

    /// An old libupnp (audit-style banner) trips the SSDP overflow cluster.
    #[test]
    fn libupnp_before_1_6_18_is_flagged() {
        let f = correlate(&upnp("1.6.17"));
        assert!(ids(&f).contains(&"CVE-2012-5958".to_string()));
    }

    /// The audit's own device is on 1.14.12 — past both the overflow fix and
    /// the CallStranger mitigation — so it must come back clean, not falsely
    /// flagged just for being libupnp.
    #[test]
    fn libupnp_1_14_12_is_clean() {
        assert!(correlate(&upnp("1.14.12")).is_empty());
    }

    #[test]
    fn libupnp_in_the_callstranger_band_is_flagged() {
        let f = correlate(&upnp("1.8.0"));
        // Below 1.6.18? No. Below 1.14.0? Yes → CallStranger only.
        assert_eq!(ids(&f), vec!["CVE-2020-12695".to_string()]);
    }

    #[test]
    fn openssh_regresshion_range() {
        assert!(ids(&correlate(&openssh("9.6"))).contains(&"CVE-2024-6387".to_string()));
        assert!(ids(&correlate(&openssh("3.9"))).contains(&"CVE-2024-6387".to_string()));
        // 8.2p1 (the common Ubuntu 20.04 build) is outside every affected band.
        assert!(correlate(&openssh("8.2p1")).is_empty());
        // 9.8p1 is the fix.
        assert!(correlate(&openssh("9.8p1")).is_empty());
    }

    /// An id is what a user greps for after a scan, so it must name exactly one
    /// row of this table.
    #[test]
    fn cve_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in CVE_DB {
            assert!(seen.insert(e.cve), "{} appears twice in CVE_DB", e.cve);
        }
    }

    /// Every entry must be traceable: a CPE to pivot on and a reference that
    /// points at the CVE it claims to be.
    #[test]
    fn entries_carry_their_provenance() {
        for e in CVE_DB {
            assert!(e.cpe.starts_with("cpe:2.3:"), "{} has no CPE 2.3 id", e.cve);
            assert!(e.reference.contains(e.cve), "{}'s reference points elsewhere", e.cve);
        }
    }

    /// Severity must follow the score, or `--min-severity` would sort the
    /// database by nothing in particular.
    #[test]
    fn severity_matches_the_cvss_score() {
        for e in CVE_DB {
            let expected = match e.cvss {
                s if s >= 9.0 => Severity::Critical,
                s if s >= 7.0 => Severity::High,
                s if s >= 4.0 => Severity::Medium,
                _ => Severity::Low,
            };
            assert_eq!(
                e.severity.label(),
                expected.label(),
                "{} scores {:.1} but is filed as {}",
                e.cve,
                e.cvss,
                e.severity.label()
            );
        }
    }

    fn http(product: &str, version: &str, extra: &str) -> ServiceInfo {
        ServiceInfo {
            name: "http".into(),
            product: product.into(),
            version: version.into(),
            banner: format!("Server: {product}/{version} {extra}"),
            extra: extra.into(),
            ..Default::default()
        }
    }
    fn smb(dialect: &str) -> ServiceInfo {
        ServiceInfo {
            name: "microsoft-ds".into(),
            product: "SMB".into(),
            version: dialect.into(),
            ..Default::default()
        }
    }

    /// A version range clears a patched host: 2.2.14 is inside Slowloris,
    /// 2.4.62 is outside every Apache entry in the table.
    #[test]
    fn apache_ranges_clear_a_current_build() {
        let old = ids(&correlate(&http("Apache", "2.2.14", "(Debian)")));
        assert!(old.contains(&"CVE-2007-6750".to_string()));
        assert!(old.contains(&"CVE-2011-3192".to_string()));
        assert!(correlate(&http("Apache", "2.4.62", "(Debian)")).is_empty());
    }

    /// OpenSSL's version rides in the module list of an httpd's `Server:`
    /// header, which is a banner match rather than a product match.
    #[test]
    fn openssl_version_is_read_from_the_server_header() {
        let old = ids(&correlate(&http("Apache", "2.4.7", "Ubuntu) OpenSSL/1.0.1f")));
        assert!(old.contains(&"CVE-2014-0160".to_string()));
        assert!(old.contains(&"CVE-2014-0224".to_string()));
        // A current OpenSSL is outside every band, even though the httpd in
        // front of it is not.
        let new = ids(&correlate(&http("Apache", "2.4.62", "Debian) OpenSSL/3.0.15")));
        assert!(!new.iter().any(|id| id.starts_with("CVE-2014-0")));
    }

    /// The SMB "version" is a negotiated dialect, so the Windows bulletins are
    /// gated on the generation that spoke it. A host on SMB 3.1.1 is current.
    #[test]
    fn smb_dialect_gates_the_windows_bulletins() {
        let legacy = ids(&correlate(&smb("1.0")));
        assert!(legacy.contains(&"CVE-2017-0143".to_string()));
        assert!(legacy.contains(&"CVE-2008-4250".to_string()));
        // MS09-050 is an SMBv2 bug: it must not fire on an SMB1-only host.
        assert!(!legacy.contains(&"CVE-2009-3103".to_string()));
        assert!(ids(&correlate(&smb("2.0.2"))).contains(&"CVE-2009-3103".to_string()));
        assert!(correlate(&smb("3.1.1")).is_empty());
    }

    /// SSL 3.0 arrives as the version string "3.0", which is numerically above
    /// TLS 1.2 — POODLE's predicate has to read that way round.
    #[test]
    fn poodle_fires_only_on_ssl_3() {
        let ssl3 = ServiceInfo {
            product: "TLS".into(),
            version: "3.0".into(),
            tls_version: "SSL 3.0".into(),
            ..Default::default()
        };
        assert!(ids(&correlate(&ssl3)).contains(&"CVE-2014-3566".to_string()));
        let tls12 = ServiceInfo {
            product: "TLS".into(),
            version: "1.2".into(),
            tls_version: "TLS 1.2".into(),
            ..Default::default()
        };
        assert!(correlate(&tls12).is_empty());
    }

    /// MS12-020 is keyed on the RDP negotiation result, because the server
    /// never publishes a build. A gateway that requires NLA is not the
    /// population the bulletin describes.
    #[test]
    fn ms12_020_needs_the_pre_nla_negotiation() {
        let old = ServiceInfo {
            product: "Microsoft Terminal Services".into(),
            extra: "standard RDP security (no NLA)".into(),
            ..Default::default()
        };
        let f = ids(&correlate(&old));
        assert!(f.contains(&"CVE-2012-0002".to_string()));
        assert!(f.contains(&"CVE-2012-0152".to_string()));

        let nla = ServiceInfo {
            product: "Microsoft Terminal Services".into(),
            extra: "CredSSP / NLA required".into(),
            ..Default::default()
        };
        assert!(correlate(&nla).is_empty());
    }

    /// A fleet of ordinary, current services, each of which trips a keyword in
    /// the table without being the product the entry is about. Tomcat's
    /// connector calls itself "Apache-Coyote/1.1" and an httpd lists "GnuTLS"
    /// in the same header as its own version — both of which walked straight
    /// into a range predicate that had an upper bound and no lower one. Every
    /// row here must come back clean.
    #[test]
    fn ordinary_modern_services_are_not_flagged() {
        let hosts: &[(&str, &str, &str)] = &[
            // Tomcat's AJP/HTTP connector: "Apache", version 1.1.
            ("Apache-Coyote", "1.1", ""),
            ("Apache Tomcat", "9.0.85", ""),
            // A current httpd that names three other products in its header.
            ("Apache", "2.4.62", "Debian) OpenSSL/3.0.15 PHP/8.2.7 GnuTLS/3.7.9"),
            ("nginx", "1.24.0", ""),
            // phpMyAdmin contains "php"; the page is served by a current stack.
            ("phpMyAdmin", "", "title \"phpMyAdmin\""),
            ("PHP", "8.2.7", ""),
            // Samba contains no "smb", but its banner does.
            ("Samba", "4.19.5", "Samba smbd 4.19.5-Debian"),
            ("SMB", "3.1.1", "signing required"),
            ("BIND", "9.18.28", ""),
            ("Exim", "4.98", "no STARTTLS"),
            ("Postfix", "3.8.6", "STARTTLS"),
            ("ProFTPD", "1.3.8", ""),
            ("Drupal", "10.2.5", ""),
            ("Microsoft Terminal Services", "", "CredSSP / NLA required"),
        ];
        for (product, version, extra) in hosts {
            let svc = ServiceInfo {
                product: (*product).into(),
                version: (*version).into(),
                extra: (*extra).into(),
                banner: format!("Server: {product}/{version} {extra}"),
                tls_version: "TLS 1.3".into(),
                ..Default::default()
            };
            let found = ids(&correlate(&svc));
            assert!(
                found.is_empty(),
                "{product}/{version} is current but was flagged: {found:?}"
            );
        }
    }

    /// A product named in the table but running a fixed build comes back clean,
    /// which is the whole contract of this module.
    #[test]
    fn patched_products_come_back_clean() {
        let bind = |v: &str| ServiceInfo {
            product: "BIND".into(),
            version: v.into(),
            ..Default::default()
        };
        assert!(ids(&correlate(&bind("9.10.0"))).contains(&"CVE-2014-3214".to_string()));
        assert!(correlate(&bind("9.18.28")).is_empty());
    }

    /// The structured version must belong to the matched product, or a
    /// device's OS version could be read as the library's.
    #[test]
    fn version_is_not_borrowed_from_a_different_product() {
        let mut s = upnp("1.6.17");
        s.product = "Linux".into();
        s.version = "4.1.52".into(); // the device OS, not libupnp
        // Still flagged, because the banner carries the real libupnp version.
        assert!(ids(&correlate(&s)).contains(&"CVE-2012-5958".to_string()));
    }
}
