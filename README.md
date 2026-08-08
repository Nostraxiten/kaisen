# Kaisen

Kaisen is a single self-contained binary you install once and run from anywhere
(`kaisen`, `kai`, or `kaison`). It combines high-speed **port scanning**,
**service/version detection**, **best-effort OS inference**, a lightweight
**vulnerability signature matcher**, and a full **DNS resolver** (a `dig`
replacement) — all built on an async engine that scans thousands of ports
concurrently.

> **No root needed.** The core engine uses unprivileged TCP `connect()` scans, so
> Kaisen runs the same on an **unrooted Termux** phone, on **Kali**, on any Linux,
> or on macOS. Features that normally require raw sockets (`-sS` SYN scan, ICMP
> ping, TCP/IP OS fingerprinting) degrade gracefully with a clear notice.

<img width="500" height="474" alt="image" src="https://github.com/user-attachments/assets/0908f363-7457-4ad0-914f-8dd10b3eba19" />

---

## Why Kaisen

-  **Faster than a stock connect scan** — Rust + `tokio` async I/O pushes
  thousands of simultaneous connections. A full 65,535-port sweep of a local host
  completes in a couple of seconds.
-  **Two tools in one** — port/service scanning *and* DNS resolution with the same
  familiar flags.
-  **Single static binary, zero heavy deps** — the DNS engine, the TLS prober and
  every protocol probe are implemented from scratch; port datasets (800+ named
  ports) and the vuln DB are embedded, so the binary works from any path with
  nothing else installed.
-  **Runs anywhere, no root** — Termux (unrooted), Kali, Debian/Ubuntu, Arch,
  Fedora, Alpine, macOS.

---

## Install

### One-liner

```sh
curl -fsSL https://raw.githubusercontent.com/nostraxiten/kaisen/main/install.sh | sh
```

The installer detects your system, installs a Rust toolchain if needed, builds the
release binary, and drops `kaisen` / `kai` / `kaison` into a directory on your
`PATH` (preferring a user-writable one — **no sudo required** on Termux or when
`~/.local/bin` is available).

### Termux (unrooted)

```sh
pkg install -y git rust
git clone https://github.com/nostraxiten/kaisen
cd kaisen && ./install.sh
```

### From source (any OS)

```sh
git clone https://github.com/nostraxiten/kaisen
cd kaisen
cargo build --release
# binary at target/release/kaisen
```

---

## Quick start

```sh
# The headline example — OS guess, versions, all ports, aggressive timing, vuln check
kaison -OS -sV -Pn -T4 -vvv -PA -vuln 192.168.1.2

# Famous top-1000 ports with version detection
kaisen -PF -sV 10.0.0.5

# Hyper speed, full range, only show what's open
kaisen -HS -PA --open scanme.example.com

# DNS like dig
kaisen dns MX example.com @8.8.8.8
kaisen -D ANY example.com +short
kaisen -x 1.1.1.1            # reverse lookup
```

---

## Flags

### Scan type
| Flag | Alias | Meaning |
|------|-------|---------|
| `-sT` | `--connect` | TCP connect() scan — **default, no root** |
| `-sS` | `--syn` | SYN half-open scan (needs root; auto-falls back to `-sT`) |

### Port selection
| Flag | Alias | Meaning |
|------|-------|---------|
| `-PF` | `--port-famous` | Top **1000 famous** ports (default) |
| `-PA` | `--ports-all`, `-p-` | **All** ports (1-65535) |
| `-F` | `--fast` | Top 100 ports |
| `-p <SPEC>` | `--ports` | Explicit, e.g. `-p 22,80,443,8000-8100` |
| `--top-ports <N>` | | Top N famous ports |

### Detection
| Flag | Alias | Meaning |
|------|-------|---------|
| `-sV` | `--service-version` | Probe open ports for service & version |
| `-OS` | `--os-detection`, `-O` | Detect OS. **Alone** = focused OS report (no port table); with a scan = adds an OS line. Heuristic, no root |
| `-vuln` | `--vuln` | Match services against known-vuln signatures |
| `-A` | `--aggressive` | Enable `-sV`, `-OS` and `-vuln` together |

### Host discovery
| Flag | Meaning |
|------|---------|
| `-Pn` / `--no-ping` | Skip discovery, treat hosts as up (default: unprivileged ICMP ping; a host also counts as up if any port responds) |

### Timing & performance
| Flag | Meaning |
|------|---------|
| `-T0` … `-T5` | Timing template: 0=paranoid … 3=normal … 5=insane |
| `-HS` / `--hyper-speed` | Hyper speed: max concurrency, minimal timeouts |
| `--concurrency <N>` | Max simultaneous connections |
| `--timeout <MS>` | Per-connection timeout (ms) |
| `--retries <N>` | Retries for filtered/timed-out ports |

### Output & display
| Flag | Meaning |
|------|---------|
| `--open` | Only show open ports |
| `--reason` | Show why a port is in its state |
| `-v`, `-vv`, `-vvv` | Increase verbosity |
| `-oN` / `-oJ` / `-oG` | Output: Normal / JSON / Grepable |
| `--color` / `--no-color` | Toggle colour (honours `NO_COLOR`) |
| `-4` / `-6` | Force IPv4 / IPv6 |

### DNS (dig replacement)
| Flag | Meaning |
|------|---------|
| `dns` / `dig` / `resolve` | DNS subcommand |
| `-D <TYPE>` / `--dns` | Record type: `A AAAA NS CNAME SOA PTR MX TXT SRV CAA ANY` |
| `-x` / `--reverse` | Reverse (PTR) lookup for an IP |
| `@server` | Query a specific DNS server (e.g. `@1.1.1.1`) |
| `--dns-port <N>` | DNS server port (default 53) |
| `+short` / `--short` | Terse output (answers only) |
| `+tcp` / `--dns-tcp` | Force DNS over TCP |
| `+ttl` / `--ttl` | Show TTL values |

### Mail (email posture audit)
| Flag | Meaning |
|------|---------|
| `mail` / `email` / `mx` | Audit a domain's mail records in one shot |
| `-M` / `--mail` | Same as the `mail` subcommand |

### Lookup & WHOIS
| Command | Meaning |
|---------|---------|
| `kaisen lookup <domain>` | Full DNS profile — A, AAAA, CNAME, NS, MX, TXT, SOA, CAA in one shot |
| `kaisen whois <domain\|ip>` | From-scratch WHOIS (TCP/43) with IANA→registry→registrar referrals; `-v` for the raw record |

`whois` is implemented directly over the WHOIS protocol (no external service or
library): it asks IANA which registry owns the TLD, follows the registrar
referral for domains, and follows the RIR referral (ARIN→RIPE/APNIC/…) for IPs,
with a built-in TLD-server fallback. It prints a summary (registrar, dates,
name servers, status / net-range, org, abuse contact) plus the raw record.

### Neighbor recon (fierce-style)
| Command | Meaning |
|---------|---------|
| `kaisen neighbor <domain>` | Subdomain brute-force + neighbourhood reverse DNS |
| `neig` / `fierce` / `-N` | Aliases for the same |

`kaisen neighbor <domain>` resolves the apex, detects wildcard DNS, brute-forces
a built-in list of ~190 common subdomains, then walks the reverse DNS of the
/24s around the discovered IPs to surface "neighbour" hosts. Purely passive DNS.

### Mail (email posture audit)
| Flag | Meaning |
|------|---------|
| `mail` / `email` / `mx` | Audit a domain's mail records in one shot |
| `-M` / `--mail` | Same as the `mail` subcommand |

`kaisen mail <domain>` checks **MX, SPF, DMARC, DKIM** (probing common selectors),
**MTA-STS, TLS-RPT** and **CAA**, interprets each, and prints a checklist plus a
pass/warn/problem verdict. Example:

```
$ kaisen mail github.com
[OK] MX        0 github-com.mail.protection.outlook.com
[OK] DMARC     v=DMARC1; p=quarantine; sp=reject; ...   (good)
[OK] DKIM      selector(s) found: google, selector1, k1, k2
[OK] CAA       issue digicert.com, issue letsencrypt.org, ...
Summary: 4 passed, 2 warning(s), 0 problem(s)
```

Run `kaisen --help` for the full, always-current reference.

---

## Service & version detection (`-sV`)

`-sV` does not just grab a banner. Kaisen runs a **per-port probe plan** in three
tiers, cheapest first:

1. **Listen** — protocols that greet you first (SSH, SMTP, FTP, IMAP/POP3, NNTP,
   VNC, rsync, MySQL, IRC, Telnet, svnserve…).
2. **Probe** — say the one thing that makes a silent service identify itself.
3. **Fallback** — for a port with no plan and no greeting, try HTTP, then TLS,
   because unusual ports are exactly where unexpected web and TLS services live.

### Protocols Kaisen speaks to get a version

| Protocol | What it sends | What you get back |
|----------|---------------|-------------------|
| **TLS/SSL** | a hand-rolled ClientHello (TLS 1.2, retried as 1.3) | negotiated version, cipher, ALPN, certificate CN, issuer, SAN hostnames, expiry |
| **SMB2** | NEGOTIATE | dialect → Windows generation, signing policy |
| **MS SQL Server** | TDS PRELOGIN | exact build → `15.0.2000` = SQL Server 2019 |
| **MongoDB** | OP_QUERY `isMaster`, then `buildInfo` | release from `maxWireVersion`, exact version if unauthenticated |
| **Oracle** | TNS connect | `VSNNUM` decoded to `11.2.0.4.0` |
| **PostgreSQL** | SSLRequest + startup | TLS support and the auth method demanded |
| **RDP** | X.224 negotiation (+ TLS) | security layer (NLA or not), machine hostname from the certificate |
| **AMQP** | protocol header | `connection.start` server properties: RabbitMQ + exact version |
| **Kafka** | ApiVersions | API map → approximate broker release |
| **Cassandra** | CQL OPTIONS | supported CQL version |
| **LDAP** | anonymous rootDSE search | AD vs OpenLDAP, DC hostname, naming contexts |
| **DNS** | `version.bind` CHAOS TXT over TCP | BIND / PowerDNS / Unbound / dnsmasq + version |
| **MQTT** | CONNECT | broker version and whether anonymous connects are accepted |
| **X11** | connection setup | protocol version, vendor, and whether access control is off |
| **epmd** | NAMES | every registered Erlang node and its distribution port |
| **Minecraft** | Server List Ping | server version, protocol, player count |
| **AJP13** | CPing | connector reachable (the Ghostcat precondition) |
| **SOCKS** | greeting | version and whether it is an open proxy |
| **Redis / memcached / ZooKeeper** | `INFO` / `version` / `srvr` | version plus whether auth is enforced |
| **HTTP** | `GET /` with a real `Host` | `Server`, `X-Powered-By`, `X-Jenkins` and friends, `<title>`, JSON version APIs |

HTTP detection also fingerprints **~180 applications and appliances** from
headers, cookies, body markers and certificate names — WordPress, Jenkins,
GitLab, Grafana, Kibana, Proxmox, pfSense, Synology, Home Assistant, MikroTik,
printers, cameras and so on — and reads the version out of JSON roots for
Elasticsearch, etcd, Docker, Consul, Vault and Kibana.

Because virtual-hosted servers answer a bare IP with a generic page, Kaisen
sends the name you actually asked for as the HTTP `Host` header and as TLS SNI.

```sh
kaisen -sV example.com
```

```
443/tcp  open  https   TLS 1.3 (CN=example.com; issuer=R11; expires 2026-09-06; ALPN=h2)
```

---

## Vulnerability signatures (`-vuln`)

`-vuln` matches whatever `-sV` found against an embedded database of **69
version signatures** plus **~70 port-level exposure heuristics**. It is a
triage aid, not a scanner: nothing is exploited, and every finding is something
you should go and confirm.

Version signatures cover the usual suspects (OpenSSH including `regreSSHion`
and Terrapin, Apache, nginx, Tomcat/Ghostcat, Exim, Dovecot, Samba, MySQL,
ProFTPD, vsFTPd) and the modern application layer (Jenkins, GitLab, Grafana,
Confluence, Elasticsearch, Kibana, BIND, dnsmasq, Oracle TNS poisoning,
end-of-life SQL Server and MySQL branches, obsolete TLS versions, expired and
self-signed certificates).

Exposure heuristics flag services that are dangerous *because they are
reachable at all* — etcd, kubelet, Docker's API, Helm Tiller, SaltStack,
Erlang EPMD, IPMI/BMC and Intel AMT, X11, r-services — including the industrial
protocols that have no authentication by design (Modbus, DNP3, EtherNet/IP,
BACnet, S7).

Findings that only apply under a condition say so only when that condition
holds: "RDP without Network Level Authentication" fires when NLA is absent,
not on every RDP port, and MongoDB is only called unauthenticated when
`buildInfo` actually answered.

---

## Targets

Kaisen accepts hostnames, IPv4/IPv6 addresses, and IPv4 CIDR ranges (up to `/16`):

```sh
kaisen -PF 192.168.1.0/24
kaisen -sV example.com
kaisen -6 -p 80,443 ::1
```

---

## Output formats

- **Normal** (default) — human-readable, coloured, nmap-style report.
- **JSON** (`-oJ`) — machine-readable array of host objects; pipe into `jq`.
- **Grepable** (`-oG`) — one line per host for quick `grep`/`awk`.

### Saving output

Everything prints to stdout, so redirect or append as usual:

```sh
kaisen -sV 10.0.0.5 > scan.txt        # overwrite
kaisen -OS 10.0.0.5 >> report.txt     # append
kaisen -PF -oJ 10.0.0.5 | jq .        # pipe JSON
```

Colours are turned off automatically when output isn't a terminal, so saved
files contain clean text (no ANSI codes). Progress/banner lines go to stderr,
so they don't pollute redirected results.

---

## What "no root" means for each feature

| Feature | Without root | With root/CAP_NET_RAW |
|---------|--------------|-----------------------|
| Connect scan `-sT` | ✅ full speed | ✅ |
| SYN scan `-sS` | ↩︎ auto-falls back to `-sT` (notice printed) | (raw SYN — roadmap) |
| Service/version `-sV` | ✅ banners + 20 protocol probes + TLS certificates | ✅ |
| DNS / `dig` | ✅ full | ✅ |
| OS detection `-OS` | ✅ multi-signal (TTL + SNMP + banners), see below | (TCP/IP fingerprint — roadmap) |
| ICMP ping discovery | ✅ via the system `ping` binary (unprivileged) | ✅ |

Kaisen is honest about these limits at runtime rather than silently doing less.

### How `-OS` detects the OS without root

A raw TCP/IP fingerprint (nmap's `-O`) needs `CAP_NET_RAW`. Instead Kaisen
combines several **unprivileged** signals and scores them by confidence:

- **ICMP TTL** via the system `ping` (unprivileged on Linux/Kali/Termux/macOS).
  Initial TTL reveals the family — 64 → Linux/Unix/macOS/Android, 128 → Windows,
  255 → network gear/BSD/Solaris — and the hop count.
- **SNMP `sysDescr`** (UDP/161, community `public`): the *exact* OS string when
  the host exposes SNMP.
- **FTP `SYST`**: the FTP server itself announces `UNIX`/`Windows`.
- **Service banners**: SSH/HTTP/SMTP version strings that name the distro
  (e.g. `OpenSSH ... Ubuntu`, `Server: Apache/2.4 (Debian)`), across ~55 distro
  and platform keywords — Ubuntu, Debian, Rocky, AlmaLinux, Amazon Linux,
  Alpine, SUSE, the BSDs, Solaris, AIX, OpenWrt, RouterOS, Synology, VxWorks.
- **Protocol probes**: an SMB dialect implies a Windows generation, a TDS
  pre-login response means Windows, an FTP `SYST` says `UNIX` or `Windows`.
- **Open-port profile** as a weak fallback (e.g. 445/3389 → Windows).

Used alone, `kaisen -OS <target>` prints a focused report (OS, confidence, role,
TTL, and the exact signals) instead of a port table. Certainty is highest when
the host answers ICMP or exposes SNMP/FTP/identifying banners; when it exposes
none of these unprivileged detection can only narrow the family, and Kaisen says
so rather than guessing.


## License

MIT — see [LICENSE](LICENSE).
