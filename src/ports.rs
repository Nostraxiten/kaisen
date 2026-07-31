//! Port datasets embedded in the binary so Kaisen stays a single, path-independent
//! executable. `TOP_PORTS` is ordered roughly by real-world popularity so that
//! `--top-ports N` and `-PF` (port famous) slice the most relevant ports first.

/// The most relevant TCP ports, ordered by popularity. `-PF` / `--port-famous`
/// uses the first 1000 of these (or all available if fewer). Extend freely.
pub const TOP_PORTS: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723,
    111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000,
    514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515,
    8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800,
    106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544, 5101, 144,
    7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13,
    1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000,
    3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031,
    1041, 255, 2967, 1049, 1048, 1053, 1054, 1056, 1064, 1065, 1521, 8010, 3260, 5555,
    5901, 993, 6666, 7000, 9200, 11211, 27017, 27018, 28017, 5984, 6379, 9042, 7474,
    50000, 5985, 5986, 47001, 623, 636, 989, 992, 1194, 1080, 3690, 4444, 5040, 8291,
    8834, 9000, 9001, 9002, 9091, 9200, 9300, 161, 162, 500, 1701, 4500, 5353, 137,
    138, 67, 68, 69, 123, 520, 1812, 1813, 2427, 2727, 5004, 5005, 8000, 8443, 8888,
    9418, 11211, 27015, 25565, 6660, 6667, 6697, 194, 6697, 7777, 8006, 10250, 2379,
    2380, 4001, 8500, 8600, 15672, 5672, 61616, 8161, 1883, 8883, 8086, 3307, 33060,
    5433, 1521, 1526, 49158, 49159, 49160, 3050, 8005, 8009, 8093, 9080, 9443, 7001,
    7002, 8880, 4848, 8686, 9010, 3299, 50070, 50075, 8020, 8042, 16010, 60010, 2181,
];

/// Return a friendly service name for a well-known TCP port, mirroring nmap's
/// nmap-services. Falls back to "unknown".
pub fn service_name(port: u16) -> &'static str {
    match port {
        7 => "echo",
        9 => "discard",
        13 => "daytime",
        19 => "chargen",
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        26 => "rsftp",
        37 => "time",
        43 => "whois",
        49 => "tacacs",
        53 => "domain",
        67 => "dhcps",
        68 => "dhcpc",
        69 => "tftp",
        70 => "gopher",
        79 => "finger",
        80 => "http",
        81 => "hosts2-ns",
        82 => "xfer",
        88 => "kerberos-sec",
        106 => "pop3pw",
        110 => "pop3",
        111 => "rpcbind",
        113 => "ident",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        144 => "news",
        161 => "snmp",
        162 => "snmptrap",
        179 => "bgp",
        194 => "irc",
        199 => "smux",
        389 => "ldap",
        427 => "svrloc",
        443 => "https",
        444 => "snpp",
        445 => "microsoft-ds",
        465 => "smtps",
        500 => "isakmp",
        513 => "login",
        514 => "syslog",
        515 => "printer",
        520 => "route",
        543 => "klogin",
        544 => "kshell",
        548 => "afp",
        554 => "rtsp",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        646 => "ldp",
        873 => "rsync",
        888 => "accessbuilder",
        902 => "vmware-auth",
        989 => "ftps-data",
        990 => "ftps",
        992 => "telnets",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1099 => "rmiregistry",
        1194 => "openvpn",
        1433 => "ms-sql-s",
        1521 => "oracle",
        1701 => "l2tp",
        1720 => "h323q931",
        1723 => "pptp",
        1755 => "wms",
        1812 => "radius",
        1813 => "radacct",
        1883 => "mqtt",
        1900 => "upnp",
        2049 => "nfs",
        2082 => "cpanel",
        2083 => "cpanel-ssl",
        2181 => "zookeeper",
        2222 => "ssh-alt",
        2375 => "docker",
        2376 => "docker-ssl",
        2379 => "etcd-client",
        2380 => "etcd-peer",
        2483 => "oracle-db",
        2484 => "oracle-db-ssl",
        3000 => "ppp",
        3050 => "firebird",
        3128 => "squid-http",
        3260 => "iscsi",
        3268 => "globalcat-ldap",
        3269 => "globalcat-ldaps",
        3306 => "mysql",
        3307 => "mysql-alt",
        3389 => "ms-wbt-server",
        3690 => "svn",
        4369 => "epmd",
        4444 => "metasploit",
        4500 => "ipsec-nat-t",
        4848 => "glassfish",
        5000 => "upnp",
        5001 => "commplex-link",
        5004 => "rtp",
        5005 => "rtp-alt",
        5060 => "sip",
        5061 => "sip-tls",
        5222 => "xmpp-client",
        5269 => "xmpp-server",
        5353 => "mdns",
        5432 => "postgresql",
        5433 => "postgresql-alt",
        5555 => "freeciv",
        5601 => "kibana",
        5666 => "nrpe",
        5672 => "amqp",
        5800 => "vnc-http",
        5900 => "vnc",
        5901 => "vnc-1",
        5984 => "couchdb",
        5985 => "wsman",
        5986 => "wsmans",
        6000 => "x11",
        6001 => "x11-1",
        6379 => "redis",
        6443 => "kube-apiserver",
        6660..=6669 => "irc",
        6697 => "ircs",
        7000 => "cassandra-thrift",
        7001 => "weblogic",
        7002 => "weblogic-ssl",
        7070 => "realserver",
        7071 => "iwg1",
        7199 => "cassandra-jmx",
        7443 => "oracle-http-ssl",
        7474 => "neo4j",
        7687 => "bolt",
        8000 => "http-alt",
        8005 => "tomcat-shutdown",
        8006 => "proxmox",
        8008 => "http",
        8009 => "ajp13",
        8020 => "hadoop-namenode",
        8042 => "hadoop-node",
        8080 => "http-proxy",
        8081 => "http-alt",
        8086 => "influxdb",
        8088 => "hadoop-yarn",
        8091 => "couchbase",
        8093 => "couchbase-query",
        8161 => "activemq",
        8443 => "https-alt",
        8500 => "consul",
        8600 => "consul-dns",
        8686 => "jmx",
        8834 => "nessus",
        8880 => "cddbp-alt",
        8883 => "mqtt-ssl",
        8888 => "http-alt",
        9000 => "cslistener",
        9001 => "tor-orport",
        9042 => "cassandra-cql",
        9080 => "glrpc",
        9090 => "websm",
        9091 => "xmltec-xmlmail",
        9092 => "kafka",
        9100 => "jetdirect",
        9200 => "elasticsearch",
        9300 => "elasticsearch-node",
        9418 => "git",
        9443 => "https-alt",
        9999 => "abyss",
        10000 => "snet-sensor-mgmt",
        10250 => "kubelet",
        11211 => "memcached",
        15672 => "rabbitmq-mgmt",
        16010 => "hbase-master",
        25565 => "minecraft",
        27015 => "steam",
        27017 => "mongodb",
        27018 => "mongodb-shard",
        28017 => "mongodb-web",
        50000 => "db2",
        50070 => "hadoop-namenode-web",
        61616 => "activemq-openwire",
        _ => "unknown",
    }
}

/// Parse a port specification like "80,443,1-1024,8080" into a sorted, de-duplicated list.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut set = std::collections::BTreeSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start: u32 = a.trim().parse().map_err(|_| format!("invalid port '{a}'"))?;
            let end: u32 = b.trim().parse().map_err(|_| format!("invalid port '{b}'"))?;
            if start > end || end > 65535 {
                return Err(format!("invalid port range '{part}'"));
            }
            for p in start..=end {
                set.insert(p as u16);
            }
        } else {
            let p: u32 = part.parse().map_err(|_| format!("invalid port '{part}'"))?;
            if p == 0 || p > 65535 {
                return Err(format!("port out of range '{part}'"));
            }
            set.insert(p as u16);
        }
    }
    if set.is_empty() {
        return Err("no ports specified".into());
    }
    Ok(set.into_iter().collect())
}

/// The famous top-N ports, de-duplicated preserving popularity order.
pub fn top_ports(n: usize) -> Vec<u16> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(n);
    for &p in TOP_PORTS {
        if out.len() >= n {
            break;
        }
        if seen.insert(p) {
            out.push(p);
        }
    }
    out
}

/// Every TCP port, 1..=65535.
pub fn all_ports() -> Vec<u16> {
    (1u16..=65535).collect()
}

/// A small, high-signal set of ports whose banners tend to reveal the OS.
/// Used by the focused `-OS` mode so it can infer the OS quickly without a
/// full scan (SSH/HTTP/FTP/SMTP expose distro strings; SMB/RDP imply Windows).
pub const OS_PROBE_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
    1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
];

pub fn os_probe_ports() -> Vec<u16> {
    OS_PROBE_PORTS.to_vec()
}
