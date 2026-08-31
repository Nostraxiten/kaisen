# Cómo contribuir a Kaisen

¡Bienvenido! Este documento explica todo lo que necesitas para empezar a contribuir sin tener que preguntar nada. Si algo no está claro, es un bug de documentación — abre un issue.

## Índice

- [Montar el entorno](#montar-el-entorno)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Añadir una firma CVE nueva](#añadir-una-firma-cve-nueva)
- [Añadir soporte a un nuevo tipo DNS](#añadir-soporte-a-un-nuevo-tipo-dns)
- [Ejecutar los tests](#ejecutar-los-tests)
- [Convenciones de código](#convenciones-de-código)
- [Gestión de versiones](#gestión-de-versiones)
- [Proceso de PR](#proceso-de-pr)

---

## Montar el entorno

Kaisen no tiene dependencias de sistema. Solo necesitas Rust:

```bash
# Instalar Rust (si no lo tienes)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clonar y compilar
git clone https://github.com/nostraxiten/kaisen
cd kaisen
cargo build

# Ejecutar directamente
cargo run -- --help
cargo run -- 127.0.0.1
cargo run -- dns A example.com @1.1.1.1
```

No hay base de datos, ni daemon, ni configuración externa. El binario es autocontenido.

---

## Estructura del proyecto

```
src/
├── main.rs           — Punto de entrada y dispatch por modo
├── cli/mod.rs        — Parser de argumentos (sin lógica de red)
├── scan/             — Orquestación del escaneo TCP/UDP
│   ├── mod.rs        — scan_host, print_report, HostReport
│   ├── osfp.rs       — Detección de sistema operativo
│   ├── udp.rs        — Escaneo UDP
│   ├── neigh.rs      — Reconocimiento de vecinos DNS
│   └── mail.rs       — Auditoría de correo
├── dns/              — Resolución y consultas DNS
│   ├── mod.rs        — query, query_dot, query_doh, trace
│   ├── nsaudit.rs    — Auditoría de servidores de nombres
│   └── whois.rs      — Consultas WHOIS
├── service/          — Detección de servicio por banner y protocolo
│   ├── mod.rs        — Lógica de detección, ServiceInfo
│   ├── probe.rs      — Handshakes binarios (SMB, TDS, Redis, etc.)
│   └── web.rs        — Fingerprinting de aplicaciones web
├── vuln/             — Matching de firmas CVE
│   ├── mod.rs        — Lógica de matching, print_catalogue
│   └── cve.rs        — Solo datos: CVE_DB (rango de versiones)
├── ports/mod.rs      — Conjuntos de puertos embebidos (TOP_PORTS, etc.)
├── tls/              — Handshakes TLS 1.2 y 1.3 sin biblioteca
│   ├── mod.rs        — TLS 1.2
│   └── tls13.rs      — TLS 1.3
└── util/             — Utilidades compartidas
    ├── output.rs     — Painter (colores ANSI), json_escape
    └── netutil.rs    — reset_on_close (SO_LINGER=0)
```

**Regla de oro:** si solo tocas un módulo, tu PR no puede romper los demás.

---

## Añadir una firma CVE nueva

Este es el caso más frecuente. Solo hay que editar un fichero: [`src/vuln/mod.rs`](src/vuln/mod.rs).

Busca el array `SIGNATURES` (está hacia el inicio del fichero, después de los structs) y añade una entrada:

```rust
Sig {
    product: "Apache HTTP Server",   // substring del producto detectado (case-insensitive)
    require: "",                     // condición extra (vacío = siempre aplica)
    check: VersionCheck::Range("2.4.0", "2.4.49"),
    id: "CVE-2021-41773",
    severity: Severity::Critical,
    title: "Path traversal y RCE en mod_cgi",
    detail: "Apache 2.4.49 permite traversal de directorio y ejecución remota si mod_cgi está activo.",
},
```

### Campos

| Campo | Tipo | Descripción |
|---|---|---|
| `product` | `&str` | Substring del `ServiceInfo.product` detectado (insensible a mayúsculas) |
| `require` | `&str` | Texto adicional que debe aparecer en el banner. Vacío = sin requisito extra |
| `check` | `VersionCheck` | `Exact("1.2.3")`, `Range("1.0", "1.9")`, o `Any` |
| `id` | `&str` | CVE-YYYY-NNNNN u otro identificador |
| `severity` | `Severity` | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `title` | `&str` | Resumen corto (máx ~80 chars) |
| `detail` | `&str` | Explicación con contexto suficiente para que el usuario decida qué hacer |

Para las CVEs de rango de versiones, el array `CVE_DB` en [`src/vuln/cve.rs`](src/vuln/cve.rs) funciona igual pero con un campo `max_excl` de versión exclusiva. Consulta los ejemplos existentes.

---

## Añadir soporte a un nuevo tipo DNS

1. **Registrar el tipo** en [`src/dns/mod.rs`](src/dns/mod.rs), función `type_to_num`:
   ```rust
   "CAA" => Some(257),
   "NUEVO" => Some(NNN),  // ← añadir aquí
   ```

2. **Parsear la respuesta** en `parse_rdata` del mismo fichero. Si es un tipo simple (valor en texto), suele bastar con añadir un `RData::Txt` con los bytes como hex o texto.

3. **Añadir un test** en `#[cfg(test)]` con un paquete DNS de ejemplo (bytes fixture → `Response`).

---

## Ejecutar los tests

```bash
# Todos los tests (incluyendo integración offline)
cargo test

# Un módulo específico
cargo test --lib dns

# Ver la salida aunque pasen
cargo test -- --nocapture

# Formato correcto (obligatorio antes de commit)
cargo fmt

# Sin warnings (obligatorio en CI)
cargo clippy -- -D warnings
```

---

## Convenciones de código

### Idioma de los comentarios
- **Comentarios** (`//`, `///`, `//!`) → **español**
- **Identificadores** (nombres de función, struct, enum, campo, variable) → **inglés**
- **Mensajes de error de cara al usuario** → **inglés** (compatibilidad con herramientas externas)

Ejemplo correcto:
```rust
/// Expande un CIDR IPv4 en la lista de IPs individuales que lo componen.
pub fn expand_cidr(cidr: &str) -> Result<Vec<IpAddr>, String> {
    // Separar base y prefijo
    let (base, prefix) = cidr.split_once('/').ok_or("invalid CIDR")?;
    // ...
}
```

### Dependencias
Kaisen tiene **exactamente 3 dependencias**: `tokio`, `futures`, `socket2`. Antes de añadir una cuarta, discútelo en un issue. El binario autocontenido es una característica, no un accidente.

### Sin root
Ningún cambio puede introducir syscalls que requieran privilegios. `CAP_NET_RAW`, `setuid`, etc. están prohibidos.

### `cargo fmt` antes de commit
El CI falla si el formato no es correcto. Ejecuta `cargo fmt` antes de cualquier commit.

---

## Gestión de versiones

Seguimos [semver](https://semver.org/):

| Tipo de cambio | Bump |
|---|---|
| Firma CVE nueva, tipo DNS nuevo, mejora de detección | `patch` (1.3.x) |
| Flag CLI nuevo, módulo nuevo, nueva funcionalidad | `minor` (1.x.0) |
| Cambio incompatible en salida JSON o flags existentes | `major` (x.0.0) |

La versión vive en `Cargo.toml`. El CI publica automáticamente cuando se crea un tag `vX.Y.Z`.

---

## Proceso de PR

1. Crea una rama desde `main`: `git checkout -b feat/descripcion-corta`
2. Haz los cambios siguiendo las convenciones
3. `cargo fmt && cargo clippy -- -D warnings && cargo test`
4. Abre el PR con una descripción que explique el **por qué**, no solo el **qué**
5. El CI debe pasar en verde antes de hacer merge

Para PRs de firmas CVE, incluye la fuente (NVD, advisory del fabricante, etc.) en la descripción.
