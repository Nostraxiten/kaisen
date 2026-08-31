//! Utilidades de salida para terminal: color ANSI (respetando --no-color / NO_COLOR)
//! y pequeños helpers de formato compartidos entre la salida de escaneo y DNS.

/// Controla si se emiten códigos ANSI de color al escribir en el terminal.
#[derive(Clone, Copy)]
pub struct Painter {
    pub enabled: bool,
}

impl Painter {
    pub fn new(enabled: bool) -> Self {
        Painter { enabled }
    }

    /// Envuelve `s` con el código de color `code` si el color está habilitado.
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn blue(&self, s: &str) -> String {
        self.wrap("34", s)
    }
    pub fn magenta(&self, s: &str) -> String {
        self.wrap("35", s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
}

/// Escapa una cadena para incrustarla en la salida JSON.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Caracteres de control U+0000..U+001F deben escaparse en JSON.
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Escapa una cadena para incrustarla en atributos o texto XML.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

