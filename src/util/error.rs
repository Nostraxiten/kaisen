//! Definición del tipo de error unificado de Kaisen.

use std::fmt;

/// Tipo de error principal para todas las operaciones en Kaisen.
#[allow(dead_code)]
#[derive(Debug)]
pub enum KaisenError {
    /// Error de entrada/salida o de conexión a nivel de socket/red.
    Io(std::io::Error),
    /// Objetivo inválido (CIDR erróneo, host no resoluble, versión IP filtrada).
    Target(String),
    /// Argumentos o parámetros de línea de comandos inválidos.
    Cli(String),
    /// Error en la respuesta o análisis del protocolo (DNS, TLS, HTTP, etc.).
    Protocol(String),
    /// Error genérico de ejecución o sondeo.
    Other(String),
}

impl fmt::Display for KaisenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KaisenError::Io(err) => write!(f, "error de red/E/S: {err}"),
            KaisenError::Target(msg) => write!(f, "objetivo inválido: {msg}"),
            KaisenError::Cli(msg) => write!(f, "error en argumentos: {msg}"),
            KaisenError::Protocol(msg) => write!(f, "error de protocolo: {msg}"),
            KaisenError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for KaisenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KaisenError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for KaisenError {
    fn from(err: std::io::Error) -> Self {
        KaisenError::Io(err)
    }
}

impl From<String> for KaisenError {
    fn from(msg: String) -> Self {
        KaisenError::Other(msg)
    }
}

impl From<&str> for KaisenError {
    fn from(msg: &str) -> Self {
        KaisenError::Other(msg.to_string())
    }
}

/// Alias conveniente para Results usando `KaisenError`.
pub type Result<T> = std::result::Result<T, KaisenError>;
