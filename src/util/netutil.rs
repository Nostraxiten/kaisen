//! Utilidades de red compartidas entre los flujos de escaneo y sondeo.
//!
//! La función principal aquí es [`reset_on_close`]: convierte un escaneo
//! ordinario con `connect()` en uno que libera su huella en el momento en que
//! termina, evitando que un barrido grande de `-sV` pueda tumbar el enlace.

use std::time::Duration;
use tokio::net::TcpStream;

/// Configura un socket de escaneo para que se cierre con un TCP **RST** en
/// lugar de con un FIN gracioso cuando se descarta.
///
/// Un escaneo con `connect()` — el único tipo que Kaisen puede hacer sin root —
/// completa el handshake completo de tres vías en cada puerto abierto. El SO,
/// y todos los dispositivos NAT / cortafuegos con estado / conntrack entre
/// el origen y el objetivo, registran eso como una conexión ESTABLISHED. Cuando
/// el socket se descarta de la forma habitual, `close()` envía un FIN y la
/// conexión se queda en TIME_WAIT (localmente) y FIN_WAIT / TIME_WAIT (en el
/// router) durante hasta un par de minutos antes de que la entrada se reclame.
///
/// Ese tiempo de espera es lo que hace que `kaisen -sV` corte brevemente la
/// conectividad donde `nmap` no lo hace: un barrido de los 1000 puertos más
/// comunes contra un host — o contra cualquier middlebox que responda a todos
/// los puertos — puede bloquear cientos de slots de conntrack *después de que
/// el escaneo ya haya terminado*. La tabla de un router doméstico pequeño
/// (normalmente 1–4k entradas) se llena y empieza a descartar tráfico no
/// relacionado — DNS, ping, otras pestañas — hasta que las entradas zombie
/// expiran "unos minutos" después.
///
/// Poner `SO_LINGER` a cero hace que `close()` emita un RST: el puerto
/// efímero local se libera inmediatamente y la entrada de conntrack sale de
/// ESTABLISHED al instante en lugar de expirar. En el momento en que
/// descartamos un socket de escaneo ya hemos aprendido todo lo que la
/// conexión puede contarnos, así que no hay nada que perder al resetearlo —
/// es el mismo truco que usan los generadores de carga para evitar el
/// agotamiento de TIME_WAIT.
///
/// Mejor esfuerzo: si una plataforma rechaza `SO_LINGER` se cae al cierre
/// ordinario en silencio, que es simplemente el comportamiento actual.
///
/// Se usa `socket2::SockRef`, que toma prestado el socket sin apropiarse del
/// descriptor de fichero — la opción se aplica en el sitio y `stream` sigue
/// siendo propietario y cierra el socket exactamente como antes.
pub fn reset_on_close(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// La función debe cambiar `SO_LINGER` a cero en un socket real, para que
    /// una conexión de escaneo descartada se cierre con RST en lugar de
    /// quedarse en TIME_WAIT. Se lee la opción de vuelta para confirmarlo.
    #[tokio::test]
    async fn reset_on_close_activa_linger_cero() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Aceptar en segundo plano para que el connect complete el handshake.
        let accept = tokio::spawn(async move { listener.accept().await });

        let client = TcpStream::connect(addr).await.unwrap();
        reset_on_close(&client);

        let linger = socket2::SockRef::from(&client).linger().unwrap();
        assert_eq!(linger, Some(Duration::ZERO));

        let _ = accept.await;
    }
}
