//! Small networking helpers shared across the scan and probe paths.
//!
//! The one thing here today is [`reset_on_close`]: it turns an ordinary
//! `connect()` scan into one that frees its footprint the instant it is done,
//! so a big `-sV` sweep can't quietly knock the whole link offline.

use std::time::Duration;
use tokio::net::TcpStream;

/// Arrange for a scan socket to be torn down with a TCP **RST** instead of a
/// graceful FIN when it is dropped.
///
/// A `connect()` scan — the only kind Kaisen can do without root — completes
/// the full three-way handshake on every port it finds open. The OS, and every
/// NAT / stateful-firewall / conntrack device between here and the target,
/// records that as an ESTABLISHED connection. When the socket is then dropped
/// the normal way, `close()` sends a FIN and the connection lingers in
/// TIME_WAIT (locally) and FIN_WAIT / TIME_WAIT (on the router) for up to a
/// couple of minutes before the entry is reclaimed.
///
/// That lingering is what makes `kaisen -sV` briefly kill connectivity where
/// `nmap` does not: a top-1000 sweep against a host — or against any middlebox
/// that answers every port — can pin hundreds of conntrack slots *after the
/// scan has already finished*. A small home router's table (typically 1–4k
/// entries) fills up and it starts dropping unrelated traffic — DNS, your
/// ping, other tabs — until the zombie entries age out "a few minutes" later.
///
/// Setting `SO_LINGER` to zero makes `close()` emit a RST: the local ephemeral
/// port is released immediately and the conntrack entry leaves ESTABLISHED at
/// once rather than aging out. By the time we drop a scan socket we have
/// already learned everything the connection can tell us, so there is nothing
/// to lose by resetting it — this is the same trick load generators use to
/// avoid TIME_WAIT exhaustion.
///
/// Best effort: if a platform rejects `SO_LINGER` we silently fall back to the
/// ordinary close, which is merely today's behaviour.
///
/// We go through `socket2::SockRef`, which borrows the socket without taking
/// ownership of the file descriptor — so the option is applied in place and
/// `stream` still owns and closes the socket exactly as before. (Tokio's own
/// `TcpStream::set_linger` is deprecated because a *non-zero* linger blocks the
/// runtime thread on close; a zero linger sends the RST immediately and never
/// blocks, which is precisely what we want.)
pub fn reset_on_close(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// The helper must actually flip `SO_LINGER` to zero on a live socket, so a
    /// dropped scan connection is torn down with a RST rather than lingering in
    /// TIME_WAIT. We read the option back through the same borrow to confirm it
    /// took, rather than trusting the set call not to error.
    #[tokio::test]
    async fn reset_on_close_arms_zero_linger() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept in the background so the connect completes the handshake.
        let accept = tokio::spawn(async move { listener.accept().await });

        let client = TcpStream::connect(addr).await.unwrap();
        reset_on_close(&client);

        let linger = socket2::SockRef::from(&client).linger().unwrap();
        assert_eq!(linger, Some(Duration::ZERO));

        let _ = accept.await;
    }
}
