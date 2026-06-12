//! V3 Game Booster Mode - Unencrypted UDP relay with atomic relay switching.

use arc_swap::ArcSwap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SESSION_ID_LEN: usize = 8;
const MAX_PAYLOAD_SIZE: usize = 1500;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_millis(10);
const RELAY_SWITCH_GRACE_PERIOD: Duration = Duration::from_secs(2);

// Relay control-frame types (must match the relay server protocol).
const AUTH_HELLO_FRAME_TYPE: u8 = 0xA1;
const AUTH_ACK_FRAME_TYPE: u8 = 0xA2;

const AUTH_HANDSHAKE_TOTAL_TIMEOUT: Duration = Duration::from_millis(1500);
const AUTH_HANDSHAKE_RETRY_DELAY: Duration = Duration::from_millis(250);
const AUTH_HANDSHAKE_ATTEMPTS: usize = 4;

/// Status returned by the relay in an auth-ack frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAuthAckStatus {
    Ok = 0,
    BadFormat = 1,
    BadSignature = 2,
    Expired = 3,
    SidMismatch = 4,
    ServerMismatch = 5,
    AuthDisabled = 6,
}

impl RelayAuthAckStatus {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::BadFormat),
            2 => Some(Self::BadSignature),
            3 => Some(Self::Expired),
            4 => Some(Self::SidMismatch),
            5 => Some(Self::ServerMismatch),
            6 => Some(Self::AuthDisabled),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::BadFormat => "bad_format",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::SidMismatch => "sid_mismatch",
            Self::ServerMismatch => "server_mismatch",
            Self::AuthDisabled => "auth_disabled",
        }
    }
}

pub struct UdpRelay {
    socket: UdpSocket,
    relay_addr: ArcSwap<SocketAddr>,
    previous_relay_addr: ArcSwap<Option<SocketAddr>>,
    switch_time: ArcSwap<Option<Instant>>,
    session_id: [u8; SESSION_ID_LEN],
    stop_flag: Arc<AtomicBool>,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    last_activity: std::sync::Mutex<Instant>,
    /// Address currently being authenticated in a mid-session auth flow.
    pending_auth_addr: ArcSwap<Option<SocketAddr>>,
    /// Last AUTH_ACK received from any pending-auth address.
    last_auth_ack: parking_lot::Mutex<Option<(SocketAddr, RelayAuthAckStatus)>>,
}

impl UdpRelay {
    pub fn new(relay_addr: SocketAddr) -> Result<Self, crate::error::SdkError> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            crate::error::SdkError::Vpn(format!("Failed to bind UDP socket: {}", e))
        })?;
        socket.set_read_timeout(Some(READ_TIMEOUT)).map_err(|e| {
            crate::error::SdkError::Vpn(format!("Failed to set read timeout: {}", e))
        })?;

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            let raw = socket.as_raw_socket();
            let buf_size: i32 = 256 * 1024;
            let sock = windows::Win32::Networking::WinSock::SOCKET(raw as usize);
            unsafe {
                let buf_bytes = std::slice::from_raw_parts(&buf_size as *const i32 as *const u8, 4);
                let rcv = windows::Win32::Networking::WinSock::setsockopt(
                    sock,
                    windows::Win32::Networking::WinSock::SOL_SOCKET,
                    windows::Win32::Networking::WinSock::SO_RCVBUF,
                    Some(buf_bytes),
                );
                if rcv != 0 {
                    log::warn!("UDP Relay: Failed to set SO_RCVBUF to 256KB");
                }
                let snd = windows::Win32::Networking::WinSock::setsockopt(
                    sock,
                    windows::Win32::Networking::WinSock::SOL_SOCKET,
                    windows::Win32::Networking::WinSock::SO_SNDBUF,
                    Some(buf_bytes),
                );
                if snd != 0 {
                    log::warn!("UDP Relay: Failed to set SO_SNDBUF to 256KB");
                }
            }
        }

        let mut session_id = [0u8; SESSION_ID_LEN];
        getrandom(&mut session_id);

        Ok(Self {
            socket,
            relay_addr: ArcSwap::from_pointee(relay_addr),
            previous_relay_addr: ArcSwap::from_pointee(None),
            switch_time: ArcSwap::from_pointee(None),
            session_id,
            stop_flag: Arc::new(AtomicBool::new(false)),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            last_activity: std::sync::Mutex::new(Instant::now()),
            pending_auth_addr: ArcSwap::from_pointee(None),
            last_auth_ack: parking_lot::Mutex::new(None),
        })
    }

    pub fn session_id_u64(&self) -> u64 {
        u64::from_be_bytes(self.session_id)
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    pub fn forward_outbound(&self, payload: &[u8]) -> Result<usize, crate::error::SdkError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            log::warn!(
                "UDP Relay: Packet too large ({} > {}), dropping",
                payload.len(),
                MAX_PAYLOAD_SIZE
            );
            return Ok(0);
        }

        let total_len = SESSION_ID_LEN + payload.len();
        let mut packet = [0u8; SESSION_ID_LEN + 1500];
        packet[..SESSION_ID_LEN].copy_from_slice(&self.session_id);
        packet[SESSION_ID_LEN..total_len].copy_from_slice(payload);

        let current_addr = **self.relay_addr.load();
        let sent = match self.socket.send_to(&packet[..total_len], current_addr) {
            Ok(sent) => sent,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_micros(50));
                self.socket
                    .send_to(&packet[..total_len], current_addr)
                    .map_err(|e| crate::error::SdkError::Vpn(format!("Retry send failed: {}", e)))?
            }
            Err(e) => return Err(crate::error::SdkError::Vpn(e.to_string())),
        };

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }
        Ok(sent)
    }

    pub fn receive_inbound(
        &self,
        buffer: &mut [u8],
    ) -> Result<Option<usize>, crate::error::SdkError> {
        let mut recv_buf = [0u8; 1600];
        match self.socket.recv_from(&mut recv_buf) {
            Ok((len, from)) => {
                // Mid-session auth: if we're authenticating a target address and
                // this packet arrives from it, check if it's an AUTH_ACK and
                // record it. Drop from normal processing either way.
                if let Some(pending) = **self.pending_auth_addr.load() {
                    if from == pending {
                        if len >= SESSION_ID_LEN + 2
                            && recv_buf[..SESSION_ID_LEN] == self.session_id
                            && recv_buf[SESSION_ID_LEN] == AUTH_ACK_FRAME_TYPE
                        {
                            let status = RelayAuthAckStatus::from_u8(recv_buf[SESSION_ID_LEN + 1])
                                .unwrap_or(RelayAuthAckStatus::BadFormat);
                            *self.last_auth_ack.lock() = Some((from, status));
                        }
                        return Ok(None);
                    }
                }

                let expected_addr = **self.relay_addr.load();
                if from != expected_addr {
                    let in_grace = if let (Some(prev), Some(switched_at)) = (
                        (**self.previous_relay_addr.load()).as_ref(),
                        (**self.switch_time.load()).as_ref(),
                    ) {
                        from == *prev && switched_at.elapsed() < RELAY_SWITCH_GRACE_PERIOD
                    } else {
                        false
                    };
                    if !in_grace {
                        return Ok(None);
                    }
                }

                if len < SESSION_ID_LEN {
                    return Ok(None);
                }
                if &recv_buf[..SESSION_ID_LEN] != &self.session_id {
                    return Ok(None);
                }

                let payload_len = len - SESSION_ID_LEN;
                if payload_len > buffer.len() {
                    return Ok(None);
                }
                buffer[..payload_len].copy_from_slice(&recv_buf[SESSION_ID_LEN..len]);
                self.packets_received.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut guard) = self.last_activity.lock() {
                    *guard = Instant::now();
                }
                Ok(Some(payload_len))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(crate::error::SdkError::Vpn(e.to_string())),
        }
    }

    pub fn send_keepalive_now(&self) -> Result<(), crate::error::SdkError> {
        let current_addr = **self.relay_addr.load();
        self.socket
            .send_to(&self.session_id, current_addr)
            .map_err(|e| crate::error::SdkError::Vpn(format!("Failed to send keepalive: {}", e)))?;
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }
        Ok(())
    }

    pub fn send_keepalive_burst(&self) -> Result<(), crate::error::SdkError> {
        let current_addr = **self.relay_addr.load();
        for i in 0..3 {
            if i > 0 {
                std::thread::sleep(Duration::from_millis(50));
            }
            match self.socket.send_to(&self.session_id, current_addr) {
                Ok(_) => {}
                Err(e) if i == 0 => {
                    return Err(crate::error::SdkError::Vpn(format!(
                        "Keepalive burst failed: {}",
                        e
                    )))
                }
                Err(e) => log::warn!("UDP Relay keepalive burst #{} failed: {}", i + 1, e),
            }
        }
        if let Ok(mut guard) = self.last_activity.lock() {
            *guard = Instant::now();
        }
        Ok(())
    }

    pub fn send_keepalive(&self) -> Result<(), crate::error::SdkError> {
        let should_send = self
            .last_activity
            .lock()
            .map(|guard| guard.elapsed() >= KEEPALIVE_INTERVAL)
            .unwrap_or(true);
        if should_send {
            self.send_keepalive_now()?;
        }
        Ok(())
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_received.load(Ordering::Relaxed),
        )
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
    }

    pub fn try_clone_socket(&self) -> Result<UdpSocket, crate::error::SdkError> {
        self.socket.try_clone().map_err(|e| {
            crate::error::SdkError::Vpn(format!("Failed to clone relay socket: {}", e))
        })
    }

    pub fn relay_addr(&self) -> SocketAddr {
        **self.relay_addr.load()
    }

    pub fn switch_relay(&self, new_addr: SocketAddr) {
        let old_addr = **self.relay_addr.load();
        self.previous_relay_addr.store(Arc::new(Some(old_addr)));
        self.switch_time.store(Arc::new(Some(Instant::now())));
        self.relay_addr.store(Arc::new(new_addr));
    }

    pub fn session_id_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// Lowercase hex of the session id, as expected by `/api/vpn/relay-ticket`.
    pub fn session_id_hex(&self) -> String {
        format!("{:016x}", self.session_id_u64())
    }

    /// Send a relay auth-hello frame to an explicit target address.
    /// Frame: [session_id:8][0xA1][token_len:2][token_utf8].
    fn send_auth_hello_to(
        &self,
        token: &str,
        target: SocketAddr,
    ) -> Result<(), crate::error::SdkError> {
        let token_bytes = token.as_bytes();
        if token_bytes.is_empty() || token_bytes.len() > u16::MAX as usize {
            return Err(crate::error::SdkError::Vpn(format!(
                "Relay auth token length must be between 1 and {} bytes",
                u16::MAX
            )));
        }

        let mut frame = Vec::with_capacity(SESSION_ID_LEN + 3 + token_bytes.len());
        frame.extend_from_slice(&self.session_id);
        frame.push(AUTH_HELLO_FRAME_TYPE);
        frame.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
        frame.extend_from_slice(token_bytes);

        self.socket.send_to(&frame, target).map_err(|e| {
            crate::error::SdkError::Vpn(format!("Failed to send relay auth hello: {}", e))
        })?;
        log::debug!(
            "UDP Relay: Sent auth hello to {} (session {:016x}, token {} bytes)",
            target,
            self.session_id_u64(),
            token_bytes.len()
        );
        Ok(())
    }

    /// Send a relay auth-hello frame to the current relay address.
    fn send_auth_hello(&self, token: &str) -> Result<(), crate::error::SdkError> {
        let current_addr = **self.relay_addr.load();
        self.send_auth_hello_to(token, current_addr)
    }

    fn wait_for_auth_ack(
        &self,
        timeout: Duration,
    ) -> Result<Option<RelayAuthAckStatus>, crate::error::SdkError> {
        let deadline = Instant::now() + timeout;
        let mut recv_buf = [0u8; 1600];
        let expected_addr = **self.relay_addr.load();

        while Instant::now() < deadline {
            match self.socket.recv_from(&mut recv_buf) {
                Ok((len, from)) => {
                    if from != expected_addr {
                        continue;
                    }
                    if len < SESSION_ID_LEN + 2 {
                        continue;
                    }
                    if recv_buf[..SESSION_ID_LEN] != self.session_id {
                        continue;
                    }
                    if recv_buf[SESSION_ID_LEN] != AUTH_ACK_FRAME_TYPE {
                        continue;
                    }
                    let status = RelayAuthAckStatus::from_u8(recv_buf[SESSION_ID_LEN + 1])
                        .unwrap_or(RelayAuthAckStatus::BadFormat);
                    return Ok(Some(status));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(e) => return Err(crate::error::SdkError::Vpn(e.to_string())),
            }
        }
        Ok(None)
    }

    /// Authenticate a new relay address mid-session (for auto-routing switch).
    ///
    /// Sets `pending_auth_addr` so `receive_inbound` intercepts the ack from
    /// `target`, then runs a retry loop, polling `last_auth_ack`.
    /// Clears `pending_auth_addr` on exit (success or timeout).
    pub async fn authenticate_addr_with_ticket(
        &self,
        token: &str,
        target: SocketAddr,
    ) -> Result<Option<RelayAuthAckStatus>, crate::error::SdkError> {
        // Signal the inbound receiver to watch for acks from this address.
        self.pending_auth_addr.store(Arc::new(Some(target)));
        *self.last_auth_ack.lock() = None;

        let result = self.authenticate_addr_inner(token, target).await;

        // Always clear the pending address.
        self.pending_auth_addr.store(Arc::new(None));
        result
    }

    /// Inner retry loop for `authenticate_addr_with_ticket`.
    async fn authenticate_addr_inner(
        &self,
        token: &str,
        target: SocketAddr,
    ) -> Result<Option<RelayAuthAckStatus>, crate::error::SdkError> {
        let deadline =
            tokio::time::Instant::now() + AUTH_HANDSHAKE_TOTAL_TIMEOUT;

        for attempt in 0..AUTH_HANDSHAKE_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(AUTH_HANDSHAKE_RETRY_DELAY).await;
            }

            if let Err(e) = self.send_auth_hello_to(token, target) {
                log::warn!("authenticate_addr_inner: send failed: {}", e);
                continue;
            }

            // Poll for the ack (set by receive_inbound from the interceptor thread).
            let poll_deadline = tokio::time::Instant::now() + AUTH_HANDSHAKE_RETRY_DELAY;
            while tokio::time::Instant::now() < poll_deadline {
                {
                    let guard = self.last_auth_ack.lock();
                    if let Some((from, status)) = *guard {
                        if from == target {
                            log::info!(
                                "UDP Relay: Mid-session auth ack {} for {} (session {:016x})",
                                status.as_str(),
                                target,
                                self.session_id_u64()
                            );
                            return Ok(Some(status));
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }

        Ok(None)
    }

    /// Send the relay auth-hello and wait for an ack.
    ///
    /// Retries up to [`AUTH_HANDSHAKE_ATTEMPTS`] times within a total
    /// [`AUTH_HANDSHAKE_TOTAL_TIMEOUT`] budget. Returns `Ok(None)` on timeout.
    pub fn authenticate_with_ticket(
        &self,
        token: &str,
    ) -> Result<Option<RelayAuthAckStatus>, crate::error::SdkError> {
        let deadline = Instant::now() + AUTH_HANDSHAKE_TOTAL_TIMEOUT;

        for attempt in 0..AUTH_HANDSHAKE_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(AUTH_HANDSHAKE_RETRY_DELAY);
            }

            self.send_auth_hello(token)?;

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            if let Some(status) = self.wait_for_auth_ack(remaining)? {
                log::info!(
                    "UDP Relay: Auth ack {} for session {:016x}",
                    status.as_str(),
                    self.session_id_u64()
                );
                return Ok(Some(status));
            }
        }

        Ok(None)
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.stop();
    }
}

fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

pub struct RelayContext {
    pub relay: Arc<UdpRelay>,
    pub session_id: [u8; SESSION_ID_LEN],
}

impl RelayContext {
    pub fn new(relay: Arc<UdpRelay>) -> Self {
        let session_id = *relay.session_id_bytes();
        Self { relay, session_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_session_id_generation() {
        let mut id1 = [0u8; 8];
        let mut id2 = [0u8; 8];
        getrandom(&mut id1);
        getrandom(&mut id2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_switch_relay_updates_addr() {
        let relay = UdpRelay::new("127.0.0.1:51821".parse().unwrap()).unwrap();
        assert_eq!(relay.relay_addr(), "127.0.0.1:51821".parse().unwrap());
        relay.switch_relay("127.0.0.1:51822".parse().unwrap());
        assert_eq!(relay.relay_addr(), "127.0.0.1:51822".parse().unwrap());
    }

    #[test]
    fn test_switch_relay_changes_outbound_destination() {
        let relay_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay_a
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        relay_b
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        let addr_a = relay_a.local_addr().unwrap();
        let addr_b = relay_b.local_addr().unwrap();

        let relay = UdpRelay::new(addr_a).unwrap();
        relay.forward_outbound(b"abc").unwrap();

        let mut buf = [0u8; 64];
        let (len_a, _) = relay_a.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[SESSION_ID_LEN..len_a], b"abc");

        relay.switch_relay(addr_b);
        relay.forward_outbound(b"xyz").unwrap();
        let (len_b, _) = relay_b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[SESSION_ID_LEN..len_b], b"xyz");

        let stale_recv = relay_a.recv_from(&mut buf);
        assert!(matches!(
            stale_recv,
            Err(ref e)
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn test_previous_relay_grace_acceptance() {
        let previous = UdpSocket::bind("127.0.0.1:0").unwrap();
        let current = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay = UdpRelay::new(previous.local_addr().unwrap()).unwrap();
        let local_addr = relay.try_clone_socket().unwrap().local_addr().unwrap();

        relay.switch_relay(current.local_addr().unwrap());

        let mut packet = Vec::from(*relay.session_id_bytes());
        packet.extend_from_slice(b"hello");
        previous.send_to(&packet, local_addr).unwrap();

        let mut out = [0u8; 64];
        let mut accepted = None;
        let deadline = Instant::now() + Duration::from_millis(250);
        while Instant::now() < deadline {
            if let Some(n) = relay.receive_inbound(&mut out).unwrap() {
                accepted = Some(n);
                break;
            }
        }

        assert_eq!(accepted, Some(5));
        assert_eq!(&out[..5], b"hello");
    }

    #[test]
    fn test_keepalive_burst_sends_three_packets() {
        let relay_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay_socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let relay = UdpRelay::new(relay_socket.local_addr().unwrap()).unwrap();

        relay.send_keepalive_burst().unwrap();

        let mut buf = [0u8; 64];
        let mut keepalive_count = 0;
        for _ in 0..3 {
            let (len, _) = relay_socket.recv_from(&mut buf).unwrap();
            if len == SESSION_ID_LEN && &buf[..SESSION_ID_LEN] == relay.session_id_bytes() {
                keepalive_count += 1;
            }
        }

        assert_eq!(keepalive_count, 3);
    }
}
