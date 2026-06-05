//! Lock-Free Process Cache - RCU-style read-copy-update pattern
//!
//! Achieves <0.1ms lookup latency by eliminating locks entirely:
//! - Single writer thread creates new snapshots atomically
//! - Multiple reader threads access snapshots without any locks
//! - Uses arc-swap for safe atomic Arc operations (NO use-after-free!)
//!
//! SDK adaptation: V3-only (no V1/V2 routing modes). Process-based routing
//! with permissive UDP tunneling for trusted processes.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use arc_swap::ArcSwap;
use super::process_tracker::{ConnectionKey, Protocol, TrackerStats};

// ============================================================================
// GAME SERVER IP RANGES (for speculative tunneling)
// ============================================================================

/// DNS port. Never tunneled even for tunnel apps — DNS must resolve locally
/// (and Route Assist repairs Roblox DNS via the hosts file instead).
pub(crate) const DNS_PORT: u16 = 53;

/// Roblox game server IP ranges - Complete list from AS22697/AS11281
const ROBLOX_RANGES: &[(u32, u32, u32)] = &[
    // PRIMARY GAME SERVERS - covers ALL regional game servers
    (0x80740000, 0xFFFF8000, 17), // 128.116.0.0/17

    // SECONDARY GAME SERVERS - San Jose/Palo Alto
    (0xD1CE2800, 0xFFFFF800, 21), // 209.206.40.0/21

    // ASIA-PACIFIC
    (0x678C1C00, 0xFFFFFE00, 23), // 103.140.28.0/23

    // CHINA (LUOBU)
    (0x678EDC00, 0xFFFFFE00, 23), // 103.142.220.0/23

    // API/MATCHMAKING
    (0x17ADC000, 0xFFFFFF00, 24), // 23.173.192.0/24
    (0x8DC10300, 0xFFFFFF00, 24), // 141.193.3.0/24
    (0xCDC93E00, 0xFFFFFF00, 24), // 205.201.62.0/24

    // INFRASTRUCTURE
    (0xCC09B800, 0xFFFFFF00, 24), // 204.9.184.0/24
    (0xCC0DA800, 0xFFFFFC00, 22), // 204.13.168.0/22
    (0xCC0DAC00, 0xFFFFFE00, 23), // 204.13.172.0/23
];

/// Roblox game server UDP port range
const ROBLOX_PORT_MIN: u16 = 49152;
const ROBLOX_PORT_MAX: u16 = 65535;

/// Validate that a mask is a valid CIDR mask for the given prefix length
#[inline(always)]
const fn is_valid_cidr_mask(mask: u32, prefix: u32) -> bool {
    if prefix > 32 {
        return false;
    }
    if prefix == 0 {
        return mask == 0;
    }
    let expected = !0u32 << (32 - prefix);
    mask == expected
}

// Compile-time validation of ROBLOX_RANGES masks
const _: () = {
    let mut i = 0;
    while i < ROBLOX_RANGES.len() {
        let (_network, mask, prefix) = ROBLOX_RANGES[i];
        assert!(is_valid_cidr_mask(mask, prefix), "Invalid CIDR mask in ROBLOX_RANGES");
        i += 1;
    }
};

/// Check if an IP address is within a CIDR range
#[inline(always)]
fn ip_in_range(ip: Ipv4Addr, network: u32, mask: u32) -> bool {
    let ip_u32 = u32::from(ip);
    (ip_u32 & mask) == (network & mask)
}

/// Check if destination is a Roblox game server.
///
/// UDP is always eligible (game traffic). TCP is eligible only when Route Assist
/// (`api_tunneling`) is enabled — that routes Roblox's API/bootstrap HTTPS to the
/// relay so a banned/blocked network can still reach Roblox.
#[inline(always)]
pub fn is_roblox_game_server(
    dst_ip: Ipv4Addr,
    dst_port: u16,
    protocol: Protocol,
    api_tunneling: bool,
) -> bool {
    if dst_port == DNS_PORT {
        return false;
    }
    match protocol {
        Protocol::Udp => {
            if dst_port < ROBLOX_PORT_MIN || dst_port > ROBLOX_PORT_MAX {
                return false;
            }
        }
        Protocol::Tcp if api_tunneling => {}
        _ => return false,
    }
    for &(network, mask, _prefix) in ROBLOX_RANGES {
        if ip_in_range(dst_ip, network, mask) {
            return true;
        }
    }
    false
}

/// Check if traffic is likely game traffic (permissive for trusted processes)
///
/// When we KNOW the packet is from a tunnel app, trust the process and
/// tunnel ALL its UDP traffic (game server, STUN, voice chat, etc.).
#[inline(always)]
pub fn is_likely_game_traffic(dst_port: u16, protocol: Protocol, api_tunneling: bool) -> bool {
    if dst_port == DNS_PORT {
        return false;
    }
    match protocol {
        Protocol::Udp => true,
        // Route Assist: trust a known tunnel app's TCP (API/bootstrap) traffic too.
        Protocol::Tcp => api_tunneling,
    }
}

/// Check if destination is any known game server
#[inline(always)]
pub fn is_game_server(
    dst_ip: Ipv4Addr,
    dst_port: u16,
    protocol: Protocol,
    api_tunneling: bool,
) -> bool {
    is_roblox_game_server(dst_ip, dst_port, protocol, api_tunneling)
}

/// Check if an IP is a Roblox game server (any port/protocol)
#[inline(always)]
pub fn is_roblox_game_server_ip(ip: Ipv4Addr) -> bool {
    for &(network, mask, _prefix) in ROBLOX_RANGES {
        if ip_in_range(ip, network, mask) {
            return true;
        }
    }
    false
}

// ============================================================================
// ON-DEMAND PID LOOKUP (for first-packet guarantee)
// ============================================================================

/// Get process name by PID using Windows API
#[cfg(windows)]
fn get_process_name_by_pid_fast(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        if handle.is_invalid() {
            return None;
        }
        let mut buffer = [0u16; 512];
        let len = K32GetProcessImageFileNameW(handle, &mut buffer);
        let _ = CloseHandle(handle);
        if len == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buffer[..len as usize]);
        path.rsplit('\\').next().map(|s| s.to_string())
    }
}

#[cfg(not(windows))]
fn get_process_name_by_pid_fast(_pid: u32) -> Option<String> {
    None
}

/// Immutable snapshot of process state
///
/// Once created, this is NEVER modified. Readers can safely access
/// without any synchronization. New snapshots replace old ones atomically.
#[derive(Clone)]
pub struct ProcessSnapshot {
    /// Connection cache: (local_ip, local_port, protocol) -> PID
    pub connections: HashMap<ConnectionKey, u32>,
    /// PID -> process name (lowercase)
    pub pid_names: HashMap<u32, String>,
    /// Apps that should be tunneled (lowercase)
    pub tunnel_apps: HashSet<String>,
    /// Local UDP ports owned by a tunnel-app PID. Used as a port-only fallback
    /// when the exact (ip, port, proto) connection lookup misses because the
    /// packet's local IP representation drifted (e.g. 0.0.0.0 bind vs LAN IP).
    pub tunnel_udp_ports: HashSet<u16>,
    /// Snapshot version (monotonically increasing)
    pub version: u64,
    /// Timestamp when snapshot was created
    pub created_at: std::time::Instant,
}

impl ProcessSnapshot {
    /// Create empty snapshot
    pub fn empty(tunnel_apps: HashSet<String>) -> Self {
        Self {
            connections: HashMap::new(),
            pid_names: HashMap::new(),
            tunnel_apps,
            tunnel_udp_ports: HashSet::new(),
            version: 0,
            created_at: std::time::Instant::now(),
        }
    }

    /// Compute the set of local UDP ports owned by a tunnel-app PID from a
    /// connection map and pid->name map.
    pub fn compute_tunnel_udp_ports(
        connections: &HashMap<ConnectionKey, u32>,
        pid_names: &HashMap<u32, String>,
        tunnel_apps: &HashSet<String>,
    ) -> HashSet<u16> {
        let mut ports = HashSet::new();
        for (key, &pid) in connections {
            if key.protocol != Protocol::Udp {
                continue;
            }
            if Self::pid_is_tunnel(pid, pid_names, tunnel_apps) {
                ports.insert(key.local_port);
            }
        }
        ports
    }

    /// PID -> tunnel-app check usable without a `ProcessSnapshot` instance.
    fn pid_is_tunnel(
        pid: u32,
        pid_names: &HashMap<u32, String>,
        tunnel_apps: &HashSet<String>,
    ) -> bool {
        if let Some(name) = pid_names.get(&pid) {
            if tunnel_apps.contains(name) {
                return true;
            }
            let name_stem = name.trim_end_matches(".exe");
            for app in tunnel_apps {
                let app_stem = app.trim_end_matches(".exe");
                if name_stem.contains(app_stem) || app_stem.contains(name_stem) {
                    return true;
                }
            }
        }
        false
    }

    /// Port-only fallback: is this local UDP port owned by a tunnel app?
    #[inline(always)]
    pub fn should_tunnel_by_port_fallback(&self, local_port: u16, protocol: Protocol) -> bool {
        protocol == Protocol::Udp && self.tunnel_udp_ports.contains(&local_port)
    }

    /// Check if connection should be tunneled (V3 mode, no locks!)
    ///
    /// V3 uses permissive routing:
    /// - If process IS a tunnel app -> tunnel all its UDP traffic
    /// - If process is NOT detected -> use speculative destination IP matching
    #[inline(always)]
    pub fn should_tunnel_v3(
        &self,
        local_ip: Ipv4Addr,
        local_port: u16,
        protocol: Protocol,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        api_tunneling: bool,
    ) -> bool {
        let is_tunnel_app = self.is_tunnel_connection(local_ip, local_port, protocol);

        if is_tunnel_app {
            return is_likely_game_traffic(dst_port, protocol, api_tunneling);
        }

        // Process not detected - use strict IP range check for speculative tunneling
        is_game_server(dst_ip, dst_port, protocol, api_tunneling)
    }

    /// Check if connection belongs to a tunnel app
    ///
    /// V3 mode: Skip expensive Windows API calls (no on-demand lookup).
    /// Relies on speculative tunneling via destination IP matching instead.
    #[inline(always)]
    fn is_tunnel_connection(&self, local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> bool {
        let key = ConnectionKey::new(local_ip, local_port, protocol);

        if let Some(&pid) = self.connections.get(&key) {
            return self.is_tunnel_pid(pid);
        }

        // Check 0.0.0.0 binding fallback
        if local_ip != Ipv4Addr::UNSPECIFIED {
            let any_key = ConnectionKey::new(Ipv4Addr::UNSPECIFIED, local_port, protocol);
            if let Some(&pid) = self.connections.get(&any_key) {
                return self.is_tunnel_pid(pid);
            }
        }

        // V3: Skip blocking Windows API calls, let speculative tunneling handle it
        false
    }

    /// Check if PID belongs to tunnel app
    #[inline(always)]
    fn is_tunnel_pid(&self, pid: u32) -> bool {
        if let Some(name) = self.pid_names.get(&pid) {
            if self.tunnel_apps.contains(name) {
                return true;
            }
            let name_stem = name.trim_end_matches(".exe");
            for app in &self.tunnel_apps {
                let app_stem = app.trim_end_matches(".exe");
                if name_stem.contains(app_stem) || app_stem.contains(name_stem) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if PID belongs to tunnel app (public, for inline lookups)
    #[inline(always)]
    pub fn is_tunnel_pid_public(&self, pid: u32) -> bool {
        self.is_tunnel_pid(pid)
    }

    /// Whether an outbound flow's source `(ip, port, proto)` belongs to a tunnel
    /// app — by connection ownership or the UDP port fallback. Used by the URL
    /// logger to record only tunnel-app destinations.
    #[inline]
    pub fn is_tunnel_source(&self, local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> bool {
        self.is_tunnel_connection(local_ip, local_port, protocol)
            || self.should_tunnel_by_port_fallback(local_port, protocol)
    }

    /// Get PID for connection (for debugging)
    #[inline]
    pub fn get_pid(&self, local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> Option<u32> {
        let key = ConnectionKey::new(local_ip, local_port, protocol);
        self.connections.get(&key).copied()
    }

    /// Get process name for PID
    #[inline]
    pub fn get_process_name(&self, pid: u32) -> Option<&str> {
        self.pid_names.get(&pid).map(|s| s.as_str())
    }

    /// Get stats
    pub fn stats(&self) -> TrackerStats {
        TrackerStats {
            tcp_connections: self.connections.keys().filter(|k| k.protocol == Protocol::Tcp).count(),
            udp_connections: self.connections.keys().filter(|k| k.protocol == Protocol::Udp).count(),
            stale_connections: 0,
            tracked_pids: self.pid_names.len(),
        }
    }
}

/// Lock-free process cache using RCU pattern with arc-swap
pub struct LockFreeProcessCache {
    /// Current snapshot (atomically swapped via arc-swap)
    current: ArcSwap<ProcessSnapshot>,
    /// Snapshot version counter
    version: AtomicU64,
    /// Apps to tunnel
    tunnel_apps: HashSet<String>,
}

impl LockFreeProcessCache {
    /// Create new lock-free cache
    pub fn new(tunnel_apps: Vec<String>) -> Self {
        let apps: HashSet<String> = tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect();
        let initial = Arc::new(ProcessSnapshot::empty(apps.clone()));

        Self {
            current: ArcSwap::from(initial),
            version: AtomicU64::new(0),
            tunnel_apps: apps,
        }
    }

    /// Get current snapshot (lock-free!)
    #[inline(always)]
    pub fn get_snapshot(&self) -> Arc<ProcessSnapshot> {
        self.current.load_full()
    }

    /// Update snapshot (called by single writer thread)
    pub fn update(&self, connections: HashMap<ConnectionKey, u32>, pid_names: HashMap<u32, String>) {
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        let pid_names_lower: HashMap<u32, String> = pid_names
            .into_iter()
            .map(|(k, v)| (k, v.to_lowercase()))
            .collect();

        let tunnel_udp_ports = ProcessSnapshot::compute_tunnel_udp_ports(
            &connections,
            &pid_names_lower,
            &self.tunnel_apps,
        );

        let new_snapshot = Arc::new(ProcessSnapshot {
            connections,
            pid_names: pid_names_lower,
            tunnel_apps: self.tunnel_apps.clone(),
            tunnel_udp_ports,
            version,
            created_at: std::time::Instant::now(),
        });

        self.current.store(new_snapshot);
    }

    /// Update tunnel apps list and immediately refresh the snapshot
    pub fn set_tunnel_apps(&mut self, apps: Vec<String>) {
        self.tunnel_apps = apps.into_iter().map(|s| s.to_lowercase()).collect();

        let old_snap = self.get_snapshot();
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        let tunnel_udp_ports = ProcessSnapshot::compute_tunnel_udp_ports(
            &old_snap.connections,
            &old_snap.pid_names,
            &self.tunnel_apps,
        );

        let new_snapshot = Arc::new(ProcessSnapshot {
            connections: old_snap.connections.clone(),
            pid_names: old_snap.pid_names.clone(),
            tunnel_apps: self.tunnel_apps.clone(),
            tunnel_udp_ports,
            version,
            created_at: std::time::Instant::now(),
        });

        self.current.store(new_snapshot);

        log::info!(
            "set_tunnel_apps: Updated snapshot with {} tunnel apps: {:?}",
            self.tunnel_apps.len(),
            self.tunnel_apps.iter().take(5).collect::<Vec<_>>()
        );
    }

    /// Get tunnel apps
    pub fn tunnel_apps(&self) -> &HashSet<String> {
        &self.tunnel_apps
    }

    /// Immediately register a process detected via ETW
    pub fn register_process_immediate(&self, pid: u32, name: String) {
        let old_snap = self.get_snapshot();
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        let mut pid_names = old_snap.pid_names.clone();
        pid_names.insert(pid, name.to_lowercase());

        let tunnel_udp_ports = ProcessSnapshot::compute_tunnel_udp_ports(
            &old_snap.connections,
            &pid_names,
            &self.tunnel_apps,
        );

        let new_snapshot = Arc::new(ProcessSnapshot {
            connections: old_snap.connections.clone(),
            pid_names,
            tunnel_apps: self.tunnel_apps.clone(),
            tunnel_udp_ports,
            version,
            created_at: std::time::Instant::now(),
        });

        self.current.store(new_snapshot);

        log::info!(
            "ETW: Immediately registered process {} (PID: {}) for tunneling",
            name, pid
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_free_snapshot() {
        let cache = LockFreeProcessCache::new(vec!["robloxplayerbeta.exe".to_string()]);

        let snap1 = cache.get_snapshot();
        assert_eq!(snap1.version, 0);

        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), 8080, Protocol::Tcp),
            1234,
        );
        let mut pid_names = HashMap::new();
        pid_names.insert(1234, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);

        let snap2 = cache.get_snapshot();
        assert_eq!(snap2.version, 1);
        assert_eq!(snap1.version, 0); // Old snapshot still valid (RCU)
    }

    #[test]
    fn test_should_tunnel_0000_fallback() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::UNSPECIFIED, 50000, Protocol::Udp),
            1234,
        );
        let mut pid_names = HashMap::new();
        pid_names.insert(1234, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);
        let snap = cache.get_snapshot();

        // Should match via 0.0.0.0 fallback
        assert!(snap.should_tunnel_v3(
            Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Udp,
            Ipv4Addr::new(128, 116, 50, 100), 55000, false
        ));
    }

    #[test]
    fn test_v3_speculative_tunneling() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let snap = cache.get_snapshot();

        // No process detected, but destination is a known game server -> speculative tunnel
        assert!(snap.should_tunnel_v3(
            Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Udp,
            Ipv4Addr::new(128, 116, 50, 100), 55000, false
        ));

        // Non-game destination -> bypass
        assert!(!snap.should_tunnel_v3(
            Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Udp,
            Ipv4Addr::new(1, 1, 1, 1), 443, false
        ));
    }

    #[test]
    fn test_concurrent_read_write_safety() {
        use std::thread;
        use std::time::Duration;

        let cache = Arc::new(LockFreeProcessCache::new(vec!["test.exe".to_string()]));

        let readers: Vec<_> = (0..4).map(|_| {
            let cache_clone = Arc::clone(&cache);
            thread::spawn(move || {
                for _ in 0..1000 {
                    let snap = cache_clone.get_snapshot();
                    let _ = snap.version;
                    let _ = snap.connections.len();
                    thread::sleep(Duration::from_micros(10));
                }
            })
        }).collect();

        let cache_writer = Arc::clone(&cache);
        let writer = thread::spawn(move || {
            for i in 0..100 {
                let mut connections = HashMap::new();
                connections.insert(
                    ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), i as u16, Protocol::Tcp),
                    i,
                );
                let mut pid_names = HashMap::new();
                pid_names.insert(i, format!("process_{}.exe", i));
                cache_writer.update(connections, pid_names);
                thread::sleep(Duration::from_micros(100));
            }
        });

        for reader in readers {
            reader.join().expect("Reader thread panicked");
        }
        writer.join().expect("Writer thread panicked");
    }
}
