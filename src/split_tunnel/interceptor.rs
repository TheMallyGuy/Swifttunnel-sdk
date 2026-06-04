//! Parallel Packet Interceptor - Per-CPU packet processing for <0.5ms latency
//!
//! V3-only SDK adaptation. Architecture modeled after WireGuard kernel module:
//! - Per-CPU packet workers with affinity
//! - Lock-free process cache (RCU pattern)
//! - Batch packet reading to amortize syscall overhead
//! - Separate reader/dispatcher thread feeds workers via MPSC channels
//! - Zero-allocation hot path using pre-allocated buffers
//!
//! V3 path: intercept packet -> lookup process -> if in tunnel_apps,
//! wrap [session_id][payload] and send to relay server:51821
//!
//! ```text
//!                    +-------------------------------------+
//!                    |          ndisapi driver              |
//!                    +----------------+--------------------+
//!                                     |
//!                                     v
//!                    +-------------------------------------+
//!                    |      Packet Reader Thread            |
//!                    |  (reads batches, dispatches by hash) |
//!                    +----------------+--------------------+
//!                                     |
//!          +--------------------------+-------------------------+
//!          v                          v                         v
//!    +-----------+             +-----------+             +-----------+
//!    | Worker 0  |             | Worker 1  |             | Worker N  |
//!    | (core 0)  |             | (core 1)  |             | (core N)  |
//!    +-----+-----+             +-----+-----+             +-----+-----+
//!          |                         |                         |
//!          +-------------------------+-------------------------+
//!                                    |
//!               +--------------------+--------------------+
//!               v                                         v
//!       +--------------+                         +--------------+
//!       | V3 UDP Relay |                         |  Passthrough |
//!       | (port 51821) |                         |  (Adapter)   |
//!       +--------------+                         +--------------+
//! ```

use std::collections::HashMap;
use std::net::Ipv4Addr;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use arrayvec::ArrayVec;

use super::process_cache::{
    is_game_server, is_likely_game_traffic, is_roblox_game_server_ip, LockFreeProcessCache,
    ProcessSnapshot,
};
use super::process_tracker::{ConnectionKey, Protocol};
use crate::error::SdkError;

/// Maximum Ethernet frame size (MTU 1500 + headers)
const MAX_PACKET_SIZE: usize = 1600;

/// Timeout for thread join operations during stop()
const THREAD_JOIN_TIMEOUT: Duration = Duration::from_secs(3);

/// Packet work item sent to workers
struct PacketWork {
    /// Raw packet data (Ethernet frame) - stack allocated
    data: ArrayVec<u8, MAX_PACKET_SIZE>,
    /// Whether packet is outbound
    is_outbound: bool,
    /// Physical adapter internal name (GUID) - shared across all work items
    physical_adapter_name: Arc<String>,
}

/// Per-worker statistics
#[derive(Default)]
pub struct WorkerStats {
    pub packets_processed: AtomicU64,
    pub packets_tunneled: AtomicU64,
    pub packets_bypassed: AtomicU64,
    pub bytes_tunneled: AtomicU64,
    pub bytes_bypassed: AtomicU64,
}

/// Shared network throughput stats
#[derive(Clone)]
pub struct ThroughputStats {
    /// Bytes sent through VPN tunnel
    pub bytes_tx: Arc<AtomicU64>,
    /// Bytes received through VPN tunnel
    pub bytes_rx: Arc<AtomicU64>,
    /// Timestamp when stats were started
    pub started_at: Instant,
}

impl Default for ThroughputStats {
    fn default() -> Self {
        Self {
            bytes_tx: Arc::new(AtomicU64::new(0)),
            bytes_rx: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        }
    }
}

impl ThroughputStats {
    pub fn reset(&self) {
        self.bytes_tx.store(0, Ordering::Relaxed);
        self.bytes_rx.store(0, Ordering::Relaxed);
    }

    pub fn get_bytes_tx(&self) -> u64 {
        self.bytes_tx.load(Ordering::Relaxed)
    }

    pub fn get_bytes_rx(&self) -> u64 {
        self.bytes_rx.load(Ordering::Relaxed)
    }

    pub fn add_tx(&self, bytes: u64) {
        self.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_rx(&self, bytes: u64) {
        self.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// Join a thread with a timeout using a polling approach
fn join_with_timeout(handle: JoinHandle<()>, name: &str) -> bool {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);

    if handle.is_finished() {
        let _ = handle.join();
        return true;
    }

    while start.elapsed() < THREAD_JOIN_TIMEOUT {
        if handle.is_finished() {
            let _ = handle.join();
            log::debug!("{} thread joined successfully", name);
            return true;
        }
        thread::sleep(poll_interval);
    }

    log::error!(
        "{} thread did not stop within {:?} - detaching thread to prevent hang",
        name,
        THREAD_JOIN_TIMEOUT
    );
    std::mem::forget(handle);
    false
}

/// Context for V3 UDP relay forwarding
///
/// Workers use this to send intercepted packets to the relay server.
/// The relay wraps packets as [session_id][payload] and forwards to server:51821.
#[derive(Clone)]
pub struct RelayForwardContext {
    pub relay: Arc<crate::vpn::UdpRelay>,
}

impl RelayForwardContext {
    pub fn forward(&self, ip_packet: &[u8]) -> Result<usize, crate::error::SdkError> {
        self.relay.forward_outbound(ip_packet)
    }
}

/// Parallel packet interceptor - V3 only
pub struct ParallelInterceptor {
    /// Number of worker threads
    num_workers: usize,
    /// Lock-free process cache shared by all workers
    process_cache: Arc<LockFreeProcessCache>,
    /// Stop flag
    stop_flag: Arc<AtomicBool>,
    /// Worker thread handles
    worker_handles: Vec<JoinHandle<()>>,
    /// Reader thread handle
    reader_handle: Option<JoinHandle<()>>,
    /// Cache refresher thread handle
    refresher_handle: Option<JoinHandle<()>>,
    /// Physical adapter index
    physical_adapter_idx: Option<usize>,
    /// Physical adapter internal name (GUID)
    physical_adapter_name: Option<String>,
    /// Physical adapter friendly name (e.g., "Ethernet")
    physical_adapter_friendly_name: Option<String>,
    /// Whether we disabled TSO on the physical adapter
    tso_was_disabled: bool,
    /// Whether we disabled IPv6 on the physical adapter
    ipv6_was_disabled: bool,
    /// Interface index of the adapter with the default route
    default_route_if_index: Option<u32>,
    /// Whether interceptor is active
    active: bool,
    /// Per-worker stats
    worker_stats: Vec<Arc<WorkerStats>>,
    /// Global stats
    total_packets: AtomicU64,
    total_tunneled: AtomicU64,
    /// Shared throughput stats
    throughput_stats: ThroughputStats,
    /// V3 relay forwarding context
    relay_ctx: Option<Arc<RelayForwardContext>>,
    /// Inbound receiver thread handle
    inbound_receiver_handle: Option<JoinHandle<()>>,
    /// Flag to trigger immediate cache refresh (set by ETW)
    refresh_now_flag: Arc<AtomicBool>,
    /// Auto-router for dynamic relay switching and whitelist bypass.
    auto_router: Option<Arc<crate::vpn::auto_routing::AutoRouter>>,
    /// Route Assist: tunnel Roblox TCP API/bootstrap traffic too (not just UDP).
    api_tunneling_enabled: Arc<AtomicBool>,
}

impl ParallelInterceptor {
    /// Create new parallel interceptor (V3 mode only)
    pub fn new(tunnel_apps: Vec<String>) -> Self {
        let physical_cores = num_cpus::get_physical();
        let num_workers = physical_cores.min(4).max(1);

        log::info!(
            "Creating parallel interceptor with {} workers (CPUs: {}), V3 mode",
            num_workers,
            num_cpus::get(),
        );

        let worker_stats: Vec<Arc<WorkerStats>> = (0..num_workers)
            .map(|_| Arc::new(WorkerStats::default()))
            .collect();

        Self {
            num_workers,
            process_cache: Arc::new(LockFreeProcessCache::new(tunnel_apps)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            worker_handles: Vec::new(),
            reader_handle: None,
            refresher_handle: None,
            physical_adapter_idx: None,
            physical_adapter_name: None,
            physical_adapter_friendly_name: None,
            tso_was_disabled: false,
            ipv6_was_disabled: false,
            default_route_if_index: None,
            active: false,
            worker_stats,
            total_packets: AtomicU64::new(0),
            total_tunneled: AtomicU64::new(0),
            throughput_stats: ThroughputStats::default(),
            relay_ctx: None,
            inbound_receiver_handle: None,
            refresh_now_flag: Arc::new(AtomicBool::new(false)),
            auto_router: None,
            api_tunneling_enabled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Enable or disable Route Assist (TCP API/bootstrap tunneling). Cheap to
    /// toggle at runtime; workers read it per-batch.
    pub fn set_api_tunneling_enabled(&self, enabled: bool) {
        self.api_tunneling_enabled.store(enabled, Ordering::Relaxed);
        log::info!("Route Assist (TCP API tunneling) set to {}", enabled);
    }

    /// Trigger immediate cache refresh (call when ETW detects game process)
    pub fn trigger_refresh(&self) {
        self.refresh_now_flag.store(true, Ordering::Release);
    }

    /// Get throughput stats
    pub fn get_throughput_stats(&self) -> ThroughputStats {
        self.throughput_stats.clone()
    }

    /// Get physical adapter name (for diagnostics)
    pub fn get_physical_adapter_name(&self) -> Option<String> {
        self.physical_adapter_friendly_name.clone()
    }

    /// Get diagnostic info
    pub fn get_diagnostics(&self) -> (Option<String>, bool, u64, u64) {
        let adapter_name = self.physical_adapter_friendly_name.clone();
        let has_default_route = self.default_route_if_index.is_some();
        let mut tunneled = 0u64;
        let mut bypassed = 0u64;
        for stats in &self.worker_stats {
            tunneled += stats.packets_tunneled.load(Ordering::Relaxed);
            bypassed += stats.packets_bypassed.load(Ordering::Relaxed);
        }
        (adapter_name, has_default_route, tunneled, bypassed)
    }

    /// Set V3 relay context for forwarding packets
    pub fn set_relay_context(&mut self, ctx: Arc<RelayForwardContext>) {
        log::info!(
            "Set relay context: server={}, session={:016x}",
            ctx.relay.relay_addr(),
            ctx.relay.session_id_u64(),
        );
        self.relay_ctx = Some(ctx);
    }

    /// Switch relay address used by workers (auto-routing).
    pub fn switch_relay_addr(&self, new_addr: std::net::SocketAddr) -> bool {
        if let Some(ref relay) = self.relay_ctx {
            relay.relay.switch_relay(new_addr);
            true
        } else {
            false
        }
    }

    /// Get current relay address for diagnostics/comparison.
    pub fn current_relay_addr(&self) -> Option<std::net::SocketAddr> {
        self.relay_ctx.as_ref().map(|r| r.relay.relay_addr())
    }

    /// Set auto-router used in worker hot path.
    pub fn set_auto_router(&mut self, router: Arc<crate::vpn::auto_routing::AutoRouter>) {
        self.auto_router = Some(router);
    }

    /// Check if driver is available
    pub fn check_driver_available() -> bool {
        match ndisapi::Ndisapi::new("NDISRD") {
            Ok(_) => {
                log::info!("Windows Packet Filter driver available");
                true
            }
            Err(e) => {
                log::warn!("Windows Packet Filter driver not available: {}", e);
                false
            }
        }
    }

    /// Initialize interceptor
    pub fn initialize(&mut self) -> Result<(), SdkError> {
        if !Self::check_driver_available() {
            return Err(SdkError::SplitTunnel(
                "Windows Packet Filter driver not available".to_string(),
            ));
        }
        log::info!("Parallel interceptor initialized");
        Ok(())
    }

    /// Configure with tunnel apps (V3 mode - no VPN adapter needed)
    pub fn configure(&mut self, tunnel_apps: Vec<String>) -> Result<(), SdkError> {
        log::info!("Configuring parallel interceptor for V3 relay mode");

        Arc::get_mut(&mut self.process_cache)
            .ok_or_else(|| SdkError::SplitTunnel("Cache in use".to_string()))?
            .set_tunnel_apps(tunnel_apps);

        // Find physical adapter with retry
        const MAX_RETRIES: u32 = 5;
        const RETRY_DELAYS_MS: [u64; 5] = [500, 750, 1000, 1500, 2000];

        let mut last_error = String::new();

        for attempt in 1..=MAX_RETRIES {
            match self.find_physical_adapter() {
                Ok(()) => {
                    if attempt > 1 {
                        log::info!("Adapter detection succeeded on attempt {}", attempt);
                    }
                    return Ok(());
                }
                Err(e) => {
                    last_error = e.to_string();
                    if attempt < MAX_RETRIES {
                        let delay = RETRY_DELAYS_MS[attempt as usize - 1];
                        log::warn!(
                            "Adapter detection failed (attempt {}/{}): {}. Retrying in {}ms...",
                            attempt,
                            MAX_RETRIES,
                            e,
                            delay
                        );
                        std::thread::sleep(Duration::from_millis(delay));
                    }
                }
            }
        }

        Err(SdkError::SplitTunnel(format!(
            "Failed to find physical adapter after {} attempts: {}",
            MAX_RETRIES, last_error
        )))
    }

    /// Find the physical network adapter to intercept
    fn find_physical_adapter(&mut self) -> Result<(), SdkError> {
        let default_route_if_index = Self::get_default_route_interface_index();
        self.default_route_if_index = default_route_if_index;

        let driver = ndisapi::Ndisapi::new("NDISRD")
            .map_err(|e| SdkError::SplitTunnel(format!("Failed to open driver: {}", e)))?;

        let adapters = driver
            .get_tcpip_bound_adapters_info()
            .map_err(|e| SdkError::SplitTunnel(format!("Failed to enumerate adapters: {}", e)))?;

        log::info!("Found {} adapters", adapters.len());

        let mut physical_candidates: Vec<(usize, String, String, i32)> = Vec::new();

        for (idx, adapter) in adapters.iter().enumerate() {
            let internal_name = adapter.get_name();
            let friendly_name = get_adapter_friendly_name(&internal_name)
                .or_else(|| get_adapter_friendly_name_v2(&internal_name))
                .unwrap_or_default();

            log::info!(
                "  Adapter {}: '{}' (internal: {})",
                idx,
                friendly_name,
                internal_name
            );

            let name_lower = internal_name.to_lowercase();
            let friendly_lower = friendly_name.to_lowercase();

            // Skip VPN and virtual adapters
            let is_virtual = name_lower.contains("loopback")
                || friendly_lower.contains("loopback")
                || friendly_lower.contains("isatap")
                || friendly_lower.contains("teredo")
                || friendly_lower.contains("swifttunnel")
                || friendly_lower.contains("wintun")
                || friendly_lower.contains("radmin")
                || friendly_lower.contains("hamachi")
                || friendly_lower.contains("zerotier")
                || friendly_lower.contains("tailscale")
                || friendly_lower.contains("wireguard")
                || friendly_lower.contains("openvpn")
                || friendly_lower.contains("tap-windows")
                || friendly_lower.contains("nordvpn")
                || friendly_lower.contains("expressvpn")
                || friendly_lower.contains("surfshark")
                || friendly_lower.contains("proton")
                || friendly_lower.contains("mullvad")
                || friendly_lower.contains("private internet")
                || friendly_lower.contains("cyberghost")
                || (!friendly_lower.is_empty()
                    && (friendly_lower.contains("virtual")
                        || friendly_lower.contains("vpn")
                        || friendly_lower.contains("tunnel")));

            if is_virtual || friendly_name.is_empty() {
                log::info!("    -> Skipped");
                continue;
            }

            let mut score = 0i32;

            let adapter_if_index = Self::get_adapter_interface_index(&internal_name);
            let has_default_route = adapter_if_index.is_some()
                && default_route_if_index.is_some()
                && adapter_if_index == default_route_if_index;

            if has_default_route {
                score += 1000;
            }
            if friendly_lower.contains("ethernet")
                || friendly_lower.contains("intel")
                || friendly_lower.contains("realtek")
                || friendly_lower.contains("broadcom")
            {
                score += 100;
            }
            if friendly_lower.contains("wi-fi")
                || friendly_lower.contains("wifi")
                || friendly_lower.contains("wireless")
            {
                score += 80;
            }
            if !friendly_name.is_empty() {
                score += 50;
            }
            score += (10 - idx.min(10)) as i32;

            log::info!("    -> Physical candidate (score: {})", score);
            physical_candidates.push((
                idx,
                friendly_name.clone(),
                internal_name.to_string(),
                score,
            ));
        }

        let selected = physical_candidates.iter().max_by_key(|x| x.3);

        if let Some((idx, friendly_name, internal_name, _score)) = selected {
            self.physical_adapter_idx = Some(*idx);
            self.physical_adapter_name = Some(internal_name.clone());
            self.physical_adapter_friendly_name = Some(friendly_name.clone());
            log::info!(
                "Selected physical adapter: {} (index {})",
                friendly_name,
                idx
            );
        } else {
            return Err(SdkError::SplitTunnel(
                "No physical adapter found".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the interface index that has the default route (0.0.0.0/0)
    #[cfg(windows)]
    fn get_default_route_interface_index() -> Option<u32> {
        use windows::Win32::Foundation::*;
        use windows::Win32::NetworkManagement::IpHelper::*;

        unsafe {
            let mut size: u32 = 0;
            let _ = GetIpForwardTable(None, &mut size, false);
            if size == 0 {
                return None;
            }

            let mut buffer = vec![0u8; size as usize];
            let table = buffer.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;

            if GetIpForwardTable(Some(table), &mut size, false) != NO_ERROR.0 {
                return None;
            }

            let num_entries = (*table).dwNumEntries as usize;
            let entries = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries);

            let mut best_metric = u32::MAX;
            let mut best_if_index = None;

            for row in entries {
                if row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardNextHop != 0 {
                    if row.dwForwardMetric1 < best_metric {
                        best_metric = row.dwForwardMetric1;
                        best_if_index = Some(row.dwForwardIfIndex);
                    }
                }
            }

            best_if_index
        }
    }

    #[cfg(not(windows))]
    fn get_default_route_interface_index() -> Option<u32> {
        None
    }

    /// Get interface index from adapter GUID
    #[cfg(windows)]
    fn get_adapter_interface_index(adapter_guid: &str) -> Option<u32> {
        use windows::Win32::NetworkManagement::IpHelper::*;
        use windows::Win32::Networking::WinSock::AF_INET;

        unsafe {
            let mut size: u32 = 0;
            let _ = GetAdaptersAddresses(
                AF_INET.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                None,
                &mut size,
            );
            if size == 0 {
                return None;
            }

            let mut buffer = vec![0u8; size as usize];
            let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

            if GetAdaptersAddresses(
                AF_INET.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(adapter_addresses),
                &mut size,
            ) != 0
            {
                return None;
            }

            let mut current = adapter_addresses;
            while !current.is_null() {
                let adapter = &*current;
                let name = adapter.AdapterName.to_string().unwrap_or_default();
                let guid_from_adapter = adapter_guid.trim_start_matches("\\DEVICE\\");
                if guid_from_adapter == name
                    || guid_from_adapter.trim_matches('{').trim_matches('}')
                        == name.trim_matches('{').trim_matches('}')
                {
                    return Some(adapter.Anonymous1.Anonymous.IfIndex);
                }
                current = adapter.Next;
            }
        }

        None
    }

    #[cfg(not(windows))]
    fn get_adapter_interface_index(_adapter_guid: &str) -> Option<u32> {
        None
    }

    /// Run a PowerShell command with a timeout
    #[cfg(windows)]
    fn run_powershell_with_timeout(script: &str, timeout_secs: u64) -> bool {
        let mut child = match std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .creation_flags(0x08000000)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return false,
        };

        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    let _ = child.kill();
                    return false;
                }
            }
        }
    }

    /// Disable TSO/LSO on the physical adapter
    #[cfg(windows)]
    pub fn disable_adapter_offload(&mut self) -> Result<(), SdkError> {
        let friendly_name = match &self.physical_adapter_friendly_name {
            Some(name) => name.clone(),
            None => return Ok(()),
        };

        log::info!("Disabling TSO/LSO on adapter: {}", friendly_name);

        let script = format!(
            r#"
            $ErrorActionPreference = 'SilentlyContinue'
            $adapter = '{}'
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv4' -RegistryValue 0 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv6' -RegistryValue 0 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv4' -RegistryValue 0 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv4' -RegistryValue 0 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv6' -RegistryValue 0 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv6' -RegistryValue 0 2>$null
            Write-Host 'Offload disabled'
            "#,
            friendly_name.replace("'", "''")
        );

        if Self::run_powershell_with_timeout(&script, 5) {
            log::info!("TSO/LSO disabled successfully on {}", friendly_name);
            self.tso_was_disabled = true;
        } else {
            log::warn!("Failed to disable TSO (non-fatal)");
        }

        Ok(())
    }

    #[cfg(not(windows))]
    pub fn disable_adapter_offload(&mut self) -> Result<(), SdkError> {
        Ok(())
    }

    /// Re-enable TSO/LSO on the physical adapter
    #[cfg(windows)]
    pub fn enable_adapter_offload(&mut self) {
        if !self.tso_was_disabled {
            return;
        }

        let friendly_name = match &self.physical_adapter_friendly_name {
            Some(name) => name.clone(),
            None => return,
        };

        let script = format!(
            r#"
            $ErrorActionPreference = 'SilentlyContinue'
            $adapter = '{}'
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv4' -RegistryValue 1 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv6' -RegistryValue 1 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv4' -RegistryValue 3 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv4' -RegistryValue 3 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv6' -RegistryValue 3 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv6' -RegistryValue 3 2>$null
            Write-Host 'Offload enabled'
            "#,
            friendly_name.replace("'", "''")
        );

        if Self::run_powershell_with_timeout(&script, 5) {
            log::info!("TSO/LSO re-enabled on {}", friendly_name);
        }
        self.tso_was_disabled = false;
    }

    #[cfg(not(windows))]
    pub fn enable_adapter_offload(&mut self) {}

    /// Disable IPv6 on the physical adapter (SwiftTunnel is IPv4-only)
    #[cfg(windows)]
    pub fn disable_ipv6(&mut self) -> Result<(), SdkError> {
        let friendly_name = match &self.physical_adapter_friendly_name {
            Some(name) => name.clone(),
            None => return Ok(()),
        };

        let script = format!(
            r#"
            $ErrorActionPreference = 'SilentlyContinue'
            Disable-NetAdapterBinding -Name '{}' -ComponentId ms_tcpip6 2>$null
            Write-Host 'IPv6 disabled'
            "#,
            friendly_name.replace("'", "''")
        );

        if Self::run_powershell_with_timeout(&script, 5) {
            log::info!("IPv6 disabled on {}", friendly_name);
            self.ipv6_was_disabled = true;
        }

        Ok(())
    }

    #[cfg(not(windows))]
    pub fn disable_ipv6(&mut self) -> Result<(), SdkError> {
        Ok(())
    }

    /// Re-enable IPv6 on the physical adapter
    #[cfg(windows)]
    pub fn enable_ipv6(&mut self) {
        if !self.ipv6_was_disabled {
            return;
        }

        let friendly_name = match &self.physical_adapter_friendly_name {
            Some(name) => name.clone(),
            None => return,
        };

        let script = format!(
            r#"
            $ErrorActionPreference = 'SilentlyContinue'
            Enable-NetAdapterBinding -Name '{}' -ComponentId ms_tcpip6 2>$null
            Write-Host 'IPv6 enabled'
            "#,
            friendly_name.replace("'", "''")
        );

        if Self::run_powershell_with_timeout(&script, 5) {
            log::info!("IPv6 re-enabled on {}", friendly_name);
        }
        self.ipv6_was_disabled = false;
    }

    #[cfg(not(windows))]
    pub fn enable_ipv6(&mut self) {}

    /// Start parallel interception
    pub fn start(&mut self) -> Result<(), SdkError> {
        if self.active {
            return Ok(());
        }

        let physical_idx = self
            .physical_adapter_idx
            .ok_or_else(|| SdkError::SplitTunnel("Physical adapter not configured".to_string()))?;

        log::info!(
            "Starting parallel interceptor with {} workers",
            self.num_workers
        );

        self.disable_adapter_offload()?;
        self.disable_ipv6()?;

        self.stop_flag.store(false, Ordering::SeqCst);
        self.active = true;

        let (senders, receivers): (Vec<_>, Vec<_>) = (0..self.num_workers)
            .map(|_| crossbeam_channel::bounded::<PacketWork>(1024))
            .unzip();

        // Start cache refresher thread
        let refresher_stop = Arc::clone(&self.stop_flag);
        let refresher_cache = Arc::clone(&self.process_cache);
        let refresh_now = Arc::clone(&self.refresh_now_flag);
        self.refresher_handle = Some(thread::spawn(move || {
            run_cache_refresher(refresher_cache, refresher_stop, refresh_now);
        }));

        self.throughput_stats.reset();

        // Start worker threads
        for (worker_id, receiver) in receivers.into_iter().enumerate() {
            let stop_flag = Arc::clone(&self.stop_flag);
            let process_cache = Arc::clone(&self.process_cache);
            let stats = Arc::clone(&self.worker_stats[worker_id]);
            let throughput = self.throughput_stats.clone();
            let relay_ctx = self.relay_ctx.clone();
            let auto_router = self.auto_router.clone();
            let api_tunneling_enabled = Arc::clone(&self.api_tunneling_enabled);

            let handle = thread::spawn(move || {
                set_thread_affinity(worker_id);
                run_packet_worker(
                    worker_id,
                    receiver,
                    process_cache,
                    stats,
                    throughput,
                    stop_flag,
                    relay_ctx,
                    auto_router,
                    api_tunneling_enabled,
                );
            });

            self.worker_handles.push(handle);
        }

        // Start packet reader/dispatcher thread
        let reader_stop = Arc::clone(&self.stop_flag);
        let num_workers = self.num_workers;
        let physical_name =
            Arc::new(self.physical_adapter_name.clone().ok_or_else(|| {
                SdkError::SplitTunnel("Physical adapter name not set".to_string())
            })?);

        self.reader_handle = Some(thread::spawn(move || {
            if let Err(e) = run_packet_reader(
                physical_idx,
                physical_name,
                senders,
                reader_stop,
                num_workers,
            ) {
                log::error!("Packet reader error: {}", e);
            }
        }));

        // Start V3 inbound receiver thread
        if let Some(ref relay_ctx) = self.relay_ctx {
            let inbound_config = self.create_inbound_config();
            if let Some(config) = inbound_config {
                let relay = Arc::clone(relay_ctx);
                let inbound_stop = Arc::clone(&self.stop_flag);
                let throughput = self.throughput_stats.clone();

                self.inbound_receiver_handle = Some(thread::spawn(move || {
                    run_v3_inbound_receiver(relay, config, inbound_stop, throughput);
                }));
                log::info!("V3 inbound receiver thread started");
            }
        }

        log::info!("Parallel interceptor started");
        Ok(())
    }

    /// Stop interception
    pub fn stop(&mut self) {
        if !self.active {
            return;
        }

        log::info!("Stopping parallel interceptor...");
        self.stop_flag.store(true, Ordering::SeqCst);

        if let Some(handle) = self.reader_handle.take() {
            join_with_timeout(handle, "Reader");
        }
        for (i, handle) in self.worker_handles.drain(..).enumerate() {
            join_with_timeout(handle, &format!("Worker-{}", i));
        }
        if let Some(handle) = self.refresher_handle.take() {
            join_with_timeout(handle, "Refresher");
        }
        if let Some(handle) = self.inbound_receiver_handle.take() {
            join_with_timeout(handle, "Inbound");
        }

        self.active = false;

        let total = self.total_packets.load(Ordering::Relaxed);
        let tunneled = self.total_tunneled.load(Ordering::Relaxed);
        log::info!(
            "Parallel interceptor stopped - {} total, {} tunneled ({:.1}%)",
            total,
            tunneled,
            if total > 0 {
                (tunneled as f64 / total as f64) * 100.0
            } else {
                0.0
            }
        );

        self.enable_adapter_offload();
        self.enable_ipv6();
    }

    /// Check if active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get snapshot for external use
    pub fn get_snapshot(&self) -> Arc<ProcessSnapshot> {
        self.process_cache.get_snapshot()
    }

    /// Immediately register a process detected via ETW
    pub fn register_process_immediate(&self, pid: u32, name: String) {
        self.process_cache.register_process_immediate(pid, name);
    }

    /// Create InboundConfig for the inbound receiver
    fn create_inbound_config(&self) -> Option<InboundConfig> {
        let physical_name = self.physical_adapter_name.clone()?;

        let driver = ndisapi::Ndisapi::new("NDISRD").ok()?;
        let adapters = driver.get_tcpip_bound_adapters_info().ok()?;

        let adapter_mac: [u8; 6] = match adapters.iter().find(|a| a.get_name() == &physical_name) {
            Some(a) => a.get_hw_address()[0..6].try_into().unwrap_or([0; 6]),
            None => return None,
        };

        Some(InboundConfig {
            physical_adapter_name: physical_name,
            adapter_mac,
        })
    }
}

impl Drop for ParallelInterceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Configuration for inbound packet injection
#[derive(Clone)]
struct InboundConfig {
    physical_adapter_name: String,
    adapter_mac: [u8; 6],
}

/// Set thread affinity to specific CPU core
fn set_thread_affinity(core_id: usize) {
    #[cfg(target_os = "windows")]
    unsafe {
        use windows::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask};
        let mask = 1usize << core_id;
        let _ = SetThreadAffinityMask(GetCurrentThread(), mask);
    }
}

/// Packet reader thread - reads from ndisapi and dispatches to workers
fn run_packet_reader(
    physical_idx: usize,
    physical_name: Arc<String>,
    senders: Vec<crossbeam_channel::Sender<PacketWork>>,
    stop_flag: Arc<AtomicBool>,
    num_workers: usize,
) -> Result<(), SdkError> {
    use ndisapi::{DirectionFlags, EthMRequest, EthMRequestMut, FilterFlags, IntermediateBuffer};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

    const BATCH_SIZE: usize = 64;

    log::info!(
        "Packet reader started (physical idx: {}, name: '{}', {} workers)",
        physical_idx,
        physical_name,
        num_workers
    );

    let driver = ndisapi::Ndisapi::new("NDISRD")
        .map_err(|e| SdkError::SplitTunnel(format!("Failed to open driver: {}", e)))?;

    let adapters = driver
        .get_tcpip_bound_adapters_info()
        .map_err(|e| SdkError::SplitTunnel(format!("Failed to get adapters: {}", e)))?;

    if physical_idx >= adapters.len() {
        return Err(SdkError::SplitTunnel(
            "Physical adapter index out of range".to_string(),
        ));
    }

    let physical_handle = adapters[physical_idx].get_handle();

    let event: HANDLE = unsafe {
        CreateEventW(None, true, false, None)
            .map_err(|e| SdkError::SplitTunnel(format!("Failed to create event: {}", e)))?
    };

    driver
        .set_packet_event(physical_handle, event)
        .map_err(|e| SdkError::SplitTunnel(format!("Failed to set packet event: {}", e)))?;

    driver
        .set_adapter_mode(physical_handle, FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)
        .map_err(|e| SdkError::SplitTunnel(format!("Failed to set adapter mode: {}", e)))?;

    let mut packets: Vec<IntermediateBuffer> = vec![Default::default(); BATCH_SIZE];
    let mut passthrough_to_adapter: EthMRequest<BATCH_SIZE>;
    let mut passthrough_to_mstcp: EthMRequest<BATCH_SIZE>;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        unsafe {
            WaitForSingleObject(event, 100);
        }

        let mut to_read = EthMRequestMut::from_iter(physical_handle, packets.iter_mut());
        let packets_read = driver.read_packets::<BATCH_SIZE>(&mut to_read).unwrap_or(0);

        if packets_read == 0 {
            unsafe {
                let _ = ResetEvent(event);
            }
            continue;
        }

        passthrough_to_adapter = EthMRequest::new(physical_handle);
        passthrough_to_mstcp = EthMRequest::new(physical_handle);

        for i in 0..packets_read {
            let direction_flags = packets[i].get_device_flags();
            let is_outbound = direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND;
            let data = packets[i].get_data();

            if is_outbound {
                if let Some((src_port, _)) = parse_ports(data) {
                    let worker_id = if num_workers > 0 {
                        (src_port as usize) % num_workers
                    } else {
                        0
                    };

                    let mut packet_data: ArrayVec<u8, MAX_PACKET_SIZE> = ArrayVec::new();
                    let copy_len = data.len().min(MAX_PACKET_SIZE);
                    packet_data.try_extend_from_slice(&data[..copy_len]).ok();

                    let work = PacketWork {
                        data: packet_data,
                        is_outbound: true,
                        physical_adapter_name: Arc::clone(&physical_name),
                    };

                    if senders[worker_id].try_send(work).is_err() {
                        let _ = passthrough_to_adapter.push(&packets[i]);
                    }
                } else {
                    let _ = passthrough_to_adapter.push(&packets[i]);
                }
            } else {
                let _ = passthrough_to_mstcp.push(&packets[i]);
            }
        }

        if passthrough_to_adapter.get_packet_number() > 0 {
            let _ = driver.send_packets_to_adapter::<BATCH_SIZE>(&passthrough_to_adapter);
        }
        if passthrough_to_mstcp.get_packet_number() > 0 {
            let _ = driver.send_packets_to_mstcp::<BATCH_SIZE>(&passthrough_to_mstcp);
        }

        unsafe {
            let _ = ResetEvent(event);
        }
    }

    let _ = driver.set_adapter_mode(physical_handle, FilterFlags::default());
    unsafe {
        let _ = CloseHandle(event);
    }

    log::info!("Packet reader stopped");
    Ok(())
}

/// Worker thread - processes packets and routes to V3 relay or passthrough
fn run_packet_worker(
    worker_id: usize,
    receiver: crossbeam_channel::Receiver<PacketWork>,
    process_cache: Arc<LockFreeProcessCache>,
    stats: Arc<WorkerStats>,
    throughput: ThroughputStats,
    stop_flag: Arc<AtomicBool>,
    relay_ctx: Option<Arc<RelayForwardContext>>,
    auto_router: Option<Arc<crate::vpn::auto_routing::AutoRouter>>,
    api_tunneling_enabled: Arc<AtomicBool>,
) {
    log::info!("Worker {} started", worker_id);

    let mut snapshot = process_cache.get_snapshot();
    let mut snapshot_version = snapshot.version;
    let mut snapshot_check_counter = 0u32;

    // Per-worker inline cache (only caches TRUE results)
    let mut inline_cache: HashMap<(Ipv4Addr, u16, Protocol), bool> = HashMap::with_capacity(1024);

    let mut relay_success = 0u64;
    let mut relay_fail = 0u64;
    let mut consecutive_timeouts = 0u32;

    // Open driver for bypass packets
    let driver = match ndisapi::Ndisapi::new("NDISRD") {
        Ok(d) => d,
        Err(e) => {
            log::error!("Worker {} failed to open driver: {}", worker_id, e);
            return;
        }
    };
    let adapters = match driver.get_tcpip_bound_adapters_info() {
        Ok(a) => a,
        Err(e) => {
            log::error!("Worker {} failed to get adapters: {}", worker_id, e);
            return;
        }
    };

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        let timeout_ms = if consecutive_timeouts > 10 { 50 } else { 5 };

        let work = match receiver.recv_timeout(Duration::from_millis(timeout_ms)) {
            Ok(w) => {
                consecutive_timeouts = 0;
                w
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };

        // Periodically refresh snapshot
        snapshot_check_counter += 1;
        if snapshot_check_counter >= 10 {
            snapshot_check_counter = 0;
            let new_snapshot = process_cache.get_snapshot();
            if new_snapshot.version != snapshot_version {
                snapshot_version = new_snapshot.version;
                inline_cache.clear();
            }
            snapshot = new_snapshot;
        }

        stats.packets_processed.fetch_add(1, Ordering::Relaxed);
        let packet_len = work.data.len() as u64;

        if work.is_outbound {
            let api_tunneling = api_tunneling_enabled.load(Ordering::Relaxed);
            let should_tunnel =
                should_route_to_relay(&work.data, &snapshot, &mut inline_cache, api_tunneling);
            let auto_routing_bypass =
                should_tunnel && auto_router.as_ref().map_or(false, |r| r.is_bypassed());

            // Log tunnel decisions periodically so we can see what's happening
            {
                let count = stats.packets_processed.load(Ordering::Relaxed);
                if count % 500 == 1 {
                    log::info!(
                        "interceptor: processed={} tunneled={} bypassed={} snapshot_pids={} tunnel_apps={:?}",
                        count,
                        stats.packets_tunneled.load(Ordering::Relaxed),
                        stats.packets_bypassed.load(Ordering::Relaxed),
                        snapshot.pid_names.len(),
                        snapshot.tunnel_apps.iter().take(3).collect::<Vec<_>>()
                    );
                }
                if should_tunnel && count % 100 == 1 {
                    log::debug!("interceptor: pkt → tunnel (bypass={})", auto_routing_bypass);
                }
            }

            if auto_routing_bypass && work.data.len() >= 14 + 20 {
                let ip_start = 14;
                let dst_ip = Ipv4Addr::new(
                    work.data[ip_start + 16],
                    work.data[ip_start + 17],
                    work.data[ip_start + 18],
                    work.data[ip_start + 19],
                );
                if is_roblox_game_server_ip(dst_ip) {
                    if let Some(ref ar) = auto_router {
                        ar.evaluate_game_server(dst_ip);
                    }
                }
            }

            if should_tunnel && !auto_routing_bypass {
                if work.data.len() <= 14 {
                    continue;
                }
                let ip_packet = &work.data[14..];

                if ip_packet.len() >= 20 {
                    let dst_ip =
                        Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
                    if is_roblox_game_server_ip(dst_ip) {
                        if let Some(ref ar) = auto_router {
                            ar.evaluate_game_server(dst_ip);
                            if ar.is_lookup_pending(dst_ip) {
                                continue;
                            }
                        }
                    }
                }

                stats.packets_tunneled.fetch_add(1, Ordering::Relaxed);
                stats
                    .bytes_tunneled
                    .fetch_add(packet_len, Ordering::Relaxed);
                throughput.add_tx(packet_len);

                // Fix checksums before forwarding
                let mut pkt_buf = ip_packet.to_vec();
                fix_packet_checksums(&mut pkt_buf);

                // V3: Forward via UDP relay
                if let Some(ref relay) = relay_ctx {
                    match relay.forward(&pkt_buf) {
                        Ok(_) => {
                            relay_success += 1;
                            if relay_success <= 5 {
                                log::info!(
                                    "Worker {}: V3 relay forward OK - {} bytes",
                                    worker_id,
                                    pkt_buf.len()
                                );
                            }
                        }
                        Err(e) => {
                            relay_fail += 1;
                            if relay_fail <= 10 {
                                log::warn!("Worker {}: V3 relay forward failed: {}", worker_id, e);
                            }
                        }
                    }
                } else {
                    // No relay context - bypass
                    send_bypass_packet(&driver, &adapters, &work);
                }
            } else {
                stats.packets_bypassed.fetch_add(1, Ordering::Relaxed);
                stats
                    .bytes_bypassed
                    .fetch_add(packet_len, Ordering::Relaxed);
                send_bypass_packet(&driver, &adapters, &work);
            }
        }
    }

    log::info!(
        "Worker {} stopped - processed: {}, tunneled: {}, bypassed: {}",
        worker_id,
        stats.packets_processed.load(Ordering::Relaxed),
        stats.packets_tunneled.load(Ordering::Relaxed),
        stats.packets_bypassed.load(Ordering::Relaxed),
    );
}

/// Send a bypass packet to the physical adapter
fn send_bypass_packet(
    driver: &ndisapi::Ndisapi,
    adapters: &[ndisapi::NetworkAdapterInfo],
    work: &PacketWork,
) {
    use ndisapi::{DirectionFlags, EthMRequest, IntermediateBuffer};

    let adapter = match adapters
        .iter()
        .find(|a| a.get_name() == work.physical_adapter_name.as_str())
    {
        Some(a) => a,
        None => return,
    };

    let adapter_handle = adapter.get_handle();

    const MAX_ETHER_FRAME: usize = 1522;
    if work.data.len() > MAX_ETHER_FRAME {
        return;
    }

    let mut buffer = IntermediateBuffer::default();
    buffer.device_flags = DirectionFlags::PACKET_FLAG_ON_SEND;
    buffer.length = work.data.len() as u32;
    buffer.buffer.0[..work.data.len()].copy_from_slice(&work.data);

    let mut to_adapter: EthMRequest<1> = EthMRequest::new(adapter_handle);
    if to_adapter.push(&buffer).is_ok() {
        let _ = driver.send_packets_to_adapter::<1>(&to_adapter);
    }
}

/// Cache refresher thread - single writer
fn run_cache_refresher(
    cache: Arc<LockFreeProcessCache>,
    stop_flag: Arc<AtomicBool>,
    refresh_now: Arc<AtomicBool>,
) {
    use super::process_tracker::{ConnectionKey, Protocol};
    #[cfg(windows)]
    use windows::Win32::NetworkManagement::IpHelper::*;

    log::info!("Cache refresher started (event-driven + 2s fallback)");

    let tunnel_apps = cache.tunnel_apps();
    log::info!(
        "Cache refresher: tunnel_apps = {:?}",
        tunnel_apps.iter().take(5).collect::<Vec<_>>()
    );

    let mut refresh_count = 0u64;
    let mut first_run = true;
    let mut connections: HashMap<ConnectionKey, u32> = HashMap::with_capacity(2048);
    let mut pid_names: HashMap<u32, String> = HashMap::with_capacity(512);

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        if first_run {
            first_run = false;
        } else {
            let mut slept_ms = 0u32;
            const SLEEP_CHUNK_MS: u32 = 50;
            const MAX_SLEEP_MS: u32 = 2000;

            while slept_ms < MAX_SLEEP_MS {
                if refresh_now.swap(false, Ordering::AcqRel) {
                    log::info!("Cache refresher: ETW triggered immediate refresh");
                    break;
                }
                if stop_flag.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(SLEEP_CHUNK_MS as u64));
                slept_ms += SLEEP_CHUNK_MS;
            }
        }

        connections.clear();
        pid_names.clear();

        // Get TCP table
        #[cfg(windows)]
        unsafe {
            let mut size: u32 = 0;
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                2,
                TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                0,
            );
            if size > 0 {
                let mut buffer = vec![0u8; size as usize];
                if GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2,
                    TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                    0,
                ) == 0
                {
                    let header_size = std::mem::size_of::<u32>();
                    if buffer.len() >= header_size {
                        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                        let num_entries = table.dwNumEntries as usize;
                        let entry_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                        let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
                        let safe_entries = num_entries.min(max_entries);
                        let entries =
                            std::slice::from_raw_parts(table.table.as_ptr(), safe_entries);
                        for entry in entries {
                            let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                            let local_port = u16::from_be(entry.dwLocalPort as u16);
                            connections.insert(
                                ConnectionKey::new(local_ip, local_port, Protocol::Tcp),
                                entry.dwOwningPid,
                            );
                        }
                    }
                }
            }
        }

        // Get UDP table
        #[cfg(windows)]
        unsafe {
            let mut size: u32 = 0;
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                2,
                UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                0,
            );
            if size > 0 {
                let mut buffer = vec![0u8; size as usize];
                if GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2,
                    UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                    0,
                ) == 0
                {
                    let header_size = std::mem::size_of::<u32>();
                    if buffer.len() >= header_size {
                        let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                        let num_entries = table.dwNumEntries as usize;
                        let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                        let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
                        let safe_entries = num_entries.min(max_entries);
                        let entries =
                            std::slice::from_raw_parts(table.table.as_ptr(), safe_entries);
                        for entry in entries {
                            let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                            let local_port = u16::from_be(entry.dwLocalPort as u16);
                            connections.insert(
                                ConnectionKey::new(local_ip, local_port, Protocol::Udp),
                                entry.dwOwningPid,
                            );
                        }
                    }
                }
            }
        }

        // Resolve process names for every PID that owns a connection.
        #[cfg(windows)]
        {
            for &pid in connections.values() {
                if !pid_names.contains_key(&pid) {
                    if let Some(name) = get_process_name_by_pid(pid) {
                        pid_names.insert(pid, name);
                    }
                }
            }
        }

        // Every 10th iteration, do a full process enumeration so we discover the
        // tunnel app's PID even when none of its sockets are in the owner tables
        // yet. This is what lets `tunnel_udp_ports` and `is_tunnel_pid` match the
        // app's game sockets the instant they appear. (Matches the desktop app's
        // sysinfo full scan.)
        let do_full_process_scan = refresh_count % 10 == 0;
        let tunnel_apps = cache.tunnel_apps();

        if do_full_process_scan {
            for (pid, name) in enumerate_all_processes() {
                let stem = name.trim_end_matches(".exe");
                let is_tunnel = tunnel_apps.contains(&name)
                    || tunnel_apps.iter().any(|app| {
                        let app_stem = app.trim_end_matches(".exe");
                        stem.contains(app_stem) || app_stem.contains(stem)
                    });
                if is_tunnel {
                    pid_names.entry(pid).or_insert(name);
                }
            }
        }

        // Log tunnel app visibility every 10 refreshes to avoid spam
        if refresh_count % 10 == 0 {
            let tunnel_apps = cache.tunnel_apps();
            let matched: Vec<_> = pid_names.values()
                .map(|n| n.to_lowercase())
                .filter(|n| tunnel_apps.contains(n.as_str()))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            let udp_ports = ProcessSnapshot::compute_tunnel_udp_ports(&connections, &pid_names, &tunnel_apps);
            if !matched.is_empty() {
                log::info!(
                    "cache refresh #{}: tunnel apps active: {:?} (tunnel_udp_ports={})",
                    refresh_count, matched, udp_ports.len()
                );
            } else {
                log::info!("cache refresh #{}: no tunnel apps in table (connections={} pids={})",
                    refresh_count, connections.len(), pid_names.len());
            }
        }

        cache.update(connections.clone(), pid_names.clone());
        refresh_count += 1;

        if refresh_count % 100 == 0 {
            let snap = cache.get_snapshot();
            log::debug!(
                "Cache refresh #{}: {} connections, {} PIDs",
                refresh_count,
                snap.connections.len(),
                snap.pid_names.len()
            );
        }
    }

    log::info!("Cache refresher stopped");
}

/// Get process name by PID
#[cfg(windows)]
fn get_process_name_by_pid(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        if handle.is_invalid() || handle.0.is_null() {
            return None;
        }

        let mut buffer = [0u16; 260];
        let mut size = buffer.len() as u32;

        if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            let _ = CloseHandle(handle);
            let path = String::from_utf16_lossy(&buffer[..size as usize]);
            let name = path.rsplit('\\').next().unwrap_or(&path);
            return Some(name.to_string());
        }

        let _ = CloseHandle(handle);
        None
    }
}

/// Enumerate all running processes as (pid, lowercase exe name).
///
/// Mirrors the desktop app's full `sysinfo` process scan: we must find the
/// tunnel app's PID even when it has no entry in the TCP/UDP owner tables yet,
/// otherwise `tunnel_udp_ports`/`is_tunnel_pid` can never match its sockets.
#[cfg(windows)]
fn enumerate_all_processes() -> Vec<(u32, String)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut out = Vec::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return out,
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase();
                if !name.is_empty() {
                    out.push((entry.th32ProcessID, name));
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }
    out
}

#[cfg(not(windows))]
fn enumerate_all_processes() -> Vec<(u32, String)> {
    Vec::new()
}

/// Parse ports from Ethernet frame (returns src_port, dst_port)
#[inline(always)]
fn parse_ports(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() < 14 + 20 + 4 {
        return None;
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return None;
    }

    let version = (data[14] >> 4) & 0xF;
    if version != 4 {
        return None;
    }

    let ihl = ((data[14] & 0xF) as usize) * 4;
    let protocol = data[14 + 9];
    if protocol != 6 && protocol != 17 {
        return None;
    }

    let transport_start = 14 + ihl;
    if data.len() < transport_start + 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
    let dst_port = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);

    Some((src_port, dst_port))
}

/// Determine if packet should be routed to V3 relay
fn should_route_to_relay(
    data: &[u8],
    snapshot: &ProcessSnapshot,
    inline_cache: &mut HashMap<(Ipv4Addr, u16, Protocol), bool>,
    api_tunneling: bool,
) -> bool {
    if data.len() < 14 + 20 + 4 {
        return false;
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return false;
    }

    let ip_start = 14;
    let version = (data[ip_start] >> 4) & 0xF;
    if version != 4 {
        return false;
    }

    let ihl = ((data[ip_start] & 0xF) as usize) * 4;
    let protocol_num = data[ip_start + 9];
    let protocol = match protocol_num {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return false,
    };

    let src_ip = Ipv4Addr::new(
        data[ip_start + 12],
        data[ip_start + 13],
        data[ip_start + 14],
        data[ip_start + 15],
    );
    let dst_ip = Ipv4Addr::new(
        data[ip_start + 16],
        data[ip_start + 17],
        data[ip_start + 18],
        data[ip_start + 19],
    );

    let transport_start = ip_start + ihl;
    if data.len() < transport_start + 4 {
        return false;
    }

    let src_port = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
    let dst_port = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);

    // Initial TCP SYN detection (used for Route Assist TCP bootstrap).
    let tcp_flags = if protocol == Protocol::Tcp && data.len() > transport_start + 13 {
        Some(data[transport_start + 13])
    } else {
        None
    };
    let is_tcp_initial_syn =
        tcp_flags.is_some_and(|flags| (flags & 0x02) != 0 && (flags & 0x10) == 0);

    // Phase 1: Check snapshot cache (fast path) - process-ownership based.
    if snapshot.should_tunnel_v3(src_ip, src_port, protocol, dst_ip, dst_port, api_tunneling) {
        let cache_key = (src_ip, src_port, protocol);
        if inline_cache.len() < 10000 {
            inline_cache.insert(cache_key, true);
        }
        return true;
    }

    // Phase 2: Per-worker inline cache (only stores TRUE results, like the app).
    // Finding the key means this source flow was already classified as tunnel.
    let cache_key = (src_ip, src_port, protocol);
    if inline_cache.contains_key(&cache_key) {
        return is_likely_game_traffic(dst_port, protocol, api_tunneling);
    }

    // Phase 3: Port-only fallback for tunnel-owned UDP ports. Recovers routing
    // when the exact (ip, port) lookup missed due to local-IP representation
    // drift (0.0.0.0 bind vs LAN IP). UDP only.
    if snapshot.should_tunnel_by_port_fallback(src_port, protocol) {
        if inline_cache.len() < 10000 {
            inline_cache.insert(cache_key, true);
        }
        return is_likely_game_traffic(dst_port, protocol, api_tunneling);
    }

    // Phase 4: Speculative tunneling based on destination IP. Catches the
    // first packets of a game flow before the owner table is populated.
    if is_game_server(dst_ip, dst_port, protocol, api_tunneling) {
        log_speculative_tunnel(src_ip, src_port, dst_ip, dst_port);
        if inline_cache.len() < 10000 {
            inline_cache.insert(cache_key, true);
        }
        return true;
    }

    // Phase 5: Route Assist TCP bootstrap. With Route Assist enabled, tunnel the
    // initial SYN of a Roblox HTTPS/API connection (port 80/443) to a repaired
    // bootstrap IP, so account/launch/teleport flows ride the relay even on a
    // banned/blocked network. Only fires when a tunnel app is actually present.
    if api_tunneling
        && protocol == Protocol::Tcp
        && is_tcp_initial_syn
        && matches!(dst_port, 80 | 443)
        && !snapshot.tunnel_apps.is_empty()
        && crate::roblox_proxy::hosts::is_active_bootstrap_ip(dst_ip)
    {
        log_speculative_tunnel(src_ip, src_port, dst_ip, dst_port);
        if inline_cache.len() < 10000 {
            inline_cache.insert(cache_key, true);
        }
        return true;
    }

    // Diagnostic: sample UDP packets in the game ephemeral-port range that we are
    // about to bypass, so we can see whether game traffic is reaching the worker
    // and why it isn't matching (dst not in ROBLOX_RANGES, etc.).
    if protocol == Protocol::Udp && (49152..=65535).contains(&dst_port) {
        log_bypassed_game_candidate(src_ip, src_port, dst_ip, dst_port);
    }

    false
}

/// Log the first few speculative-tunnel decisions (per process).
fn log_speculative_tunnel(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let n = COUNT.fetch_add(1, Ordering::Relaxed);
    if n < 20 {
        log::info!(
            "SPECULATIVE TUNNEL: {}:{} -> {}:{} (PID unknown, destination is a game server)",
            src_ip, src_port, dst_ip, dst_port
        );
    }
}

/// Sample-log UDP packets in the game port range that get bypassed, so we can
/// confirm whether in-game traffic is being seen and why it doesn't match.
fn log_bypassed_game_candidate(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let n = COUNT.fetch_add(1, Ordering::Relaxed);
    if n % 200 == 0 {
        log::info!(
            "BYPASS UDP candidate #{}: {}:{} -> {}:{} (not owned by tunnel app, dst not in ROBLOX_RANGES)",
            n, src_ip, src_port, dst_ip, dst_port
        );
    }
}

/// V3 Inbound receiver thread - reads unencrypted packets from UDP relay,
/// and injects to MSTCP (no decryption needed, no NAT rewriting in V3)
fn run_v3_inbound_receiver(
    relay: Arc<RelayForwardContext>,
    config: InboundConfig,
    stop_flag: Arc<AtomicBool>,
    throughput: ThroughputStats,
) {
    log::info!("V3 inbound receiver starting");
    log::info!("  Relay: {}", relay.relay.relay_addr());
    log::info!("  Adapter: {}", config.physical_adapter_name);

    let driver = match ndisapi::Ndisapi::new("NDISRD") {
        Ok(d) => d,
        Err(e) => {
            log::error!("V3 inbound receiver: failed to open driver: {}", e);
            return;
        }
    };

    let adapters = match driver.get_tcpip_bound_adapters_info() {
        Ok(a) => a,
        Err(e) => {
            log::error!("V3 inbound receiver: failed to get adapters: {}", e);
            return;
        }
    };

    let adapter = match adapters
        .iter()
        .find(|a| a.get_name() == &config.physical_adapter_name)
    {
        Some(a) => a,
        None => {
            log::error!(
                "V3 inbound receiver: adapter '{}' not found",
                config.physical_adapter_name
            );
            return;
        }
    };

    let adapter_handle = adapter.get_handle();

    let mut recv_buf = vec![0u8; 2048];
    let mut packets_received = 0u64;
    let mut packets_injected = 0u64;
    let start_time = Instant::now();
    let mut last_health_check = Instant::now();

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        // Health check every 5 seconds
        let now = Instant::now();
        if now.duration_since(last_health_check).as_secs() >= 5 {
            last_health_check = now;
            let uptime = now.duration_since(start_time).as_secs();
            log::info!(
                "V3 inbound health: {}s uptime, {} recv, {} injected",
                uptime,
                packets_received,
                packets_injected
            );
        }

        // Receive payload from relay (session ID already verified/stripped).
        let n = match relay.relay.receive_inbound(&mut recv_buf) {
            Ok(Some(n)) => n,
            Ok(None) => continue,
            Err(e) => {
                log::warn!("V3 inbound: recv error: {}", e);
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
        };

        let ip_packet = &recv_buf[..n];
        if ip_packet.len() < 20 {
            continue;
        }

        packets_received += 1;
        throughput.add_rx(ip_packet.len() as u64);

        // Inject to MSTCP
        if inject_inbound_packet(ip_packet, &config, adapter_handle, &driver) {
            packets_injected += 1;
        }
    }

    log::info!(
        "V3 inbound receiver stopped - {} recv, {} injected, {}s uptime",
        packets_received,
        packets_injected,
        start_time.elapsed().as_secs()
    );
}

/// Inject an inbound IP packet to MSTCP
fn inject_inbound_packet(
    ip_packet: &[u8],
    config: &InboundConfig,
    adapter_handle: windows::Win32::Foundation::HANDLE,
    driver: &ndisapi::Ndisapi,
) -> bool {
    use ndisapi::{DirectionFlags, EthMRequest, IntermediateBuffer};

    const MAX_ETHER_FRAME: usize = 1522;
    let frame_len = 14 + ip_packet.len();

    if frame_len > MAX_ETHER_FRAME {
        return false;
    }

    let mut ethernet_frame = vec![0u8; frame_len];
    ethernet_frame[0..6].copy_from_slice(&config.adapter_mac);
    ethernet_frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    ethernet_frame[12] = 0x08;
    ethernet_frame[13] = 0x00;
    ethernet_frame[14..].copy_from_slice(ip_packet);

    let mut buffer = IntermediateBuffer::default();
    buffer.device_flags = DirectionFlags::PACKET_FLAG_ON_RECEIVE;
    buffer.length = ethernet_frame.len() as u32;
    buffer.buffer.0[..ethernet_frame.len()].copy_from_slice(&ethernet_frame);

    let mut to_mstcp: EthMRequest<1> = EthMRequest::new(adapter_handle);
    if to_mstcp.push(&buffer).is_ok() {
        return driver.send_packets_to_mstcp::<1>(&to_mstcp).is_ok();
    }

    false
}

// ============================================================================
// CHECKSUM UTILITIES
// ============================================================================

/// Calculate IP header checksum (RFC 1071)
fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Calculate TCP checksum with pseudo-header (RFC 793)
fn calculate_tcp_checksum(packet: &[u8], ihl: usize) -> u16 {
    if packet.len() < ihl + 20 {
        return 0;
    }

    let src_ip = &packet[12..16];
    let dst_ip = &packet[16..20];
    let tcp_len = packet.len() - ihl;
    let tcp_segment = &packet[ihl..];

    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32;
    sum += tcp_len as u32;

    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        if i == 16 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Calculate UDP checksum with pseudo-header (RFC 768)
fn calculate_udp_checksum(packet: &[u8], ihl: usize) -> u16 {
    if packet.len() < ihl + 8 {
        return 0;
    }

    let src_ip = &packet[12..16];
    let dst_ip = &packet[16..20];
    let udp_len = packet.len() - ihl;
    let udp_datagram = &packet[ihl..];

    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 17u32;
    sum += udp_len as u32;

    let mut i = 0;
    while i + 1 < udp_datagram.len() {
        if i == 6 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([udp_datagram[i], udp_datagram[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_datagram.len() {
        sum += (udp_datagram[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    if checksum == 0 {
        0xFFFF
    } else {
        checksum
    }
}

/// Fix checksums in an IP packet (modifies packet in place)
fn fix_packet_checksums(packet: &mut [u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }

    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl {
        return false;
    }

    // Fix IP header checksum
    packet[10] = 0;
    packet[11] = 0;
    let ip_checksum = calculate_ip_checksum(&packet[..ihl]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = (ip_checksum & 0xFF) as u8;

    let protocol = packet[9];
    let transport_offset = ihl;

    if protocol == 6 && packet.len() >= transport_offset + 20 {
        packet[transport_offset + 16] = 0;
        packet[transport_offset + 17] = 0;
        let tcp_checksum = calculate_tcp_checksum(packet, ihl);
        packet[transport_offset + 16] = (tcp_checksum >> 8) as u8;
        packet[transport_offset + 17] = (tcp_checksum & 0xFF) as u8;
        return true;
    }

    if protocol == 17 && packet.len() >= transport_offset + 8 {
        packet[transport_offset + 6] = 0;
        packet[transport_offset + 7] = 0;
        let udp_checksum = calculate_udp_checksum(packet, ihl);
        packet[transport_offset + 6] = (udp_checksum >> 8) as u8;
        packet[transport_offset + 7] = (udp_checksum & 0xFF) as u8;
        return true;
    }

    true
}

// ============================================================================
// ADAPTER FRIENDLY NAME UTILITIES
// ============================================================================

/// Get adapter friendly name via GetAdaptersInfo
#[cfg(windows)]
fn get_adapter_friendly_name(internal_name: &str) -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO};

    let guid = internal_name
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '{' || c == '}');

    if guid.is_empty() {
        return None;
    }

    unsafe {
        let mut buf_len: u32 = 0;
        let _ = GetAdaptersInfo(None, &mut buf_len);
        if buf_len == 0 {
            return None;
        }

        let mut buffer: Vec<u8> = vec![0; buf_len as usize];
        let adapter_info_ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;

        if GetAdaptersInfo(Some(adapter_info_ptr), &mut buf_len) != 0 {
            return None;
        }

        let mut current = adapter_info_ptr;
        while !current.is_null() {
            let adapter = &*current;
            let adapter_name_bytes: Vec<u8> = adapter
                .AdapterName
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            let adapter_guid = String::from_utf8_lossy(&adapter_name_bytes);

            if adapter_guid.to_lowercase().contains(&guid.to_lowercase()) {
                let desc_bytes: Vec<u8> = adapter
                    .Description
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as u8)
                    .collect();
                return Some(String::from_utf8_lossy(&desc_bytes).to_string());
            }

            current = adapter.Next;
        }
    }
    None
}

#[cfg(not(windows))]
fn get_adapter_friendly_name(_internal_name: &str) -> Option<String> {
    None
}

/// Get adapter friendly name via GetAdaptersAddresses
#[cfg(windows)]
fn get_adapter_friendly_name_v2(internal_name: &str) -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let guid = internal_name
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '{' || c == '}')
        .to_lowercase();

    if guid.is_empty() {
        return None;
    }

    unsafe {
        let mut buf_len: u32 = 0;
        let _ = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut buf_len,
        );
        if buf_len == 0 {
            return None;
        }

        let mut buffer: Vec<u8> = vec![0; buf_len as usize];
        let adapter_addr_ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

        if GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(adapter_addr_ptr),
            &mut buf_len,
        ) != 0
        {
            return None;
        }

        let mut current = adapter_addr_ptr;
        while !current.is_null() {
            let adapter = &*current;
            if !adapter.AdapterName.0.is_null() {
                let adapter_name = std::ffi::CStr::from_ptr(adapter.AdapterName.0 as *const i8);
                if let Ok(name_str) = adapter_name.to_str() {
                    let adapter_guid = name_str
                        .trim_matches(|c| c == '{' || c == '}')
                        .to_lowercase();
                    if adapter_guid == guid {
                        if !adapter.FriendlyName.0.is_null() {
                            let len = (0..)
                                .take_while(|&i| *adapter.FriendlyName.0.add(i) != 0)
                                .count();
                            let friendly_slice =
                                std::slice::from_raw_parts(adapter.FriendlyName.0, len);
                            return Some(String::from_utf16_lossy(friendly_slice));
                        }
                    }
                }
            }
            current = adapter.Next;
        }
    }
    None
}

#[cfg(not(windows))]
fn get_adapter_friendly_name_v2(_internal_name: &str) -> Option<String> {
    None
}
