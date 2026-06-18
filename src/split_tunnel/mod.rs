//! Split Tunnel Module for SwiftTunnel SDK
//!
//! V3-only implementation that routes selected application traffic through
//! the relay server while letting other traffic pass through normally.
//!
//! ## Architecture
//!
//! - interceptor.rs: Per-CPU packet processing (ndisapi + V3 relay)
//! - process_cache.rs: Lock-free RCU cache for PID -> app mapping
//! - process_tracker.rs: IP Helper API connection-to-PID mapping
//! - process_watcher.rs: ETW instant process detection
//!
//! ## Usage
//!
//! ```no_run
//! use swifttunnel_sdk::split_tunnel::SplitTunnelDriver;
//!
//! let mut driver = SplitTunnelDriver::new(vec!["robloxplayerbeta.exe".into()]);
//! driver.initialize()?;
//! driver.configure(vec!["robloxplayerbeta.exe".into()])?;
//! // After relay is connected:
//! // driver.set_relay_context(relay_ctx);
//! // driver.start()?;
//! ```

pub mod interceptor;
pub mod process_cache;
pub mod process_tracker;
pub mod process_watcher;

pub use interceptor::{ParallelInterceptor, RelayForwardContext, ThroughputStats};
pub use process_cache::{LockFreeProcessCache, ProcessSnapshot};
pub use process_tracker::{ConnectionKey, ProcessTracker, Protocol, TrackerStats};
pub use process_watcher::{ProcessStartEvent, ProcessWatcher};

use crate::error::SdkError;
use std::sync::Arc;
use std::time::Duration;

const WINPKFILTER_BINDING_CLEANUP_TIMEOUT: Duration = Duration::from_secs(12);

/// Combined split tunnel driver that orchestrates all components.
///
/// Owns the packet interceptor, process cache, tracker, and ETW watcher.
/// Provides a high-level API for the host application / FFI layer.
pub struct SplitTunnelDriver {
    /// Packet interceptor (per-CPU workers, ndisapi, V3 relay)
    interceptor: ParallelInterceptor,
    /// ETW process watcher (instant detection)
    watcher: Option<ProcessWatcher>,
    /// Apps to tunnel (stored for re-configuration)
    tunnel_apps: Vec<String>,
}

impl SplitTunnelDriver {
    /// Create a new split tunnel driver with the given list of apps to tunnel.
    ///
    /// App names should be exe names (e.g., "robloxplayerbeta.exe") and are
    /// matched case-insensitively.
    pub fn new(tunnel_apps: Vec<String>) -> Self {
        Self {
            interceptor: ParallelInterceptor::new(tunnel_apps.clone()),
            watcher: None,
            tunnel_apps,
        }
    }

    /// Initialize the driver (check that ndisapi is available).
    pub fn initialize(&mut self) -> Result<(), SdkError> {
        self.interceptor.initialize()
    }

    /// Check whether the Windows Packet Filter driver is available.
    pub fn check_driver_available() -> bool {
        ParallelInterceptor::check_driver_available()
    }

    /// Configure the interceptor for the given tunnel apps.
    ///
    /// Finds the physical adapter and prepares for packet interception.
    /// Call this before `start()`.
    pub fn configure(&mut self, tunnel_apps: Vec<String>) -> Result<(), SdkError> {
        self.tunnel_apps = tunnel_apps.clone();
        self.interceptor.configure(tunnel_apps)
    }

    /// Set the V3 relay forwarding context.
    ///
    /// Must be called after the relay connection is established and before
    /// `start()`. The context provides the socket, relay address, and
    /// session ID used to forward intercepted packets.
    pub fn set_relay_context(&mut self, ctx: Arc<RelayForwardContext>) {
        self.interceptor.set_relay_context(ctx);
    }

    /// Create a `RelayForwardContext` from a `UdpRelay` instance.
    ///
    /// Convenience method that clones the relay socket and extracts the
    /// session ID + address.
    pub fn relay_context_from_udp_relay(
        relay: &Arc<crate::vpn::UdpRelay>,
    ) -> Result<Arc<RelayForwardContext>, SdkError> {
        Ok(Arc::new(RelayForwardContext {
            relay: Arc::clone(relay),
            asset_relays: Vec::new(),
        }))
    }

    /// Build a relay context with a pool of asset relays for asset-host traffic.
    pub fn relay_context_with_asset_relays(
        relay: &Arc<crate::vpn::UdpRelay>,
        asset_relays: Vec<Arc<crate::vpn::UdpRelay>>,
    ) -> Arc<RelayForwardContext> {
        Arc::new(RelayForwardContext {
            relay: Arc::clone(relay),
            asset_relays,
        })
    }

    /// Set auto-router used for runtime relay switching + whitelist bypass.
    pub fn set_auto_router(&mut self, router: Arc<crate::vpn::auto_routing::AutoRouter>) {
        self.interceptor.set_auto_router(router);
    }

    /// Enable/disable Route Assist (tunnel Roblox TCP API/bootstrap traffic).
    pub fn set_api_tunneling_enabled(&self, enabled: bool) {
        self.interceptor.set_api_tunneling_enabled(enabled);
    }

    /// Enable/disable UDP tunneling. When disabled, UDP packets always bypass
    /// the relay. Used with partial-country-ban mode where only TCP needs bypass.
    pub fn set_udp_tunneling_enabled(&self, enabled: bool) {
        self.interceptor.set_udp_tunneling_enabled(enabled);
    }

    /// Switch relay destination without restarting split tunnel.
    pub fn switch_relay_addr(&self, new_addr: std::net::SocketAddr) -> bool {
        self.interceptor.switch_relay_addr(new_addr)
    }

    /// Get current relay address.
    pub fn current_relay_addr(&self) -> Option<std::net::SocketAddr> {
        self.interceptor.current_relay_addr()
    }

    /// Start packet interception and the ETW process watcher.
    ///
    /// The interceptor must be configured and a relay context must be set
    /// before calling this.
    pub fn start(&mut self) -> Result<(), SdkError> {
        // Start ETW watcher for instant process detection
        let watch_set: std::collections::HashSet<String> =
            self.tunnel_apps.iter().map(|s| s.to_lowercase()).collect();

        match ProcessWatcher::start(watch_set) {
            Ok(watcher) => {
                log::info!("ETW process watcher started");
                self.watcher = Some(watcher);
            }
            Err(e) => {
                // ETW failure is non-fatal - polling still works
                log::warn!("ETW process watcher failed to start: {}", e);
            }
        }

        // Disable TSO and IPv6 on the physical adapter to avoid oversized
        // packets and IPv6 leaks
        self.interceptor.disable_adapter_offload()?;
        self.interceptor.disable_ipv6()?;

        // Start packet interception threads
        self.interceptor.start()?;

        log::info!("Split tunnel driver started");
        Ok(())
    }

    /// Stop packet interception, restore adapter settings, stop ETW watcher.
    pub fn close(&mut self) {
        log::info!("Closing split tunnel driver");

        // Stop packet interceptor
        self.interceptor.stop();

        // Restore adapter settings
        self.interceptor.enable_adapter_offload();
        self.interceptor.enable_ipv6();

        // Stop ETW watcher
        if let Some(mut watcher) = self.watcher.take() {
            watcher.stop();
        }

        log::info!("Split tunnel driver closed");
    }

    /// Check if split tunneling is currently active.
    pub fn is_active(&self) -> bool {
        self.interceptor.is_active()
    }

    /// Get the list of currently running tunnel apps (by name).
    pub fn get_tunneled_processes(&self) -> Vec<String> {
        let snapshot = self.interceptor.get_snapshot();
        let mut names: Vec<String> = snapshot
            .pid_names
            .iter()
            .filter(|(pid, _)| snapshot.is_tunnel_pid_public(**pid))
            .map(|(_, name)| name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Get packet statistics: (packets_tunneled, packets_bypassed).
    pub fn get_stats(&self) -> (u64, u64) {
        let (_, _, tunneled, bypassed) = self.interceptor.get_diagnostics();
        (tunneled, bypassed)
    }

    /// Get throughput statistics (bytes sent/received through relay).
    pub fn get_throughput_stats(&self) -> ThroughputStats {
        self.interceptor.get_throughput_stats()
    }

    /// Get diagnostic info: (adapter_name, has_default_route, tunneled, bypassed).
    pub fn get_diagnostics(&self) -> (Option<String>, bool, u64, u64) {
        self.interceptor.get_diagnostics()
    }

    /// Trigger an immediate refresh of the process cache.
    ///
    /// Call this when ETW detects a new game process launching to ensure
    /// the cache is updated before the first packets arrive.
    pub fn refresh_processes(&self) {
        self.interceptor.trigger_refresh();
    }

    /// Register a process for immediate tunneling (bypass normal scan cycle).
    ///
    /// Used by ETW watcher to register a process the instant it's detected,
    /// before the next cache refresh cycle.
    pub fn register_process_immediate(&self, pid: u32, name: String) {
        self.interceptor.register_process_immediate(pid, name);
    }

    /// Drain pending ETW events and register detected processes.
    ///
    /// Call this periodically (e.g., from a timer or main loop) to process
    /// any ETW-detected process starts and register them immediately.
    pub fn drain_etw_events(&self) {
        if let Some(ref watcher) = self.watcher {
            while let Some(event) = watcher.try_recv() {
                log::info!(
                    "ETW event: {} (PID: {}) - registering immediately",
                    event.name,
                    event.pid
                );
                self.interceptor
                    .register_process_immediate(event.pid, event.name);
                self.interceptor.trigger_refresh();
            }
        }
    }

    /// Get the physical adapter friendly name (for UI display).
    pub fn get_physical_adapter_name(&self) -> Option<String> {
        self.interceptor.get_physical_adapter_name()
    }

    /// Get the current process cache snapshot.
    pub fn get_snapshot(&self) -> Arc<ProcessSnapshot> {
        self.interceptor.get_snapshot()
    }
}

/// Run a hidden subprocess with a wall-clock timeout. Kills the child if it
/// exceeds the timeout. Uses `CREATE_NO_WINDOW` so powershell never flashes.
#[cfg(windows)]
fn run_hidden_command_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    use std::time::Instant;

    let mut child = std::process::Command::new(program)
        .args(args)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()?;

    let started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            return child.wait_with_output();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl SplitTunnelDriver {
    fn build_winpkfilter_binding_cleanup_script() -> &'static str {
        r#"
        $ErrorActionPreference = 'Stop'
        # Skip the adapter carrying the default route — it needs the binding to
        # stay attached so ndisapi can see and bind to it on the next connect.
        $defaultRouteAlias = try {
            (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias
        } catch { $null }
        $bindings = @(
            Get-NetAdapterBinding -ComponentID 'nt_ndisrd' -ErrorAction SilentlyContinue |
                Where-Object { $_.Enabled -eq $true -and $_.Name -ne $defaultRouteAlias } |
                Sort-Object -Property Name -Unique
        )

        if ($bindings.Count -eq 0) {
            Write-Output 'No enabled WinpkFilter bindings found during uninstall cleanup.'
            exit 0
        }

        $disabled = New-Object System.Collections.Generic.List[string]
        $failures = New-Object System.Collections.Generic.List[string]

        foreach ($binding in $bindings) {
            $adapterName = [string]$binding.Name
            if ([string]::IsNullOrWhiteSpace($adapterName)) {
                continue
            }

            try {
                Disable-NetAdapterBinding -Name $adapterName -ComponentID 'nt_ndisrd' -Confirm:$false -ErrorAction Stop | Out-Null
                Start-Sleep -Milliseconds 500
                $verification = Get-NetAdapterBinding -Name $adapterName -ComponentID 'nt_ndisrd' -ErrorAction SilentlyContinue |
                    Select-Object -First 1

                if ($verification -and $verification.Enabled) {
                    $failures.Add($adapterName + ': binding still enabled after Disable-NetAdapterBinding')
                    continue
                }

                $disabled.Add($adapterName)
            } catch {
                $failures.Add($adapterName + ': ' + $_.Exception.Message)
            }
        }

        if ($disabled.Count -gt 0) {
            Write-Output ('Disabled WinpkFilter binding on adapters: ' + ($disabled -join ', '))
        }

        if ($failures.Count -gt 0) {
            Write-Error ('Failed to disable WinpkFilter binding on adapters: ' + ($failures -join '; '))
            exit 1
        }
        "#
    }

    #[cfg(windows)]
    fn parse_disabled_winpkfilter_adapters(stdout: &str) -> Vec<String> {
        const PREFIX: &str = "Disabled WinpkFilter binding on adapters: ";
        stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix(PREFIX))
            .map(|rest| {
                rest.split(',')
                    .map(|name| name.trim().to_string())
                    .filter(|name| !name.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Ensure the default-route adapter has the nt_ndisrd LWF binding enabled
    /// so ndisapi can enumerate it. Returns true if the binding was enabled.
    #[cfg(windows)]
    pub fn ensure_default_route_adapter_binding() -> Result<bool, String> {
        let script = r#"
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric | Select-Object -First 1
        if (-not $route) { exit 0 }
        $alias = $route.InterfaceAlias
        $binding = Get-NetAdapterBinding -Name $alias -ComponentID 'nt_ndisrd' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($binding -and -not $binding.Enabled) {
            Enable-NetAdapterBinding -Name $alias -ComponentID 'nt_ndisrd' -ErrorAction SilentlyContinue
            Write-Output "Enabled nt_ndisrd on $alias"
        }
        "#;
        let output = run_hidden_command_with_timeout(
            "powershell",
            &["-NoProfile", "-Command", script],
            std::time::Duration::from_secs(10),
        )
        .map_err(|e| format!("ensure binding: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(stdout.starts_with("Enabled"))
    }

    /// Disable any leftover `nt_ndisrd` adapter bindings as part of Internet
    /// recovery after a crash or force-close. Safe while disconnected — the next
    /// connect re-enables the binding on the active adapter.
    #[cfg(windows)]
    pub fn disable_leftover_winpkfilter_bindings() -> Result<Vec<String>, String> {
        let output = run_hidden_command_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                Self::build_winpkfilter_binding_cleanup_script(),
            ],
            WINPKFILTER_BINDING_CLEANUP_TIMEOUT,
        )
        .map_err(|e| format!("Failed to run WinpkFilter binding recovery: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if !output.status.success() {
            let details = if !stderr.is_empty() {
                stderr
            } else if !stdout.is_empty() {
                stdout
            } else {
                format!(
                    "PowerShell exited with code {}",
                    output.status.code().unwrap_or(-1)
                )
            };
            return Err(format!(
                "Failed to disable leftover WinpkFilter adapter bindings: {}",
                details
            ));
        }

        let disabled = Self::parse_disabled_winpkfilter_adapters(&stdout);
        if disabled.is_empty() {
            log::info!("Internet recovery: no leftover WinpkFilter adapter bindings to disable");
        } else {
            log::info!(
                "Internet recovery: disabled leftover WinpkFilter binding on adapter(s): {}",
                disabled.join(", ")
            );
        }
        Ok(disabled)
    }
}

impl Drop for SplitTunnelDriver {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_creation() {
        let driver = SplitTunnelDriver::new(vec!["robloxplayerbeta.exe".to_string()]);
        assert_eq!(driver.tunnel_apps, vec!["robloxplayerbeta.exe"]);
        assert!(!driver.is_active());
    }

    #[test]
    fn test_driver_default_stats() {
        let driver = SplitTunnelDriver::new(vec![]);
        let (tunneled, bypassed) = driver.get_stats();
        assert_eq!(tunneled, 0);
        assert_eq!(bypassed, 0);
    }
}
