//! VPN Connection Manager (V3 SDK)
//!
//! Manages V3 relay lifecycle:
//! - Config fetch
//! - UDP relay creation
//! - Split tunnel setup (ndisapi)
//! - Optional auto-routing

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::Mutex;

use crate::auth::types::VpnConfig;
use crate::callbacks::{fire_auto_routing_event, fire_error, fire_state_change};

use super::auto_routing::{AutoRouter, AutoRoutingEvent, SAME_REGION_UPGRADE_THRESHOLD_MS};
use super::geolocation::{lookup_game_server_region, GameServerRegionLookup};
use super::relay::UdpRelay;

const REFRESH_INTERVAL_MS: u64 = 50;

/// Resolve a relay SocketAddr for `region` from the pre-loaded server list.
/// Picks the candidate with the lowest known latency, falling back to the first match.
fn resolve_relay_for_region(
    region: &str,
    available_servers: &[(String, SocketAddr, Option<u32>)],
) -> Result<SocketAddr, crate::error::SdkError> {
    if available_servers.is_empty() {
        return Err(crate::error::SdkError::Vpn(
            "No servers available — call swifttunnel_servers_fetch first".to_string(),
        ));
    }

    // Exact match first, then prefix (e.g. "us-east" matches "us-east-nj")
    let candidates: Vec<_> = available_servers
        .iter()
        .filter(|(r, _, _)| r == region || r.starts_with(region) || region.starts_with(r.as_str()))
        .collect();

    let chosen = candidates
        .iter()
        .min_by_key(|(_, _, lat)| lat.unwrap_or(u32::MAX))
        .or_else(|| candidates.first())
        .map(|(_, addr, _)| *addr);

    chosen.ok_or_else(|| {
        crate::error::SdkError::Vpn(format!("No server found for region '{}'", region))
    })
}

fn region_matches(server_region: &str, region: &str) -> bool {
    server_region == region
        || server_region.starts_with(region)
        || region.starts_with(server_region)
}

/// Pick up to `count` SwiftTunnel servers for the asset-relay pool.
///
/// Prefers servers in *different* regions from gameplay (e.g. US, Mumbai) so
/// asset load lands far away and doesn't consume the gameplay region's (SG)
/// capacity. Only distinct IPs (and never the gameplay relay's IP). Shuffled so
/// load spreads across the fleet. Falls back to any different-IP server if every
/// server is in the gameplay region. Returns `(region, addr)` pairs.
fn pick_asset_relays(
    available: &[(String, SocketAddr, Option<u32>)],
    primary: SocketAddr,
    region: &str,
    count: usize,
) -> Vec<(String, SocketAddr)> {
    use rand::seq::SliceRandom;
    use std::collections::HashSet;

    let mut rng = rand::thread_rng();

    let dedup = |servers: Vec<&(String, SocketAddr, Option<u32>)>| -> Vec<(String, SocketAddr)> {
        let mut seen: HashSet<std::net::IpAddr> = HashSet::new();
        let mut out = Vec::new();
        for (r, a, _) in servers {
            if a.ip() != primary.ip() && seen.insert(a.ip()) {
                out.push((r.clone(), *a));
            }
        }
        out
    };

    // Prefer far regions (different from gameplay) so SG stays free for gameplay.
    let mut far: Vec<&(String, SocketAddr, Option<u32>)> = available
        .iter()
        .filter(|(r, _, _)| !region_matches(r, region))
        .collect();
    far.shuffle(&mut rng);
    let mut pool = dedup(far);

    // Fall back to any different-IP server (incl. same region) if needed.
    if pool.len() < count {
        let mut rest: Vec<&(String, SocketAddr, Option<u32>)> = available.iter().collect();
        rest.shuffle(&mut rng);
        for (r, a) in dedup(rest) {
            if pool.len() >= count {
                break;
            }
            if !pool.iter().any(|(_, pa)| pa.ip() == a.ip()) {
                pool.push((r, a));
            }
        }
    }

    pool.truncate(count);
    pool
}

/// V3 relay auth handshake (free fn so the asset-relay pool can authenticate
/// members concurrently). Best-effort: on ticket/handshake failure we fall back
/// to legacy mode and continue — the relay itself rejects traffic if auth is
/// mandatory.
async fn authenticate_relay_handshake(
    access_token: &str,
    region: &str,
    relay: &Arc<UdpRelay>,
) -> String {
    let auth_client = crate::auth::client::AuthClient::new();
    let session_id_hex = relay.session_id_hex();

    let ticket = match auth_client
        .get_relay_ticket(access_token, region, &session_id_hex)
        .await
    {
        Ok(ticket) => ticket,
        Err(e) => {
            log::warn!(
                "Relay ticket unavailable for '{}' ({}); falling back to legacy relay mode",
                region,
                e
            );
            return "legacy_fallback".to_string();
        }
    };

    let relay_for_auth = Arc::clone(relay);
    let token = ticket.token.clone();
    let handshake =
        tokio::task::spawn_blocking(move || relay_for_auth.authenticate_with_ticket(&token)).await;

    match handshake {
        Ok(Ok(Some(super::relay::RelayAuthAckStatus::Ok))) => {
            log::info!("Relay authenticated (session {}, region {})", session_id_hex, region);
            "authenticated".to_string()
        }
        Ok(Ok(Some(super::relay::RelayAuthAckStatus::AuthDisabled))) => {
            log::info!("Relay reports auth disabled; using legacy relay mode");
            "legacy_fallback".to_string()
        }
        Ok(Ok(Some(status))) => {
            log::warn!(
                "Relay auth rejected ({}) for session {}; falling back to legacy relay mode",
                status.as_str(),
                session_id_hex
            );
            "legacy_fallback".to_string()
        }
        Ok(Ok(None)) => {
            log::warn!(
                "Relay auth timed out for session {}; falling back to legacy relay mode",
                session_id_hex
            );
            "legacy_fallback".to_string()
        }
        Ok(Err(e)) => {
            log::warn!("Relay auth handshake error: {}; falling back to legacy relay mode", e);
            "legacy_fallback".to_string()
        }
        Err(e) => {
            log::warn!("Relay auth task join error: {}; falling back to legacy relay mode", e);
            "legacy_fallback".to_string()
        }
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Compute the cached latency improvement moving to `to_region`.
/// Returns `Some(SAME_REGION_UPGRADE_THRESHOLD_MS)` when the current relay has
/// no cached latency (conservative: always allow the switch).
fn compute_cached_latency_improvement(
    router: &AutoRouter,
    to_region: &str,
) -> Option<u32> {
    let servers = router.available_servers_snapshot();
    let current_region = router.current_region();

    let current_latency = servers
        .iter()
        .find(|(r, _, _)| *r == current_region)
        .and_then(|(_, _, lat)| *lat);

    let target_latency = servers
        .iter()
        .find(|(r, _, _)| {
            r == to_region
                || r.starts_with(&format!("{}-", to_region))
                || to_region.starts_with(&format!("{}-", r.as_str()))
        })
        .and_then(|(_, _, lat)| *lat);

    match (current_latency, target_latency) {
        (Some(cur), Some(tgt)) if cur > tgt => Some(cur - tgt),
        (None, _) => Some(SAME_REGION_UPGRADE_THRESHOLD_MS),
        _ => Some(0),
    }
}

async fn ping_and_select_best(
    candidates: &[(String, SocketAddr)],
) -> Option<(String, SocketAddr, u32)> {
    let mut tasks = Vec::new();
    for (region, addr) in candidates {
        let region = region.clone();
        let addr = *addr;
        tasks.push(tokio::spawn(async move {
            let endpoint = addr.to_string();
            super::servers::measure_latency(&endpoint)
                .await
                .map(|ms| (region, addr, ms))
        }));
    }

    let mut best: Option<(String, SocketAddr, u32)> = None;
    for task in tasks {
        if let Ok(Some((region, addr, ms))) = task.await {
            if best.as_ref().map_or(true, |(_, _, best_ms)| ms < *best_ms) {
                best = Some((region, addr, ms));
            }
        }
    }
    best
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    FetchingConfig,
    Connecting,
    ConfiguringSplitTunnel,
    Connected {
        since: Instant,
        server_region: String,
        server_endpoint: String,
        /// Client's assigned IP address from the VPN config
        assigned_ip: String,
        /// Authentication mode used by the relay (e.g. "authenticated")
        relay_auth_mode: String,
        split_tunnel_active: bool,
        tunneled_processes: Vec<String>,
        /// Relay health: None = healthy, "stale" = no traffic 30s+, "dead" = no response 60s+
        relay_status: Option<String>,
    },
    Disconnecting,
    Error(String),
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. })
    }

    pub fn is_connecting(&self) -> bool {
        matches!(
            self,
            ConnectionState::FetchingConfig
                | ConnectionState::Connecting
                | ConnectionState::ConfiguringSplitTunnel
        )
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            ConnectionState::Error(msg) => Some(msg),
            _ => None,
        }
    }

    pub fn status_text(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::FetchingConfig => "Fetching configuration...",
            ConnectionState::Connecting => "Connecting to server...",
            ConnectionState::ConfiguringSplitTunnel => "Configuring split tunnel...",
            ConnectionState::Connected { .. } => "Connected",
            ConnectionState::Disconnecting => "Disconnecting...",
            ConnectionState::Error(_) => "Error",
        }
    }

    pub fn as_code(&self) -> i32 {
        match self {
            ConnectionState::Disconnected => 0,
            ConnectionState::FetchingConfig => 1,
            ConnectionState::Connecting => 2,
            ConnectionState::ConfiguringSplitTunnel => 3,
            ConnectionState::Connected { .. } => 4,
            ConnectionState::Disconnecting => 5,
            ConnectionState::Error(_) => -1,
        }
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

pub struct VpnConnection {
    state: Arc<Mutex<ConnectionState>>,
    relay: Option<Arc<UdpRelay>>,
    /// Pool of relays for asset traffic (separate exit IPs in far regions).
    asset_relays: Vec<Arc<UdpRelay>>,
    split_tunnel: Option<Arc<Mutex<crate::split_tunnel::SplitTunnelDriver>>>,
    config: Option<VpnConfig>,
    process_monitor_stop: Arc<AtomicBool>,
    auto_router: Option<Arc<AutoRouter>>,
    /// Whether Route Assist wrote bootstrap DNS overrides to the hosts file
    /// (so cleanup knows to remove them).
    bootstrap_dns_applied: bool,
    /// Running GoodbyeDPI helper process (present when `enable_country_ban`
    /// was requested and the helper was found and started successfully).
    goodbye_dpi_guard: Option<crate::roblox_proxy::goodbyedpi::GoodbyeDpiGuard>,
    /// Non-fatal failure message from the GoodbyeDPI startup attempt, surfaced
    /// to the caller via `take_country_ban_bypass_failure()`.
    country_ban_bypass_failure: Option<String>,
}

impl VpnConnection {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            relay: None,
            asset_relays: Vec::new(),
            split_tunnel: None,
            config: None,
            process_monitor_stop: Arc::new(AtomicBool::new(false)),
            auto_router: None,
            bootstrap_dns_applied: false,
            goodbye_dpi_guard: None,
            country_ban_bypass_failure: None,
        }
    }

    pub async fn state(&self) -> ConnectionState {
        self.state.lock().await.clone()
    }

    pub fn state_handle(&self) -> Arc<Mutex<ConnectionState>> {
        Arc::clone(&self.state)
    }

    pub fn get_config_id(&self) -> Option<String> {
        self.config.as_ref().map(|c| c.id.clone())
    }

    pub fn relay_stats(&self) -> Option<(u64, u64)> {
        self.relay.as_ref().map(|r| r.stats())
    }

    pub fn auto_routing_snapshot(&self) -> Option<serde_json::Value> {
        let router = self.auto_router.as_ref()?;
        let events = router
            .recent_events(20)
            .into_iter()
            .map(|e: AutoRoutingEvent| {
                json!({
                    "type": e.event_type,
                    "timestamp_ms": e.timestamp_ms,
                    "from_region": e.from_region,
                    "to_region": e.to_region,
                    "game_server_region": e.game_server_region,
                    "reason": e.reason,
                    "location": e.location,
                    "relay_addr": e.relay_addr,
                })
            })
            .collect::<Vec<_>>();

        Some(json!({
            "enabled": router.is_enabled(),
            "current_region": router.current_region(),
            "game_region": router.current_game_region().map(|r| r.display_name().to_string()),
            "bypassed": router.is_bypassed(),
            "pending_lookups": router.pending_lookup_count(),
            "events": events,
        }))
    }

    async fn set_state(&self, state: ConnectionState) {
        log::info!("Connection state: {:?}", state);
        let code = state.as_code();
        if let Some(msg) = state.error_message() {
            fire_error(code, msg);
        }
        *self.state.lock().await = state;
        fire_state_change(code);
    }

    pub async fn connect(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
    ) -> Result<(), crate::error::SdkError> {
        self.connect_ex(
            access_token,
            region,
            tunnel_apps,
            false,
            Vec::new(),
            Vec::new(),
            false,
            Vec::new(),
            None,
            Vec::new(),
            0,
            false,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn connect_ex(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
        enable_api_tunneling: bool,
        excluded_urls: Vec<String>,
        asset_relay_server: Option<String>,
        asset_urls: Vec<String>,
        asset_relay_count: usize,
        enable_country_ban: bool,
        enable_partial_country_ban: bool,
    ) -> Result<(), crate::error::SdkError> {
        {
            let state = self.state.lock().await;
            if state.is_connected() {
                return Err(crate::error::SdkError::Vpn("Already connected".to_string()));
            }
            if state.is_connecting() {
                return Err(crate::error::SdkError::Vpn(
                    "Connection in progress".to_string(),
                ));
            }
        }

        log::info!(
            "connect_ex: region={} apps={:?} auto_routing={} whitelisted={:?} servers={} route_assist={} country_ban={} partial_ban={} excluded_urls={:?}",
            region,
            tunnel_apps,
            auto_routing_enabled,
            whitelisted_regions,
            available_servers.len(),
            enable_api_tunneling,
            enable_country_ban,
            enable_partial_country_ban,
            excluded_urls
        );

        if crate::diskless::system_is_diskless() {
            log::info!("Network-booted (diskless) PC detected for this session");
        }

        // Resolve user URL exclusions to IPs up-front so the classifier can
        // bypass them. Best-effort; failures just mean fewer exclusions.
        crate::exclusions::resolve_and_set(&excluded_urls).await;

        // Start a fresh destination ("URL") log session for this connect.
        crate::url_log::begin_session(region, enable_api_tunneling);

        self.set_state(ConnectionState::FetchingConfig).await;

        // Route Assist: repair Roblox bootstrap DNS via the hosts file so the
        // banned/blocked client can reach Roblox's launch/API endpoints, and so
        // those IPs become eligible for TCP tunneling. Best-effort; a failure
        // here must not block the game-traffic tunnel.
        if enable_api_tunneling && !tunnel_apps.is_empty() {
            let country_ban_bypass = enable_country_ban || enable_partial_country_ban;
            match crate::roblox_proxy::hosts::apply_bootstrap_overrides(country_ban_bypass).await {
                Ok(()) => {
                    self.bootstrap_dns_applied = true;
                    log::info!(
                        "Route Assist: applied Roblox bootstrap DNS repair (country_ban_bypass={})",
                        country_ban_bypass
                    );
                }
                Err(e) => {
                    log::warn!("Route Assist: bootstrap DNS repair skipped: {}", e);
                }
            }
        }

        // Studio exclusion: keep Studio direct unless country ban requires relaying
        // it to reach Roblox at all. Studio breaks Team Create through the relay
        // (its place-sync TCP exceeds the relay forward buffer).
        let mut tunnel_apps = tunnel_apps;
        if !(enable_country_ban || enable_partial_country_ban) {
            tunnel_apps.retain(|app| !crate::process_names::is_roblox_studio_process_name(app));
        }

        // Bypass Country Bans: launch GoodbyeDPI so DPI/SNI-based blocks on
        // Roblox traffic are bypassed at the ISP level. GoodbyeDPI is now
        // best-effort: the relay is the primary bypass, so a failure or timeout
        // here is logged but does NOT surface as a user-facing error.
        if enable_country_ban {
            match crate::roblox_proxy::goodbyedpi::start_for_roblox().await {
                Ok(Some(guard)) => {
                    log::info!("GoodbyeDPI helper started for country ban bypass");
                    self.goodbye_dpi_guard = Some(guard);
                }
                Ok(None) => {
                    log::info!(
                        "V3: GoodbyeDPI helper unavailable; relying on the relay for country-ban bypass"
                    );
                }
                Err(e) => {
                    log::warn!(
                        "V3: GoodbyeDPI could not confirm a working mode; relying on the relay for country-ban bypass: {}",
                        e
                    );
                }
            }
        }

        // V3: resolve the relay address directly from the server list — no API call needed.
        let relay_addr = resolve_relay_for_region(region, &available_servers)?;
        log::info!("connect_ex: resolved relay {} for region {}", relay_addr, region);

        let config = crate::auth::types::VpnConfig {
            region: region.to_string(),
            endpoint: relay_addr.to_string(),
            ..Default::default()
        };

        self.config = Some(config.clone());
        self.set_state(ConnectionState::Connecting).await;

        let relay = Arc::new(UdpRelay::new(relay_addr)?);
        self.relay = Some(Arc::clone(&relay));

        // V3: authenticate the relay session. The relay server requires an
        // auth-hello handshake before it will forward any packets. Without this
        // the tunnel "connects" but no traffic is relayed (the symptom we saw:
        // Roblox detected + split tunnel up, but nothing tunneled).
        let relay_auth_mode = self
            .authenticate_relay(access_token, &config.region, &relay)
            .await;
        log::info!("connect_ex: relay auth mode = {}", relay_auth_mode);

        // Optional asset-relay pool (separate exit IPs in far regions) to dodge
        // Roblox's per-IP 429 on assetdelivery. Resolve the asset host set + bring
        // up N authenticated relays. Best-effort: if empty, assets fall back to
        // the primary relay.
        let asset_relays = self
            .setup_asset_relays(
                access_token,
                region,
                asset_relay_server,
                asset_urls,
                &available_servers,
                relay_addr,
                asset_relay_count,
            )
            .await;

        self.set_state(ConnectionState::ConfiguringSplitTunnel)
            .await;

        let (tunneled_processes, split_tunnel_active) = if !tunnel_apps.is_empty() {
            // Resolve routing flags: UDP tunneling is disabled in partial-ban mode
            // (TCP-only relay escape).
            let udp_tunneling = !enable_partial_country_ban || enable_api_tunneling || enable_country_ban;
            match self
                .setup_split_tunnel(
                    &config,
                    &relay,
                    asset_relays.clone(),
                    tunnel_apps.clone(),
                    auto_routing_enabled,
                    available_servers,
                    whitelisted_regions,
                    enable_api_tunneling,
                    udp_tunneling,
                )
                .await
            {
                Ok(processes) => (processes, true),
                Err(e) => {
                    self.cleanup().await;
                    self.set_state(ConnectionState::Error(format!(
                        "Split tunnel failed: {}",
                        e
                    )))
                    .await;
                    return Err(e);
                }
            }
        } else {
            (Vec::new(), false)
        };

        // Full bypass + a real DNS block (Egypt): local DoH is dead and system
        // DNS is poisoned, so the pins above may be wrong. Now that the relay
        // tunnel is up, resolve Roblox's real IPs *through* the relay (which
        // sits outside the censorship) and merge them into the hosts-file pins.
        // Best-effort: an older relay without resolve support returns nothing.
        if enable_country_ban {
            let resolved = relay
                .resolve_roblox_hosts(
                    crate::roblox_proxy::hosts::ROBLOX_BOOTSTRAP_DOMAINS,
                    std::time::Duration::from_secs(3),
                )
                .await;
            if resolved.is_empty() {
                log::info!(
                    "Relay-resolved DNS returned nothing (relay without resolve support, or hosts unresolved)"
                );
            } else {
                let count = resolved.len();
                match crate::roblox_proxy::hosts::apply_relay_resolved_overrides(resolved).await {
                    Ok(()) => log::info!(
                        "Applied relay-resolved pins for {count} Roblox host(s) (DNS via relay)"
                    ),
                    Err(e) => log::warn!("Relay-resolved Roblox pins could not be applied: {e}"),
                }
            }
        }

        self.set_state(ConnectionState::Connected {
            since: Instant::now(),
            server_region: config.region.clone(),
            server_endpoint: config.endpoint.clone(),
            assigned_ip: config.assigned_ip.clone(),
            relay_auth_mode,
            split_tunnel_active,
            tunneled_processes,
            relay_status: None,
        })
        .await;

        Ok(())
    }

    /// Bring up the asset-relay pool: resolve the asset host set, pick up to
    /// `count` far-region SwiftTunnel servers (or an explicit override), connect
    /// + authenticate them concurrently. Returns the relay handles (also stored
    /// on `self`). Best-effort — asset traffic falls back to the primary relay
    /// when the pool is empty.
    #[allow(clippy::too_many_arguments)]
    async fn setup_asset_relays(
        &mut self,
        access_token: &str,
        region: &str,
        asset_relay_server: Option<String>,
        asset_urls: Vec<String>,
        available_servers: &[(String, SocketAddr, Option<u32>)],
        primary_addr: SocketAddr,
        count: usize,
    ) -> Vec<Arc<UdpRelay>> {
        // Asset routing is requested by providing asset_urls.
        if asset_urls.is_empty() {
            return Vec::new();
        }

        // Resolve which destination IPs should ride the asset relays.
        let n = crate::asset_route::resolve_and_set(&asset_urls).await;
        if n == 0 {
            log::warn!("asset relay: no asset IPs resolved; skipping asset relays");
            return Vec::new();
        }

        // Default pool size of 3 when unspecified.
        let count = if count == 0 { 3 } else { count };

        // Determine target endpoints: explicit override (single), or a pool of
        // far-region SwiftTunnel servers with distinct IPs.
        let targets: Vec<(String, SocketAddr)> = if let Some(server) = asset_relay_server {
            let a = match server.parse::<SocketAddr>() {
                Ok(a) => a,
                Err(_) => match tokio::net::lookup_host(&server).await {
                    Ok(mut it) => it.next(),
                    Err(e) => {
                        log::warn!("asset relay: failed to resolve '{}': {}", server, e);
                        None
                    }
                }
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
            };
            if a.ip().is_unspecified() {
                Vec::new()
            } else {
                vec![(region.to_string(), a)]
            }
        } else {
            pick_asset_relays(available_servers, primary_addr, region, count)
        };

        if targets.is_empty() {
            log::warn!(
                "asset relay: no alternate SwiftTunnel servers available; assets use primary relay"
            );
            return Vec::new();
        }

        // Create all relays, then authenticate them concurrently so connect time
        // doesn't grow linearly with the pool size.
        let mut created: Vec<(String, SocketAddr, Arc<UdpRelay>)> = Vec::new();
        for (r, addr) in targets {
            match UdpRelay::new(addr) {
                Ok(relay) => created.push((r, addr, Arc::new(relay))),
                Err(e) => log::warn!("asset relay: failed to create relay to {}: {}", addr, e),
            }
        }

        let mut set: tokio::task::JoinSet<(String, SocketAddr, Arc<UdpRelay>, String)> =
            tokio::task::JoinSet::new();
        for (r, addr, relay) in created {
            let token = access_token.to_string();
            set.spawn(async move {
                let mode = authenticate_relay_handshake(&token, &r, &relay).await;
                (r, addr, relay, mode)
            });
        }

        let mut relays = Vec::new();
        while let Some(joined) = set.join_next().await {
            if let Ok((r, addr, relay, mode)) = joined {
                log::info!("asset relay: {} (region={}) auth mode = {}", addr, r, mode);
                relays.push(relay);
            }
        }

        log::info!(
            "asset relay pool: {} relay(s) up across far regions, routing {} asset IP(s)",
            relays.len(),
            n
        );

        self.asset_relays = relays.clone();
        relays
    }

    /// Perform the V3 relay auth handshake. Delegates to the free function so
    /// the asset-relay pool can authenticate members concurrently.
    async fn authenticate_relay(
        &self,
        access_token: &str,
        region: &str,
        relay: &Arc<UdpRelay>,
    ) -> String {
        authenticate_relay_handshake(access_token, region, relay).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn setup_split_tunnel(
        &mut self,
        config: &VpnConfig,
        relay: &Arc<UdpRelay>,
        asset_relays: Vec<Arc<UdpRelay>>,
        tunnel_apps: Vec<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
        enable_api_tunneling: bool,
        udp_tunneling: bool,
    ) -> Result<Vec<String>, crate::error::SdkError> {
        log::info!("setup_split_tunnel: apps={:?} relay={} auto_routing={} whitelisted={:?} route_assist={} udp_tunneling={}",
            tunnel_apps, config.endpoint, auto_routing_enabled, whitelisted_regions, enable_api_tunneling, udp_tunneling);

        if !crate::split_tunnel::SplitTunnelDriver::check_driver_available() {
            log::error!("setup_split_tunnel: WPF driver not available");
            return Err(crate::error::SdkError::SplitTunnel(
                "Windows Packet Filter driver not available".to_string(),
            ));
        }
        log::info!("setup_split_tunnel: WPF driver available");

        let mut driver = crate::split_tunnel::SplitTunnelDriver::new(tunnel_apps.clone());
        driver.initialize().map_err(|e| {
            crate::error::SdkError::SplitTunnel(format!("Failed to initialize driver: {}", e))
        })?;
        log::info!("setup_split_tunnel: driver initialized");
        driver.configure(tunnel_apps.clone()).map_err(|e| {
            crate::error::SdkError::SplitTunnel(format!("Failed to configure split tunnel: {}", e))
        })?;
        log::info!("setup_split_tunnel: driver configured");

        // Route Assist: tell the interceptor to tunnel Roblox TCP API/bootstrap
        // traffic in addition to UDP game traffic.
        driver.set_api_tunneling_enabled(enable_api_tunneling);
        driver.set_udp_tunneling_enabled(udp_tunneling);

        let relay_ctx = crate::split_tunnel::SplitTunnelDriver::relay_context_with_asset_relays(
            relay,
            asset_relays,
        );
        driver.set_relay_context(relay_ctx);

        let auto_router = Arc::new(AutoRouter::new(auto_routing_enabled, &config.region));
        auto_router.set_current_relay(relay.relay_addr(), &config.region);
        auto_router.set_available_servers(available_servers.clone());
        if !whitelisted_regions.is_empty() {
            auto_router.set_whitelisted_regions(whitelisted_regions);
        }

        if auto_routing_enabled {
            if available_servers.is_empty() {
                let reason =
                    "Auto-routing enabled but no available servers; continuing without switching"
                        .to_string();
                auto_router.push_degraded_event(reason.clone());
                auto_router.set_enabled(false);
                fire_auto_routing_event(
                    &json!({
                        "type": "degraded",
                        "timestamp_ms": now_millis(),
                        "from_region": config.region,
                        "to_region": config.region,
                        "game_server_region": "Unknown",
                        "location": null,
                        "relay_addr": relay.relay_addr().to_string(),
                        "reason": reason,
                    })
                    .to_string(),
                );
            } else {
                let (lookup_tx, mut lookup_rx) =
                    tokio::sync::mpsc::unbounded_channel::<(std::net::Ipv4Addr, u64, u64)>();
                auto_router.set_lookup_channel(lookup_tx);

                let router_for_lookup = Arc::clone(&auto_router);
                let relay_for_lookup = Arc::clone(relay);
                tokio::spawn(async move {
                    while let Some((ip, _generation, session_epoch)) = lookup_rx.recv().await {
                        // Drop if router disabled.
                        if !router_for_lookup.is_enabled() {
                            router_for_lookup.clear_pending_lookup(ip);
                            continue;
                        }
                        if !router_for_lookup.should_process_lookup_result(ip) {
                            continue;
                        }

                        let lookup_result = lookup_game_server_region(ip).await;

                        // Retry once on transient failure.
                        let lookup_result = if lookup_result == GameServerRegionLookup::Failed {
                            lookup_game_server_region(ip).await
                        } else {
                            lookup_result
                        };

                        // Drop if disabled or stale.
                        if !router_for_lookup.is_enabled() {
                            router_for_lookup.clear_pending_lookup(ip);
                            continue;
                        }
                        if !router_for_lookup.lookup_commit_allowed(ip, session_epoch) {
                            router_for_lookup.clear_pending_lookup(ip);
                            continue;
                        }

                        match lookup_result {
                            GameServerRegionLookup::Resolved(region, location) => {
                                let old_region = router_for_lookup.current_region();
                                let candidates =
                                    router_for_lookup.get_candidates_for_region(&region);

                                if let Some(candidates) = candidates {
                                    let best = ping_and_select_best(&candidates).await;
                                    let selected = best
                                        .map(|(r, a, _)| (r, a))
                                        .unwrap_or_else(|| candidates[0].clone());

                                    // Pre-check before committing.
                                    let latency_improvement =
                                        compute_cached_latency_improvement(&router_for_lookup, &selected.0);
                                    if !router_for_lookup.switch_allowed_precheck(
                                        &selected.0,
                                        selected.1,
                                        latency_improvement,
                                    ) {
                                        router_for_lookup.clear_pending_lookup(ip);
                                        continue;
                                    }

                                    if let Some((new_addr, new_region)) = router_for_lookup
                                        .commit_switch(
                                            region.clone(),
                                            selected.0,
                                            selected.1,
                                            Some(location.clone()),
                                        )
                                    {
                                        relay_for_lookup.switch_relay(new_addr);
                                        let _ = relay_for_lookup.send_keepalive_burst();
                                        fire_auto_routing_event(
                                            &json!({
                                                "type": "relay_switched",
                                                "timestamp_ms": now_millis(),
                                                "from_region": old_region,
                                                "to_region": new_region,
                                                "game_server_region": region.display_name(),
                                                "location": location,
                                                "relay_addr": new_addr.to_string(),
                                                "reason": format!(
                                                    "Game server moved to {}",
                                                    region.display_name()
                                                ),
                                            })
                                            .to_string(),
                                        );
                                    }
                                }
                            }
                            GameServerRegionLookup::NoRegion | GameServerRegionLookup::Failed => {}
                        }
                        router_for_lookup.clear_pending_lookup(ip);
                    }
                });
            }
        }

        driver.set_auto_router(Arc::clone(&auto_router));
        self.auto_router = Some(Arc::clone(&auto_router));

        driver.start().map_err(|e| {
            crate::error::SdkError::SplitTunnel(format!("Failed to start split tunnel: {}", e))
        })?;

        let running = driver.get_tunneled_processes();
        let driver = Arc::new(Mutex::new(driver));
        self.split_tunnel = Some(Arc::clone(&driver));

        self.process_monitor_stop.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&self.process_monitor_stop);
        let state_handle = Arc::clone(&self.state);
        let auto_router_for_monitor = self.auto_router.clone();

        tokio::spawn(async move {
            while !stop_flag.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(REFRESH_INTERVAL_MS)).await;
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                let driver_guard = driver.lock().await;
                driver_guard.drain_etw_events();
                driver_guard.refresh_processes();
                let running_names = driver_guard.get_tunneled_processes();
                drop(driver_guard);

                let mut state = state_handle.lock().await;
                if let ConnectionState::Connected {
                    ref mut tunneled_processes,
                    ref mut server_region,
                    ..
                } = *state
                {
                    if *tunneled_processes != running_names {
                        *tunneled_processes = running_names;
                    }

                    if let Some(ref auto_router) = auto_router_for_monitor {
                        let routed_region = auto_router.current_region();
                        if !routed_region.is_empty() && *server_region != routed_region {
                            *server_region = routed_region;
                        }
                    }
                }
            }
        });

        Ok(running)
    }

    pub async fn disconnect(&mut self) -> Result<(), crate::error::SdkError> {
        self.set_state(ConnectionState::Disconnecting).await;
        self.cleanup().await;
        self.set_state(ConnectionState::Disconnected).await;
        Ok(())
    }

    async fn cleanup(&mut self) {
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        if let Some(ref relay) = self.relay {
            relay.stop();
        }
        self.relay = None;

        for asset_relay in &self.asset_relays {
            asset_relay.stop();
        }
        self.asset_relays.clear();
        crate::asset_route::clear();

        if let Some(ref auto_router) = self.auto_router {
            auto_router.reset();
        }
        self.auto_router = None;

        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            guard.close();
        }
        self.split_tunnel = None;

        // Drop any user URL exclusions.
        crate::exclusions::clear();

        // Route Assist: remove any hosts-file DNS overrides we applied.
        if self.bootstrap_dns_applied {
            if let Err(e) = crate::roblox_proxy::hosts::remove_overrides_async().await {
                log::warn!("Route Assist: failed to remove bootstrap DNS overrides: {}", e);
            }
            self.bootstrap_dns_applied = false;
        }

        // Stop GoodbyeDPI helper (Drop impl kills the subprocess and removes the
        // hostlist file).
        if let Some(mut guard) = self.goodbye_dpi_guard.take() {
            guard.stop();
        }
        self.country_ban_bypass_failure = None;

        self.config = None;
    }

    pub fn config(&self) -> Option<&VpnConfig> {
        self.config.as_ref()
    }

    pub fn is_split_tunnel_active(&self) -> bool {
        self.split_tunnel.is_some()
    }

    /// Take the non-fatal GoodbyeDPI failure message from the last connect, if any.
    /// Clears the stored message so it is only returned once.
    pub fn take_country_ban_bypass_failure(&mut self) -> Option<String> {
        self.country_ban_bypass_failure.take()
    }

    pub async fn add_tunnel_app(&mut self, _exe_name: &str) -> Result<(), crate::error::SdkError> {
        Err(crate::error::SdkError::SplitTunnel(
            "Dynamic tunnel app updates are not supported in this SDK build".to_string(),
        ))
    }

    pub async fn remove_tunnel_app(
        &mut self,
        _exe_name: &str,
    ) -> Result<(), crate::error::SdkError> {
        Err(crate::error::SdkError::SplitTunnel(
            "Dynamic tunnel app updates are not supported in this SDK build".to_string(),
        ))
    }
}

impl Default for VpnConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VpnConnection {
    fn drop(&mut self) {
        self.process_monitor_stop.store(true, Ordering::SeqCst);
        if let Some(ref relay) = self.relay {
            relay.stop();
        }
        for asset_relay in &self.asset_relays {
            asset_relay.stop();
        }
        if let Some(ref driver) = self.split_tunnel {
            if let Ok(mut guard) = driver.try_lock() {
                guard.close();
            }
        }
        // Route Assist: best-effort synchronous hosts cleanup so we never leave
        // stale DNS overrides behind if the process is torn down.
        if self.bootstrap_dns_applied {
            let _ = crate::roblox_proxy::hosts::remove_overrides();
            self.bootstrap_dns_applied = false;
        }
    }
}
