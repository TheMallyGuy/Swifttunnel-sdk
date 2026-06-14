//! Auto routing: detect game-server region changes and switch relay dynamically.

use super::geolocation::RobloxRegion;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MIN_SWITCH_INTERVAL: Duration = Duration::from_secs(10);
const MAX_SWITCHES_PER_MINUTE: u32 = 3;
const MAX_EVENT_LOG: usize = 20;

pub(crate) const SAME_REGION_UPGRADE_THRESHOLD_MS: u32 = 10;
const GAME_TRAFFIC_QUIET_HANDOFF: Duration = Duration::from_secs(3);
const MAX_TRACKED_GAME_TRAFFIC_IPS: usize = 4096;
const GAME_TRAFFIC_UPDATE_GRANULARITY: Duration = Duration::from_millis(250);

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
pub struct AutoRoutingEvent {
    pub timestamp_ms: u64,
    pub event_type: String,
    pub from_region: String,
    pub to_region: String,
    pub game_server_region: String,
    pub reason: String,
    pub location: Option<String>,
    pub relay_addr: Option<String>,
}

#[derive(Debug)]
pub enum AutoRoutingAction {
    NoAction,
}

pub struct AutoRouter {
    enabled: AtomicBool,
    current_game_region: RwLock<Option<RobloxRegion>>,
    current_relay_addr: RwLock<Option<SocketAddr>>,
    current_st_region: RwLock<String>,
    last_switch_time: RwLock<Instant>,
    switches_this_minute: RwLock<(u32, Instant)>,
    seen_game_servers: RwLock<HashSet<Ipv4Addr>>,
    available_servers: RwLock<Vec<(String, SocketAddr, Option<u32>)>>,
    event_log: RwLock<VecDeque<AutoRoutingEvent>>,
    lookup_sender: RwLock<Option<tokio::sync::mpsc::UnboundedSender<(Ipv4Addr, u64, u64)>>>,
    pending_lookups: RwLock<HashSet<Ipv4Addr>>,
    whitelisted_regions: RwLock<HashSet<String>>,
    auto_routing_bypassed: AtomicBool,
    // v2.2.3 additions
    lookup_session_epoch: AtomicU64,
    active_game_server_ip: RwLock<Option<Ipv4Addr>>,
    game_traffic: RwLock<HashMap<Ipv4Addr, Instant>>,
    latest_lookup_generation: AtomicU64,
    pending_any: AtomicBool,
    forced_servers: RwLock<HashMap<String, String>>,
}

impl AutoRouter {
    pub fn new(enabled: bool, initial_region: &str) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            current_game_region: RwLock::new(None),
            current_relay_addr: RwLock::new(None),
            current_st_region: RwLock::new(initial_region.to_string()),
            last_switch_time: RwLock::new(Instant::now() - MIN_SWITCH_INTERVAL),
            switches_this_minute: RwLock::new((0, Instant::now())),
            seen_game_servers: RwLock::new(HashSet::new()),
            available_servers: RwLock::new(Vec::new()),
            event_log: RwLock::new(VecDeque::new()),
            lookup_sender: RwLock::new(None),
            pending_lookups: RwLock::new(HashSet::new()),
            whitelisted_regions: RwLock::new(HashSet::new()),
            auto_routing_bypassed: AtomicBool::new(false),
            lookup_session_epoch: AtomicU64::new(0),
            active_game_server_ip: RwLock::new(None),
            game_traffic: RwLock::new(HashMap::new()),
            latest_lookup_generation: AtomicU64::new(0),
            pending_any: AtomicBool::new(false),
            forced_servers: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_lookup_channel(
        &self,
        sender: tokio::sync::mpsc::UnboundedSender<(Ipv4Addr, u64, u64)>,
    ) {
        *self.lookup_sender.write() = Some(sender);
    }

    pub fn set_enabled(&self, enabled: bool) {
        let was_enabled = self.enabled.load(Ordering::Acquire);
        self.enabled.store(enabled, Ordering::Release);

        if !enabled {
            // Bump epoch so in-flight lookups from the old session are discarded.
            self.lookup_session_epoch.fetch_add(1, Ordering::AcqRel);
            // Release all pending lookups immediately.
            self.pending_lookups.write().clear();
            self.pending_any.store(false, Ordering::Release);
        } else if !was_enabled {
            // Turning back on: clear seen-servers so re-routing can happen.
            self.seen_game_servers.write().clear();
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn set_whitelisted_regions(&self, regions: Vec<String>) {
        let new_set: HashSet<String> = regions.into_iter().collect();
        // If the current game region is no longer whitelisted, clear bypass flag.
        if self.auto_routing_bypassed.load(Ordering::Relaxed) {
            let current_game = self.current_game_region.read().clone();
            if let Some(ref region) = current_game {
                if !new_set.contains(region.display_name()) {
                    self.auto_routing_bypassed.store(false, Ordering::Release);
                }
            }
        }
        *self.whitelisted_regions.write() = new_set;
    }

    pub fn set_available_servers(&self, servers: Vec<(String, SocketAddr, Option<u32>)>) {
        *self.available_servers.write() = servers;
    }

    pub fn set_current_relay(&self, addr: SocketAddr, region: &str) {
        *self.current_relay_addr.write() = Some(addr);
        *self.current_st_region.write() = region.to_string();
    }

    pub fn set_forced_servers(&self, servers: HashMap<String, String>) {
        *self.forced_servers.write() = servers;
    }

    pub fn forced_server_for_region(&self, region: &str) -> Option<String> {
        self.forced_servers.read().get(region).cloned()
    }

    pub fn current_game_region(&self) -> Option<RobloxRegion> {
        self.current_game_region.read().clone()
    }

    pub fn current_region(&self) -> String {
        self.current_st_region.read().clone()
    }

    pub fn is_bypassed(&self) -> bool {
        self.auto_routing_bypassed.load(Ordering::Acquire)
    }

    pub fn pending_lookup_count(&self) -> usize {
        self.pending_lookups.read().len()
    }

    pub fn recent_events(&self, max: usize) -> Vec<AutoRoutingEvent> {
        self.event_log
            .read()
            .iter()
            .rev()
            .take(max)
            .cloned()
            .collect()
    }

    fn log_event(&self, event: AutoRoutingEvent) {
        let mut log = self.event_log.write();
        log.push_back(event);
        if log.len() > MAX_EVENT_LOG {
            log.pop_front();
        }
    }

    fn is_region_whitelisted(&self, region: &RobloxRegion) -> bool {
        self.whitelisted_regions
            .read()
            .contains(region.display_name())
    }

    /// Record that `ip` just sent game traffic (throttled update).
    pub fn note_game_traffic(&self, ip: Ipv4Addr) {
        // Throttle writes to avoid lock contention on every packet.
        let needs_update = {
            let read = self.game_traffic.read();
            match read.get(&ip) {
                Some(last) => last.elapsed() >= GAME_TRAFFIC_UPDATE_GRANULARITY,
                None => true,
            }
        };
        if needs_update {
            let mut write = self.game_traffic.write();
            // Cap the map size.
            if write.len() >= MAX_TRACKED_GAME_TRAFFIC_IPS && !write.contains_key(&ip) {
                return;
            }
            write.insert(ip, Instant::now());
        }
    }

    /// Returns true if all other tracked game-traffic IPs (excluding `candidate`)
    /// have been quiet for at least GAME_TRAFFIC_QUIET_HANDOFF.
    fn other_game_traffic_quiet(&self, candidate: Ipv4Addr) -> bool {
        let read = self.game_traffic.read();
        read.iter()
            .filter(|(ip, _)| **ip != candidate)
            .all(|(_, last)| last.elapsed() >= GAME_TRAFFIC_QUIET_HANDOFF)
    }

    fn is_current_lookup_generation(&self, gen: u64) -> bool {
        self.latest_lookup_generation.load(Ordering::Acquire) == gen
    }

    fn is_current_lookup_session(&self, epoch: u64) -> bool {
        self.lookup_session_epoch.load(Ordering::Acquire) == epoch
    }

    /// Record the current game region without switching relay.
    pub fn record_game_region(&self, region: RobloxRegion) {
        *self.current_game_region.write() = Some(region);
    }

    /// Pin `ip` as the active game server (no session-epoch check).
    pub fn pin_active_game_server(&self, ip: Ipv4Addr) -> bool {
        *self.active_game_server_ip.write() = Some(ip);
        true
    }

    /// Pin `ip` as the active game server, gated by session epoch and
    /// gone-quiet handoff.
    pub fn pin_active_game_server_for_session(&self, ip: Ipv4Addr, session_epoch: u64) -> bool {
        if !self.is_current_lookup_session(session_epoch) {
            return false;
        }
        if !self.other_game_traffic_quiet(ip) {
            return false;
        }
        *self.active_game_server_ip.write() = Some(ip);
        true
    }

    pub fn is_active_game_server(&self, ip: Ipv4Addr) -> bool {
        self.active_game_server_ip
            .read()
            .map(|a| a == ip)
            .unwrap_or(false)
    }

    /// Returns true if the lookup result for `ip` should still be processed
    /// (IP is in pending_lookups).
    pub fn should_process_lookup_result(&self, ip: Ipv4Addr) -> bool {
        self.pending_lookups.read().contains(&ip)
    }

    /// Returns true if a commit for `ip` with `session_epoch` is still valid.
    pub fn lookup_commit_allowed(&self, ip: Ipv4Addr, session_epoch: u64) -> bool {
        self.is_current_lookup_session(session_epoch)
            && self.pending_lookups.read().contains(&ip)
    }

    /// Pre-check before authenticating: verify region/addr/latency thresholds.
    pub fn switch_allowed_precheck(
        &self,
        to_region: &str,
        _new_addr: SocketAddr,
        latency_improvement_ms: Option<u32>,
    ) -> bool {
        // Same region — only allow if latency improvement exceeds threshold.
        let current_st = self.current_st_region.read().clone();
        let regions_match = current_st == to_region
            || current_st.starts_with(&format!("{}-", to_region))
            || to_region.starts_with(&format!("{}-", current_st));

        if regions_match {
            return latency_improvement_ms
                .map(|ms| ms >= SAME_REGION_UPGRADE_THRESHOLD_MS)
                .unwrap_or(false);
        }
        true
    }

    pub fn available_servers_snapshot(&self) -> Vec<(String, SocketAddr, Option<u32>)> {
        self.available_servers.read().clone()
    }

    pub fn current_relay(&self) -> Option<(String, SocketAddr)> {
        let region = self.current_st_region.read().clone();
        let addr = *self.current_relay_addr.read();
        addr.map(|a| (region, a))
    }

    /// True when `ip`'s last observed packet is older than the gone-quiet
    /// handoff window (or it has no tracked traffic at all).
    fn game_server_is_quiet(&self, ip: Ipv4Addr) -> bool {
        self.game_traffic
            .read()
            .get(&ip)
            .map(|last| Instant::now().duration_since(*last) >= GAME_TRAFFIC_QUIET_HANDOFF)
            .unwrap_or(true)
    }

    /// Expire the per-session routing pin when the game server that currently
    /// owns the route has gone quiet — i.e. the player left that match or closed
    /// that Roblox instance.
    ///
    /// Without this, the next server a player joins frequently first appears
    /// *within* [`GAME_TRAFFIC_QUIET_HANDOFF`] of the old server's last packet
    /// (the teleport / relaunch overlap), so `evaluate_game_server` marks it
    /// `seen` and defers it — and once the old connection goes quiet it is never
    /// re-evaluated, leaving the relay stuck on the old region until a full
    /// disconnect. Clearing the pin and the seen-set here lets the next server
    /// route like a fresh join. Returns `true` when a stale pin was expired.
    fn maybe_expire_quiet_pin(&self) -> bool {
        let active = match *self.active_game_server_ip.read() {
            Some(ip) => ip,
            None => return false,
        };
        if !self.game_server_is_quiet(active) {
            return false;
        }

        // Re-check under the write lock so a concurrent handoff/pin can't be
        // clobbered between the read above and the clear below.
        let mut active_pin = self.active_game_server_ip.write();
        match *active_pin {
            Some(pinned) if pinned == active && self.game_server_is_quiet(pinned) => {
                *active_pin = None;
                drop(active_pin);
                self.seen_game_servers.write().clear();
                log::info!(
                    "Auto-routing: Active game server {} went quiet (left match / closed instance) — \
                     routing reset so the next game re-routes",
                    active
                );
                true
            }
            _ => false,
        }
    }

    pub fn evaluate_game_server(&self, game_server_ip: Ipv4Addr) -> AutoRoutingAction {
        // Always note traffic (even when disabled) for gone-quiet tracking.
        self.note_game_traffic(game_server_ip);

        if !self.is_enabled() {
            return AutoRoutingAction::NoAction;
        }

        // Fast path: already pending a lookup.
        if self.pending_any.load(Ordering::Relaxed) {
            return AutoRoutingAction::NoAction;
        }

        // Gone-quiet gate: don't evaluate until other IPs have gone quiet.
        if !self.other_game_traffic_quiet(game_server_ip) {
            return AutoRoutingAction::NoAction;
        }

        let already_seen = match self.seen_game_servers.try_read() {
            Some(seen) => seen.contains(&game_server_ip),
            None => return AutoRoutingAction::NoAction,
        };
        if already_seen {
            // This IP was already evaluated. If the server that owns the route
            // has since gone quiet (player left the match / closed that instance),
            // expire the pin so this IP re-routes like a fresh join instead of
            // staying stuck on the old relay.
            if !self.maybe_expire_quiet_pin() {
                return AutoRoutingAction::NoAction;
            }
        }

        // Add to seen set (write lock).
        match self.seen_game_servers.try_write() {
            Some(mut seen) => {
                seen.insert(game_server_ip);
            }
            None => return AutoRoutingAction::NoAction,
        }

        let session_epoch = self.lookup_session_epoch.load(Ordering::Acquire);
        let generation = self
            .latest_lookup_generation
            .fetch_add(1, Ordering::AcqRel)
            + 1;

        if let Some(mut pending) = self.pending_lookups.try_write() {
            pending.insert(game_server_ip);
            self.pending_any.store(true, Ordering::Release);
        }
        if let Some(sender) = self.lookup_sender.read().as_ref() {
            let _ = sender.send((game_server_ip, generation, session_epoch));
        }

        AutoRoutingAction::NoAction
    }

    pub fn is_lookup_pending(&self, ip: Ipv4Addr) -> bool {
        self.pending_lookups.read().contains(&ip)
    }

    pub fn clear_pending_lookup(&self, ip: Ipv4Addr) {
        self.pending_lookups.write().remove(&ip);
        if self.pending_lookups.read().is_empty() {
            self.pending_any.store(false, Ordering::Release);
        }
    }

    /// Get the best server for `game_region`. Returns `None` if already on the
    /// correct region or no servers available. Handles whitelist bypass.
    pub fn get_best_server_for_region(
        &self,
        game_region: &RobloxRegion,
    ) -> Option<(String, SocketAddr)> {
        if *game_region == RobloxRegion::Unknown {
            return None;
        }

        if self.is_region_whitelisted(game_region) {
            self.auto_routing_bypassed.store(true, Ordering::Release);
            *self.current_game_region.write() = Some(game_region.clone());
            self.log_event(AutoRoutingEvent {
                timestamp_ms: now_millis(),
                event_type: "bypassed".to_string(),
                from_region: self.current_st_region.read().clone(),
                to_region: "BYPASS".to_string(),
                game_server_region: game_region.display_name().to_string(),
                reason: format!(
                    "{} is whitelisted - using direct connection",
                    game_region.display_name()
                ),
                location: None,
                relay_addr: None,
            });
            return None;
        }

        self.auto_routing_bypassed.store(false, Ordering::Release);

        let best_st_region = game_region.best_swifttunnel_region()?;
        let current_st_region = self.current_st_region.read().clone();
        if current_st_region == best_st_region
            || current_st_region.starts_with(&format!("{}-", best_st_region))
        {
            *self.current_game_region.write() = Some(game_region.clone());
            return None;
        }

        // Check forced server override first.
        if let Some(forced) = self.forced_server_for_region(best_st_region) {
            let servers = self.available_servers.read();
            if let Some((_, addr, _)) = servers.iter().find(|(r, _, _)| r == &forced) {
                return Some((forced, *addr));
            }
        }

        let servers = self.available_servers.read();
        let mut candidates_with_latency: Vec<&(String, SocketAddr, Option<u32>)> = servers
            .iter()
            .filter(|(region, _, _)| {
                region == best_st_region || region.starts_with(&format!("{}-", best_st_region))
            })
            .collect();
        candidates_with_latency.sort_by_key(|(_, _, latency)| latency.unwrap_or(u32::MAX));
        candidates_with_latency
            .into_iter()
            .next()
            .map(|(region, addr, _)| (region.clone(), *addr))
    }

    /// Legacy: return all candidates for a region (kept for existing callers).
    pub fn get_candidates_for_region(
        &self,
        game_region: &RobloxRegion,
    ) -> Option<Vec<(String, SocketAddr)>> {
        if *game_region == RobloxRegion::Unknown {
            return None;
        }

        if self.is_region_whitelisted(game_region) {
            self.auto_routing_bypassed.store(true, Ordering::Release);
            *self.current_game_region.write() = Some(game_region.clone());
            self.log_event(AutoRoutingEvent {
                timestamp_ms: now_millis(),
                event_type: "bypassed".to_string(),
                from_region: self.current_st_region.read().clone(),
                to_region: "BYPASS".to_string(),
                game_server_region: game_region.display_name().to_string(),
                reason: format!(
                    "{} is whitelisted - using direct connection",
                    game_region.display_name()
                ),
                location: None,
                relay_addr: None,
            });
            return None;
        }

        self.auto_routing_bypassed.store(false, Ordering::Release);

        let best_st_region = game_region.best_swifttunnel_region()?;
        let current_st_region = self.current_st_region.read().clone();
        if current_st_region == best_st_region
            || current_st_region.starts_with(&format!("{}-", best_st_region))
        {
            *self.current_game_region.write() = Some(game_region.clone());
            return None;
        }

        let servers = self.available_servers.read();
        let mut candidates_with_latency: Vec<&(String, SocketAddr, Option<u32>)> = servers
            .iter()
            .filter(|(region, _, _)| {
                region == best_st_region || region.starts_with(&format!("{}-", best_st_region))
            })
            .collect();
        candidates_with_latency.sort_by_key(|(_, _, latency)| latency.unwrap_or(u32::MAX));
        let candidates = candidates_with_latency
            .into_iter()
            .map(|(region, addr, _)| (region.clone(), *addr))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            None
        } else {
            Some(candidates)
        }
    }

    pub fn commit_switch(
        &self,
        game_region: RobloxRegion,
        selected_region: String,
        selected_addr: SocketAddr,
        location: Option<String>,
    ) -> Option<(SocketAddr, String)> {
        let current_st_region = self.current_st_region.read().clone();
        if self.record_switch(
            &current_st_region,
            &selected_region,
            &game_region,
            selected_addr,
            location,
        ) {
            Some((selected_addr, selected_region))
        } else {
            None
        }
    }

    fn record_switch(
        &self,
        from_region: &str,
        to_region: &str,
        game_region: &RobloxRegion,
        new_addr: SocketAddr,
        location: Option<String>,
    ) -> bool {
        if *self.current_st_region.read() == to_region {
            return false;
        }

        let now = Instant::now();
        if now.duration_since(*self.last_switch_time.read()) < MIN_SWITCH_INTERVAL {
            return false;
        }

        let mut window = self.switches_this_minute.write();
        if now.duration_since(window.1) > Duration::from_secs(60) {
            *window = (0, now);
        }
        if window.0 >= MAX_SWITCHES_PER_MINUTE {
            return false;
        }
        window.0 += 1;
        drop(window);

        *self.last_switch_time.write() = now;
        *self.current_st_region.write() = to_region.to_string();
        *self.current_relay_addr.write() = Some(new_addr);
        *self.current_game_region.write() = Some(game_region.clone());

        self.log_event(AutoRoutingEvent {
            timestamp_ms: now_millis(),
            event_type: "relay_switched".to_string(),
            from_region: from_region.to_string(),
            to_region: to_region.to_string(),
            game_server_region: game_region.display_name().to_string(),
            reason: format!(
                "Game server moved to {} - switching from {} to {}",
                game_region.display_name(),
                from_region,
                to_region
            ),
            location,
            relay_addr: Some(new_addr.to_string()),
        });

        true
    }

    pub fn push_degraded_event(&self, reason: String) {
        self.log_event(AutoRoutingEvent {
            timestamp_ms: now_millis(),
            event_type: "degraded".to_string(),
            from_region: self.current_st_region.read().clone(),
            to_region: self.current_st_region.read().clone(),
            game_server_region: "Unknown".to_string(),
            reason,
            location: None,
            relay_addr: self.current_relay_addr.read().map(|a| a.to_string()),
        });
    }

    pub fn reset(&self) {
        *self.current_game_region.write() = None;
        *self.current_relay_addr.write() = None;
        *self.active_game_server_ip.write() = None;
        self.seen_game_servers.write().clear();
        self.pending_lookups.write().clear();
        self.pending_any.store(false, Ordering::Release);
        self.game_traffic.write().clear();
        self.lookup_session_epoch.fetch_add(1, Ordering::AcqRel);
        self.auto_routing_bypassed.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_servers() -> Vec<(String, SocketAddr, Option<u32>)> {
        vec![
            (
                "singapore".to_string(),
                "54.255.205.216:51821".parse().unwrap(),
                None,
            ),
            (
                "america-01".to_string(),
                "54.225.245.114:51821".parse().unwrap(),
                None,
            ),
            (
                "tokyo-02".to_string(),
                "45.32.253.124:51821".parse().unwrap(),
                None,
            ),
        ]
    }

    #[test]
    fn test_auto_router_disabled() {
        let router = AutoRouter::new(false, "singapore");
        router.set_available_servers(make_servers());
        let action = router.evaluate_game_server(Ipv4Addr::new(128, 116, 102, 1));
        assert!(matches!(action, AutoRoutingAction::NoAction));
    }

    #[test]
    fn test_duplicate_ip_suppressed_and_pending_lookup_clears() {
        let router = AutoRouter::new(true, "singapore");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 102, 1);
        router.evaluate_game_server(ip);
        // Second call: pending_any is set, so it's suppressed early.
        router.evaluate_game_server(ip);

        assert_eq!(router.pending_lookup_count(), 1);
        assert!(router.is_lookup_pending(ip));
        // Channel should have received the tuple.
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg.0, ip);
        assert!(rx.try_recv().is_err());

        router.clear_pending_lookup(ip);
        assert!(!router.is_lookup_pending(ip));
        assert_eq!(router.pending_lookup_count(), 0);
    }

    #[test]
    fn test_get_candidates_and_commit_switch() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        let candidates = router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(candidates.is_some());
        let candidates = candidates.unwrap();
        assert_eq!(candidates[0].0, "america-01");
        let result = router.commit_switch(
            RobloxRegion::UsEast,
            candidates[0].0.clone(),
            candidates[0].1,
            Some("Ashburn, US".to_string()),
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_same_region_no_switch() {
        let router = AutoRouter::new(true, "america-01");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.225.245.114:51821".parse().unwrap(), "america-01");

        let candidates = router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(candidates.is_none());
        assert_eq!(router.current_game_region(), Some(RobloxRegion::UsEast));
    }

    #[test]
    fn test_rate_limits_enforced() {
        let router = AutoRouter::new(true, "singapore");
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        let sequence = vec![
            (
                RobloxRegion::UsEast,
                "america-01".to_string(),
                "54.225.245.114:51821",
            ),
            (
                RobloxRegion::Tokyo,
                "tokyo-02".to_string(),
                "45.32.253.124:51821",
            ),
            (
                RobloxRegion::Singapore,
                "singapore".to_string(),
                "54.255.205.216:51821",
            ),
            (
                RobloxRegion::UsEast,
                "america-01".to_string(),
                "54.225.245.114:51821",
            ),
        ];

        for (idx, (game_region, region, addr_str)) in sequence.into_iter().enumerate() {
            *router.last_switch_time.write() = Instant::now() - MIN_SWITCH_INTERVAL;
            let addr: SocketAddr = addr_str.parse().unwrap();
            let switched = router.commit_switch(game_region, region, addr, None);
            if idx < MAX_SWITCHES_PER_MINUTE as usize {
                assert!(switched.is_some(), "switch {} should be allowed", idx + 1);
            } else {
                assert!(
                    switched.is_none(),
                    "switch {} should be rate-limited",
                    idx + 1
                );
            }
        }
    }

    #[test]
    fn test_whitelisted_region_bypasses_vpn() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_whitelisted_regions(vec!["US East".to_string()]);
        let candidates = router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(candidates.is_none());
        assert!(router.is_bypassed());

        let candidates2 = router.get_candidates_for_region(&RobloxRegion::Tokyo);
        assert!(!router.is_bypassed());
        assert!(candidates2.is_some());
    }
}
