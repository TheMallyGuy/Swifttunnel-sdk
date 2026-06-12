//! VPN Module for SwiftTunnel SDK
//!
//! V3 relay-only implementation. Routes game traffic through optimized
//! server paths without encryption for minimum latency.
//!
//! ## Architecture
//!
//! - relay.rs: UDP relay client (session-based packet forwarding)
//! - config.rs: VPN configuration fetching from API
//! - servers.rs: Server list, caching, and latency measurement
//! - connection.rs: V3 connection state machine and lifecycle

pub mod auto_routing;
pub mod config;
pub mod connection;
pub mod diskless_passthrough;
pub mod geolocation;
pub mod ipv6_recovery;
pub mod relay;
pub mod servers;

pub use auto_routing::{AutoRouter, AutoRoutingEvent};
pub use config::{fetch_vpn_config, update_latency, VpnConfigRequest};
pub use connection::{ConnectionState, VpnConnection};
pub use geolocation::{lookup_game_server_region, RobloxRegion};
pub use relay::{RelayContext, UdpRelay};
pub use servers::{
    load_server_list, measure_latency, DynamicGamingRegion, DynamicServerInfo, ServerList,
    ServerListSource,
};
