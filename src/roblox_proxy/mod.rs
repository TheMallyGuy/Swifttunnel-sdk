//! Roblox Route Assist support.
//!
//! "Route Assist" tunnels Roblox's TCP API/bootstrap traffic (not just UDP game
//! traffic) through the relay and repairs DNS for the small set of Roblox launch
//! hostnames via the Windows hosts file. Together these let a user bypass a
//! network/country ban and improve the odds Roblox places them near the tunneled
//! region.

pub mod goodbyedpi;
pub mod hosts;
pub mod tls_sni;
