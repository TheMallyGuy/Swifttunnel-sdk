//! IP geolocation + Roblox region mapping for auto-routing.

use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

/// Shared HTTP client with a 5s timeout for ipinfo lookups.
fn geo_http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to build geolocation HTTP client")
    })
}

/// Cache for IP -> location string.
static LOCATION_CACHE: std::sync::OnceLock<Arc<Mutex<HashMap<Ipv4Addr, String>>>> =
    std::sync::OnceLock::new();

/// Limit concurrent external geolocation requests.
static API_SEMAPHORE: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();

fn get_cache() -> Arc<Mutex<HashMap<Ipv4Addr, String>>> {
    LOCATION_CACHE
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn get_semaphore() -> &'static Semaphore {
    API_SEMAPHORE.get_or_init(|| Semaphore::new(2))
}

#[derive(Debug, Deserialize)]
struct IpInfoResponse {
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
}

fn format_location(info: &IpInfoResponse) -> Option<String> {
    let city = info.city.as_ref()?;
    let country = info.country.as_ref()?;
    if let Some(region) = &info.region {
        if city == region {
            Some(format!("{}, {}", city, country))
        } else {
            Some(format!("{}, {}, {}", city, region, country))
        }
    } else {
        Some(format!("{}, {}", city, country))
    }
}

/// Region classification used by auto-routing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RobloxRegion {
    Singapore,
    Tokyo,
    Mumbai,
    Sydney,
    London,
    Amsterdam,
    Paris,
    Frankfurt,
    Warsaw,
    UsEast,
    UsCentral,
    UsWest,
    Brazil,
    Unknown,
}

impl RobloxRegion {
    pub fn best_swifttunnel_region(&self) -> Option<&'static str> {
        match self {
            RobloxRegion::Unknown => None,
            RobloxRegion::Singapore => Some("singapore"),
            RobloxRegion::Tokyo => Some("tokyo"),
            RobloxRegion::Mumbai => Some("mumbai"),
            RobloxRegion::Sydney => Some("sydney"),
            RobloxRegion::London => Some("london"),
            RobloxRegion::Amsterdam => Some("amsterdam"),
            RobloxRegion::Paris => Some("paris"),
            RobloxRegion::Frankfurt => Some("germany"),
            RobloxRegion::Warsaw => Some("germany"),
            RobloxRegion::UsEast => Some("america"),
            RobloxRegion::UsCentral => Some("america"),
            RobloxRegion::UsWest => Some("america"),
            RobloxRegion::Brazil => Some("brazil"),
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            RobloxRegion::Singapore => "Singapore",
            RobloxRegion::Tokyo => "Tokyo",
            RobloxRegion::Mumbai => "Mumbai",
            RobloxRegion::Sydney => "Sydney",
            RobloxRegion::London => "London",
            RobloxRegion::Amsterdam => "Amsterdam",
            RobloxRegion::Paris => "Paris",
            RobloxRegion::Frankfurt => "Frankfurt",
            RobloxRegion::Warsaw => "Warsaw",
            RobloxRegion::UsEast => "US East",
            RobloxRegion::UsCentral => "US Central",
            RobloxRegion::UsWest => "US West",
            RobloxRegion::Brazil => "Brazil",
            RobloxRegion::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for RobloxRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Convert ipinfo city/country into runtime Roblox region.
pub fn ipinfo_to_roblox_region(city: &str, country: &str) -> RobloxRegion {
    match country {
        "SG" => RobloxRegion::Singapore,
        "JP" => RobloxRegion::Tokyo,
        "IN" => RobloxRegion::Mumbai,
        "AU" => RobloxRegion::Sydney,
        "BR" => RobloxRegion::Brazil,
        "GB" => RobloxRegion::London,
        "NL" => RobloxRegion::Amsterdam,
        "FR" => RobloxRegion::Paris,
        "PL" => RobloxRegion::Warsaw,
        "DE" => RobloxRegion::Frankfurt,
        "US" => {
            let city_lower = city.to_lowercase();
            if city_lower.contains("chicago")
                || city_lower.contains("elk grove")
                || city_lower.contains("dallas")
                || city_lower.contains("houston")
            {
                RobloxRegion::UsCentral
            } else if city_lower.contains("ashburn")
                || city_lower.contains("leesburg")
                || city_lower.contains("sterling")
                || city_lower.contains("reston")
                || city_lower.contains("new york")
                || city_lower.contains("secaucus")
                || city_lower.contains("newark")
                || city_lower.contains("atlanta")
                || city_lower.contains("miami")
                || city_lower.contains("jacksonville")
                || city_lower.contains("fort lauderdale")
            {
                RobloxRegion::UsEast
            } else {
                RobloxRegion::UsWest
            }
        }
        _ => RobloxRegion::Unknown,
    }
}

/// Result of a game server region lookup.
#[derive(Debug, Clone, PartialEq)]
pub enum GameServerRegionLookup {
    /// Successfully resolved a known region.
    Resolved(RobloxRegion, String),
    /// Got a response but the region was Unknown or location was missing.
    NoRegion,
    /// HTTP/network error — caller may retry.
    Failed,
}

/// Lookup runtime region for a game server IP via ipinfo.
pub async fn lookup_game_server_region(ip: Ipv4Addr) -> GameServerRegionLookup {
    let _permit = match get_semaphore().acquire().await {
        Ok(p) => p,
        Err(_) => return GameServerRegionLookup::Failed,
    };

    let cached_location = {
        let cache = get_cache();
        cache.lock().ok().and_then(|c| c.get(&ip).cloned())
    };

    let (city, country, location) = if let Some(loc) = cached_location {
        let parts: Vec<&str> = loc.split(", ").collect();
        let city = parts.first().unwrap_or(&"").to_string();
        let country = parts.last().unwrap_or(&"").to_string();
        (city, country, loc)
    } else {
        let url = format!("https://ipinfo.io/{}/json", ip);
        let client = geo_http_client();
        let response = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("ipinfo.io request failed for {}: {}", ip, e);
                return GameServerRegionLookup::Failed;
            }
        };
        if !response.status().is_success() {
            log::warn!("ipinfo.io returned status {} for {}", response.status(), ip);
            return GameServerRegionLookup::Failed;
        }
        let info: IpInfoResponse = match response.json().await {
            Ok(i) => i,
            Err(e) => {
                log::warn!("ipinfo.io JSON parse failed for {}: {}", ip, e);
                return GameServerRegionLookup::Failed;
            }
        };
        let city = info.city.clone().unwrap_or_default();
        let country = info.country.clone().unwrap_or_default();
        let location = match format_location(&info) {
            Some(l) => l,
            None => return GameServerRegionLookup::NoRegion,
        };

        if let Ok(mut cache) = get_cache().lock() {
            cache.insert(ip, location.clone());
        }

        (city, country, location)
    };

    let region = ipinfo_to_roblox_region(&city, &country);
    if region == RobloxRegion::Unknown {
        return GameServerRegionLookup::NoRegion;
    }
    GameServerRegionLookup::Resolved(region, location)
}
