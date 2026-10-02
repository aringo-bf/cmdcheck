use crate::config::PreflightConfig;
use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn cache_path(config: &PreflightConfig) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    config.proxy_url.hash(&mut hasher);
    config.check_url.hash(&mut hasher);
    std::env::temp_dir().join(format!("cmdcheck-preflight-{:016x}", hasher.finish()))
}

pub fn ensure(config: &PreflightConfig) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let cache = cache_path(config);
    if let Ok(value) = fs::read_to_string(&cache) {
        if let Ok(checked_at) = value.trim().parse::<u64>() {
            if now.saturating_sub(checked_at) <= config.ttl_seconds {
                return Ok(());
            }
        }
    }

    let proxy = ureq::Proxy::new(&config.proxy_url)
        .map_err(|error| format!("invalid preflight proxy URL: {error}"))?;
    let agent = ureq::AgentBuilder::new()
        .proxy(proxy)
        .timeout(Duration::from_millis(config.timeout_ms))
        .build();
    agent
        .get(&config.check_url)
        .call()
        .map_err(|error| format!("proxy preflight failed: {error}"))?;
    fs::write(cache, now.to_string())
        .map_err(|error| format!("could not update preflight cache: {error}"))?;
    Ok(())
}
