// src/randomizer.rs
use rand::prelude::IndexedRandom;

/// Handles randomization of browser fingerprints (User-Agent, Accept-Language).
pub struct Randomizer {
    /// The current randomized User-Agent string.
    pub current_ua: String,
    /// The current randomized Accept-Language string.
    pub current_lang: String,
    /// Rotation mode: "every_request", "interval", or "launch".
    pub mode: String,
    /// Interval in seconds for "interval" rotation mode.
    pub interval_secs: u64,
    // flags controlling what to randomize
    /// Whether to randomize the User-Agent header.
    pub randomize_user_agent: bool,
    /// Whether to randomize the Accept-Language header.
    pub randomize_accept_language: bool,
    /// Whether to strip the Referer header.
    pub strip_referer: bool,
    // configurable language options
    languages: Vec<String>,
}

impl Randomizer {
    /// Creates a new Randomizer instance based on the configuration.
    ///
    /// # Arguments
    ///
    /// * `cfg` - Fingerprint configuration.
    pub fn new(cfg: &crate::config::FingerprintConfig) -> Self {
        let mut rng = rand::rng();
        let ua = rand_agents::user_agent().to_string();
        let lang = cfg
            .accept_languages
            .choose(&mut rng)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "en-US,en;q=0.9".to_string());

        Self {
            current_ua: ua,
            current_lang: lang,
            mode: cfg.rotation_mode.clone(),
            interval_secs: cfg.rotation_interval,
            randomize_user_agent: cfg.randomize_user_agent,
            randomize_accept_language: cfg.randomize_accept_language,
            strip_referer: cfg.strip_referer,
            languages: cfg.accept_languages.clone(),
        }
    }

    /// Rotates the User-Agent string to a new random value.
    ///
    /// Returns the new User-Agent string.
    pub fn rotate_user_agent(&mut self) -> String {
        self.current_ua = rand_agents::user_agent().to_string();
        self.current_ua.clone()
    }

    /// Rotates the Accept-Language string to a new random value from the configured list.
    ///
    /// Returns the new Accept-Language string.
    pub fn rotate_accept_language(&mut self) -> String {
        let mut rng = rand::rng();
        self.current_lang = self
            .languages
            .choose(&mut rng)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "en-US,en;q=0.9".to_string());
        self.current_lang.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FingerprintConfig;

    #[test]
    fn test_randomizer_initialization() {
        let cfg = FingerprintConfig {
            rotation_mode: "launch".to_string(),
            rotation_interval: 0,
            randomize_user_agent: true,
            randomize_accept_language: true,
            strip_referer: false,
            accept_languages: vec!["en-US".to_string(), "de-DE".to_string()],
        };
        let randomizer = Randomizer::new(&cfg);
        assert!(!randomizer.current_ua.is_empty());
        assert!(cfg.accept_languages.contains(&randomizer.current_lang));
    }

    #[test]
    fn test_rotate_user_agent() {
        let cfg = FingerprintConfig {
            rotation_mode: "launch".to_string(),
            rotation_interval: 0,
            randomize_user_agent: true,
            randomize_accept_language: true,
            strip_referer: false,
            accept_languages: vec!["en-US".to_string()],
        };
        let mut randomizer = Randomizer::new(&cfg);
        let _ua1 = randomizer.current_ua.clone();
        let ua2 = randomizer.rotate_user_agent();

        // It's statistically possible but unlikely they are the same,
        // but rand_agents has a large pool.
        assert!(!ua2.is_empty());
        // We can't strictly assert inequality because of randomness, but we can check format.
    }
}
