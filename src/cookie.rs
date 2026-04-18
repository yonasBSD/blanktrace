// src/cookie.rs
use crate::config::Config;
use hudsucker::Body;
use hyper::{Request, Response};

/// Handles cookie stripping logic based on configuration.
#[derive(Clone)]
pub struct CookieHandler {
    /// Application configuration.
    pub config: Config,
}

impl CookieHandler {
    /// Creates a new CookieHandler.
    ///
    /// # Arguments
    ///
    /// * `config` - Application configuration.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Checks and strips cookies from an incoming request.
    ///
    /// Returns the stripped cookie value if one was removed, or None.
    ///
    /// # Arguments
    ///
    /// * `req` - The mutable HTTP request.
    /// * `host` - The hostname of the request.
    pub fn strip_cookies_request(&self, req: &mut Request<Body>, host: &str) -> Option<String> {
        // Check allow list
        if self.config.cookies.allow_list.iter().any(|d| host.ends_with(d)) {
            return None;
        }

        // Check block list or block_all
        let explicitly_blocked = self.config.cookies.block_list.iter().any(|d| host.ends_with(d));
        let should_block = explicitly_blocked || self.config.cookies.block_all;

        if should_block {
            if let Some(cookie) = req.headers_mut().remove(hyper::header::COOKIE) {
                return cookie.to_str().ok().map(|s| s.to_string());
            }
        } else if self.config.cookies.log_attempts {
            if let Some(cookie) = req.headers().get(hyper::header::COOKIE) {
                return cookie.to_str().ok().map(|s| s.to_string());
            }
        }
        None
    }

    /// Checks and strips Set-Cookie headers from an outgoing response.
    ///
    /// Returns the stripped cookie value if one was removed, or None.
    ///
    /// # Arguments
    ///
    /// * `res` - The mutable HTTP response.
    /// * `host` - The hostname of the request (optional, as it might not be available in response context).
    pub fn strip_cookies_response(&self, res: &mut Response<Body>, host: Option<&str>) -> Option<String> {
        // If host is known, check allow list
        if let Some(h) = host {
            if self.config.cookies.allow_list.iter().any(|d| h.ends_with(d)) {
                return None;
            }
        }

        // Check block list (if host known) or block_all
        let explicitly_blocked = host.map_or(false, |h| {
            self.config.cookies.block_list.iter().any(|d| h.ends_with(d))
        });
        
        let should_block = explicitly_blocked || self.config.cookies.block_all;

        if should_block {
            if let Some(cookie) = res.headers_mut().remove(hyper::header::SET_COOKIE) {
                return cookie.to_str().ok().map(|s| s.to_string());
            }
        } else if self.config.cookies.log_attempts {
            if let Some(cookie) = res.headers().get(hyper::header::SET_COOKIE) {
                return cookie.to_str().ok().map(|s| s.to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BlockingConfig, CleanupConfig, Config, CookiesConfig, FingerprintConfig};

    fn create_test_config(
        block_all: bool,
        allow_list: Vec<String>,
        block_list: Vec<String>,
    ) -> Config {
        Config {
            fingerprint: FingerprintConfig {
                rotation_mode: "launch".to_string(),
                rotation_interval: 0,
                randomize_user_agent: false,
                randomize_accept_language: false,
                strip_referer: false,
                accept_languages: vec![],
            },
            cookies: CookiesConfig {
                block_all,
                log_attempts: true,
                allow_list,
                block_list,
            },
            blocking: BlockingConfig {
                auto_block: false,
                auto_block_threshold: 0,
                block_patterns: vec![],
            },
            cleanup: CleanupConfig::default(),
            port: None,
            db_path: ":memory:".to_string(),
        }
    }

    #[test]
    fn test_strip_cookies_block_all() {
        let config = create_test_config(true, vec![], vec![]);
        let handler = CookieHandler::new(config);
        let mut req = Request::new(Body::empty());
        req.headers_mut().insert(hyper::header::COOKIE, "foo=bar".parse().unwrap());

        let stripped = handler.strip_cookies_request(&mut req, "example.com");
        assert_eq!(stripped, Some("foo=bar".to_string()));
        assert!(req.headers().get(hyper::header::COOKIE).is_none());
    }

    #[test]
    fn test_strip_cookies_allow_list() {
        let config = create_test_config(true, vec!["trusted.com".to_string()], vec![]);
        let handler = CookieHandler::new(config);
        let mut req = Request::new(Body::empty());
        req.headers_mut().insert(hyper::header::COOKIE, "foo=bar".parse().unwrap());

        let stripped = handler.strip_cookies_request(&mut req, "trusted.com");
        assert_eq!(stripped, None);
        assert!(req.headers().get(hyper::header::COOKIE).is_some());
    }

    #[test]
    fn test_strip_cookies_block_list_override() {
        let config = create_test_config(false, vec![], vec!["evil.com".to_string()]);
        let handler = CookieHandler::new(config);
        let mut req = Request::new(Body::empty());
        req.headers_mut().insert(hyper::header::COOKIE, "foo=bar".parse().unwrap());

        let stripped = handler.strip_cookies_request(&mut req, "evil.com");
        assert_eq!(stripped, Some("foo=bar".to_string()));
        assert!(req.headers().get(hyper::header::COOKIE).is_none());
    }
}
