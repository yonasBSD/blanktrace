use crate::{blocker::Blocker, cookie::CookieHandler, db::LogEvent, randomizer::Randomizer};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose},
    rustls::crypto::aws_lc_rs,
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use hyper::{Request, Response, StatusCode};
use log::info;
use std::sync::Arc;
use tokio::sync::{mpsc::Sender, Mutex};

/// Shared state for the proxy handler.
#[derive(Clone)]
pub struct ProxyState {
    /// Randomizer for User-Agent and Accept-Language.
    pub randomizer: Arc<Mutex<Randomizer>>,
    /// Handler for cookie stripping.
    pub cookie_handler: Arc<CookieHandler>,
    /// Blocker for tracking domains.
    pub blocker: Arc<Blocker>,
    /// Channel for async database logging.
    pub db_logger: Sender<LogEvent>,
}

/// HTTP handler for the privacy proxy.
#[derive(Clone)]
pub struct PrivacyHandler {
    /// Shared state.
    pub state: ProxyState,
}

impl HttpHandler for PrivacyHandler {
    async fn handle_request(
        &mut self,
        _context: &HttpContext,
        mut request: Request<Body>,
    ) -> RequestOrResponse {
        // Extract host for blocking
        let host = request.uri().host().unwrap_or("unknown").to_string();

        // Check if domain should be blocked (handles tracking logic internally)
        if self.state.blocker.check_and_track(&host).await {
            info!("Blocking request to: {}", host);
            let response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Blocked by privacy proxy"))
                .unwrap();
            return RequestOrResponse::Response(response);
        }

        // Strip cookies from request and log if configured
        if let Some(cookie) = self
            .state
            .cookie_handler
            .strip_cookies_request(&mut request, &host)
        {
            let _ = self
                .state
                .db_logger
                .send(LogEvent::Cookie {
                    domain: host.clone(),
                    cookie,
                    blocked: true,
                })
                .await;
        }

        // Apply fingerprint randomization
        {
            let mut rand = self.state.randomizer.lock().await;
            let mut rotated = false;
            let mut ua = String::new();
            let mut lang = String::new();

            if rand.randomize_user_agent {
                ua = rand.rotate_user_agent();
                if let Ok(header_value) = hyper::header::HeaderValue::from_str(&ua) {
                    request
                        .headers_mut()
                        .insert(hyper::header::USER_AGENT, header_value);
                    rotated = true;
                }
            }
            if rand.randomize_accept_language {
                lang = rand.rotate_accept_language();
                if let Ok(header_value) = hyper::header::HeaderValue::from_str(&lang) {
                    request
                        .headers_mut()
                        .insert(hyper::header::ACCEPT_LANGUAGE, header_value);
                    rotated = true;
                }
            }
            if rand.strip_referer {
                request.headers_mut().remove(hyper::header::REFERER);
            }

            if rotated {
                let _ = self
                    .state
                    .db_logger
                    .send(LogEvent::Fingerprint {
                        user_agent: ua,
                        accept_language: lang,
                        mode: rand.mode.clone(),
                    })
                    .await;
            }
        }

        // Log request (non-blocking)
        let path = request.uri().path().to_string();
        let user_agent = request
            .headers()
            .get(hyper::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        let _ = self
            .state
            .db_logger
            .send(LogEvent::Request {
                domain: host,
                path,
                user_agent,
                client_ip: "unknown".to_string(),
            })
            .await;

        RequestOrResponse::Request(request)
    }

    async fn handle_response(
        &mut self,
        _context: &HttpContext,
        mut response: Response<Body>,
    ) -> Response<Body> {
        // Strip Set-Cookie headers from response
        if let Some(cookie) = self
            .state
            .cookie_handler
            .strip_cookies_response(&mut response, None)
        {
            // We don't easily have the domain here in handle_response without context
            // For now, we log "unknown" or skip logging response cookies if domain is critical
            // Or we could store domain in context? Hudsucker context is immutable.
            // Let's log with "response" as domain for now or skip.
            // Better: skip logging response cookies for now to avoid noise/inaccuracy
            // OR: LogEvent::Cookie { domain: "response".to_string(), ... }
            let _ = self
                .state
                .db_logger
                .send(LogEvent::Cookie {
                    domain: "response".to_string(),
                    cookie,
                    blocked: true,
                })
                .await;
        }
        response
    }
}

/// Generates or loads the Certificate Authority for HTTPS interception.
fn generate_ca() -> anyhow::Result<RcgenAuthority> {
    let cert_path = "ca_cert.pem";
    let key_path = "ca_key.pem";

    // Try to load existing CA
    if std::path::Path::new(cert_path).exists() && std::path::Path::new(key_path).exists() {
        info!("Loading existing CA certificate from disk");

        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;

        let key_pair = KeyPair::from_pem(&key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;

        return Ok(RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider()));
    }

    // Generate new CA certificate
    info!("Generating new CA certificate");
    let mut params = CertificateParams::new(vec![])?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    // Save to disk as PEM
    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, key_pair.serialize_pem())?;

    info!("CA certificate saved to {} and {}", cert_path, key_path);
    info!(
        "Install {} in your browser to trust HTTPS connections",
        cert_path
    );

    let issuer = Issuer::new(params, key_pair);
    Ok(RcgenAuthority::new(issuer, 1000, aws_lc_rs::default_provider()))
}

/// Starts the proxy server.
///
/// # Arguments
///
/// * `state` - Initial proxy state.
/// * `port` - Port to listen on.
pub async fn run_proxy(state: ProxyState, port: u16) -> anyhow::Result<()> {
    info!("Initializing privacy proxy on port {}", port);

    // Generate CA for HTTPS interception
    let ca = generate_ca()?;
    info!("Generated CA certificate for HTTPS interception");
    info!("Note: You'll need to trust the CA certificate in your browser");

    // Create handler
    let handler = PrivacyHandler { state };

    let proxy = Proxy::builder()
        .with_addr(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C signal handler");
        })
        .build()?;

    info!("Privacy proxy listening on 127.0.0.1:{}", port);
    info!("Configure your browser to use this proxy for HTTP/HTTPS traffic");
    info!("Press Ctrl+C to stop the proxy");

    proxy.start().await?;

    Ok(())
}
