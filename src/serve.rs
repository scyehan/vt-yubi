use crate::core::{do_decrypt, do_encrypt, DecryptReq, EncryptItem};
use crate::security::AesGcmCrypto;
use crate::yk_backend;

use anyhow::Result;
use axum::{
    body::{to_bytes, Body},
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

const MAX_BODY_SIZE: usize = 1024 * 1024;

fn create_auth_middleware(
    auth_cipher: Arc<AesGcmCrypto>,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone {
    move |request: Request, next: Next| {
        let auth_cipher = Arc::clone(&auth_cipher);

        Box::pin(async move { auth_middleware_impl(request, next, auth_cipher).await })
    }
}

async fn auth_middleware_impl(
    request: Request,
    next: Next,
    auth_cipher: Arc<AesGcmCrypto>,
) -> Response {
    let request_path = request.uri().path().to_string();

    let (parts, body) = request.into_parts();
    let decrypted_req = match to_bytes(body, MAX_BODY_SIZE).await {
        Ok(body_bytes) => match auth_cipher.decrypt(&body_bytes) {
            Ok(decrypted_bytes) => {
                match std::str::from_utf8(&decrypted_bytes) {
                    Ok(s) => {
                        let modified_s = regex::Regex::new(r#""plaintext":"[^"]*""#)
                            .unwrap()
                            .replace_all(s, r#""plaintext":"****""#)
                            .to_string();
                        info!("request body: {}", modified_s)
                    }
                    Err(_) => info!("Decrypted request body: <non-UTF8 data>"),
                }
                Request::from_parts(parts, Body::from(decrypted_bytes))
            }
            Err(_) => return (StatusCode::FORBIDDEN, "Request failed").into_response(),
        },
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Request failed").into_response(),
    };

    let response = next.run(decrypted_req).await;

    let (parts, body) = response.into_parts();
    match to_bytes(body, MAX_BODY_SIZE).await {
        Ok(raw_bytes) => {
            match std::str::from_utf8(&raw_bytes) {
                Ok(s) => {
                    if request_path == "/decrypt" {
                        let modified_s = regex::Regex::new(r#""result":"[^"]*""#)
                            .unwrap()
                            .replace_all(s, r#""result":"****""#)
                            .to_string();
                        info!("response body: {}", modified_s);
                    } else {
                        info!("response body: {}", s);
                    }
                }
                Err(_) => info!("raw response body: <non-UTF8 data>"),
            }
            match auth_cipher.encrypt(&raw_bytes) {
                Ok(encrypted_bytes) => Response::from_parts(parts, Body::from(encrypted_bytes)),
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Request failed").into_response()
                }
            }
        }
        Err(_) => {
            warn!("Failed to read response body in auth middleware");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Request failed").into_response();
        }
    }
}

async fn log_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();
    let (body_content, response) = match status {
        StatusCode::OK => ("".to_string(), response),
        _ => {
            let (parts, body) = response.into_parts();
            match to_bytes(body, MAX_BODY_SIZE).await {
                Ok(body_bytes) => match std::str::from_utf8(&body_bytes) {
                    Ok(s) => (
                        s.to_string(),
                        Response::from_parts(parts, Body::from(body_bytes)),
                    ),
                    Err(_) => (
                        "response body: <non-UTF8 data>".to_string(),
                        Response::from_parts(parts, Body::from(body_bytes)),
                    ),
                },
                Err(_) => (
                    "invalid body".to_string(),
                    Response::from_parts(parts, Body::empty()),
                ),
            }
        }
    };

    info!(
        "{:?} {} {} {:?} {}",
        status, method, uri, duration, body_content
    );
    response
}

#[derive(Clone)]
struct AppState {
    passphrase: Arc<[u8; 32]>,
    pin: Arc<String>,
}

pub async fn serve(
    addr: &str,
    enable_http: bool,
    ssh_idle_timeout: u64,
    auth_cache_mode: crate::ssh_agent::AuthCacheMode,
    auth_cache_duration: u64,
    decrypt_cache_duration: u64,
) -> Result<()> {
    // Open YubiKey, verify PIN, decrypt secrets at startup
    let (mut yk, pin) = yk_backend::open_and_verify_pin()?;

    tracing::info!("Touch YubiKey to decrypt auth token...");
    let auth_token = yk_backend::load_auth_token(&mut yk)?;

    tracing::info!("Touch YubiKey to decrypt passphrase...");
    let passphrase = yk_backend::load_passphrase(&mut yk)?;

    // Drop YubiKey handle
    drop(yk);

    let auth_cipher = AesGcmCrypto::new(&auth_token)?;

    // Start SSH agent — share PIN + decrypted secrets so it doesn't re-prompt
    let ssh_pin = pin.clone();
    let ssh_handle = tokio::spawn(async move {
        if let Err(e) = crate::ssh_agent::run_ssh_agent_with_secrets(
            false,
            ssh_idle_timeout,
            auth_cache_mode,
            auth_cache_duration,
            decrypt_cache_duration,
            passphrase,
            auth_token,
            ssh_pin,
        )
        .await
        {
            tracing::warn!("SSH agent failed: {}", e);
        }
    });

    if enable_http {
        let addr = addr.parse::<SocketAddr>()?;
        tracing::info!("Starting HTTP server on {}", addr);

        let app = Router::new()
            .route("/decrypt", post(handler_decrypt))
            .route("/encrypt", post(handler_encrypt))
            .with_state(AppState {
                passphrase: Arc::new(passphrase),
                pin: Arc::new(pin),
            })
            .layer(middleware::from_fn(create_auth_middleware(Arc::new(
                auth_cipher,
            ))))
            .layer(middleware::from_fn(log_middleware))
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE));

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    } else {
        tracing::info!("HTTP server disabled, running SSH agent only");
        ssh_handle.await?;
    }

    Ok(())
}

async fn handler_decrypt(
    State(state): State<AppState>,
    Json(payload): Json<DecryptReq>,
) -> impl IntoResponse {
    let local_auth_message = format!(
        "decrypt {} items from {} to run `{}`",
        payload.items.len(),
        payload.host,
        payload.command,
    );

    // YubiKey presence check for HTTP decrypt (uses cached PIN)
    if !yk_backend::verify_presence_with_pin(&state.pin, &local_auth_message).unwrap_or(false) {
        return (StatusCode::FORBIDDEN, "User Rejected").into_response();
    }

    match AesGcmCrypto::new(&state.passphrase) {
        Ok(cipher) => Json(do_decrypt(&cipher, payload.items)).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to load passphrase cipher",
        )
            .into_response(),
    }
}

async fn handler_encrypt(
    State(state): State<AppState>,
    Json(payload): Json<Vec<EncryptItem>>,
) -> impl IntoResponse {
    match AesGcmCrypto::new(&state.passphrase) {
        Ok(cipher) => Json(do_encrypt(&cipher, payload)).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to load passphrase cipher",
        )
            .into_response(),
    }
}
