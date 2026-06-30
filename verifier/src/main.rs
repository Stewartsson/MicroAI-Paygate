use axum::extract::rejection::JsonRejection;
use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use dashmap::{mapref::entry::Entry, DashMap};
use ethers::types::transaction::eip712::TypedData;
use ethers::types::Signature;
use ethers::utils::keccak256;
mod metrics;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_BODY_SIZE: usize = 1024 * 1024; // 1MB
const NONCE_SWEEP_INTERVAL_SECONDS: u64 = 60;

const SUPPORTED_CHAINS: [u64; 3] = [84532, 11155111, 11155420];

const DEFAULT_PORT: u16 = 3002;
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0";

#[derive(Clone)]
struct AppState {
    max_body_size: usize,
    supported_chains: Vec<u64>,
    nonce_store: Arc<NonceStore>,
    signature_expiry_seconds: u64,
    clock_skew_seconds: u64,
}

struct MemoryNonceStore {
    used_nonces: Arc<DashMap<[u8; 32], Instant>>,
    last_nonce_sweep: Arc<Mutex<Instant>>,
}

#[derive(Clone)]
struct RedisNonceStore {
    client: redis::Client,
    key_prefix: String,
    timeout: Duration,
}

enum NonceStore {
    Memory(MemoryNonceStore),
    Redis(RedisNonceStore),
}

impl Clone for NonceStore {
    fn clone(&self) -> Self {
        match self {
            NonceStore::Memory(store) => NonceStore::Memory(MemoryNonceStore {
                used_nonces: store.used_nonces.clone(),
                last_nonce_sweep: store.last_nonce_sweep.clone(),
            }),
            NonceStore::Redis(store) => NonceStore::Redis(store.clone()),
        }
    }
}

#[derive(Debug)]
struct NonceStoreError { message: String }

impl std::fmt::Display for NonceStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.message) }
}

impl std::error::Error for NonceStoreError {}

impl From<redis::RedisError> for NonceStoreError {
    fn from(err: redis::RedisError) -> Self { Self { message: format!("redis nonce store unavailable: {}", err) } }
}

impl NonceStoreError {
    fn timeout(operation: &str) -> Self { Self { message: format!("redis nonce store timed out during {operation}") } }
}

fn get_max_body_size() -> usize {
    std::env::var("MAX_REQUEST_BODY_BYTES").ok().and_then(|v| v.parse().ok()).filter(|&s| s > 0).unwrap_or(MAX_BODY_SIZE)
}

fn get_port() -> u16 {
    match std::env::var("PORT") {
        Ok(v) => match v.parse::<u16>() {
            Ok(port) if port > 0 => port,
            Ok(_) => {
                eprintln!("Warning: PORT must be > 0, using default {}", DEFAULT_PORT);
                DEFAULT_PORT
            }
            Err(_) => {
                eprintln!(
                    "Warning: Invalid PORT '{}', using default {}",
                    v, DEFAULT_PORT
                );
                DEFAULT_PORT
            }
        },
        Err(_) => DEFAULT_PORT,
    }
}

fn get_bind_address() -> IpAddr {
    match std::env::var("BIND_ADDRESS") {
        Ok(v) => match v.parse::<IpAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                eprintln!(
                    "Warning: Invalid BIND_ADDRESS '{}', using default {}",
                    v, DEFAULT_BIND_ADDRESS
                );
                DEFAULT_BIND_ADDRESS.parse().unwrap()
            }
        },
        Err(_) => DEFAULT_BIND_ADDRESS.parse().unwrap(),
    }
}

fn memory_nonce_store() -> Arc<NonceStore> {
    Arc::new(NonceStore::Memory(MemoryNonceStore {
        used_nonces: Arc::new(DashMap::new()),
        last_nonce_sweep: Arc::new(Mutex::new(Instant::now())),
    }))
}

fn normalize_redis_url(raw_url: &str) -> String {
    if raw_url.starts_with("redis://") || raw_url.starts_with("rediss://") { raw_url.to_string() } else { format!("redis://{raw_url}") }
}

fn redis_url_has_database(redis_url: &str) -> bool {
    let without_scheme = redis_url.split_once("://").map(|(_, rest)| rest).unwrap_or(redis_url);
    let path_end = without_scheme.find(['?', '#']).unwrap_or(without_scheme.len());
    let Some(path_start) = without_scheme[..path_end].find('/') else { return false; };
    !without_scheme[path_start + 1..path_end].trim().is_empty()
}

fn get_non_empty_env(key: &str) -> Option<String> { env::var(key).ok().filter(|value| !value.trim().is_empty()) }

fn verifier_redis_connection_info(raw_url: &str) -> Result<redis::ConnectionInfo, redis::RedisError> {
    let redis_url = normalize_redis_url(raw_url);
    let has_database = redis_url_has_database(&redis_url);
    let mut connection_info: redis::ConnectionInfo = redis_url.as_str().parse()?;
    if connection_info.redis.password.is_none() { connection_info.redis.password = get_non_empty_env("REDIS_PASSWORD"); }
    if !has_database {
        if let Some(db) = get_non_empty_env("REDIS_DB").and_then(|value| value.parse::<i64>().ok()) { connection_info.redis.db = db; }
    }
    Ok(connection_info)
}

fn get_redis_nonce_key_prefix() -> String {
    env::var("VERIFIER_NONCE_KEY_PREFIX").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| "microai:verifier:nonce:".to_string())
}

fn redis_nonce_timeout() -> Duration {
    let timeout_ms = env::var("VERIFIER_REDIS_TIMEOUT_MS").ok().and_then(|v| v.trim().parse::<u64>().ok()).filter(|v| *v > 0).unwrap_or(2_000);
    Duration::from_millis(timeout_ms)
}

fn build_nonce_store_from_env() -> Result<Arc<NonceStore>, String> {
    let mode = env::var("VERIFIER_NONCE_STORE").unwrap_or_else(|_| "memory".to_string()).to_ascii_lowercase();
    match mode.as_str() {
        "memory" => Ok(memory_nonce_store()),
        "redis" => {
            let redis_url = env::var("REDIS_URL").map_err(|_| "VERIFIER_NONCE_STORE=redis requires REDIS_URL".to_string())?;
            let client = redis::Client::open(verifier_redis_connection_info(&redis_url).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            Ok(Arc::new(NonceStore::Redis(RedisNonceStore { client, key_prefix: get_redis_nonce_key_prefix(), timeout: redis_nonce_timeout() })))
        }
        other => Err(format!("unsupported store: {other}")),
    }
}

#[tokio::main]
async fn main() {
    let limit = get_max_body_size();
    let nonce_store = build_nonce_store_from_env().expect("failed to configure nonce store");
    let mut supported_chains = SUPPORTED_CHAINS.to_vec();
    for var in &["EXPECTED_CHAIN_ID", "CHAIN_ID"] {
        if let Ok(env_chain_str) = std::env::var(var) {
            if let Ok(parsed_env_id) = env_chain_str.parse::<u64>() {
                if !supported_chains.contains(&parsed_env_id) { supported_chains.push(parsed_env_id); }
            }
        }
    }
    let state = AppState {
        max_body_size: limit,
        supported_chains,
        nonce_store,
        signature_expiry_seconds: get_env_u64("SIGNATURE_EXPIRY_SECONDS", 300),
        clock_skew_seconds: get_env_u64("SIGNATURE_CLOCK_SKEW_SECONDS", 60),
    };
    let recorder = PrometheusBuilder::new().install_recorder().expect("failed to install recorder");
    spawn_metrics_upkeep(recorder.clone());
    let app = Router::new()
        .route("/health", get(health))
        .route("/verify", post(verify_signature))
        .route("/metrics", get(metrics_route(recorder)))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state);
    let _addr = SocketAddr::from(([0, 0, 0, 0], 3002));

    let addr = SocketAddr::new(get_bind_address(), get_port());
    println!("Rust Verifier listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("Failed to bind listener");
    axum::serve(listener, app).await.expect("Failed to start server");
}

fn metrics_route(handle: PrometheusHandle) -> impl Fn() -> std::future::Ready<String> + Clone + Send + Sync + 'static {
    move || std::future::ready(handle.clone().render())
}

fn spawn_metrics_upkeep(handle: PrometheusHandle) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop { interval.tick().await; handle.run_upkeep(); }
    });
}

async fn health(headers: HeaderMap) -> (HeaderMap, Json<HealthResponse>) {
    let (_, res_headers) = correlation_id_headers(&headers);
    (res_headers, Json(HealthResponse { status: "healthy", service: "verifier", version: env!("CARGO_PKG_VERSION") }))
}

#[derive(Deserialize, Debug, Clone)]
struct VerifyRequest { context: PaymentContext, signature: String }

#[derive(Deserialize, Debug, Clone)]
struct PaymentContext { recipient: String, token: String, amount: String, nonce: String, #[serde(rename = "chainId")] chain_id: u64, timestamp: Option<u64> }

#[derive(Serialize)]
struct VerifyResponse { is_valid: bool, recovered_address: Option<String>, error: Option<String>, #[serde(skip_serializing_if = "Option::is_none")] error_code: Option<String> }

#[derive(Serialize)]
struct HealthResponse { status: &'static str, service: &'static str, version: &'static str }

fn correlation_id_headers(headers: &HeaderMap) -> (String, HeaderMap) {
    let correlation_id = headers.get("X-Correlation-ID").and_then(|v| v.to_str().ok()).unwrap_or("unknown");
    let mut res_headers = HeaderMap::new();
    if let Ok(val) = correlation_id.parse() { res_headers.insert("X-Correlation-ID", val); }
    (correlation_id.to_string(), res_headers)
}

#[derive(Debug)]
enum VerifyError { SignatureExpired, FutureTimestamp, MissingTimestamp }

fn get_env_u64(key: &str, default: u64) -> u64 { env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default) }

fn validate_timestamp(timestamp: Option<u64>, window: u64, skew: u64) -> Result<(), VerifyError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let ts = timestamp.ok_or(VerifyError::MissingTimestamp)?;
    if ts > now.saturating_add(skew) { return Err(VerifyError::FutureTimestamp); }
    let age = now.saturating_sub(ts);
    if age > window { return Err(VerifyError::SignatureExpired); }
    Ok(())
}

fn evict_expired_nonces(store: &DashMap<[u8; 32], Instant>, now: Instant, ttl: Duration) { store.retain(|_, inserted_at| now.saturating_duration_since(*inserted_at) <= ttl); }
fn nonce_retention_ttl(state: &AppState) -> Duration { Duration::from_secs(state.signature_expiry_seconds.saturating_add(state.clock_skew_seconds).saturating_add(1)) }
fn maybe_evict(store: &MemoryNonceStore, now: Instant, ttl: Duration) {
    let mut last = store.last_nonce_sweep.lock().unwrap();
    if now.saturating_duration_since(*last) < Duration::from_secs(NONCE_SWEEP_INTERVAL_SECONDS) { return; }
    *last = now;
    evict_expired_nonces(&store.used_nonces, now, ttl);
}

fn redis_nonce_key(prefix: &str, nonce: &str) -> String { format!("{}{}", prefix, hex::encode(keccak256(nonce.as_bytes()))) }

fn claim_memory_nonce(store: &MemoryNonceStore, nonce: &str, now: Instant, ttl: Duration) -> Result<bool, NonceStoreError> {
    maybe_evict(store, now, ttl);
    match store.used_nonces.entry(keccak256(nonce.as_bytes())) {
        Entry::Occupied(mut entry) => { if now.saturating_duration_since(*entry.get()) > ttl { entry.insert(now); Ok(true) } else { Ok(false) } },
        Entry::Vacant(entry) => { entry.insert(now); Ok(true) }
    }
}

async fn claim_redis_nonce(store: &RedisNonceStore, nonce: &str, ttl: Duration) -> Result<bool, NonceStoreError> {
    let mut conn = tokio::time::timeout(store.timeout, store.client.get_multiplexed_async_connection()).await.map_err(|_| NonceStoreError::timeout("conn"))??;
    let res: Option<String> = tokio::time::timeout(store.timeout, conn.set_options(redis_nonce_key(&store.key_prefix, nonce), "1", redis::SetOptions::default().conditional_set(redis::ExistenceCheck::NX).with_expiration(redis::SetExpiry::EX(ttl.as_secs().max(1))))).await.map_err(|_| NonceStoreError::timeout("claim"))??;
    Ok(res.is_some())
}

async fn claim_nonce(state: &AppState, nonce: &str, now: Instant) -> Result<bool, NonceStoreError> {
    let ttl = nonce_retention_ttl(state);
    match state.nonce_store.as_ref() {
        NonceStore::Memory(s) => claim_memory_nonce(s, nonce, now, ttl),
        NonceStore::Redis(s) => claim_redis_nonce(s, nonce, ttl).await,
    }
}

fn handle_rejection(err: JsonRejection, res_headers: HeaderMap) -> (StatusCode, HeaderMap, Json<VerifyResponse>) {
    let (status, msg, code) = match err {
        JsonRejection::BytesRejection(_) => (StatusCode::PAYLOAD_TOO_LARGE, "Payload too large", "payload_too_large"),
        _ => (StatusCode::BAD_REQUEST, "Invalid JSON payload", "invalid_payload"),
    };
    metrics::record_verification(false, 0.0, Some(code));
    (status, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some(msg.into()), error_code: Some(code.into()) }))
}

async fn verify_signature(State(state): State<AppState>, headers: HeaderMap, payload: Result<Json<VerifyRequest>, JsonRejection>) -> (StatusCode, HeaderMap, Json<VerifyResponse>) {
    let start = Instant::now();
    let (_, res_headers) = correlation_id_headers(&headers);
    let payload = match payload {
        Ok(Json(p)) => p,
        Err(e) => return handle_rejection(e, res_headers),
    };

    if !state.supported_chains.contains(&payload.context.chain_id) {
        metrics::record_verification(false, start.elapsed().as_secs_f64(), Some("chain_id_mismatch"));
        return (StatusCode::BAD_REQUEST, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("Unsupported chain".into()), error_code: Some("chain_id_mismatch".into()) }));
    }

    if let Err(err) = validate_timestamp(payload.context.timestamp, state.signature_expiry_seconds, state.clock_skew_seconds) {
        let (err_msg, err_code) = match err {
            VerifyError::SignatureExpired => ("Timestamp expired", "timestamp_expired"),
            VerifyError::FutureTimestamp => ("Timestamp in future", "timestamp_future"),
            VerifyError::MissingTimestamp => ("Timestamp missing", "timestamp_missing"),
        };
        metrics::record_verification(false, start.elapsed().as_secs_f64(), Some(err_code));
        return (StatusCode::BAD_REQUEST, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some(err_msg.into()), error_code: Some(err_code.into()) }));
    }

    let typed_data_raw = serde_json::json!({
        "domain": { "name": "MicroAI Paygate", "version": "1", "chainId": payload.context.chain_id, "verifyingContract": "0x0000000000000000000000000000000000000000" },
        "types": { "Payment": [ { "name": "recipient", "type": "address" }, { "name": "token", "type": "string" }, { "name": "amount", "type": "string" }, { "name": "nonce", "type": "string" }, { "name": "timestamp", "type": "uint256" } ] },
        "primaryType": "Payment",
        "message": { "recipient": payload.context.recipient, "token": payload.context.token, "amount": payload.context.amount, "nonce": payload.context.nonce, "timestamp": payload.context.timestamp }
    });

    let typed_data: TypedData = match serde_json::from_value(typed_data_raw) {
        Ok(data) => data,
        Err(_) => {
            metrics::record_verification(false, start.elapsed().as_secs_f64(), Some("malformed_typed_data"));
            return (StatusCode::BAD_REQUEST, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("Malformed typed data".into()), error_code: Some("malformed_typed_data".into()) }));
        }
    };

    let sig = match Signature::from_str(&payload.signature) {
        Ok(signature) => signature,
        Err(_) => {
            metrics::record_verification(false, start.elapsed().as_secs_f64(), Some("malformed_signature"));
            return (StatusCode::BAD_REQUEST, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("Malformed signature".into()), error_code: Some("malformed_signature".into()) }));
        }
    };
    
    match sig.recover_typed_data(&typed_data) {
        Ok(addr) => match claim_nonce(&state, &payload.context.nonce, Instant::now()).await {
            Ok(true) => {
                metrics::record_verification(true, start.elapsed().as_secs_f64(), None);
                (StatusCode::OK, res_headers, Json(VerifyResponse { is_valid: true, recovered_address: Some(format!("{:?}", addr)), error: None, error_code: None }))
            },
            Ok(false) => {
                metrics::record_verification(false, start.elapsed().as_secs_f64(), Some("nonce_already_used"));
                (StatusCode::CONFLICT, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("Nonce already used".into()), error_code: Some("nonce_already_used".into()) }))
            },
            Err(_) => {
                metrics::record_verification(false, start.elapsed().as_secs_f64(), Some("nonce_store_failure"));
                (StatusCode::INTERNAL_SERVER_ERROR, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("Nonce store failure".into()), error_code: Some("nonce_store_failure".into()) }))
            }
        },
        Err(_) => {
            metrics::record_verification(false, start.elapsed().as_secs_f64(), Some("invalid_signature"));
            (StatusCode::BAD_REQUEST, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("Invalid signature".into()), error_code: Some("invalid_signature".into()) }))
        }
    }
}

#[cfg(test)]
async fn signed_req(nonce: &str, chain_id: u64) -> VerifyRequest {
    use ethers::signers::{LocalWallet, Signer};
    let wallet: LocalWallet = "380eb0f3d505f087e438eca80bc4df9a7faa24f868e69fc0440261a0fc0567dc".parse().unwrap();
    let typed = serde_json::json!({
        "domain": { "name": "MicroAI Paygate", "version": "1", "chainId": chain_id, "verifyingContract": "0x0000000000000000000000000000000000000000" },
        "types": { "Payment": [ { "name": "recipient", "type": "address" }, { "name": "token", "type": "string" }, { "name": "amount", "type": "string" }, { "name": "nonce", "type": "string" }, { "name": "timestamp", "type": "uint256" } ] },
        "primaryType": "Payment",
        "message": { "recipient": "0x1234567890123456789012345678901234567890", "token": "USDC", "amount": "100", "nonce": nonce, "timestamp": 123456 }
    });
    let sig = wallet.sign_typed_data(&serde_json::from_value(typed).unwrap()).await.unwrap();
    VerifyRequest { context: PaymentContext { recipient: "0x1234567890123456789012345678901234567890".into(), token: "USDC".into(), amount: "100".into(), nonce: nonce.into(), chain_id, timestamp: Some(123456) }, signature: format!("0x{}", hex::encode(sig.to_vec())) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::{LocalWallet, Signer};
    use std::sync::Arc;

    const BASE_SEPOLIA_CHAIN_ID: u64 = 84532;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn app_state() -> AppState {
        app_state_with_window(300, 60)
    }

    fn app_state_with_window(signature_expiry_seconds: u64, clock_skew_seconds: u64) -> AppState {
        app_state_with_nonce_store(
            memory_nonce_store(),
            signature_expiry_seconds,
            clock_skew_seconds,
        )
    }

    fn app_state_with_nonce_store(
        nonce_store: Arc<NonceStore>,
        signature_expiry_seconds: u64,
        clock_skew_seconds: u64,
    ) -> AppState {
        AppState {
            max_body_size: MAX_BODY_SIZE,
            supported_chains: SUPPORTED_CHAINS.to_vec(),
            nonce_store,
            signature_expiry_seconds,
            clock_skew_seconds,
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn with_chain_env(
        expected_chain_id: Option<&str>,
        chain_id: Option<&str>,
        test: impl FnOnce(),
    ) {
        let _guard = ENV_LOCK.lock().unwrap();
        let old_expected = env::var("EXPECTED_CHAIN_ID").ok();
        let old_chain = env::var("CHAIN_ID").ok();

        match expected_chain_id {
            Some(value) => env::set_var("EXPECTED_CHAIN_ID", value),
            None => env::remove_var("EXPECTED_CHAIN_ID"),
        }
        match chain_id {
            Some(value) => env::set_var("CHAIN_ID", value),
            None => env::remove_var("CHAIN_ID"),
        }

        test();

        match old_expected {
            Some(value) => env::set_var("EXPECTED_CHAIN_ID", value),
            None => env::remove_var("EXPECTED_CHAIN_ID"),
        }
        match old_chain {
            Some(value) => env::set_var("CHAIN_ID", value),
            None => env::remove_var("CHAIN_ID"),
        }
    }

    fn with_nonce_env(
        nonce_store: Option<&str>,
        redis_url: Option<&str>,
        key_prefix: Option<&str>,
        redis_timeout_ms: Option<&str>,
        test: impl FnOnce(),
    ) {
        let _guard = ENV_LOCK.lock().unwrap();
        let old_nonce_store = env::var("VERIFIER_NONCE_STORE").ok();
        let old_redis_url = env::var("REDIS_URL").ok();
        let old_key_prefix = env::var("VERIFIER_NONCE_KEY_PREFIX").ok();
        let old_redis_timeout_ms = env::var("VERIFIER_REDIS_TIMEOUT_MS").ok();

        match nonce_store {
            Some(value) => env::set_var("VERIFIER_NONCE_STORE", value),
            None => env::remove_var("VERIFIER_NONCE_STORE"),
        }
        match redis_url {
            Some(value) => env::set_var("REDIS_URL", value),
            None => env::remove_var("REDIS_URL"),
        }
        match key_prefix {
            Some(value) => env::set_var("VERIFIER_NONCE_KEY_PREFIX", value),
            None => env::remove_var("VERIFIER_NONCE_KEY_PREFIX"),
        }
        match redis_timeout_ms {
            Some(value) => env::set_var("VERIFIER_REDIS_TIMEOUT_MS", value),
            None => env::remove_var("VERIFIER_REDIS_TIMEOUT_MS"),
        }

        test();

        match old_nonce_store {
            Some(value) => env::set_var("VERIFIER_NONCE_STORE", value),
            None => env::remove_var("VERIFIER_NONCE_STORE"),
        }
        match old_redis_url {
            Some(value) => env::set_var("REDIS_URL", value),
            None => env::remove_var("REDIS_URL"),
        }
        match old_key_prefix {
            Some(value) => env::set_var("VERIFIER_NONCE_KEY_PREFIX", value),
            None => env::remove_var("VERIFIER_NONCE_KEY_PREFIX"),
        }
        match old_redis_timeout_ms {
            Some(value) => env::set_var("VERIFIER_REDIS_TIMEOUT_MS", value),
            None => env::remove_var("VERIFIER_REDIS_TIMEOUT_MS"),
        }
    }

    fn with_port_env(port: Option<&str>, test: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap();
        let old_port = env::var("PORT").ok();

        match port {
            Some(value) => env::set_var("PORT", value),
            None => env::remove_var("PORT"),
        }

        test();

        match old_port {
            Some(value) => env::set_var("PORT", value),
            None => env::remove_var("PORT"),
        }
    }

    fn with_redis_auth_env(
        redis_password: Option<&str>,
        redis_db: Option<&str>,
        test: impl FnOnce(),
    ) {
        let _guard = ENV_LOCK.lock().unwrap();
        let old_redis_password = env::var("REDIS_PASSWORD").ok();
        let old_redis_db = env::var("REDIS_DB").ok();

        match redis_password {
            Some(value) => env::set_var("REDIS_PASSWORD", value),
            None => env::remove_var("REDIS_PASSWORD"),
        }
        match redis_db {
            Some(value) => env::set_var("REDIS_DB", value),
            None => env::remove_var("REDIS_DB"),
        }

        test();

        match old_redis_password {
            Some(value) => env::set_var("REDIS_PASSWORD", value),
            None => env::remove_var("REDIS_PASSWORD"),
        }
        match old_redis_db {
            Some(value) => env::set_var("REDIS_DB", value),
            None => env::remove_var("REDIS_DB"),
        }
    }

    #[test]
    fn test_normalize_redis_url_accepts_bare_host_port() {
        assert_eq!(normalize_redis_url("redis:6379"), "redis://redis:6379");
        assert_eq!(
            normalize_redis_url("redis://localhost:6379"),
            "redis://localhost:6379"
        );
        assert_eq!(
            normalize_redis_url("rediss://cache.example.com:6380"),
            "rediss://cache.example.com:6380"
        );
    }

    #[test]
    fn test_verifier_redis_connection_info_uses_env_fallbacks_for_bare_url() {
        with_redis_auth_env(Some("secret"), Some("2"), || {
            let connection_info = verifier_redis_connection_info("redis:6379").unwrap();
            assert_eq!(connection_info.redis.password.as_deref(), Some("secret"));
            assert_eq!(connection_info.redis.db, 2);
        });
    }

    #[test]
    fn test_verifier_redis_connection_info_preserves_explicit_url_auth_and_db() {
        with_redis_auth_env(Some("env-secret"), Some("2"), || {
            let connection_info =
                verifier_redis_connection_info("redis://user:url-secret@redis:6379/4").unwrap();
            assert_eq!(connection_info.redis.username.as_deref(), Some("user"));
            assert_eq!(
                connection_info.redis.password.as_deref(),
                Some("url-secret")
            );
            assert_eq!(connection_info.redis.db, 4);
        });
    }

    #[test]
    fn test_build_nonce_store_defaults_to_memory() {
        with_nonce_env(None, None, None, None, || {
            let store = build_nonce_store_from_env().unwrap();
            assert!(matches!(store.as_ref(), NonceStore::Memory(_)));
        });
    }

    #[test]
    fn test_build_redis_nonce_store_requires_redis_url() {
        with_nonce_env(Some("redis"), None, None, None, || {
            let err = match build_nonce_store_from_env() {
                Ok(_) => panic!("expected REDIS_URL error"),
                Err(err) => err,
            };
            assert!(err.contains("REDIS_URL"));
        });
    }

    #[test]
    fn test_redis_nonce_timeout_defaults_to_two_seconds() {
        with_nonce_env(None, None, None, None, || {
            assert_eq!(redis_nonce_timeout(), Duration::from_millis(2_000));
        });
    }

    #[test]
    fn test_redis_nonce_timeout_uses_env_milliseconds() {
        with_nonce_env(None, None, None, Some("750"), || {
            assert_eq!(redis_nonce_timeout(), Duration::from_millis(750));
        });
    }

    #[test]
    fn test_redis_nonce_timeout_rejects_invalid_env() {
        with_nonce_env(None, None, None, Some("not-a-number"), || {
            assert_eq!(redis_nonce_timeout(), Duration::from_millis(2_000));
        });
        with_nonce_env(None, None, None, Some("0"), || {
            assert_eq!(redis_nonce_timeout(), Duration::from_millis(2_000));
        });
    }

    #[test]
    fn test_redis_nonce_key_hashes_raw_nonce() {
        let key = redis_nonce_key("prefix:", "sensitive-nonce-value");
        assert!(key.starts_with("prefix:"));
        assert!(!key.contains("sensitive-nonce-value"));
        assert_eq!(key.len(), "prefix:".len() + 64);
    }

    async fn signed_request(nonce: &str, chain_id: u64, timestamp: u64) -> VerifyRequest {
        let wallet: LocalWallet =
            "380eb0f3d505f087e438eca80bc4df9a7faa24f868e69fc0440261a0fc0567dc"
                .parse()
                .unwrap();
        let wallet = wallet.with_chain_id(chain_id);
        let typed = serde_json::json!({
            "domain": {
                "name": "MicroAI Paygate",
                "version": "1",
                "chainId": chain_id,
                "verifyingContract": "0x0000000000000000000000000000000000000000"
            },
            "types": {
                "Payment": [
                    { "name": "recipient", "type": "address" },
                    { "name": "token", "type": "string" },
                    { "name": "amount", "type": "string" },
                    { "name": "nonce", "type": "string" },
                    { "name": "timestamp", "type": "uint256" }
                ]
            },
            "primaryType": "Payment",
            "message": {
                "recipient": "0x1234567890123456789012345678901234567890",
                "token": "USDC",
                "amount": "100",
                "nonce": nonce,
                "timestamp": timestamp
            }
        });

        let typed: TypedData = serde_json::from_value(typed).unwrap();
        let sig = wallet.sign_typed_data(&typed).await.unwrap();

        VerifyRequest {
            context: PaymentContext {
                recipient: "0x1234567890123456789012345678901234567890".into(),
                token: "USDC".into(),
                amount: "100".into(),
                nonce: nonce.into(),
                chain_id,
                timestamp: Some(timestamp),
            },
            signature: format!("0x{}", hex::encode(sig.to_vec())),
        }
    }

    #[test]
    fn test_timestamp_valid() {
        let n = now();
        assert!(validate_timestamp(Some(n), 300, 60).is_ok());
    }

    #[test]
    fn test_timestamp_expired() {
        let n = now();
        let _res = validate_timestamp(Some(n - 1000), 300, 60);
        assert!(matches!(_res, Err(VerifyError::SignatureExpired)));
    }

    #[test]
    fn test_timestamp_future() {
        let n = now();
        let _res = validate_timestamp(Some(n + 120), 300, 60);
        assert!(matches!(_res, Err(VerifyError::FutureTimestamp)));
    }

    #[test]
    fn test_timestamp_missing() {
        let _res = validate_timestamp(None, 300, 60);
        assert!(matches!(_res, Err(VerifyError::MissingTimestamp)));
    }

    #[test]
    fn test_timestamp_within_clock_skew() {
        let n = now();
        let res = validate_timestamp(Some(n + 30), 300, 60);
        assert!(res.is_ok());
    }

    #[test]
    fn test_timestamp_boundary() {
        let n = now();
        let res = validate_timestamp(Some(n - 300), 300, 60);
        assert!(res.is_ok());

        let res2 = validate_timestamp(Some(n - 301), 300, 60);
        assert!(matches!(res2, Err(VerifyError::SignatureExpired)));
    }

    #[test]
    fn test_get_port_defaults_when_unset() {
        with_port_env(None, || {
            assert_eq!(get_port(), DEFAULT_PORT);
        });
    }

    #[test]
    fn test_get_port_reads_valid_port() {
        with_port_env(Some("4000"), || {
            assert_eq!(get_port(), 4000);
        });
    }

    #[test]
    fn test_get_port_falls_back_on_invalid_value() {
        with_port_env(Some("abc"), || {
            assert_eq!(get_port(), DEFAULT_PORT);
        });
    }

    #[test]
    fn test_get_bind_address_defaults_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = env::var("BIND_ADDRESS").ok();
        env::remove_var("BIND_ADDRESS");

        assert_eq!(get_bind_address().to_string(), "0.0.0.0");

        match old {
            Some(v) => env::set_var("BIND_ADDRESS", v),
            None => env::remove_var("BIND_ADDRESS"),
        }
    }

    #[test]
    fn test_get_bind_address_reads_valid_address() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = env::var("BIND_ADDRESS").ok();
        env::set_var("BIND_ADDRESS", "127.0.0.1");

        assert_eq!(get_bind_address().to_string(), "127.0.0.1");

        match old {
            Some(v) => env::set_var("BIND_ADDRESS", v),
            None => env::remove_var("BIND_ADDRESS"),
        }
    }

    #[test]
    fn test_get_bind_address_falls_back_on_invalid_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old = env::var("BIND_ADDRESS").ok();
        env::set_var("BIND_ADDRESS", "not-an-ip");

        assert_eq!(get_bind_address().to_string(), "0.0.0.0");

        match old {
            Some(v) => env::set_var("BIND_ADDRESS", v),
            None => env::remove_var("BIND_ADDRESS"),
        }
    }

    #[tokio::test]
    async fn test_verify_signature_valid() {
        let wallet: LocalWallet =
            "380eb0f3d505f087e438eca80bc4df9a7faa24f868e69fc0440261a0fc0567dc"
                .parse()
                .unwrap();
        let wallet = wallet.with_chain_id(BASE_SEPOLIA_CHAIN_ID);

        let ts = now();
        let typed = serde_json::json!({
            "domain": {
                "name": "MicroAI Paygate",
                "version": "1",
                "chainId": BASE_SEPOLIA_CHAIN_ID,
                "verifyingContract": "0x0000000000000000000000000000000000000000"
            },
            "types": {
                "Payment": [
                    { "name": "recipient", "type": "address" },
                    { "name": "token", "type": "string" },
                    { "name": "amount", "type": "string" },
                    { "name": "nonce", "type": "string" },
                    { "name": "timestamp", "type": "uint256" }
                ]
            },
            "primaryType": "Payment",
            "message": {
                "recipient": "0x1234567890123456789012345678901234567890",
                "token": "USDC",
                "amount": "100",
                "nonce": "nonce-1",
                "timestamp": ts
            }
        });

        let typed: TypedData = serde_json::from_value(typed).unwrap();
        let sig = wallet.sign_typed_data(&typed).await.unwrap();

        let req = VerifyRequest {
            context: PaymentContext {
                recipient: "0x1234567890123456789012345678901234567890".into(),
                token: "USDC".into(),
                amount: "100".into(),
                nonce: "nonce-1".into(),
                chain_id: BASE_SEPOLIA_CHAIN_ID,
                timestamp: Some(ts),
            },
            signature: format!("0x{}", hex::encode(sig.to_vec())),
        }

        let (status, _, Json(resp)) =
            verify_signature(State(app_state()), HeaderMap::new(), Ok(Json(req))).await;

        assert_eq!(status, StatusCode::OK);
        assert!(resp.is_valid);
    }

    #[tokio::test]
    async fn test_verify_signature_rejects_wrong_chain_id() {
        let wallet: LocalWallet =
            "380eb0f3d505f087e438eca80bc4df9a7faa24f868e69fc0440261a0fc0567dc"
                .parse()
                .unwrap();
        let wallet = wallet.with_chain_id(1u64);

        let ts = now();
        let typed = serde_json::json!({
            "domain": {
                "name": "MicroAI Paygate",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0x0000000000000000000000000000000000000000"
            },
            "types": {
                "Payment": [
                    { "name": "recipient", "type": "address" },
                    { "name": "token", "type": "string" },
                    { "name": "amount", "type": "string" },
                    { "name": "nonce", "type": "string" },
                    { "name": "timestamp", "type": "uint256" }
                ]
            },
            "primaryType": "Payment",
            "message": {
                "recipient": "0x1234567890123456789012345678901234567890",
                "token": "USDC",
                "amount": "100",
                "nonce": "wrong-chain-nonce",
                "timestamp": ts
            }
        });

        let typed: TypedData = serde_json::from_value(typed).unwrap();
        let sig = wallet.sign_typed_data(&typed).await.unwrap();

        let req = VerifyRequest {
            context: PaymentContext {
                recipient: "0x1234567890123456789012345678901234567890".into(),
                token: "USDC".into(),
                amount: "100".into(),
                nonce: "wrong-chain-nonce".into(),
                chain_id: 1,
                timestamp: Some(ts),
            },
            signature: format!("0x{}", hex::encode(sig.to_vec())),
        };

        let (status, _, Json(resp)) =
            verify_signature(State(app_state()), HeaderMap::new(), Ok(Json(req))).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!resp.is_valid);
        assert_eq!(resp.recovered_address, None);
        assert_eq!(resp.error_code.as_deref(), Some("chain_id_mismatch"));
    }

    #[tokio::test]
    async fn test_verify_signature_rejects_replayed_nonce() {
        let state = app_state();
        let req = signed_request("replay-nonce", BASE_SEPOLIA_CHAIN_ID, now()).await;

        let (first_status, _, Json(first_resp)) = verify_signature(
            State(state.clone()),
            HeaderMap::new(),
            Ok(Json(req.clone())),
        )
        .await;
        let (second_status, _, Json(second_resp)) =
            verify_signature(State(state), HeaderMap::new(), Ok(Json(req))).await;

        assert_eq!(first_status, StatusCode::OK);
        assert!(first_resp.is_valid);
        assert_eq!(second_status, StatusCode::CONFLICT);
        assert!(!second_resp.is_valid);
        assert_eq!(
            second_resp.error_code.as_deref(),
            Some("nonce_already_used")
        );
    }

    #[tokio::test]
    async fn test_verify_signature_allows_one_concurrent_duplicate_nonce() {
        let state = app_state();
        let req = signed_request("concurrent-replay-nonce", BASE_SEPOLIA_CHAIN_ID, now()).await;
        let mut handles = Vec::new();

        for _ in 0..100 {
            let state = state.clone();
            let req = req.clone();
            handles.push(tokio::spawn(async move {
                let (status, _, Json(resp)) =
                    verify_signature(State(state), HeaderMap::new(), Ok(Json(req))).await;
                (status, resp.error_code)
            }));
        }

        let mut successes = 0;
        let mut conflicts = 0;
        for handle in handles {
            let (status, error_code) = handle.await.unwrap();
            match status {
                StatusCode::OK => successes += 1,
                StatusCode::CONFLICT => {
                    assert_eq!(error_code.as_deref(), Some("nonce_already_used"));
                    conflicts += 1;
                }
                other => panic!("unexpected status: {}", other),
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(conflicts, 99);
    }

    #[tokio::test]
    async fn test_claim_nonce_retains_entries_through_clock_skew_window() {
        let state = app_state_with_window(1, 2);
        let start = Instant::now();

        assert!(claim_nonce(&state, "ttl-replay-nonce", start)
            .await
            .unwrap());
        assert!(!claim_nonce(
            &state,
            "ttl-replay-nonce",
            start + Duration::from_millis(1100)
        )
        .await
        .unwrap());
        assert!(!claim_nonce(
            &state,
            "ttl-replay-nonce",
            start + Duration::from_millis(3100)
        )
        .await
        .unwrap());
        assert!(!claim_nonce(
            &state,
            "ttl-replay-nonce",
            start + Duration::from_millis(4000)
        )
        .await
        .unwrap());
        assert!(claim_nonce(
            &state,
            "ttl-replay-nonce",
            start + Duration::from_millis(4100)
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn test_verify_signature_invalid_signature_does_not_burn_nonce() {
        let state = app_state();
        let mut bad_req =
            signed_request("invalid-does-not-burn", BASE_SEPOLIA_CHAIN_ID, now()).await;
        let good_req = bad_req.clone();
        bad_req.signature = format!("0x{}", "00".repeat(65));

        let (bad_status, _, Json(bad_resp)) =
            verify_signature(State(state.clone()), HeaderMap::new(), Ok(Json(bad_req))).await;
        let (good_status, _, Json(good_resp)) =
            verify_signature(State(state), HeaderMap::new(), Ok(Json(good_req))).await;

        assert_eq!(bad_status, StatusCode::BAD_REQUEST);
        assert!(!bad_resp.is_valid);
        assert_eq!(bad_resp.error_code.as_deref(), Some("invalid_signature"));
        assert_eq!(good_status, StatusCode::OK);
        assert!(good_resp.is_valid);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let (_headers, Json(response)) = health(HeaderMap::new()).await;

        assert_eq!(response.status, "healthy");
        assert_eq!(response.service, "verifier");
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn test_health_endpoint_correlation_id() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Correlation-ID", "health-check-id".parse().unwrap());

        let (res_headers, Json(response)) = health(headers).await;

        assert_eq!(response.status, "healthy");

        let response_id = res_headers.get("X-Correlation-ID");
        assert!(response_id.is_some());
        assert_eq!(response_id.unwrap().to_str().unwrap(), "health-check-id");
    }

    #[tokio::test]
    async fn test_verify_signature_invalid() {
        let ts = now();
        let req = VerifyRequest {
            context: PaymentContext {
                recipient: "0x1234567890123456789012345678901234567890".to_string(),
                token: "USDC".to_string(),
                amount: "100".to_string(),
                nonce: "nonce".to_string(),
                chain_id: BASE_SEPOLIA_CHAIN_ID,
                timestamp: Some(ts),
            },
            signature: "0x1234567890".to_string(),
        };

        let (status, _headers, Json(_response)) =
            verify_signature(State(app_state()), HeaderMap::new(), Ok(Json(req))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_correlation_id_preserved_in_response() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Correlation-ID",
            "test-correlation-id-12345".parse().unwrap(),
        );

        let ts = now();
        let req = VerifyRequest {
            context: PaymentContext {
                recipient: "0x1234567890123456789012345678901234567890".to_string(),
                token: "USDC".to_string(),
                amount: "100".to_string(),
                nonce: "nonce".to_string(),
                chain_id: BASE_SEPOLIA_CHAIN_ID,
                timestamp: Some(ts),
            },
            signature: "0x1234567890".to_string(),
        };

        let (_status, response_headers, _json) =
            verify_signature(State(app_state()), headers, Ok(Json(req))).await;

        let response_id = response_headers.get("X-Correlation-ID");
        assert!(
            response_id.is_some(),
            "Expected X-Correlation-ID in response headers"
        );
        assert_eq!(
            response_id.unwrap().to_str().unwrap(),
            "test-correlation-id-12345",
            "Correlation ID should be preserved from request"
        );
    }

    #[tokio::test]
    async fn test_correlation_id_unknown_when_missing() {
        let headers = HeaderMap::new();

        let ts = now();
        let req = VerifyRequest {
            context: PaymentContext {
                recipient: "0x1234567890123456789012345678901234567890".to_string(),
                token: "USDC".to_string(),
                amount: "100".to_string(),
                nonce: "nonce".to_string(),
                chain_id: BASE_SEPOLIA_CHAIN_ID,
                timestamp: Some(ts),
            },
            signature: "0x1234567890".to_string(),
        };

        let (_status, response_headers, _json) =
            verify_signature(State(app_state()), headers, Ok(Json(req))).await;

        let response_id = response_headers.get("X-Correlation-ID");
        assert!(
            response_id.is_some(),
            "Expected X-Correlation-ID header even with unknown value"
        );
        assert_eq!(
            response_id.unwrap().to_str().unwrap(),
            "unknown",
            "Should use 'unknown' as fallback correlation ID"
        );
    }

    #[tokio::test]
    async fn test_verify_signature_rejects_unsupported_chain_id() {
        let req = super::signed_req("n1", 999).await;
        let (status, _, Json(resp)) = verify_signature(State(app_state()), HeaderMap::new(), Ok(Json(req))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp.error_code, Some("chain_id_mismatch".into()));
    }
}

