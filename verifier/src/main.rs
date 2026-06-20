use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
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
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_BODY_SIZE: usize = 1024 * 1024; // 1MB
const NONCE_SWEEP_INTERVAL_SECONDS: u64 = 60;
const SUPPORTED_CHAINS: [u64; 3] = [84532, 11155111, 11155420];

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
struct NonceStoreError {
    message: String,
}

impl std::fmt::Display for NonceStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for NonceStoreError {}

impl From<redis::RedisError> for NonceStoreError {
    fn from(err: redis::RedisError) -> Self {
        Self {
            message: format!("redis nonce store unavailable: {}", err),
        }
    }
}

impl NonceStoreError {
    fn timeout(operation: &str) -> Self {
        Self {
            message: format!("redis nonce store timed out during {operation}"),
        }
    }
}

fn get_max_body_size() -> usize {
    match std::env::var("MAX_REQUEST_BODY_BYTES") {
        Ok(v) => match v.parse() {
            Ok(size) if size > 0 => size,
            Ok(_) => MAX_BODY_SIZE,
            Err(_) => MAX_BODY_SIZE,
        },
        Err(_) => MAX_BODY_SIZE,
    }
}

fn memory_nonce_store() -> Arc<NonceStore> {
    Arc::new(NonceStore::Memory(MemoryNonceStore {
        used_nonces: Arc::new(DashMap::new()),
        last_nonce_sweep: Arc::new(Mutex::new(Instant::now())),
    }))
}

fn normalize_redis_url(raw_url: &str) -> String {
    if raw_url.starts_with("redis://") || raw_url.starts_with("rediss://") {
        raw_url.to_string()
    } else {
        format!("redis://{raw_url}")
    }
}

fn redis_url_has_database(redis_url: &str) -> bool {
    let without_scheme = redis_url.split_once("://").map(|(_, rest)| rest).unwrap_or(redis_url);
    let path_end = without_scheme.find(['?', '#']).unwrap_or(without_scheme.len());
    let Some(path_start) = without_scheme[..path_end].find('/') else { return false; };
    !without_scheme[path_start + 1..path_end].trim().is_empty()
}

fn get_non_empty_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

fn verifier_redis_connection_info(raw_url: &str) -> Result<redis::ConnectionInfo, redis::RedisError> {
    let redis_url = normalize_redis_url(raw_url);
    let has_database = redis_url_has_database(&redis_url);
    let mut connection_info: redis::ConnectionInfo = redis_url.as_str().parse()?;
    if connection_info.redis.password.is_none() {
        connection_info.redis.password = get_non_empty_env("REDIS_PASSWORD");
    }
    if !has_database {
        if let Some(db) = get_non_empty_env("REDIS_DB").and_then(|value| value.parse::<i64>().ok()) {
            connection_info.redis.db = db;
        }
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
    
    // Fallback parsing for EXPECTED_CHAIN_ID and CHAIN_ID
    for var in &["EXPECTED_CHAIN_ID", "CHAIN_ID"] {
        if let Ok(env_chain_str) = std::env::var(var) {
            if let Ok(parsed_env_id) = env_chain_str.parse::<u64>() {
                if !supported_chains.contains(&parsed_env_id) {
                    supported_chains.push(parsed_env_id);
                }
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

    let addr = SocketAddr::from(([0, 0, 0, 0], 3002));
    println!("Rust Verifier listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
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
enum VerifyError { SignatureExpired { age_seconds: u64, max_seconds: u64 }, FutureTimestamp { timestamp: u64, now: u64 }, MissingTimestamp }

fn get_env_u64(key: &str, default: u64) -> u64 { env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default) }

fn validate_timestamp(timestamp: Option<u64>, window: u64, skew: u64) -> Result<(), VerifyError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let ts = timestamp.ok_or(VerifyError::MissingTimestamp)?;
    if ts > now.saturating_add(skew) { return Err(VerifyError::FutureTimestamp { timestamp: ts, now }); }
    let age = now.saturating_sub(ts);
    if age > window { return Err(VerifyError::SignatureExpired { age_seconds: age, max_seconds: window }); }
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

fn claim_memory_nonce(store: &MemoryNonceStore, nonce: &str, now: Instant, ttl: Duration) -> bool {
    maybe_evict(store, now, ttl);
    match store.used_nonces.entry(keccak256(nonce.as_bytes())) {
        Entry::Occupied(mut entry) => { if now.saturating_duration_since(*entry.get()) > ttl { entry.insert(now); true } else { false } },
        Entry::Vacant(entry) => { entry.insert(now); true }
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
        NonceStore::Memory(s) => Ok(claim_memory_nonce(s, nonce, now, ttl)),
        NonceStore::Redis(s) => claim_redis_nonce(s, nonce, ttl).await,
    }
}

async fn verify_signature(State(state): State<AppState>, headers: HeaderMap, payload: Result<Json<VerifyRequest>, JsonRejection>) -> (StatusCode, HeaderMap, Json<VerifyResponse>) {
    let (cid, res_headers) = correlation_id_headers(&headers);
    let start = Instant::now();
    let payload = match payload {
        Ok(Json(p)) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("invalid payload".into()), error_code: None })),
    };

    if !state.supported_chains.contains(&payload.context.chain_id) {
        return (StatusCode::BAD_REQUEST, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("unsupported chain".into()), error_code: Some("chain_id_mismatch".into()) }));
    }

    if let Err(err) = validate_timestamp(payload.context.timestamp, state.signature_expiry_seconds, state.clock_skew_seconds) {
        return (StatusCode::OK, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some(format!("{:?}", err)), error_code: Some("timestamp_invalid".into()) }));
    }

    let typed_data = serde_json::json!({
        "domain": { "name": "MicroAI Paygate", "version": "1", "chainId": payload.context.chain_id, "verifyingContract": "0x0000000000000000000000000000000000000000" },
        "types": { "Payment": [ { "name": "recipient", "type": "address" }, { "name": "token", "type": "string" }, { "name": "amount", "type": "string" }, { "name": "nonce", "type": "string" }, { "name": "timestamp", "type": "uint256" } ] },
        "primaryType": "Payment",
        "message": { "recipient": payload.context.recipient, "token": payload.context.token, "amount": payload.context.amount, "nonce": payload.context.nonce, "timestamp": payload.context.timestamp }
    });

    let typed_data: TypedData = serde_json::from_value(typed_data).unwrap();
    let sig = Signature::from_str(&payload.signature).unwrap();
    
    match sig.recover_typed_data(&typed_data) {
        Ok(addr) => match claim_nonce(&state, &payload.context.nonce, Instant::now()).await {
            Ok(true) => (StatusCode::OK, res_headers, Json(VerifyResponse { is_valid: true, recovered_address: Some(format!("{:?}", addr)), error: None, error_code: None })),
            _ => (StatusCode::CONFLICT, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("nonce error".into()), error_code: Some("nonce_error".into()) })),
        },
        Err(_) => (StatusCode::BAD_REQUEST, res_headers, Json(VerifyResponse { is_valid: false, recovered_address: None, error: Some("bad sig".into()), error_code: Some("bad_sig".into()) })),
    }
}

fn record_verification_failure(start: &Instant, reason: &'static str) { metrics::record_verification(false, start.elapsed().as_secs_f64(), Some(reason)); }

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::{LocalWallet, Signer};

    fn app_state() -> AppState { AppState { max_body_size: MAX_BODY_SIZE, supported_chains: SUPPORTED_CHAINS.to_vec(), nonce_store: memory_nonce_store(), signature_expiry_seconds: 300, clock_skew_seconds: 60 } }

    async fn signed_req(nonce: &str, chain_id: u64) -> VerifyRequest {
        let wallet: LocalWallet = "380eb0f3d505f087e438eca80bc4df9a7faa24f868e69fc0440261a0fc0567dc".parse().unwrap();
        let wallet = wallet.with_chain_id(chain_id);
        let typed = serde_json::json!({
            "domain": { "name": "MicroAI Paygate", "version": "1", "chainId": chain_id, "verifyingContract": "0x0000000000000000000000000000000000000000" },
            "types": { "Payment": [ { "name": "recipient", "type": "address" }, { "name": "token", "type": "string" }, { "name": "amount", "type": "string" }, { "name": "nonce", "type": "string" }, { "name": "timestamp", "type": "uint256" } ] },
            "primaryType": "Payment",
            "message": { "recipient": "0x1234567890123456789012345678901234567890", "token": "USDC", "amount": "100", "nonce": nonce, "timestamp": 123456 }
        });
        let sig = wallet.sign_typed_data(&serde_json::from_value(typed).unwrap()).await.unwrap();
        VerifyRequest { context: PaymentContext { recipient: "0x1234567890123456789012345678901234567890".into(), token: "USDC".into(), amount: "100".into(), nonce: nonce.into(), chain_id, timestamp: Some(123456) }, signature: format!("0x{}", hex::encode(sig.to_vec())) }
    }

    #[tokio::test]
    async fn test_verify_signature_rejects_unsupported_chain_id() {
        let req = signed_req("n1", 999).await;
        let (status, _, Json(resp)) = verify_signature(State(app_state()), HeaderMap::new(), Ok(Json(req))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(resp.error_code, Some("chain_id_mismatch".into()));
    }
}
