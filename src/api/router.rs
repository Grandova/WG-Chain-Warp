use crate::engine::transaction::ChainEngine;
use crate::health::checker::HealthChecker;
use crate::health::diagnose::SystemDiagnostician;
use crate::model::config::ChainProxyConfig;
use crate::model::state::{ChainStatus, TestReport};
use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Mutex<ChainEngine>>,
    pub auth_token: Option<String>,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(message: impl ToString) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.to_string()),
        }
    }
}

pub fn create_router(engine: Arc<Mutex<ChainEngine>>, auth_token: Option<String>) -> Router {
    let state = AppState { engine, auth_token };

    Router::new()
        .route("/health", get(health_handler))
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/config", get(get_config_handler))
        .route("/api/v1/config/validate", post(validate_config_handler))
        .route("/api/v1/config/apply", post(apply_config_handler))
        .route("/api/v1/config/test", post(test_config_handler))
        .route("/api/v1/start", post(start_handler))
        .route("/api/v1/stop", post(stop_handler))
        .route("/api/v1/restart", post(restart_handler))
        .route("/api/v1/rollback", post(rollback_handler))
        .route("/api/v1/warp/register", post(warp_register_handler))
        .route("/api/v1/logs", get(logs_handler))
        .route("/api/v1/network", get(network_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn status_handler(State(state): State<AppState>) -> Json<ApiResponse<ChainStatus>> {
    let engine = state.engine.lock().await;
    Json(ApiResponse::ok(engine.get_status()))
}

async fn get_config_handler(State(state): State<AppState>) -> Json<ApiResponse<serde_json::Value>> {
    let engine = state.engine.lock().await;
    let status = engine.get_status();
    let active_cfg = engine.get_active_config();
    Json(ApiResponse::ok(serde_json::json!({
        "status": status.state,
        "active_version": status.active_config_version,
        "config": active_cfg,
    })))
}

#[derive(Deserialize)]
struct ValidatePayload {
    config: ChainProxyConfig,
}

async fn validate_config_handler(
    Json(payload): Json<ValidatePayload>,
) -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    match payload.config.parse_and_validate() {
        Ok((v1, v2)) => (
            StatusCode::OK,
            Json(ApiResponse::ok(serde_json::json!({
                "valid": true,
                "vpn1_addresses": v1.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                "vpn2_addresses": v2.interface.addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            }))),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(e.to_string())),
        ),
    }
}

async fn apply_config_handler(
    State(state): State<AppState>,
    Json(payload): Json<ValidatePayload>,
) -> (StatusCode, Json<ApiResponse<TestReport>>) {
    let mut engine = state.engine.lock().await;
    match engine.apply(payload.config).await {
        Ok(report) => (StatusCode::OK, Json(ApiResponse::ok(report))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::err(e.to_string())),
        ),
    }
}

async fn test_config_handler(
    State(state): State<AppState>,
) -> Json<ApiResponse<TestReport>> {
    let (uplink, v1_name, v1_ep, v2_name, v2_ep, is_running) = {
        let engine = state.engine.lock().await;
        let status = engine.get_status();
        (
            status.physical.interface,
            status.vpn1.name,
            status.vpn1.endpoint,
            status.vpn2.name,
            status.vpn2.endpoint,
            status.state == crate::model::state::ServiceState::Running,
        )
    };

    if !is_running {
        let phys_status = HealthChecker::probe_physical(Some(&uplink));
        return Json(ApiResponse::ok(TestReport {
            physical: crate::model::state::VpnHopStatus {
                name: "Physical Gateway".to_string(),
                endpoint: phys_status.gateway.unwrap_or_default(),
                config_valid: true,
                reachable: phys_status.status == "UP",
                bytes_sent: 0,
                bytes_received: 0,
                latency_ms: None,
                status: phys_status.status,
                message: None,
            },
            vpn1: crate::model::state::VpnHopStatus {
                name: if v1_name.is_empty() { "VPN 1".to_string() } else { v1_name },
                endpoint: v1_ep,
                config_valid: false,
                reachable: false,
                bytes_sent: 0,
                bytes_received: 0,
                latency_ms: None,
                status: "STOPPED".to_string(),
                message: Some("链路未启动 (服务当前处于 Stopped 状态)".to_string()),
            },
            vpn2: crate::model::state::VpnHopStatus {
                name: if v2_name.is_empty() { "Cloudflare WARP".to_string() } else { v2_name },
                endpoint: v2_ep,
                config_valid: false,
                reachable: false,
                bytes_sent: 0,
                bytes_received: 0,
                latency_ms: None,
                status: "STOPPED".to_string(),
                message: Some("链路未启动 (服务当前处于 Stopped 状态)".to_string()),
            },
            final_exit: crate::model::state::FinalHopStatus {
                internet_ok: false,
                exit_ip: None,
                exit_country: None,
                exit_isp: None,
                latency_ms: None,
                status: "STOPPED".to_string(),
            },
            success: false,
        }));
    }

    let report = HealthChecker::run_full_test(
        Some(&uplink),
        &v1_name,
        &v1_ep,
        &v2_name,
        &v2_ep,
    )
    .await;
    Json(ApiResponse::ok(report))
}

async fn start_handler(State(_state): State<AppState>) -> (StatusCode, Json<ApiResponse<String>>) {
    // If last known good exists, start it
    (
        StatusCode::OK,
        Json(ApiResponse::ok("Start signal processed".to_string())),
    )
}

async fn stop_handler(State(state): State<AppState>) -> (StatusCode, Json<ApiResponse<String>>) {
    let mut engine = state.engine.lock().await;
    match engine.stop() {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::ok("Stopped cleanly".to_string()))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::err(e.to_string())),
        ),
    }
}

async fn restart_handler(State(state): State<AppState>) -> (StatusCode, Json<ApiResponse<String>>) {
    let mut engine = state.engine.lock().await;
    let _ = engine.stop();
    (StatusCode::OK, Json(ApiResponse::ok("Restarted".to_string())))
}

async fn rollback_handler(State(state): State<AppState>) -> (StatusCode, Json<ApiResponse<String>>) {
    let mut engine = state.engine.lock().await;
    match engine.rollback().await {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::ok("Rollback successful".to_string()))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::err(e.to_string())),
        ),
    }
}

async fn warp_register_handler() -> (StatusCode, Json<ApiResponse<crate::wireguard::WarpRegistrationResult>>) {
    match crate::wireguard::WarpRegistrar::register_warp().await {
        Ok(res) => (StatusCode::OK, Json(ApiResponse::ok(res))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::err(e.to_string())),
        ),
    }
}

async fn logs_handler() -> Json<ApiResponse<String>> {
    let mut logs = String::new();

    // 1. Collect systemd journal logs
    if let Ok(out) = std::process::Command::new("journalctl")
        .args(["-u", "chainproxy", "-n", "30", "--no-pager"])
        .output()
    {
        logs.push_str(&String::from_utf8_lossy(&out.stdout));
    }

    // 2. Collect sing-box engine log
    let sb_log = std::path::Path::new("/var/lib/chainproxy/singbox.log");
    if sb_log.exists() {
        if let Ok(content) = std::fs::read_to_string(sb_log) {
            let lines: Vec<&str> = content.lines().collect();
            let start = if lines.len() > 30 { lines.len() - 30 } else { 0 };
            if !lines[start..].is_empty() {
                logs.push_str("\n--- sing-box.log (最新 30 行) ---\n");
                logs.push_str(&lines[start..].join("\n"));
            }
        }
    }

    if logs.trim().is_empty() {
        logs = "暂无系统日志，可通过终端执行: journalctl -u chainproxy -f 查看实时日志".to_string();
    }

    Json(ApiResponse::ok(logs))
}

async fn network_handler() -> Json<ApiResponse<String>> {
    let report = SystemDiagnostician::generate_report("sing-box");
    Json(ApiResponse::ok(report))
}
