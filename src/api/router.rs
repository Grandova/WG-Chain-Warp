use crate::engine::transaction::ChainEngine;
use crate::health::checker::HealthChecker;
use crate::health::diagnose::SystemDiagnostician;
use crate::health::sysinfo::{ServerSystemStatus, SysInfoCollector};
use crate::model::config::ChainProxyConfig;
use crate::model::panel::PanelSetting;
use crate::model::state::{ChainStatus, TestReport};
use crate::web::{INDEX_HTML, LOGIN_HTML, SESSION_COOKIE_NAME};
use axum::extract::{Json, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Mutex<ChainEngine>>,
    pub reader: ChainEngine,
    pub panel: Arc<Mutex<PanelSetting>>,
    pub sysinfo: Arc<SysInfoCollector>,
    pub data_dir: PathBuf,
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
        Self { success: true, data: Some(data), error: None }
    }

    pub fn err(message: impl ToString) -> Self {
        Self { success: false, data: None, error: Some(message.to_string()) }
    }
}

fn build_core_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(web_index_handler))
        .route("/login", get(web_login_page_handler).post(web_login_submit_handler))
        .route("/logout", post(web_logout_handler))
        .route("/panel/api/bootstrap", get(panel_bootstrap_handler))
        .route("/panel/api/server/status", get(panel_server_status_handler))
        .route("/panel/api/chain/config", get(panel_get_config_handler))
        .route("/panel/api/outbounds", get(panel_get_outbounds_handler).post(panel_save_outbounds_handler))
        .route("/panel/api/warp/register", post(warp_register_handler))
        .route("/panel/api/setting/update", post(panel_update_setting_handler))
        .route("/panel/api/setting/updateUser", post(panel_update_user_handler))
        .route("/panel/api/setting/restart", post(panel_restart_handler))
        .route("/health", get(health_handler))
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/config", get(get_config_handler))
        .route("/api/v1/config/apply", post(apply_config_handler))
        .route("/api/v1/config/test", post(test_config_handler))
        .route("/api/v1/stop", post(stop_handler))
        .route("/api/v1/socks5/apply", post(socks5_apply_handler))
        .route("/api/v1/socks5/stop", post(socks5_stop_handler))
        .route("/api/v1/warp/register", post(warp_register_handler))
        .route("/api/v1/logs", get(logs_handler))
        .route("/api/v1/network", get(network_handler))
}

pub fn create_router(engine: Arc<Mutex<ChainEngine>>) -> Router {
    let (reader, data_dir) = if let Ok(guard) = engine.try_lock() {
        (guard.clone(), guard.base_dir().to_path_buf())
    } else {
        let fallback_dir = PathBuf::from("/var/lib/sooya");
        (ChainEngine::new(&fallback_dir), fallback_dir)
    };

    let panel_setting = PanelSetting::load_or_default(&data_dir);
    let base_path = panel_setting.base_path.clone();

    let state = AppState {
        engine,
        reader,
        panel: Arc::new(Mutex::new(panel_setting)),
        sysinfo: Arc::new(SysInfoCollector::new()),
        data_dir,
    };

    let mut router = build_core_routes();
    let trimmed_bp = base_path.trim_end_matches('/');
    if !trimmed_bp.is_empty() && trimmed_bp != "/" {
        router = router.nest(trimmed_bp, build_core_routes());
    }

    router.layer(CorsLayer::permissive()).with_state(state)
}

async fn is_authenticated(headers: &HeaderMap, state: &AppState) -> bool {
    let expected = state.panel.lock().await.session_secret.clone();
    if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie_hdr.split(';') {
            if let Some(val) = part.trim().strip_prefix(&format!("{}=", SESSION_COOKIE_NAME)) {
                if !expected.is_empty() && val == expected {
                    return true;
                }
            }
        }
    }
    false
}

async fn web_index_handler(headers: HeaderMap, State(state): State<AppState>) -> Response {
    if !is_authenticated(&headers, &state).await {
        return Redirect::to("./login").into_response();
    }
    Html(INDEX_HTML).into_response()
}

async fn web_login_page_handler(headers: HeaderMap, State(state): State<AppState>) -> Response {
    if is_authenticated(&headers, &state).await {
        return Redirect::to("./").into_response();
    }
    Html(LOGIN_HTML).into_response()
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

async fn web_login_submit_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Response {
    let panel = state.panel.lock().await;
    if panel.verify_credentials(payload.username.trim(), &payload.password) {
        let cookie = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000",
            SESSION_COOKIE_NAME, panel.session_secret
        );
        (StatusCode::OK, [(header::SET_COOKIE, cookie)], Json(ApiResponse::ok("登录成功".to_string()))).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(ApiResponse::<String>::err("用户名或密码错误"))).into_response()
    }
}

async fn web_logout_handler() -> Response {
    let cookie = format!("{}=; Path=/; HttpOnly; Max-Age=0", SESSION_COOKIE_NAME);
    (StatusCode::OK, [(header::SET_COOKIE, cookie)], Json(ApiResponse::ok("已退出登录".to_string()))).into_response()
}

#[derive(Serialize)]
struct CombinedDashboardStatus {
    system: ServerSystemStatus,
    chain: ChainStatus,
}

async fn panel_bootstrap_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    let system = state.sysinfo.collect();
    let chain = state.reader.get_status();
    let config = state.reader.get_active_config().unwrap_or_default();
    let outbounds = state.reader.get_outbounds();
    let panel = state.panel.lock().await;
    let setting = serde_json::json!({
        "listen": panel.listen,
        "port": panel.port,
        "base_path": panel.base_path,
        "username": panel.username,
    });
    drop(panel);

    (
        StatusCode::OK,
        Json(ApiResponse::ok(serde_json::json!({
            "system": system,
            "chain": chain,
            "config": config,
            "outbounds": outbounds,
            "setting": setting,
        }))),
    )
}

async fn panel_server_status_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<CombinedDashboardStatus>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    let system = state.sysinfo.collect();
    let chain = state.reader.get_status();
    (StatusCode::OK, Json(ApiResponse::ok(CombinedDashboardStatus { system, chain })))
}

async fn panel_get_config_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    let status = state.reader.get_status();
    let cfg = state.reader.get_active_config().unwrap_or_default();
    (
        StatusCode::OK,
        Json(ApiResponse::ok(serde_json::json!({
            "status": status.state,
            "socks5_running": status.socks5_running,
            "socks5_listen": status.socks5_listen,
            "active_version": status.active_config_version,
            "config": cfg,
        }))),
    )
}

async fn panel_get_outbounds_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    (StatusCode::OK, Json(ApiResponse::ok(state.reader.get_outbounds())))
}

async fn panel_save_outbounds_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    match state.reader.save_outbounds(&payload) {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::ok("已保存出站列表".to_string()))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

#[derive(Deserialize)]
struct UpdatePanelSettingPayload {
    listen: String,
    port: u16,
    base_path: String,
}

async fn panel_update_setting_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<UpdatePanelSettingPayload>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    let mut panel = state.panel.lock().await;
    panel.listen = payload.listen;
    panel.port = payload.port;
    panel.base_path = payload.base_path;
    panel.normalize();
    if let Err(e) = panel.validate() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e.to_string())));
    }
    match panel.save(&state.data_dir) {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::ok("面板设置已保存".to_string()))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

#[derive(Deserialize)]
struct UpdatePanelUserPayload {
    old_username: String,
    old_password: String,
    new_username: String,
    new_password: String,
}

async fn panel_update_user_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<UpdatePanelUserPayload>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    let mut panel = state.panel.lock().await;
    if !panel.verify_credentials(payload.old_username.trim(), &payload.old_password) {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("原用户名或原密码不正确")));
    }
    if payload.new_username.trim().is_empty() || payload.new_password.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("新用户名和新密码不能为空")));
    }
    panel.username = payload.new_username.trim().to_string();
    panel.password = payload.new_password;
    panel.rotate_session_secret();
    match panel.save(&state.data_dir) {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::ok("登录账号与密码已更新".to_string()))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

async fn panel_restart_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let _ = std::process::Command::new("systemctl").args(["restart", "sooya"]).spawn();
    });
    (StatusCode::OK, Json(ApiResponse::ok("面板即将重启".to_string())))
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn status_handler(State(state): State<AppState>) -> Json<ApiResponse<ChainStatus>> {
    Json(ApiResponse::ok(state.reader.get_status()))
}

async fn get_config_handler(State(state): State<AppState>) -> Json<ApiResponse<serde_json::Value>> {
    let status = state.reader.get_status();
    let active_cfg = state.reader.get_active_config();
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

async fn apply_config_handler(
    State(state): State<AppState>,
    Json(payload): Json<ValidatePayload>,
) -> (StatusCode, Json<ApiResponse<TestReport>>) {
    let mut engine = state.engine.lock().await;
    match engine.apply(payload.config).await {
        Ok(report) => (StatusCode::OK, Json(ApiResponse::ok(report))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

async fn test_config_handler(State(state): State<AppState>) -> Json<ApiResponse<TestReport>> {
    let status = state.reader.get_status();
    let config = state.reader.get_active_config().unwrap_or_default();
    let uplink = status.physical.interface;
    let v1_name = status.vpn1.name;
    let v1_ep = status.vpn1.endpoint;
    let v2_name = status.vpn2.name;
    let v2_ep = status.vpn2.endpoint;

    if status.state != crate::model::state::ServiceState::Running {
        let phys = HealthChecker::probe_physical(Some(&uplink));
        return Json(ApiResponse::ok(TestReport {
            physical: crate::model::state::VpnHopStatus {
                name: "Physical Gateway".to_string(),
                endpoint: phys.gateway.unwrap_or_default(),
                config_valid: true,
                reachable: phys.status == "UP",
                bytes_sent: 0,
                bytes_received: 0,
                latency_ms: None,
                status: phys.status,
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
                message: Some("链路未启动".to_string()),
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
                message: Some("链路未启动".to_string()),
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

    let report = HealthChecker::run_full_test(&config, Some(&uplink), &v1_name, &v1_ep, &v2_name, &v2_ep).await;
    state.reader.update_last_report(report.clone());
    Json(ApiResponse::ok(report))
}

#[derive(Deserialize, Default)]
struct StopPayload {
    #[serde(default)]
    all: bool,
}

async fn stop_handler(
    State(state): State<AppState>,
    payload: Option<Json<StopPayload>>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let stop_all = payload.map(|Json(p)| p.all).unwrap_or(false);
    let mut engine = state.engine.lock().await;
    let res = if stop_all {
        let r = engine.stop_tunnel();
        let _ = engine.stop_socks5();
        r
    } else {
        engine.stop()
    };
    match res {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::ok("Stopped cleanly".to_string()))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

#[derive(Deserialize)]
struct Socks5ApplyPayload {
    socks5_server: crate::model::config::Socks5ServerConfig,
}

async fn socks5_apply_handler(
    State(state): State<AppState>,
    Json(payload): Json<Socks5ApplyPayload>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    match state.reader.start_socks5(payload.socks5_server.clone()) {
        Ok(_) => (
            StatusCode::OK,
            Json(ApiResponse::ok(format!("{}:{}", payload.socks5_server.listen, payload.socks5_server.port))),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

async fn socks5_stop_handler(State(state): State<AppState>) -> (StatusCode, Json<ApiResponse<String>>) {
    match state.reader.stop_socks5() {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::ok("SOCKS5 server stopped".to_string()))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

async fn warp_register_handler() -> (StatusCode, Json<ApiResponse<crate::wireguard::WarpRegistrationResult>>) {
    match crate::wireguard::WarpRegistrar::register_warp().await {
        Ok(res) => (StatusCode::OK, Json(ApiResponse::ok(res))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

async fn logs_handler() -> Json<ApiResponse<String>> {
    let mut logs = String::new();
    if let Ok(out) = std::process::Command::new("journalctl")
        .args(["-u", "sooya", "-n", "50", "--no-pager"])
        .output()
    {
        logs.push_str(&String::from_utf8_lossy(&out.stdout));
    }
    if logs.trim().is_empty() {
        logs = "暂无系统日志，可通过终端执行: journalctl -u sooya -f 查看实时日志".to_string();
    }
    Json(ApiResponse::ok(logs))
}

async fn network_handler() -> Json<ApiResponse<String>> {
    Json(ApiResponse::ok(SystemDiagnostician::generate_report()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_web_panel_login_and_authenticated_routes() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(Mutex::new(ChainEngine::new(dir.path())));
        let app = create_router(engine);

        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/panel/api/server/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let login_req = Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"username":"admin","password":"admin"}"#))
            .unwrap();
        let login_resp = app.clone().oneshot(login_req).await.unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let set_cookie = login_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.contains(SESSION_COOKIE_NAME));
        let cookie_pair = set_cookie.split(';').next().unwrap().to_string();

        let idx_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, &cookie_pair)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(idx_resp.status(), StatusCode::OK);

        let st_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/panel/api/server/status")
                    .header(header::COOKIE, &cookie_pair)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(st_resp.status(), StatusCode::OK);
    }
}
