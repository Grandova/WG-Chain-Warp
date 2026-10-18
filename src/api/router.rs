use crate::engine::transaction::ChainEngine;
use crate::health::checker::HealthChecker;
use crate::health::diagnose::SystemDiagnostician;
use crate::health::sysinfo::{ServerSystemStatus, SysInfoCollector};
use crate::model::config::ChainProxyConfig;
use crate::model::panel::PanelSetting;
use crate::model::state::{ChainStatus, TestReport};
use crate::web::{INDEX_HTML, LOGIN_HTML};
use axum::extract::{Json, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

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

    router.with_state(state)
}

fn is_https_request(headers: &HeaderMap) -> bool {
    if let Some(proto) = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()) {
        if proto.split(',').next().unwrap_or("").trim().eq_ignore_ascii_case("https") {
            return true;
        }
    }
    if let Some(ssl) = headers.get("x-forwarded-ssl").and_then(|v| v.to_str().ok()) {
        if ssl.trim().eq_ignore_ascii_case("on") {
            return true;
        }
    }
    if let Some(fe) = headers.get("front-end-https").and_then(|v| v.to_str().ok()) {
        if fe.trim().eq_ignore_ascii_case("on") {
            return true;
        }
    }
    if let Some(fwd) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        for part in fwd.split(';') {
            if part.trim().eq_ignore_ascii_case("proto=https") {
                return true;
            }
        }
    }
    false
}

fn build_session_cookie(cookie_name: &str, value: &str, max_age: u64, is_https: bool) -> String {
    let secure_attr = if is_https { "; Secure" } else { "" };
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax{}; Max-Age={}",
        cookie_name, value, secure_attr, max_age
    )
}

async fn is_authenticated(headers: &HeaderMap, state: &AppState) -> bool {
    let (cookie_name, expected) = {
        let panel = state.panel.lock().await;
        (panel.cookie_name(), panel.session_secret.clone())
    };
    if expected.is_empty() {
        return false;
    }

    if let Some(token) = headers.get("x-sooya-token").and_then(|v| v.to_str().ok()) {
        if token.trim() == expected {
            return true;
        }
    }

    if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        let prefix = format!("{}=", cookie_name);
        for part in cookie_hdr.split(';') {
            if let Some(val) = part.trim().strip_prefix(&prefix) {
                if val == expected {
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
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Response {
    let panel = state.panel.lock().await;
    if panel.verify_credentials(payload.username.trim(), &payload.password) {
        let cookie = build_session_cookie(
            &panel.cookie_name(),
            &panel.session_secret,
            2592000,
            is_https_request(&headers),
        );
        (StatusCode::OK, [(header::SET_COOKIE, cookie)], Json(ApiResponse::ok("登录成功".to_string()))).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(ApiResponse::<String>::err("用户名或密码错误"))).into_response()
    }
}

async fn web_logout_handler(headers: HeaderMap, State(state): State<AppState>) -> Response {
    let cookie_name = state.panel.lock().await.cookie_name();
    let cookie = build_session_cookie(&cookie_name, "", 0, is_https_request(&headers));
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
        "instance_id": panel.instance_id,
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

async fn status_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<ChainStatus>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    (StatusCode::OK, Json(ApiResponse::ok(state.reader.get_status())))
}

async fn get_config_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<serde_json::Value>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    let status = state.reader.get_status();
    let active_cfg = state.reader.get_active_config();
    (
        StatusCode::OK,
        Json(ApiResponse::ok(serde_json::json!({
            "status": status.state,
            "active_version": status.active_config_version,
            "config": active_cfg,
        }))),
    )
}

#[derive(Deserialize)]
struct ValidatePayload {
    config: ChainProxyConfig,
}

async fn apply_config_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<ValidatePayload>,
) -> (StatusCode, Json<ApiResponse<TestReport>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    let mut engine = state.engine.lock().await;
    match engine.apply(payload.config).await {
        Ok(report) => (StatusCode::OK, Json(ApiResponse::ok(report))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

async fn test_config_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<TestReport>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    let status = state.reader.get_status();
    let mut config = state.reader.get_active_config().unwrap_or_default();
    if status.state != crate::model::state::ServiceState::Running && status.socks5_running {
        config.mode = crate::model::config::ProxyMode::Socks5Server;
    }
    let uplink = status.physical.interface;
    let v1_name = status.vpn1.name;
    let v1_ep = status.vpn1.endpoint;
    let v2_name = status.vpn2.name;
    let v2_ep = status.vpn2.endpoint;

    if status.state != crate::model::state::ServiceState::Running && !status.socks5_running {
        let phys = HealthChecker::probe_physical(Some(&uplink));
        return (
            StatusCode::OK,
            Json(ApiResponse::ok(TestReport {
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
            })),
        );
    }

    let probe_sender = state.reader.probe_sender();
    let report = HealthChecker::run_full_test(&config, Some(&uplink), &v1_name, &v1_ep, &v2_name, &v2_ep, &probe_sender).await;
    state.reader.update_last_report(report.clone());
    (StatusCode::OK, Json(ApiResponse::ok(report)))
}

#[derive(Deserialize, Default)]
struct StopPayload {
    #[serde(default)]
    all: bool,
}

async fn stop_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    payload: Option<Json<StopPayload>>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
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
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<Socks5ApplyPayload>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    match state.reader.start_socks5(payload.socks5_server.clone()) {
        Ok(_) => (
            StatusCode::OK,
            Json(ApiResponse::ok(format!("{}:{}", payload.socks5_server.listen, payload.socks5_server.port))),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

async fn socks5_stop_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    match state.reader.stop_socks5() {
        Ok(_) => (StatusCode::OK, Json(ApiResponse::ok("SOCKS5 server stopped".to_string()))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

async fn warp_register_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<crate::wireguard::WarpRegistrationResult>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    match crate::wireguard::WarpRegistrar::register_warp().await {
        Ok(res) => (StatusCode::OK, Json(ApiResponse::ok(res))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e.to_string()))),
    }
}

async fn logs_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
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
    (StatusCode::OK, Json(ApiResponse::ok(logs)))
}

async fn network_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if !is_authenticated(&headers, &state).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse::err("Unauthorized")));
    }
    (StatusCode::OK, Json(ApiResponse::ok(SystemDiagnostician::generate_report())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::SESSION_COOKIE_NAME;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    async fn login_instance(app: &Router, username: &str, password: &str, https: bool) -> (String, String) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::CONTENT_TYPE, "application/json");
        if https {
            builder = builder.header("x-forwarded-proto", "https");
        }
        let req = builder
            .body(Body::from(format!(r#"{{"username":"{}","password":"{}"}}"#, username, password)))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let cookie_pair = set_cookie.split(';').next().unwrap().to_string();
        (set_cookie, cookie_pair)
    }

    async fn get_json(app: &Router, uri: &str, cookie_header: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::COOKIE, cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let val = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, val)
    }

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

        // Verify all protected APIs reject unauthenticated requests
        for uri in [
            "/panel/api/bootstrap",
            "/panel/api/server/status",
            "/panel/api/chain/config",
            "/panel/api/outbounds",
            "/api/v1/status",
            "/api/v1/config",
            "/api/v1/logs",
            "/api/v1/network",
        ] {
            let r = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "Endpoint {} must require auth", uri);
        }

        for post_uri in ["/api/v1/stop", "/api/v1/socks5/stop", "/panel/api/outbounds"] {
            let r = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(post_uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "POST {} must require auth", post_uri);
        }

        let (set_cookie, cookie_pair) = login_instance(&app, "admin", "admin", false).await;
        assert!(set_cookie.starts_with(&format!("{}_", SESSION_COOKIE_NAME)));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(!set_cookie.contains("; Secure"));

        // Verify HTTPS sets Secure flag
        let (https_cookie, _) = login_instance(&app, "admin", "admin", true).await;
        assert!(https_cookie.contains("; Secure"));

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

        let (st_code, _) = get_json(&app, "/panel/api/server/status", &cookie_pair).await;
        assert_eq!(st_code, StatusCode::OK);

        // Verify local CLI token authentication works on /api/v1/status
        let panel = PanelSetting::load_or_default(dir.path());
        let cli_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header("x-sooya-token", &panel.session_secret)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cli_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multi_instance_same_ip_different_ports_session_and_node_isolation() {
        // Simulate Container A (port 10008 -> 10.12.144.106:5000) and Container B (port 50000 -> 10.12.144.121:5000)
        // behind the same public IP 108.186.202.44 where the browser sends all cookies for that IP together.
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();

        let app_a = create_router(Arc::new(Mutex::new(ChainEngine::new(dir_a.path()))));
        let app_b = create_router(Arc::new(Mutex::new(ChainEngine::new(dir_b.path()))));

        let panel_a = PanelSetting::load_or_default(dir_a.path());
        let panel_b = PanelSetting::load_or_default(dir_b.path());
        assert_ne!(panel_a.instance_id, panel_b.instance_id);
        assert_ne!(panel_a.cookie_name(), panel_b.cookie_name());
        assert_ne!(panel_a.session_secret, panel_b.session_secret);

        // 1. Login A, then Login B; browser stores both cookies on IP 108.186.202.44
        let (_, cookie_a) = login_instance(&app_a, "admin", "admin", false).await;
        let (_, cookie_b) = login_instance(&app_b, "admin", "admin", false).await;
        let shared_ip_cookie_jar = format!("{}; {}", cookie_a, cookie_b);

        // Both A and B remain logged in simultaneously without kicking each other offline
        let (code_a, boot_a) = get_json(&app_a, "/panel/api/bootstrap", &shared_ip_cookie_jar).await;
        let (code_b, boot_b) = get_json(&app_b, "/panel/api/bootstrap", &shared_ip_cookie_jar).await;
        assert_eq!(code_a, StatusCode::OK);
        assert_eq!(code_b, StatusCode::OK);
        assert_eq!(boot_a["data"]["outbounds"], serde_json::json!([]));
        assert_eq!(boot_b["data"]["outbounds"], serde_json::json!([]));

        // 2. A adds WG node "冰岛" (node-1792180423787); B does NOT show it
        let iceland_nodes = serde_json::json!([{
            "id": "node-1792180423787",
            "name": "冰岛",
            "mode": "standalone_wg",
            "wg": {
                "endpoint": "82.221.139.1:51820",
                "private_key": "aGVsbG93b3JsZGhpc2lzYXRlc3Rwcml2YXRla2V5MTIzNDU=",
                "public_key": "cHVibGlja2V5dGVzdDEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbg==",
                "local_ip": "10.0.0.2/32",
                "dns": "1.1.1.1",
                "mtu": 1420
            },
            "socks": {},
            "warp": {}
        }]);
        let save_req = Request::builder()
            .method("POST")
            .uri("/panel/api/outbounds")
            .header(header::COOKIE, &shared_ip_cookie_jar)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&iceland_nodes).unwrap()))
            .unwrap();
        let save_resp = app_a.clone().oneshot(save_req).await.unwrap();
        assert_eq!(save_resp.status(), StatusCode::OK);

        let (_, out_a) = get_json(&app_a, "/panel/api/outbounds", &shared_ip_cookie_jar).await;
        let (_, out_b) = get_json(&app_b, "/panel/api/outbounds", &shared_ip_cookie_jar).await;
        assert_eq!(out_a["data"].as_array().unwrap().len(), 1);
        assert_eq!(out_a["data"][0]["id"], "node-1792180423787");
        assert_eq!(out_a["data"][0]["name"], "冰岛");
        assert_eq!(out_b["data"].as_array().unwrap().len(), 0);

        // 3. A modifies WG node; B remains unchanged
        let modified_nodes = serde_json::json!([{
            "id": "node-1792180423787",
            "name": "冰岛-直连",
            "mode": "wg_chain_warp",
            "wg": {
                "endpoint": "82.221.139.1:51820",
                "private_key": "aGVsbG93b3JsZGhpc2lzYXRlc3Rwcml2YXRla2V5MTIzNDU=",
                "public_key": "cHVibGlja2V5dGVzdDEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbg==",
                "local_ip": "10.0.0.2/32",
                "dns": "1.1.1.1",
                "mtu": 1420
            },
            "socks": {},
            "warp": {}
        }]);
        let mod_req = Request::builder()
            .method("POST")
            .uri("/panel/api/outbounds")
            .header(header::COOKIE, &shared_ip_cookie_jar)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&modified_nodes).unwrap()))
            .unwrap();
        assert_eq!(app_a.clone().oneshot(mod_req).await.unwrap().status(), StatusCode::OK);

        // 5 & 6. Restart both instances and refresh; data and cookies stay independent and valid
        let app_a = create_router(Arc::new(Mutex::new(ChainEngine::new(dir_a.path()))));
        let app_b = create_router(Arc::new(Mutex::new(ChainEngine::new(dir_b.path()))));

        let (code_a_after, boot_a_after) = get_json(&app_a, "/panel/api/bootstrap", &shared_ip_cookie_jar).await;
        let (code_b_after, boot_b_after) = get_json(&app_b, "/panel/api/bootstrap", &shared_ip_cookie_jar).await;
        assert_eq!(code_a_after, StatusCode::OK);
        assert_eq!(code_b_after, StatusCode::OK);
        assert_eq!(boot_a_after["data"]["outbounds"][0]["name"], "冰岛-直连");
        assert_eq!(boot_b_after["data"]["outbounds"], serde_json::json!([]));

        // 4. B adds its own node, A deletes its node; neither affects the other or resurrects deleted node
        let b_nodes = serde_json::json!([{
            "id": "node-b-tokyo",
            "name": "日本东京",
            "mode": "standalone_wg",
            "wg": { "endpoint": "203.0.113.9:51820" },
            "socks": {},
            "warp": {}
        }]);
        let b_save = Request::builder()
            .method("POST")
            .uri("/panel/api/outbounds")
            .header(header::COOKIE, &shared_ip_cookie_jar)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&b_nodes).unwrap()))
            .unwrap();
        assert_eq!(app_b.clone().oneshot(b_save).await.unwrap().status(), StatusCode::OK);

        let a_del = Request::builder()
            .method("POST")
            .uri("/panel/api/outbounds")
            .header(header::COOKIE, &shared_ip_cookie_jar)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("[]"))
            .unwrap();
        assert_eq!(app_a.clone().oneshot(a_del).await.unwrap().status(), StatusCode::OK);

        let (_, boot_a_del) = get_json(&app_a, "/panel/api/bootstrap", &shared_ip_cookie_jar).await;
        let (_, boot_b_keep) = get_json(&app_b, "/panel/api/bootstrap", &shared_ip_cookie_jar).await;
        assert_eq!(boot_a_del["data"]["outbounds"], serde_json::json!([]));
        assert_eq!(boot_b_keep["data"]["outbounds"][0]["id"], "node-b-tokyo");

        // 9. Logout from A ONLY clears A's cookie; B remains logged in
        let logout_a = app_a
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header(header::COOKIE, &shared_ip_cookie_jar)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout_a.status(), StatusCode::OK);
        let logout_set_cookie = logout_a
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(logout_set_cookie.starts_with(&format!("{}=", panel_a.cookie_name())));
        assert!(logout_set_cookie.contains("Max-Age=0"));
        assert!(!logout_set_cookie.contains(&panel_b.cookie_name()));

        // After browser clears cookie_a, only cookie_b remains in the cookie jar
        let (code_a_logged_out, _) = get_json(&app_a, "/panel/api/bootstrap", &cookie_b).await;
        let (code_b_still_in, _) = get_json(&app_b, "/panel/api/bootstrap", &cookie_b).await;
        assert_eq!(code_a_logged_out, StatusCode::UNAUTHORIZED);
        assert_eq!(code_b_still_in, StatusCode::OK);

        // Password change on B rotates B's session_secret and invalidates old cookie_b
        let pw_change = Request::builder()
            .method("POST")
            .uri("/panel/api/setting/updateUser")
            .header(header::COOKIE, &cookie_b)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"old_username":"admin","old_password":"admin","new_username":"admin","new_password":"newStrongPassword123"}"#,
            ))
            .unwrap();
        assert_eq!(app_b.clone().oneshot(pw_change).await.unwrap().status(), StatusCode::OK);

        let (code_b_old_cookie, _) = get_json(&app_b, "/panel/api/bootstrap", &cookie_b).await;
        assert_eq!(code_b_old_cookie, StatusCode::UNAUTHORIZED);

        let (_, new_cookie_b) = login_instance(&app_b, "admin", "newStrongPassword123", false).await;
        let (code_b_new_cookie, _) = get_json(&app_b, "/panel/api/bootstrap", &new_cookie_b).await;
        assert_eq!(code_b_new_cookie, StatusCode::OK);
    }
}

