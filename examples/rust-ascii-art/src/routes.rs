//! Axum route handlers for the ASCII art server.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use serde::Deserialize;

use cdk::spilman::configurable_host::ConfigurableHost;
use cdk::spilman::configurable_networking::ReqwestNetworking;
use cdk::spilman::{ClosePreparationError, SpilmanBridge, SpilmanHost};

// ============================================================================
// Application State
// ============================================================================

pub type AppState = Arc<AppStateInner>;

pub struct AppStateInner {
    pub bridge: SpilmanBridge<ConfigurableHost>,
    pub host: Arc<ConfigurableHost>,
    pub networking: Arc<ReqwestNetworking>,
    pub figlet_font: figlet_rs::FIGfont,
}

// ============================================================================
// Router
// ============================================================================

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/channel/params", get(get_channel_params))
        .route("/channel/register", post(post_channel_register))
        .route("/channel/{id}/status", get(get_channel_status_handler))
        .route("/channel/{id}/close", post(post_channel_close))
        .route(
            "/channel/{id}/unilateral-close",
            post(post_unilateral_close),
        )
        .route("/ascii", post(post_ascii))
        .with_state(state)
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Deserialize)]
pub struct AsciiRequest {
    pub message: String,
}

#[derive(Deserialize)]
pub struct CloseRequest {
    pub balance: u64,
    pub signature: String,
    pub params: Option<serde_json::Value>,
    pub funding_proofs: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
pub struct RegisterRequest {
    pub channel_id: Option<String>,
    pub balance: Option<u64>,
    pub signature: Option<String>,
    pub params: Option<serde_json::Value>,
    pub funding_proofs: Option<serde_json::Value>,
}

// ============================================================================
// GET /channel/params
// ============================================================================

async fn get_channel_params(State(state): State<AppState>) -> Json<serde_json::Value> {
    let active_pricing = state.host.get_active_pricing();
    let pricing_json: serde_json::Value = active_pricing
        .iter()
        .map(|(unit, cfg)| {
            // Emit per_char for backward compatibility (== the "chars" variable price).
            let per_char = cfg.variables.get("chars").copied().unwrap_or(0);
            let mut obj = serde_json::json!({
                "per_char": per_char,
                "minCapacity": cfg.min_capacity,
            });
            if let Some(max) = cfg.max_amount_per_output {
                obj["maxAmountPerOutput"] = serde_json::json!(max);
            }
            (unit.clone(), obj)
        })
        .collect();

    Json(serde_json::json!({
        "receiver_pubkey": state.host.server_pubkey().to_hex(),
        "pricing": pricing_json,
        "mints_units_keysets": state.host.get_mints_units_keysets(),
        "min_expiry_in_seconds": state.host.config().min_expiry_seconds,
    }))
}

// ============================================================================
// POST /channel/register
// ============================================================================

async fn post_channel_register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Response {
    let channel_id = match body.channel_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Bad request", "reason": "missing channel_id" })),
            )
                .into_response()
        }
    };

    let signature = match body.signature {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Bad request", "reason": "missing signature" })),
            )
                .into_response()
        }
    };

    let params = match body.params {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Bad request", "reason": "missing params" })),
            )
                .into_response()
        }
    };

    let funding_proofs = match body.funding_proofs {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({ "error": "Bad request", "reason": "missing funding_proofs" }),
                ),
            )
                .into_response()
        }
    };

    if body.balance.unwrap_or(0) != 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({ "error": "Bad request", "reason": "funding requires balance=0" }),
            ),
        )
            .into_response();
    }

    let register_body = serde_json::json!({
        "channel_id": channel_id,
        "balance": 0,
        "signature": signature,
        "params": params,
        "funding_proofs": funding_proofs,
    });

    match state
        .bridge
        .fund_channel_via_json(&register_body.to_string())
    {
        Ok(result) => Json(serde_json::json!({
            "success": true,
            "channel_id": result.channel_id,
            "capacity": result.capacity,
            "already_known": result.already_known
        }))
        .into_response(),
        Err(e) => {
            let error_response = ClosePreparationError::from_bridge_error(e);
            let status = match error_response.status {
                402 => StatusCode::PAYMENT_REQUIRED,
                404 => StatusCode::NOT_FOUND,
                500 => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_REQUEST,
            };
            (
                status,
                Json(serde_json::json!({
                    "success": false,
                    "error": error_response.error,
                    "reason": error_response.reason,
                    "status": error_response.status
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// POST /ascii
// ============================================================================

async fn post_ascii(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AsciiRequest>,
) -> Response {
    let payment_header_b64 = match headers.get("x-cashu-channel").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => {
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({
                    "error": "Payment required",
                    "reason": "Missing X-Cashu-Channel header"
                })),
            )
                .into_response()
        }
    };

    let payment_json = match base64::engine::general_purpose::STANDARD.decode(payment_header_b64) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid payment header",
                    "reason": "invalid base64 encoding"
                })),
            )
                .into_response()
        }
    };

    // Context uses the same variable names as the YAML config.
    let context = serde_json::json!({ "chars": body.message.len() });

    match state
        .bridge
        .process_payment_via_json(&payment_json, &context.to_string())
    {
        Ok(success) => {
            // Calculate cost from config pricing.
            let unit = state
                .host
                .get_funding_data(&success.channel_id)
                .and_then(|f| {
                    serde_json::from_str::<serde_json::Value>(&f.params_json)
                        .ok()?
                        .get("unit")?
                        .as_str()
                        .map(String::from)
                })
                .unwrap_or_else(|| "sat".to_string());
            let cost = state
                .host
                .config()
                .pricing
                .get(&unit)
                .and_then(|p| p.variables.get("chars"))
                .map(|&price| (body.message.len() as u64) * price)
                .unwrap_or(body.message.len() as u64);

            let art = state
                .figlet_font
                .convert(&body.message)
                .map(|f| f.to_string())
                .unwrap_or_else(|| body.message.clone());

            Json(serde_json::json!({
                "art": art,
                "message": body.message,
                "cost": cost,
                "payment": {
                    "channel_id": success.channel_id,
                    "balance": success.balance,
                    "amount_due": success.amount_due,
                    "capacity": success.capacity
                }
            }))
            .into_response()
        }
        Err(e) => {
            let error_response = ClosePreparationError::from_bridge_error(e);
            let status = match error_response.status {
                400 => StatusCode::BAD_REQUEST,
                402 => StatusCode::PAYMENT_REQUIRED,
                404 => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(serde_json::json!({
                    "error": error_response.error,
                    "reason": error_response.reason
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// GET /channel/:id/status
// ============================================================================

async fn get_channel_status_handler(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
) -> Response {
    let funding = match state.host.get_funding_data(&channel_id) {
        Some(f) => f,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "unknown channel" })),
            )
                .into_response()
        }
    };

    let params: serde_json::Value =
        serde_json::from_str(&funding.params_json).unwrap_or_default();
    let capacity = params.get("capacity").and_then(|v| v.as_u64()).unwrap_or(0);

    let balance = state.host.get_balance(&channel_id).map(|p| p.balance).unwrap_or(0);
    let usage = state.host.get_usage(&channel_id).unwrap_or_default();
    let closed_data = state.host.get_closed_data(&channel_id);
    let amount_due = state.host.get_amount_due(&channel_id, None);

    // Include chars_served for backward compatibility with integration tests.
    let chars_served = usage.get("chars").copied().unwrap_or(0);

    Json(serde_json::json!({
        "channel_id": channel_id,
        "capacity": capacity,
        "balance": balance,
        "usage": usage,
        "chars_served": chars_served,
        "amount_due": amount_due,
        "closed": closed_data.is_some(),
        "closed_amount": closed_data.as_ref().map(|c| c.closed_amount),
    }))
    .into_response()
}

// ============================================================================
// POST /channel/:id/close
// ============================================================================

async fn post_channel_close(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    Json(body): Json<CloseRequest>,
) -> Response {
    if let Some(closed_data) = state.host.get_closed_data(&channel_id) {
        if body.balance == closed_data.closed_amount {
            return Json(serde_json::json!({
                "success": true,
                "channel_id": channel_id,
                "total_value": closed_data.value_after_stage1,
                "receiver_sum": closed_data.receiver_sum,
                "sender_sum": closed_data.sender_sum,
                "sender_proofs": serde_json::from_str::<serde_json::Value>(
                    &closed_data.sender_proofs_json
                )
                .unwrap_or(serde_json::json!([])),
                "already_closed": true
            }))
            .into_response();
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "channel already closed with a different amount",
                    "closed_amount": closed_data.closed_amount,
                    "requested_amount": body.balance
                })),
            )
                .into_response();
        }
    }

    let mut close_body = serde_json::json!({
        "channel_id": channel_id,
        "balance": body.balance,
        "signature": body.signature
    });
    if let Some(params) = &body.params {
        close_body["params"] = params.clone();
    }
    if let Some(funding_proofs) = &body.funding_proofs {
        close_body["funding_proofs"] = funding_proofs.clone();
    }

    match state
        .bridge
        .execute_cooperative_close_async(&close_body.to_string(), &*state.networking)
        .await
    {
        Ok(result) => Json(result).into_response(),
        Err(e) => (
            StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_REQUEST),
            Json(e),
        )
            .into_response(),
    }
}

// ============================================================================
// POST /channel/:id/unilateral-close
// ============================================================================

async fn post_unilateral_close(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
) -> Response {
    if let Some(closed_data) = state.host.get_closed_data(&channel_id) {
        return Json(serde_json::json!({
            "success": true,
            "channel_id": channel_id,
            "earnedBeforeStage2Fees": closed_data.receiver_sum,
            "already_closed": true
        }))
        .into_response();
    }

    match state
        .bridge
        .execute_unilateral_close_async(&channel_id, &*state.networking)
        .await
    {
        Ok(result) => Json(serde_json::json!({
            "success": true,
            "channel_id": channel_id,
            "earnedBeforeStage2Fees": result.receiver_sum,
            "already_closed": false
        }))
        .into_response(),
        Err(e) => (
            StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(e),
        )
            .into_response(),
    }
}
