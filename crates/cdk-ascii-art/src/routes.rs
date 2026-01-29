//! Axum route handlers for the ASCII art server.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use cdk::spilman::{unblind_and_verify_dleq, BridgeStatus, SpilmanBridge, SpilmanHost};

use crate::host::AsciiArtHost;
use crate::stores::{get_channel_status, Stores, UnitPricing};

// ============================================================================
// Application State
// ============================================================================

pub type AppState = Arc<AppStateInner>;

pub struct AppStateInner {
    pub bridge: SpilmanBridge<AsciiArtHost>,
    pub host: Arc<AsciiArtHost>,
    pub stores: Arc<Stores>,
    pub pricing: HashMap<String, UnitPricing>,
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
        .route("/channel/{id}/unilateral-close", post(post_unilateral_close))
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

#[derive(Serialize)]
pub struct AsciiResponse {
    pub art: String,
    pub message: String,
    pub cost: u64,
    pub payment: serde_json::Value,
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
    // Build pricing with only active units
    let active_units = state.stores.get_active_units();
    let active_pricing: serde_json::Value = state
        .pricing
        .iter()
        .filter(|(unit, _)| active_units.contains(*unit))
        .map(|(unit, p)| {
            (
                unit.clone(),
                serde_json::json!({
                    "per_char": p.per_char,
                    "minCapacity": p.min_capacity,
                }),
            )
        })
        .collect();

    Json(serde_json::json!({
        "receiver_pubkey": state.host.server_pubkey.to_hex(),
        "pricing": active_pricing,
        "mints_units_keysets": state.stores.get_mints_units_keysets(),
        "min_expiry_in_seconds": state.host.min_expiry_seconds,
    }))
}

// ============================================================================
// POST /channel/register
// ============================================================================

async fn post_channel_register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Response {
    // Validate required fields
    let channel_id = match body.channel_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Bad request",
                    "reason": "missing required field: channel_id"
                })),
            )
                .into_response();
        }
    };

    let balance = body.balance.unwrap_or(0);
    let signature = match body.signature {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Bad request",
                    "reason": "missing required field: signature"
                })),
            )
                .into_response();
        }
    };

    let params = match body.params {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Bad request",
                    "reason": "missing required field: params"
                })),
            )
                .into_response();
        }
    };

    let funding_proofs = match body.funding_proofs {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Bad request",
                    "reason": "missing required field: funding_proofs"
                })),
            )
                .into_response();
        }
    };

    // balance must be 0 for registration
    if balance != 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Bad request",
                "reason": format!("funding requires balance=0, got {}", balance)
            })),
        )
            .into_response();
    }

    tracing::info!(
        "[Register] Request for channel={}",
        &channel_id[..8.min(channel_id.len())]
    );

    // Build request body in the same format as payment
    let register_body = serde_json::json!({
        "channel_id": channel_id,
        "balance": 0,
        "signature": signature,
        "params": params,
        "funding_proofs": funding_proofs,
    });

    // Use fund_channel to validate and store the channel
    match state.bridge.fund_channel(&register_body.to_string()) {
        Ok(result) => {
            tracing::info!(
                "  [Register] SUCCESS! channel={} capacity={} already_known={}",
                &result.channel_id[..8.min(result.channel_id.len())],
                result.capacity,
                result.already_known
            );
            Json(serde_json::json!({
                "success": true,
                "channel_id": result.channel_id,
                "capacity": result.capacity,
                "already_known": result.already_known,
            }))
            .into_response()
        }
        Err(e) => {
            let error_msg = e.to_string();
            tracing::info!("  [Register] REJECTED: {}", error_msg);

            // Determine status code based on error type
            let status = if error_msg.contains("invalid signature") {
                StatusCode::PAYMENT_REQUIRED
            } else {
                StatusCode::BAD_REQUEST
            };

            (
                status,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Bad request",
                    "reason": error_msg,
                    "status": status.as_u16(),
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
    let message = &body.message;
    let message_length = message.len() as u64;

    // Check for payment header
    let payment_header_b64 = headers
        .get("x-cashu-channel")
        .and_then(|h| h.to_str().ok());

    let Some(header_b64) = payment_header_b64 else {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({
                "error": "Payment required",
                "reason": "Missing X-Cashu-Channel header",
            })),
        )
            .into_response();
    };

    // Decode base64 payment header
    let payment_json = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        header_b64,
    ) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "Invalid payment header",
                        "reason": "invalid base64 encoding",
                    })),
                )
                    .into_response();
            }
        },
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid payment header",
                    "reason": "invalid base64 encoding",
                })),
            )
                .into_response();
        }
    };

    tracing::info!(
        "[Request] ASCII art for '{}' ({} chars)",
        message,
        message_length
    );

    // Create context with message length for pricing
    let context = serde_json::json!({ "chars": message_length, "message_length": message_length });

    // Process payment through bridge
    let result = state
        .bridge
        .process_payment(&payment_json, &context.to_string());

    if !result.success {
        tracing::info!(
            "  [Payment] REJECTED: {}",
            result.error.as_deref().unwrap_or("unknown")
        );

        let mut resp_headers = HeaderMap::new();
        if let Some(ref header) = result.header {
            if let Ok(header_val) = header.to_string().parse() {
                resp_headers.insert("X-Cashu-Channel", header_val);
            }
        }

        let status = match result.status {
            BridgeStatus::BadRequest => StatusCode::BAD_REQUEST,
            BridgeStatus::PaymentRequired => StatusCode::PAYMENT_REQUIRED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        return (
            status,
            resp_headers,
            Json(result.body.unwrap_or_else(|| {
                serde_json::json!({ "error": result.error.unwrap_or_else(|| "unknown".into()) })
            })),
        )
            .into_response();
    }

    // Payment accepted - generate ASCII art
    let payment_info = result.header.unwrap_or(serde_json::json!({}));

    // Look up unit from stored channel params to calculate cost
    let channel_id = payment_info
        .get("channel_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let unit = state
        .stores
        .get_funding(channel_id)
        .and_then(|f| {
            serde_json::from_str::<serde_json::Value>(&f.params_json)
                .ok()?
                .get("unit")?
                .as_str()
                .map(String::from)
        })
        .unwrap_or_else(|| "sat".to_string());

    let cost = message_length * state.pricing.get(&unit).map(|p| p.per_char).unwrap_or(1);

    tracing::info!(
        "  [Payment] ACCEPTED: cost={} balance={}/{}",
        cost,
        payment_info.get("balance").and_then(|v| v.as_u64()).unwrap_or(0),
        payment_info.get("capacity").and_then(|v| v.as_u64()).unwrap_or(0)
    );

    // Generate ASCII art
    let art = state
        .figlet_font
        .convert(message)
        .map(|f| f.to_string())
        .unwrap_or_else(|| message.to_string());

    Json(serde_json::json!({
        "art": art,
        "message": message,
        "cost": cost,
        "payment": payment_info,
    }))
    .into_response()
}

// ============================================================================
// GET /channel/:id/status
// ============================================================================

async fn get_channel_status_handler(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
) -> Response {
    match get_channel_status(&state.stores, &channel_id, &state.pricing) {
        Ok(status) => Json(status).into_response(),
        Err(e) if e == "unknown channel" => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown channel" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

// ============================================================================
// POST /channel/:id/close
// ============================================================================

async fn post_channel_close(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    Json(body): Json<CloseRequest>,
) -> Response {
    tracing::info!(
        "[Close] Request for channel={} balance={}",
        &channel_id[..8.min(channel_id.len())],
        body.balance
    );

    // Check if already closed (idempotent)
    if let Some(closed_data) = state.stores.get_closed(&channel_id) {
        if body.balance == closed_data.closed_amount {
            tracing::info!("  [Close] Already closed with same amount");
            let sender_proofs: serde_json::Value =
                serde_json::from_str(&closed_data.sender_proofs_json).unwrap_or(serde_json::json!([]));
            return Json(serde_json::json!({
                "success": true,
                "channel_id": channel_id,
                "total_value": closed_data.value_after_stage1,
                "receiver_sum": closed_data.receiver_sum,
                "sender_sum": closed_data.sender_sum,
                "sender_proofs": sender_proofs,
                "already_closed": true,
            }))
            .into_response();
        } else {
            tracing::info!("  [Close] Already closed with different amount");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "channel already closed with a different amount",
                    "closed_amount": closed_data.closed_amount,
                    "requested_amount": body.balance,
                })),
            )
                .into_response();
        }
    }

    // Build payment body (include params/funding_proofs for unknown channels)
    let mut close_body = serde_json::json!({
        "channel_id": channel_id,
        "balance": body.balance,
        "signature": body.signature,
    });

    if let Some(params) = &body.params {
        close_body["params"] = params.clone();
    }
    if let Some(funding_proofs) = &body.funding_proofs {
        close_body["funding_proofs"] = funding_proofs.clone();
    }

    // Prepare cooperative close
    let prepared = match state
        .bridge
        .prepare_cooperative_close_for_execution(&close_body.to_string())
    {
        Ok(p) => p,
        Err(e) => {
            tracing::info!("  [Close] Failed: {} (status={})", e.reason, e.status);
            return (
                StatusCode::from_u16(e.status).unwrap_or(StatusCode::BAD_REQUEST),
                Json(serde_json::from_str::<serde_json::Value>(&e.to_json()).unwrap_or_default()),
            )
                .into_response();
        }
    };

    // Submit swap to mint (async)
    let swap_response = match state
        .host
        .call_mint_swap_async(&prepared.mint_url, &prepared.swap_request.to_string())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::info!("  [Close] Swap failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "swap failed",
                    "reason": e,
                })),
            )
                .into_response();
        }
    };

    // Parse swap response to get signatures
    let swap_data: serde_json::Value = match serde_json::from_str(&swap_response) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!("  [Close] Invalid swap response: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "invalid swap response",
                    "reason": e.to_string(),
                })),
            )
                .into_response();
        }
    };

    let signatures = swap_data.get("signatures").cloned().unwrap_or(serde_json::json!([]));

    // Unblind and verify
    let unblind_result = match unblind_and_verify_dleq(
        &signatures.to_string(),
        &prepared.secrets_with_blinding.to_string(),
        &prepared.params_json,
        &prepared.keyset_info_json,
        &prepared.shared_secret,
        prepared.balance,
        Some(&prepared.output_keyset_info.to_string()),
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::info!("  [Close] Unblind failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "unblind failed",
                    "reason": e,
                })),
            )
                .into_response();
        }
    };

    let result: serde_json::Value = serde_json::from_str(&unblind_result).unwrap_or_default();

    let receiver_sum = result
        .get("receiver_sum_after_stage1")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let sender_sum = result
        .get("sender_sum_after_stage1")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let receiver_proofs = result.get("receiver_proofs").cloned().unwrap_or(serde_json::json!([]));
    let sender_proofs = result.get("sender_proofs").cloned().unwrap_or(serde_json::json!([]));

    // Mark channel as closed
    let funding = state.stores.get_funding(&channel_id);
    let locktime = funding
        .and_then(|f| {
            serde_json::from_str::<serde_json::Value>(&f.params_json)
                .ok()?
                .get("locktime")?
                .as_u64()
        })
        .unwrap_or(0);

    let _ = state.host.mark_channel_closed(
        &channel_id,
        locktime,
        body.balance,
        &receiver_proofs.to_string(),
        &sender_proofs.to_string(),
        receiver_sum,
        sender_sum,
    );

    tracing::info!("  [Close] SUCCESS! total_value={}", receiver_sum + sender_sum);

    Json(serde_json::json!({
        "success": true,
        "channel_id": channel_id,
        "total_value": receiver_sum + sender_sum,
        "receiver_sum": receiver_sum,
        "sender_sum": sender_sum,
        "sender_proofs": sender_proofs,
        "already_closed": false,
    }))
    .into_response()
}

// ============================================================================
// POST /channel/:id/unilateral-close
// ============================================================================

async fn post_unilateral_close(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
) -> Response {
    tracing::info!(
        "[Unilateral Close] Request for channel={}",
        &channel_id[..8.min(channel_id.len())]
    );

    // Check if already closed (idempotent)
    if let Some(closed_data) = state.stores.get_closed(&channel_id) {
        tracing::info!("  [Unilateral Close] Already closed, returning cached result");
        return Json(serde_json::json!({
            "success": true,
            "channel_id": channel_id,
            "earnedBeforeStage2Fees": closed_data.receiver_sum,
            "already_closed": true,
        }))
        .into_response();
    }

    // Check if channel exists
    if state.stores.get_funding(&channel_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown channel" })),
        )
            .into_response();
    }

    // Prepare unilateral close
    let prepared = match state
        .bridge
        .prepare_unilateral_close_for_execution(&channel_id)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::info!("  [Unilateral Close] Failed: {} (status={})", e.reason, e.status);
            return (
                StatusCode::from_u16(e.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(serde_json::from_str::<serde_json::Value>(&e.to_json()).unwrap_or_default()),
            )
                .into_response();
        }
    };

    // Submit swap to mint (async)
    let swap_response = match state
        .host
        .call_mint_swap_async(&prepared.mint_url, &prepared.swap_request.to_string())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::info!("  [Unilateral Close] Swap failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "swap failed",
                    "reason": e,
                })),
            )
                .into_response();
        }
    };

    // Parse swap response to get signatures
    let swap_data: serde_json::Value = match serde_json::from_str(&swap_response) {
        Ok(v) => v,
        Err(e) => {
            tracing::info!("  [Unilateral Close] Invalid swap response: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "invalid swap response",
                    "reason": e.to_string(),
                })),
            )
                .into_response();
        }
    };

    let signatures = swap_data.get("signatures").cloned().unwrap_or(serde_json::json!([]));

    // Unblind and verify
    let unblind_result = match unblind_and_verify_dleq(
        &signatures.to_string(),
        &prepared.secrets_with_blinding.to_string(),
        &prepared.params_json,
        &prepared.keyset_info_json,
        &prepared.shared_secret,
        prepared.balance,
        Some(&prepared.output_keyset_info.to_string()),
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::info!("  [Unilateral Close] Unblind failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": "unblind failed",
                    "reason": e,
                })),
            )
                .into_response();
        }
    };

    let result: serde_json::Value = serde_json::from_str(&unblind_result).unwrap_or_default();

    let receiver_sum = result
        .get("receiver_sum_after_stage1")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let sender_sum = result
        .get("sender_sum_after_stage1")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let receiver_proofs = result.get("receiver_proofs").cloned().unwrap_or(serde_json::json!([]));
    let sender_proofs = result.get("sender_proofs").cloned().unwrap_or(serde_json::json!([]));

    // Mark channel as closed
    let funding = state.stores.get_funding(&channel_id);
    let locktime = funding
        .and_then(|f| {
            serde_json::from_str::<serde_json::Value>(&f.params_json)
                .ok()?
                .get("locktime")?
                .as_u64()
        })
        .unwrap_or(0);

    let _ = state.host.mark_channel_closed(
        &channel_id,
        locktime,
        prepared.balance,
        &receiver_proofs.to_string(),
        &sender_proofs.to_string(),
        receiver_sum,
        sender_sum,
    );

    tracing::info!("  [Unilateral Close] SUCCESS! Earned {} sat", receiver_sum);

    Json(serde_json::json!({
        "success": true,
        "channel_id": channel_id,
        "earnedBeforeStage2Fees": receiver_sum,
        "already_closed": false,
    }))
    .into_response()
}


