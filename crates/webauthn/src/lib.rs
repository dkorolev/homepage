//! Passkey (WebAuthn) auth: registration and assertion endpoints, state.

use askama::Template;
use axum::{
  extract::State,
  http::StatusCode,
  response::{Html, IntoResponse},
  routing::{get, post},
  Json, Router,
};
use base64::Engine;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use webauthn_rs::prelude::*;

fn to_b64url(data: &[u8]) -> String {
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[derive(Serialize)]
struct AuthedCredential {
  cred_id: String,
  algorithm: String,
  key: AuthedKey,
}

#[derive(Serialize)]
#[serde(tag = "type")]
#[allow(non_camel_case_types)]
enum AuthedKey {
  EC_EC2 { curve: String, x: String, y: String },
  EC_OKP { curve: String, x: String },
  RSA { n: String, e: String },
}

fn build_authed_credential(passkey: &Passkey) -> AuthedCredential {
  let pubkey = passkey.get_public_key();
  let key = match &pubkey.key {
    COSEKeyType::EC_EC2(ec) => {
      AuthedKey::EC_EC2 { curve: format!("{:?}", ec.curve), x: to_b64url(ec.x.as_ref()), y: to_b64url(ec.y.as_ref()) }
    }
    COSEKeyType::EC_OKP(okp) => AuthedKey::EC_OKP { curve: format!("{:?}", okp.curve), x: to_b64url(okp.x.as_ref()) },
    COSEKeyType::RSA(rsa) => AuthedKey::RSA { n: to_b64url(rsa.n.as_ref()), e: to_b64url(&rsa.e) },
  };
  AuthedCredential { cred_id: to_b64url(passkey.cred_id().as_ref()), algorithm: format!("{:?}", pubkey.type_), key }
}

pub struct AppState {
  webauthn: Webauthn,
  credentials: Arc<RwLock<Vec<Passkey>>>,
  pending_reg: Arc<RwLock<HashMap<String, PasskeyRegistration>>>,
  pending_auth: Arc<RwLock<HashMap<String, PasskeyAuthentication>>>,
  keys_jsonl: PathBuf,
}

pub fn build_state(
  fqdn: &str,
  origin_str: &str,
  keys_jsonl: PathBuf,
) -> Result<Arc<AppState>, Box<dyn std::error::Error + Send + Sync>> {
  let origin = url::Url::parse(origin_str).map_err(|e| format!("origin URL: {}", e))?;
  let webauthn_instance = WebauthnBuilder::new(fqdn, &origin)
    .map_err(|e| format!("webauthn builder: {}", e))?
    .build()
    .map_err(|e| format!("webauthn build: {}", e))?;
  tracing::info!("keys JSONL: {}", keys_jsonl.display());
  Ok(Arc::new(AppState {
    webauthn: webauthn_instance,
    credentials: Arc::new(RwLock::new(load_credentials(&keys_jsonl))),
    pending_reg: Arc::new(RwLock::new(HashMap::new())),
    pending_auth: Arc::new(RwLock::new(HashMap::new())),
    keys_jsonl,
  }))
}

fn load_credentials(path: &PathBuf) -> Vec<Passkey> {
  let data = match std::fs::read_to_string(path) {
    Ok(d) => d,
    Err(_) => return Vec::new(),
  };
  let mut creds = Vec::new();
  for (i, line) in data.lines().enumerate() {
    let line = line.trim();
    if line.is_empty() {
      continue;
    }
    match serde_json::from_str::<Passkey>(line) {
      Ok(p) => creds.push(p),
      Err(e) => tracing::warn!("{} line {}: {}", path.display(), i + 1, e),
    }
  }
  tracing::info!("loaded {} passkey(s) from {}", creds.len(), path.display());
  creds
}

fn append_credential(state: &AppState, passkey: &Passkey) {
  match serde_json::to_string(passkey) {
    Ok(json) => {
      use std::io::Write;
      match std::fs::OpenOptions::new().create(true).append(true).open(&state.keys_jsonl) {
        Ok(mut f) => {
          if let Err(e) = writeln!(f, "{}", json) {
            tracing::warn!("failed to write to {}: {}", state.keys_jsonl.display(), e);
          }
        }
        Err(e) => tracing::warn!("failed to open {}: {}", state.keys_jsonl.display(), e),
      }
    }
    Err(e) => tracing::warn!("failed to serialize credential: {}", e),
  }
}

// -- Piarun passkey page (Askama template).

#[derive(Template)]
#[template(path = "piarun.html")]
struct PiarunTemplate {
  title: String,
  message: String,
}

async fn piarun_page() -> impl IntoResponse {
  let t = PiarunTemplate {
    title: "Piarun".to_string(),
    message: "Authenticate with a passkey or register a new one.".to_string(),
  };
  match t.render() {
    Ok(html) => Html(html).into_response(),
    Err(e) => {
      tracing::error!(%e, "piarun template render failed");
      (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
    }
  }
}

/// Routes are mounted under `/piarun/...`.
pub fn router(state: Arc<AppState>) -> Router {
  Router::new()
    .route("/piarun", get(piarun_page))
    .route("/piarun/webauthn/status", get(status))
    .route("/piarun/webauthn/register/options", post(register_options))
    .route("/piarun/webauthn/register", post(register_verify))
    .route("/piarun/webauthn/auth/options", post(auth_options))
    .route("/piarun/webauthn/auth", post(auth_verify))
    .with_state(state)
}

async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
  let has_key = !state.credentials.read().await.is_empty();
  Json(serde_json::json!({"registered": has_key}))
}

async fn register_options(State(state): State<Arc<AppState>>) -> impl IntoResponse {
  let (ccr, reg_state) = match state.webauthn.start_passkey_registration(Uuid::new_v4(), "user", "User", None) {
    Ok(x) => x,
    Err(e) => {
      tracing::warn!(%e, "start_passkey_registration failed");
      return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::Value::Null)).into_response();
    }
  };
  let challenge = match serde_json::to_value(&ccr).ok().and_then(|v: serde_json::Value| {
    v.get("publicKey").and_then(|pk| pk.get("challenge")).and_then(|c| c.as_str().map(String::from))
  }) {
    Some(s) => s,
    None => {
      tracing::warn!("could not extract challenge from CreationChallengeResponse");
      return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::Value::Null)).into_response();
    }
  };
  state.pending_reg.write().await.insert(challenge, reg_state);
  (StatusCode::OK, Json(ccr)).into_response()
}

async fn register_verify(
  State(state): State<Arc<AppState>>, Json(cred): Json<RegisterPublicKeyCredential>,
) -> impl IntoResponse {
  let challenge = match client_data_challenge(&cred.response.client_data_json) {
    Some(c) => c,
    None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false}))).into_response(),
  };
  let reg_state = match state.pending_reg.write().await.remove(&challenge) {
    Some(s) => s,
    None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false}))).into_response(),
  };
  let passkey = match state.webauthn.finish_passkey_registration(&cred, &reg_state) {
    Ok(p) => p,
    Err(e) => {
      tracing::warn!(%e, "finish_passkey_registration failed");
      return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false}))).into_response();
    }
  };
  append_credential(&state, &passkey);
  state.credentials.write().await.push(passkey);
  tracing::info!("passkey registered successfully");
  (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

async fn auth_options(State(state): State<Arc<AppState>>) -> impl IntoResponse {
  let creds = state.credentials.read().await;
  if creds.is_empty() {
    return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "no_credentials"}))).into_response();
  }
  let (rcr, auth_state) = match state.webauthn.start_passkey_authentication(creds.as_slice()) {
    Ok(x) => x,
    Err(e) => {
      tracing::warn!(%e, "start_passkey_authentication failed");
      return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::Value::Null)).into_response();
    }
  };
  let challenge = match serde_json::to_value(&rcr).ok().and_then(|v: serde_json::Value| {
    v.get("publicKey").and_then(|pk| pk.get("challenge")).and_then(|c| c.as_str().map(String::from))
  }) {
    Some(s) => s,
    None => {
      tracing::warn!("could not extract challenge from RequestChallengeResponse");
      return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::Value::Null)).into_response();
    }
  };
  state.pending_auth.write().await.insert(challenge, auth_state);
  (StatusCode::OK, Json(rcr)).into_response()
}

async fn auth_verify(State(state): State<Arc<AppState>>, Json(cred): Json<PublicKeyCredential>) -> impl IntoResponse {
  let challenge = match client_data_challenge(&cred.response.client_data_json) {
    Some(c) => c,
    None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false}))).into_response(),
  };
  let auth_state = match state.pending_auth.write().await.remove(&challenge) {
    Some(s) => s,
    None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false}))).into_response(),
  };
  match state.webauthn.finish_passkey_authentication(&cred, &auth_state) {
    Ok(result) => {
      let auth_cred_id = result.cred_id();
      let creds = state.credentials.read().await;
      match creds.iter().find(|p| p.cred_id() == auth_cred_id) {
        Some(passkey) => {
          let ac = build_authed_credential(passkey);
          let cred_id = ac.cred_id.clone();
          match serde_json::to_string(&ac) {
            Ok(json) => tracing::info!("passkey auth OK: {}", json),
            Err(e) => tracing::info!("passkey auth OK (serialize error: {})", e),
          }
          return (StatusCode::OK, Json(serde_json::json!({"ok": true, "cred_id": cred_id}))).into_response();
        }
        None => {
          tracing::info!(
            "passkey auth OK but credential not found in store (cred_id: {})",
            to_b64url(auth_cred_id.as_ref())
          );
        }
      }
      (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
    }
    Err(e) => {
      tracing::warn!(%e, "finish_passkey_authentication failed");
      (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok": false}))).into_response()
    }
  }
}

fn client_data_challenge(client_data_json: &Base64UrlSafeData) -> Option<String> {
  let bytes: &[u8] = client_data_json.as_ref();
  let s = std::str::from_utf8(bytes).ok()?;
  let v: serde_json::Value = serde_json::from_str(s).ok()?;
  v.get("challenge").and_then(|c| c.as_str()).map(String::from)
}
