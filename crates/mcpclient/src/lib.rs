//! MCP client UI: connect to a remote MCP server, OAuth, list and invoke tools.
//! Served at /mcpclient.

use axum::{
  extract::{Query, State},
  response::{Html, IntoResponse, Json},
  routing::{get, post},
  Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use turul_mcp_client::transport::{BoxedTransport, HttpTransport};
use turul_mcp_client::{McpClient, McpClientBuilder};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct McpClientState {
  inner: Arc<Mutex<Inner>>,
}

struct Inner {
  base_url: String,
  mcp_url: String,
  client: Option<McpClient>,
  access_token: Option<String>,
  refresh_token: Option<String>,
  pkce_verifier: Option<String>,
  oauth_state: Option<String>,
  scopes: Option<String>,
  resource_metadata: Option<serde_json::Value>,
  auth_server_metadata: Option<serde_json::Value>,
  client_id: Option<String>,
  client_secret: Option<String>,
  http: reqwest::Client,
}

fn local_origin(base_url: &str) -> String {
  format!("{}/mcpclient", base_url.trim_end_matches('/'))
}

pub fn new_state(base_url: &str) -> McpClientState {
  McpClientState {
    inner: Arc::new(Mutex::new(Inner {
      base_url: base_url.to_string(),
      mcp_url: String::new(),
      client: None,
      access_token: None,
      refresh_token: None,
      pkce_verifier: None,
      oauth_state: None,
      scopes: None,
      resource_metadata: None,
      auth_server_metadata: None,
      client_id: None,
      client_secret: None,
      http: reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .expect("HTTP client"),
    })),
  }
}

// ---------------------------------------------------------------------------
// Transport & probe
// ---------------------------------------------------------------------------

fn build_transport(mcp_url: &str, access_token: Option<&str>) -> Result<BoxedTransport, String> {
  let transport: BoxedTransport = if let Some(token) = access_token {
    let mut headers = HeaderMap::new();
    headers.insert(
      ACCEPT,
      HeaderValue::from_static("application/json, text/event-stream"),
    );
    headers.insert(
      AUTHORIZATION,
      HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| format!("Invalid token header: {e}"))?,
    );
    let reqwest_client = reqwest::Client::builder()
      .default_headers(headers)
      .build()
      .map_err(|e| format!("HTTP client build: {e}"))?;
    let t = HttpTransport::with_client(mcp_url, reqwest_client).map_err(|e| format!("HttpTransport: {e}"))?;
    Box::new(t)
  } else {
    let t = HttpTransport::new(mcp_url).map_err(|e| format!("HttpTransport: {e}"))?;
    Box::new(t)
  };
  Ok(transport)
}

async fn probe_401(mcp_url: &str) -> Result<String, ()> {
  let body = serde_json::json!({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-11-25",
      "capabilities": {},
      "clientInfo": { "name": "mcp-web-client", "version": "0.1.0" }
    }
  });
  let client = reqwest::Client::builder().build().map_err(|_| ())?;
  let resp = client
    .post(mcp_url)
    .header("Accept", "application/json, text/event-stream")
    .json(&body)
    .send()
    .await
    .map_err(|_| ())?;
  if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
    let www_auth = resp
      .headers()
      .get("www-authenticate")
      .and_then(|v| v.to_str().ok())
      .unwrap_or("")
      .to_string();
    Ok(www_auth)
  } else {
    Err(())
  }
}

// ---------------------------------------------------------------------------
// PKCE & OAuth helpers
// ---------------------------------------------------------------------------

fn b64url(bytes: &[u8]) -> String {
  URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_pair() -> (String, String) {
  let mut buf = [0u8; 32];
  rand::thread_rng().fill_bytes(&mut buf);
  let verifier = b64url(&buf);
  let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
  (verifier, challenge)
}

fn random_state() -> String {
  let mut buf = [0u8; 16];
  rand::thread_rng().fill_bytes(&mut buf);
  b64url(&buf)
}

fn canonical_resource(url: &str) -> String {
  if let Ok(parsed) = url::Url::parse(url) {
    let mut r = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
    if let Some(port) = parsed.port() {
      r.push_str(&format!(":{port}"));
    }
    let path = parsed.path().trim_end_matches('/');
    if !path.is_empty() {
      r.push_str(path);
    }
    r
  } else {
    url.to_string()
  }
}

fn parse_www_authenticate(header: &str) -> Vec<(String, String)> {
  let mut results = Vec::new();
  let mut remaining = header;
  while !remaining.is_empty() {
    if let Some(pos) = remaining.find('=') {
      let before = &remaining[..pos];
      let key = before
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
      let after = &remaining[pos + 1..];
      if after.starts_with('"') {
        if let Some(end) = after[1..].find('"') {
          let value = &after[1..1 + end];
          results.push((key, value.to_string()));
          remaining = &after[2 + end..];
          continue;
        }
      } else {
        let value: String = after.chars().take_while(|c| !c.is_whitespace() && *c != ',').collect();
        if !key.is_empty() {
          results.push((key, value.clone()));
        }
        remaining = &after[value.len()..];
        continue;
      }
    }
    break;
  }
  results
}

fn get_www_auth_param(pairs: &[(String, String)], key: &str) -> Option<String> {
  pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

fn normalize_mcp_url(url: &str) -> String {
  let s = url.trim();
  if s.starts_with("http") {
    s.to_string()
  } else {
    format!("https://{s}")
  }
}

// ---------------------------------------------------------------------------
// API types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatusResponse {
  connected: bool,
  authenticated: bool,
  server_info: Option<serde_json::Value>,
  capabilities: Option<serde_json::Value>,
  mcp_url: String,
}

#[derive(Serialize)]
struct ConnectResponse {
  ok: bool,
  needs_auth: bool,
  auth_url: Option<String>,
  error: Option<String>,
  server_info: Option<serde_json::Value>,
  capabilities: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ConnectBody {
  url: Option<String>,
  force_reauth: Option<bool>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn page() -> Html<&'static str> {
  Html(include_str!("../static/mcpclient.html"))
}

async fn api_status(State(state): State<McpClientState>) -> Json<StatusResponse> {
  let inner = state.inner.lock().await;
  let (server_info, capabilities) = if let Some(ref client) = inner.client {
    let info = client.session_info().await;
    let caps = serde_json::to_value(info.server_capabilities.as_ref()).ok();
    let info_short = Some(serde_json::json!({
      "protocolVersion": info.protocol_version,
      "serverCapabilities": info.server_capabilities,
    }));
    (info_short, caps)
  } else {
    (None, None)
  };
  Json(StatusResponse {
    connected: inner.client.is_some(),
    authenticated: inner.access_token.is_some(),
    server_info,
    capabilities,
    mcp_url: inner.mcp_url.clone(),
  })
}

async fn api_connect(State(state): State<McpClientState>, Json(body): Json<ConnectBody>) -> Json<ConnectResponse> {
  let mut inner = state.inner.lock().await;
  let force_reauth = body.force_reauth.unwrap_or(false);

  if let Some(ref url) = body.url {
    inner.mcp_url = normalize_mcp_url(url);
  }
  if force_reauth {
    inner.client = None;
    inner.access_token = None;
    inner.refresh_token = None;
    inner.pkce_verifier = None;
    inner.oauth_state = None;
    inner.scopes = None;
    inner.resource_metadata = None;
    inner.auth_server_metadata = None;
    inner.client_id = None;
    inner.client_secret = None;
  }
  if inner.mcp_url.is_empty() {
    return Json(ConnectResponse {
      ok: false,
      needs_auth: false,
      auth_url: None,
      error: Some("Provide MCP server URL".to_string()),
      server_info: None,
      capabilities: None,
    });
  }

  if let Some(ref client) = inner.client {
    let info = client.session_info().await;
    let server_info = Some(serde_json::json!({
      "protocolVersion": info.protocol_version,
      "serverCapabilities": info.server_capabilities,
    }));
    let capabilities = serde_json::to_value(info.server_capabilities).ok();
    return Json(ConnectResponse {
      ok: true,
      needs_auth: false,
      auth_url: None,
      error: None,
      server_info,
      capabilities,
    });
  }

  let transport = match build_transport(&inner.mcp_url, inner.access_token.as_deref()) {
    Ok(t) => t,
    Err(e) => {
      return Json(ConnectResponse {
        ok: false,
        needs_auth: false,
        auth_url: None,
        error: Some(e),
        server_info: None,
        capabilities: None,
      })
    }
  };

  let client = McpClientBuilder::new().with_transport(transport).build();

  match client.connect().await {
    Ok(()) => {
      let info = client.session_info().await;
      let server_info = Some(serde_json::json!({
        "protocolVersion": info.protocol_version,
        "serverCapabilities": info.server_capabilities,
      }));
      let capabilities = serde_json::to_value(info.server_capabilities).ok();
      inner.client = Some(client);
      Json(ConnectResponse {
        ok: true,
        needs_auth: false,
        auth_url: None,
        error: None,
        server_info,
        capabilities,
      })
    }
    Err(e) => {
      let err_str = e.to_string();
      let err_lower = err_str.to_lowercase();
      let is_auth_required = err_str.contains("401")
        || err_lower.contains("unauthorized")
        || err_lower.contains("authentication required")
        || (err_lower.contains("oauth") && err_lower.contains("connect"));

      if is_auth_required {
        if inner.access_token.is_some() {
          info!("Token rejected (invalid/expired), attempting recovery");

          if let Some(ref rt) = inner.refresh_token.clone() {
            if let Some(ref asm) = inner.auth_server_metadata.clone() {
              if let Some(token_endpoint) = asm.get("token_endpoint").and_then(|v| v.as_str()) {
                let cid = inner.client_id.clone().unwrap_or_default();
                let csecret = inner.client_secret.clone();
                let resource = canonical_resource(&inner.mcp_url);
                let mut params = vec![
                  ("grant_type", "refresh_token".to_string()),
                  ("refresh_token", rt.clone()),
                  ("client_id", cid.clone()),
                  ("resource", resource),
                ];
                if let Some(ref s) = inner.scopes {
                  params.push(("scope", s.clone()));
                }
                if let Some(ref secret) = csecret {
                  params.push(("client_secret", secret.clone()));
                }
                info!("Trying token refresh -> {token_endpoint}");
                if let Ok(resp) = inner.http.post(token_endpoint).form(&params).send().await {
                  if resp.status().is_success() {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                      if let Some(new_token) = json.get("access_token").and_then(|v| v.as_str()) {
                        info!("Token refresh succeeded, retrying connect");
                        inner.access_token = Some(new_token.to_string());
                        inner.refresh_token =
                          json.get("refresh_token").and_then(|v| v.as_str()).map(|s| s.to_string()).or(inner.refresh_token.take());

                        let transport2 = match build_transport(&inner.mcp_url, Some(new_token)) {
                          Ok(t) => t,
                          Err(e) => {
                            return Json(ConnectResponse {
                              ok: false, needs_auth: false, auth_url: None,
                              error: Some(e), server_info: None, capabilities: None,
                            });
                          }
                        };
                        let client2 = McpClientBuilder::new().with_transport(transport2).build();
                        if let Ok(()) = client2.connect().await {
                          let info2 = client2.session_info().await;
                          let server_info = Some(serde_json::json!({
                            "protocolVersion": info2.protocol_version,
                            "serverCapabilities": info2.server_capabilities,
                          }));
                          let capabilities = serde_json::to_value(info2.server_capabilities).ok();
                          inner.client = Some(client2);
                          return Json(ConnectResponse {
                            ok: true, needs_auth: false, auth_url: None,
                            error: None, server_info, capabilities,
                          });
                        }
                        info!("Connect after token refresh still failed");
                      }
                    }
                  } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    info!("Token refresh failed: HTTP {status}: {body}");
                  }
                }
              }
            }
          }

          info!("Token recovery failed; clearing token and restarting OAuth flow");
          inner.client = None;
          inner.access_token = None;
          inner.refresh_token = None;
        }

        if inner.access_token.is_none() {
          if let Ok(www_auth) = probe_401(&inner.mcp_url).await {
            drop(inner);
            match start_oauth_flow_www_auth(&state, &www_auth).await {
              Ok(url) => {
                return Json(ConnectResponse {
                  ok: false, needs_auth: true, auth_url: Some(url),
                  error: None, server_info: None, capabilities: None,
                });
              }
              Err(e) => {
                return Json(ConnectResponse {
                  ok: false, needs_auth: true, auth_url: None,
                  error: Some(e), server_info: None, capabilities: None,
                });
              }
            }
          }
          let well_known = url::Url::parse(&inner.mcp_url)
            .ok()
            .map(|u| format!("{}://{}/.well-known/oauth-protected-resource", u.scheme(), u.authority()));
          if let Some(ref url) = well_known {
            if let Ok(resp) = inner.http.get(url).send().await {
              if resp.status().is_success() {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                  if json.get("authorization_servers").is_some() {
                    let synthetic_www_auth = format!("Bearer resource_metadata=\"{url}\"");
                    drop(inner);
                    match start_oauth_flow_www_auth(&state, &synthetic_www_auth).await {
                      Ok(auth_url) => {
                        return Json(ConnectResponse {
                          ok: false, needs_auth: true, auth_url: Some(auth_url),
                          error: None, server_info: None, capabilities: None,
                        });
                      }
                      Err(e) => {
                        return Json(ConnectResponse {
                          ok: false, needs_auth: true, auth_url: None,
                          error: Some(e), server_info: None, capabilities: None,
                        });
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      Json(ConnectResponse {
        ok: false,
        needs_auth: false,
        auth_url: None,
        error: Some(err_str),
        server_info: None,
        capabilities: None,
      })
    }
  }
}

async fn start_oauth_flow_www_auth(state: &McpClientState, www_auth: &str) -> Result<String, String> {
  let mut inner = state.inner.lock().await;
  start_oauth_flow(&mut *inner, www_auth).await
}

async fn start_oauth_flow(inner: &mut Inner, www_auth: &str) -> Result<String, String> {
  let pairs = parse_www_authenticate(www_auth);
  let parsed_url = url::Url::parse(&inner.mcp_url).map_err(|e| e.to_string())?;
  let rm_url = get_www_auth_param(&pairs, "resource_metadata");

  let mut candidates = Vec::new();
  if let Some(ref u) = rm_url {
    candidates.push(u.clone());
  }
  let path = parsed_url.path();
  if path != "/" && !path.is_empty() {
    candidates.push(format!(
      "{}://{}/.well-known/oauth-protected-resource{}",
      parsed_url.scheme(),
      parsed_url.authority(),
      path
    ));
  }
  candidates.push(format!(
    "{}://{}/.well-known/oauth-protected-resource",
    parsed_url.scheme(),
    parsed_url.authority()
  ));

  let mut rm: Option<serde_json::Value> = None;
  for url in &candidates {
    if let Ok(resp) = inner.http.get(url).send().await {
      if resp.status().is_success() {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
          info!("Protected Resource Metadata from {url}");
          rm = Some(json);
          break;
        }
      }
    }
  }

  let rm = rm.ok_or("Could not discover Protected Resource Metadata")?;
  inner.resource_metadata = Some(rm.clone());

  let auth_servers = rm
    .get("authorization_servers")
    .and_then(|v| v.as_array())
    .cloned()
    .unwrap_or_default();

  let issuer = auth_servers
    .first()
    .and_then(|v| v.as_str())
    .ok_or("No authorization_servers in resource metadata")?
    .to_string();

  info!("Authorization server: {issuer}");

  let issuer_url = url::Url::parse(&issuer).map_err(|e| e.to_string())?;
  let has_path = issuer_url.path() != "/" && !issuer_url.path().is_empty();

  let as_candidates = if has_path {
    vec![
      format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/')),
      format!(
        "{}://{}/.well-known/openid-configuration{}",
        issuer_url.scheme(),
        issuer_url.authority(),
        issuer_url.path()
      ),
      format!(
        "{}://{}/.well-known/oauth-authorization-server{}",
        issuer_url.scheme(),
        issuer_url.authority(),
        issuer_url.path()
      ),
    ]
  } else {
    vec![
      format!(
        "{}://{}/.well-known/openid-configuration",
        issuer_url.scheme(),
        issuer_url.authority()
      ),
      format!(
        "{}://{}/.well-known/oauth-authorization-server",
        issuer_url.scheme(),
        issuer_url.authority()
      ),
    ]
  };

  let mut asm: Option<serde_json::Value> = None;
  for url in &as_candidates {
    if let Ok(resp) = inner.http.get(url).send().await {
      if resp.status().is_success() {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
          info!("Authorization Server Metadata from {url}");
          asm = Some(json);
          break;
        }
      }
    }
  }

  let asm = asm.ok_or("Could not discover Authorization Server Metadata")?;
  inner.auth_server_metadata = Some(asm.clone());

  if inner.client_id.is_none() {
    if let Some(reg_endpoint) = asm.get("registration_endpoint").and_then(|v| v.as_str()) {
      let callback = format!("{}/oauth/callback", local_origin(&inner.base_url));
      let client_uri = local_origin(&inner.base_url);
      let reg_body = serde_json::json!({
        "client_name": "MCP Web Client",
        "client_uri": client_uri,
        "redirect_uris": [callback],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
      });
      info!("Dynamic client registration -> {reg_endpoint}");
      match inner.http.post(reg_endpoint).json(&reg_body).send().await {
        Ok(resp) => {
          let status = resp.status();
          if status.is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
              inner.client_id = json.get("client_id").and_then(|v| v.as_str()).map(|s| s.to_string());
              inner.client_secret = json.get("client_secret").and_then(|v| v.as_str()).map(|s| s.to_string());
              info!("DCR success: client_id={:?} has_secret={}", inner.client_id, inner.client_secret.is_some());
            }
          } else {
            let body = resp.text().await.unwrap_or_default();
            info!("DCR failed: HTTP {status}: {body}");
          }
        }
        Err(e) => info!("DCR request error: {e}"),
      }
    }
  }

  if inner.client_id.is_none() {
    inner.client_id = Some("default-client".to_string());
    inner.client_secret = Some("default-client-secret".to_string());
  }
  let client_id = inner.client_id.as_ref().unwrap();

  let auth_endpoint = asm
    .get("authorization_endpoint")
    .and_then(|v| v.as_str())
    .ok_or("No authorization_endpoint in server metadata")?;

  let (verifier, challenge) = pkce_pair();
  let state_val = random_state();
  inner.pkce_verifier = Some(verifier);
  inner.oauth_state = Some(state_val.clone());

  let scope_from_challenge = get_www_auth_param(&pairs, "scope");
  let scopes_supported = rm.get("scopes_supported").and_then(|v| v.as_array()).map(|arr| {
    arr.iter()
      .filter_map(|v| v.as_str())
      .collect::<Vec<_>>()
      .join(" ")
  });
  let scope = scope_from_challenge.or(scopes_supported);
  inner.scopes = scope.clone();

  let callback = format!("{}/oauth/callback", local_origin(&inner.base_url));
  let resource = canonical_resource(&inner.mcp_url);

  let mut params = vec![
    ("response_type", "code".to_string()),
    ("client_id", client_id.to_string()),
    ("redirect_uri", callback),
    ("state", state_val),
    ("code_challenge", challenge),
    ("code_challenge_method", "S256".to_string()),
    ("resource", resource),
  ];
  if let Some(ref s) = scope {
    params.push(("scope", s.clone()));
  }

  let query = url::form_urlencoded::Serializer::new(String::new())
    .extend_pairs(&params)
    .finish();

  Ok(format!("{auth_endpoint}?{query}"))
}

#[derive(Deserialize)]
struct OAuthCallbackParams {
  code: Option<String>,
  state: Option<String>,
  error: Option<String>,
}

async fn oauth_callback(State(state): State<McpClientState>, Query(params): Query<OAuthCallbackParams>) -> impl IntoResponse {
  if let Some(ref err) = params.error {
    return Html(format!("<html><body><h2>Authorization Error</h2><p>{err}</p></body></html>"));
  }

  let code = match params.code {
    Some(c) => c,
    None => {
      return Html(
        "<html><body><h2>Error</h2><p>No authorization code received.</p></body></html>".to_string(),
      )
    }
  };

  let mut inner = state.inner.lock().await;

  if let Some(ref expected) = inner.oauth_state {
    if params.state.as_deref() != Some(expected.as_str()) {
      return Html("<html><body><h2>Error</h2><p>State mismatch.</p></body></html>".to_string());
    }
  }

  let asm = match inner.auth_server_metadata.as_ref() {
    Some(v) => v.clone(),
    None => {
      return Html(
        "<html><body><h2>Error</h2><p>No auth server metadata.</p></body></html>".to_string(),
      )
    }
  };

  let token_endpoint = match asm.get("token_endpoint").and_then(|v| v.as_str()) {
    Some(u) => u.to_string(),
    None => {
      return Html(
        "<html><body><h2>Error</h2><p>No token_endpoint.</p></body></html>".to_string(),
      )
    }
  };

  let callback = format!("{}/oauth/callback", local_origin(&inner.base_url));
  let resource = canonical_resource(&inner.mcp_url);

  let cid = inner.client_id.clone().unwrap_or_default();
  let csecret = inner.client_secret.clone();

  let mut token_params = vec![
    ("grant_type", "authorization_code".to_string()),
    ("code", code),
    ("redirect_uri", callback.clone()),
    ("client_id", cid.clone()),
    ("resource", resource),
  ];
  if let Some(ref verifier) = inner.pkce_verifier {
    token_params.push(("code_verifier", verifier.clone()));
  }
  if let Some(ref secret) = csecret {
    token_params.push(("client_secret", secret.clone()));
  }

  info!("Token exchange -> {token_endpoint} client_id={cid} has_secret={} redirect_uri={callback}", csecret.is_some());

  let resp: Result<reqwest::Response, _> = inner.http.post(&token_endpoint).form(&token_params).send().await;

  match resp {
    Ok(r) if r.status().is_success() => {
      if let Ok(json) = r.json::<serde_json::Value>().await {
        let has_access = json.get("access_token").and_then(|v| v.as_str()).is_some();
        let has_refresh = json.get("refresh_token").and_then(|v| v.as_str()).is_some();
        let token_type = json.get("token_type").and_then(|v| v.as_str()).unwrap_or("?");
        let scope = json.get("scope").and_then(|v| v.as_str()).unwrap_or("?");
        let expires = json.get("expires_in").and_then(|v| v.as_u64());
        info!("Token response: has_access={has_access} has_refresh={has_refresh} type={token_type} scope={scope} expires_in={expires:?}");
        inner.access_token = json.get("access_token").and_then(|v| v.as_str()).map(|s| s.to_string());
        inner.refresh_token = json.get("refresh_token").and_then(|v| v.as_str()).map(|s| s.to_string());
        if inner.access_token.is_none() {
          info!("WARNING: token exchange returned success but no access_token in response");
        } else {
          info!("Access token obtained (len={})", inner.access_token.as_ref().unwrap().len());
        }
        Html(
          r#"<html><body>
<h2>Authorized!</h2>
<p>Connecting to MCP server…</p>
<script>
if (window.opener) {
  window.opener.postMessage({type:'mcp-oauth-complete'}, '*');
}
setTimeout(function(){ window.close(); }, 800);
</script>
</body></html>"#
            .to_string(),
        )
      } else {
        Html("<html><body><h2>Error</h2><p>Failed to parse token response.</p></body></html>".to_string())
      }
    }
    Ok(r) => {
      let status = r.status();
      let text = r.text().await.unwrap_or_default();
      info!("Token exchange failed: HTTP {status}: {text}");
      Html(format!(
        "<html><body><h2>Token Error</h2><p>HTTP {status}</p><pre>{text}</pre></body></html>"
      ))
    }
    Err(e) => Html(format!("<html><body><h2>Token Error</h2><p>{e}</p></body></html>")),
  }
}

async fn api_tools(State(state): State<McpClientState>) -> Json<serde_json::Value> {
  let inner = state.inner.lock().await;
  let Some(ref client) = inner.client else {
    return Json(serde_json::json!({ "ok": false, "error": "Not connected" }));
  };
  match client.list_tools().await {
    Ok(tools) => {
      let tools_json = serde_json::to_value(&tools).unwrap_or(serde_json::json!([]));
      Json(serde_json::json!({ "ok": true, "tools": tools_json }))
    }
    Err(e) => Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
  }
}

#[derive(Deserialize)]
struct CallRequest {
  name: String,
  arguments: serde_json::Value,
}

async fn api_call(State(state): State<McpClientState>, Json(req): Json<CallRequest>) -> Json<serde_json::Value> {
  let inner = state.inner.lock().await;
  let Some(ref client) = inner.client else {
    return Json(serde_json::json!({ "ok": false, "error": "Not connected" }));
  };
  match client.call_tool(&req.name, req.arguments).await {
    Ok(content) => {
      let result =
        serde_json::json!({ "content": serde_json::to_value(&content).unwrap_or_default() });
      Json(serde_json::json!({ "ok": true, "result": result }))
    }
    Err(e) => Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
  }
}

async fn api_resources(State(state): State<McpClientState>) -> Json<serde_json::Value> {
  let inner = state.inner.lock().await;
  let Some(ref client) = inner.client else {
    return Json(serde_json::json!({ "ok": false, "error": "Not connected" }));
  };
  match client.list_resources().await {
    Ok(resources) => {
      let json = serde_json::to_value(&resources).unwrap_or(serde_json::json!([]));
      Json(serde_json::json!({ "ok": true, "resources": json }))
    }
    Err(e) => Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
  }
}

async fn api_prompts(State(state): State<McpClientState>) -> Json<serde_json::Value> {
  let inner = state.inner.lock().await;
  let Some(ref client) = inner.client else {
    return Json(serde_json::json!({ "ok": false, "error": "Not connected" }));
  };
  match client.list_prompts().await {
    Ok(prompts) => {
      let json = serde_json::to_value(&prompts).unwrap_or(serde_json::json!([]));
      Json(serde_json::json!({ "ok": true, "prompts": json }))
    }
    Err(e) => Json(serde_json::json!({ "ok": false, "error": e.to_string() })),
  }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router(state: McpClientState) -> Router {
  Router::new()
    .route("/mcpclient", get(page))
    .route("/mcpclient/oauth/callback", get(oauth_callback))
    .route("/mcpclient/api/status", get(api_status))
    .route("/mcpclient/api/connect", post(api_connect))
    .route("/mcpclient/api/tools", get(api_tools))
    .route("/mcpclient/api/call", post(api_call))
    .route("/mcpclient/api/resources", get(api_resources))
    .route("/mcpclient/api/prompts", get(api_prompts))
    .with_state(state)
}
