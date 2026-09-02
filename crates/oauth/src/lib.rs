//! OAuth 2.0 login: manual Authorization Code flow with Google, GitHub and topsecret.

use askama::Template;
use axum::{
  extract::{Form, Path, Query, State},
  http::StatusCode,
  response::{Html, IntoResponse, Redirect},
  routing::{get, post},
  Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// -- Provider definition.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Provider {
  Google,
  GitHub,
  TopSecret,
}

impl Provider {
  fn from_slug(s: &str) -> Option<Self> {
    match s {
      "google" => Some(Self::Google),
      "github" => Some(Self::GitHub),
      "topsecret" => Some(Self::TopSecret),
      _ => None,
    }
  }

  fn slug(&self) -> &'static str {
    match self {
      Self::Google => "google",
      Self::GitHub => "github",
      Self::TopSecret => "topsecret",
    }
  }

  fn display_name(&self) -> &'static str {
    match self {
      Self::Google => "google",
      Self::GitHub => "github",
      Self::TopSecret => "topsecret",
    }
  }

  fn auth_url(&self) -> &'static str {
    match self {
      Self::Google => "https://accounts.google.com/o/oauth2/v2/auth",
      Self::GitHub => "https://github.com/login/oauth/authorize",
      Self::TopSecret => "", // use state.topsecret_issuer_base
    }
  }

  fn token_url(&self) -> &'static str {
    match self {
      Self::Google => "https://oauth2.googleapis.com/token",
      Self::GitHub => "https://github.com/login/oauth/access_token",
      Self::TopSecret => "",
    }
  }

  fn userinfo_url(&self) -> &'static str {
    match self {
      Self::Google => "https://www.googleapis.com/oauth2/v3/userinfo",
      Self::GitHub => "https://api.github.com/user",
      Self::TopSecret => "",
    }
  }

  fn scopes(&self) -> &'static str {
    match self {
      Self::Google => "openid email profile",
      Self::GitHub => "read:user user:email",
      Self::TopSecret => "openid profile email read write",
    }
  }
}

// -- State.

#[derive(Clone)]
struct ProviderConfig {
  client_id: String,
  client_secret: String,
}

struct PendingAuth {
  provider: Provider,
  /// PKCE code_verifier for TopSecret (server may require pkce_required: true).
  code_verifier: Option<String>,
  /// For TopSecret dynamic client: credentials from POST /register (used at callback for token exchange).
  topsecret_config: Option<ProviderConfig>,
}

struct SessionInfo {
  provider: Provider,
  access_token: String,
}

pub struct OAuthState {
  providers: HashMap<Provider, ProviderConfig>,
  /// Issuer base URL for TopSecret (from TOPSECRET_OAUTH2_URL). TopSecret is only available when set.
  topsecret_issuer_base: Option<String>,
  pending: Arc<RwLock<HashMap<String, PendingAuth>>>,
  sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
  http_client: reqwest::Client,
  base_url: String,
}

pub fn build_state(base_url: &str) -> Arc<OAuthState> {
  let mut providers = HashMap::new();

  if let (Ok(id), Ok(secret)) = (std::env::var("GOOGLE_CLIENT_ID"), std::env::var("GOOGLE_CLIENT_SECRET")) {
    tracing::info!("OAuth: Google configured");
    providers.insert(Provider::Google, ProviderConfig { client_id: id, client_secret: secret });
  }

  if let (Ok(id), Ok(secret)) = (std::env::var("GITHUB_CLIENT_ID"), std::env::var("GITHUB_CLIENT_SECRET")) {
    tracing::info!("OAuth: GitHub configured");
    providers.insert(Provider::GitHub, ProviderConfig { client_id: id, client_secret: secret });
  }

  let topsecret_issuer_base = std::env::var("TOPSECRET_OAUTH2_URL").ok().map(|u| u.trim_end_matches('/').to_string());
  if topsecret_issuer_base.is_some() {
    tracing::info!("OAuth: TopSecret configured via TOPSECRET_OAUTH2_URL");
  }

  if providers.len() == 1 && topsecret_issuer_base.is_none() {
    tracing::info!("OAuth: only one provider (set GOOGLE_CLIENT_ID/SECRET or GITHUB_CLIENT_ID/SECRET or TOPSECRET_OAUTH2_URL for more)");
  }

  Arc::new(OAuthState {
    providers,
    topsecret_issuer_base,
    pending: Arc::new(RwLock::new(HashMap::new())),
    sessions: Arc::new(RwLock::new(HashMap::new())),
    http_client: reqwest::Client::new(),
    base_url: base_url.to_string(),
  })
}

/// RFC 7591 dynamic client registration. `redirect_uri` must be the exact callback URL used in the authorization request.
async fn register_dynamic_client(
  issuer_base: &str,
  redirect_uri: &str,
  scope: &str,
  http_client: &reqwest::Client,
) -> Option<(String, String)> {
  let register_url = format!("{}/register", issuer_base.trim_end_matches('/'));
  let body = serde_json::json!({
    "redirect_uris": [redirect_uri],
    "scope": scope
  });
  let resp = http_client
    .post(&register_url)
    .header("Content-Type", "application/json")
    .json(&body)
    .send()
    .await
    .ok()?;
  if !resp.status().is_success() {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    tracing::warn!("OAuth DCR failed: {} {}", status, text);
    return None;
  }
  let json: serde_json::Value = resp.json().await.ok()?;
  let client_id = json.get("client_id").and_then(|v| v.as_str()).map(String::from)?;
  let client_secret = json.get("client_secret").and_then(|v| v.as_str()).map(String::from).unwrap_or_default();
  tracing::info!("OAuth DCR success: client_id={}", client_id);
  Some((client_id, client_secret))
}

// -- Templates.

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
  providers: Vec<ProviderInfo>,
  git_hash: &'static str,
}

struct ProviderInfo {
  slug: &'static str,
  name: &'static str,
}

#[derive(Template)]
#[template(path = "login_result.html")]
struct LoginResultTemplate {
  success: bool,
  provider_name: String,
  user_name: String,
  user_email: String,
  avatar_url: String,
  raw_json: String,
  error_message: String,
  session_id: String,
  /// RFC: UserInfo (OIDC/OAuth 2.0) curl.
  curl_userinfo: String,
  /// RFC 7662: Token Introspection curl (POST application/x-www-form-urlencoded).
  curl_introspect: String,
  git_hash: &'static str,
}

#[derive(Template)]
#[template(path = "logout_result.html")]
struct LogoutResultTemplate {
  provider_name: String,
  revoke_ok: bool,
  revoke_detail: String,
  git_hash: &'static str,
}

// -- Route handlers.

async fn login_debug() -> impl IntoResponse {
  let vars = [
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GITHUB_CLIENT_ID",
    "GITHUB_CLIENT_SECRET",
    "TOPSECRET_OAUTH2_URL",
  ];
  let lines: Vec<String> = vars
    .iter()
    .map(|name| {
      let len = std::env::var(name).map(|v| v.len()).unwrap_or(0);
      format!("{name}: {len} chars")
    })
    .collect();
  lines.join("\n")
}

async fn login_page(State(state): State<Arc<OAuthState>>) -> impl IntoResponse {
  let order = [Provider::Google, Provider::GitHub, Provider::TopSecret];
  let providers: Vec<ProviderInfo> = order
    .iter()
    .filter(|p| {
      state.providers.contains_key(p)
        || (**p == Provider::TopSecret && state.topsecret_issuer_base.is_some())
    })
    .map(|p| ProviderInfo { slug: p.slug(), name: p.display_name() })
    .collect();
  let t = LoginTemplate { providers, git_hash: env!("GIT_HASH") };
  match t.render() {
    Ok(html) => Html(html).into_response(),
    Err(e) => {
      tracing::error!(%e, "login template render failed");
      (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
    }
  }
}

async fn start_oauth(Path(slug): Path<String>, State(state): State<Arc<OAuthState>>) -> impl IntoResponse {
  let provider = match Provider::from_slug(&slug) {
    Some(p) => p,
    None => return (StatusCode::NOT_FOUND, "unknown provider").into_response(),
  };

  // TopSecret: always use a new client via POST /register (dynamic client, no caching).
  let redirect_uri = format!("{}/login/{}/callback", state.base_url.trim_end_matches('/'), provider.slug());
  let (config, topsecret_config) = if provider == Provider::TopSecret {
    let issuer_base = match &state.topsecret_issuer_base {
      Some(b) => b.as_str(),
      None => return (StatusCode::NOT_FOUND, "provider not configured").into_response(),
    };
    let config_opt = register_dynamic_client(
      issuer_base,
      &redirect_uri,
      provider.scopes(),
      &state.http_client,
    )
    .await;
    let config = match config_opt {
      Some((id, secret)) => ProviderConfig { client_id: id, client_secret: secret },
      None => {
        tracing::warn!("OAuth: TopSecret /register failed");
        return (
          StatusCode::SERVICE_UNAVAILABLE,
          "OAuth: client registration failed. Try again.",
        )
          .into_response();
      }
    };
    (config.clone(), Some(config))
  } else {
    let config = match state.providers.get(&provider) {
      Some(c) => c.clone(),
      None => return (StatusCode::NOT_FOUND, "provider not configured").into_response(),
    };
    (config, None)
  };

  let csrf_state = uuid::Uuid::new_v4().to_string();
  let (code_verifier, code_challenge) = if provider == Provider::TopSecret {
    let (v, c) = pkce_pair();
    (Some(v), Some(c))
  } else {
    (None, None)
  };
  state.pending.write().await.insert(
    csrf_state.clone(),
    PendingAuth {
      provider,
      code_verifier,
      topsecret_config,
    },
  );

  let auth_url = match provider {
    Provider::TopSecret => format!(
      "{}/authorize",
      state.topsecret_issuer_base.as_deref().unwrap_or("")
    ),
    _ => provider.auth_url().to_string(),
  };
  let mut url = format!(
    "{}?client_id={}&redirect_uri={}&scope={}&state={}&response_type=code",
    auth_url,
    urlencod(&config.client_id),
    urlencod(&redirect_uri),
    urlencod(provider.scopes()),
    urlencod(&csrf_state),
  );
  if let Some(ref ch) = code_challenge {
    url.push_str("&code_challenge=");
    url.push_str(&urlencod(ch));
    url.push_str("&code_challenge_method=S256");
  }

  if provider == Provider::TopSecret {
    url.push_str("&resource=");
    url.push_str(&urlencod("https://mcp.dima.ai"));
  }

  if provider == Provider::Google {
    url.push_str("&prompt=consent");
  }

  Redirect::temporary(&url).into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
  code: Option<String>,
  state: Option<String>,
  error: Option<String>,
}

async fn oauth_callback(
  Path(slug): Path<String>, Query(query): Query<CallbackQuery>, State(state): State<Arc<OAuthState>>,
) -> impl IntoResponse {
  let provider = match Provider::from_slug(&slug) {
    Some(p) => p,
    None => return render_error("Unknown provider", ""),
  };

  // Provider denied or user cancelled.
  if let Some(ref err) = query.error {
    return render_error(&format!("Provider error: {}", err), provider.display_name());
  }

  let code = match query.code {
    Some(ref c) => c.clone(),
    None => return render_error("Missing authorization code", provider.display_name()),
  };

  let csrf_state = match query.state {
    Some(ref s) => s.clone(),
    None => return render_error("Missing state parameter", provider.display_name()),
  };

  // Validate CSRF and retrieve PKCE verifier and (for TopSecret) dynamic client config.
  let pending = state.pending.write().await.remove(&csrf_state);
  let (code_verifier, topsecret_config) = match pending {
    Some(p) if p.provider == provider => (p.code_verifier, p.topsecret_config),
    _ => return render_error("Invalid or expired state (CSRF check failed)", provider.display_name()),
  };

  let config = if provider == Provider::TopSecret {
    topsecret_config.ok_or("missing dynamic client config")
  } else {
    state.providers.get(&provider).cloned().ok_or("provider not configured")
  };
  let config = match config {
    Ok(c) => c,
    Err(_) => return render_error("Provider not configured", provider.display_name()),
  };

  let redirect_uri = format!("{}/login/{}/callback", state.base_url, provider.slug());
  let (token_url, userinfo_url, introspect_url) = match provider {
    Provider::TopSecret => {
      let base = state.topsecret_issuer_base.as_deref().unwrap_or("");
      (
        format!("{}/token", base),
        format!("{}/userinfo", base),
        Some(format!("{}/introspect", base)),
      )
    }
    _ => (
      provider.token_url().to_string(),
      provider.userinfo_url().to_string(),
      None,
    ),
  };

  // Exchange code for token (include code_verifier when PKCE was used, e.g. TopSecret with pkce_required).
  let token_res = if let Some(ref verifier) = code_verifier {
    state
      .http_client
      .post(&token_url)
      .header("Accept", "application/json")
      .form(&[
        ("code", code.as_str()),
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
        ("code_verifier", verifier.as_str()),
      ])
      .send()
      .await
  } else {
    state
      .http_client
      .post(&token_url)
      .header("Accept", "application/json")
      .form(&[
        ("code", code.as_str()),
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
      ])
      .send()
      .await
  };

  let token_body: serde_json::Value = match token_res {
    Ok(resp) => match resp.json().await {
      Ok(v) => v,
      Err(e) => return render_error(&format!("Token response parse error: {}", e), provider.display_name()),
    },
    Err(e) => return render_error(&format!("Token request failed: {}", e), provider.display_name()),
  };

  let access_token = match token_body.get("access_token").and_then(|v| v.as_str()) {
    Some(t) => t.to_string(),
    None => {
      let desc = token_body
        .get("error_description")
        .or_else(|| token_body.get("error"))
        .and_then(|v| v.as_str())
        .unwrap_or("no access_token in response");
      return render_error(&format!("Token error: {}", desc), provider.display_name());
    }
  };

  // Fetch user info.
  let userinfo_res = state
    .http_client
    .get(&userinfo_url)
    .header("Authorization", format!("Bearer {}", access_token))
    .header("User-Agent", "homepage-oauth/1.0")
    .send()
    .await;

  let userinfo: serde_json::Value = match userinfo_res {
    Ok(resp) => match resp.json().await {
      Ok(v) => v,
      Err(e) => return render_error(&format!("Userinfo parse error: {}", e), provider.display_name()),
    },
    Err(e) => return render_error(&format!("Userinfo request failed: {}", e), provider.display_name()),
  };

  // Extract fields (Google and GitHub have different shapes).
  let (name, email, avatar) = match provider {
    Provider::Google => (
      userinfo.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
      userinfo.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string(),
      userinfo.get("picture").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    ),
    Provider::GitHub => (
      userinfo
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| userinfo.get("login").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string(),
      userinfo.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string(),
      userinfo.get("avatar_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    ),
    Provider::TopSecret => (
      userinfo.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
      userinfo.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string(),
      userinfo.get("picture").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    ),
  };

  let raw_json = serde_json::to_string_pretty(&userinfo).unwrap_or_default();

  tracing::info!("OAuth login: {} via {} ({})", name, provider.display_name(), email);

  // Store session so logout can revoke the grant.
  let session_id = uuid::Uuid::new_v4().to_string();
  state.sessions.write().await.insert(
    session_id.clone(),
    SessionInfo { provider, access_token: access_token.clone() },
  );

  // RFC: Bearer token request to UserInfo endpoint (OIDC / OAuth 2.0 resource).
  let escaped_token = access_token.replace('\\', "\\\\").replace('"', "\\\"");
  let curl_userinfo = format!(
    "curl -H \"Authorization: Bearer {}\" \"{}\"",
    escaped_token,
    userinfo_url
  );

  // RFC 7662: Token Introspection (POST application/x-www-form-urlencoded).
  let curl_introspect = introspect_url.map(|url| {
    format!(
      "curl -X POST \"{}\" -H \"Content-Type: application/x-www-form-urlencoded\" -d \"token={}\" -d \"token_type_hint=access_token\"",
      url,
      escaped_token
    )
  }).unwrap_or_default();

  let t = LoginResultTemplate {
    success: true,
    provider_name: provider.display_name().to_string(),
    user_name: name,
    user_email: email,
    avatar_url: avatar,
    raw_json,
    error_message: String::new(),
    session_id,
    curl_userinfo,
    curl_introspect,
    git_hash: env!("GIT_HASH"),
  };
  match t.render() {
    Ok(html) => Html(html).into_response(),
    Err(e) => {
      tracing::error!(%e, "login_result template render failed");
      (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
    }
  }
}

fn render_error(message: &str, provider_name: &str) -> axum::response::Response {
  let t = LoginResultTemplate {
    success: false,
    provider_name: provider_name.to_string(),
    user_name: String::new(),
    user_email: String::new(),
    avatar_url: String::new(),
    raw_json: String::new(),
    error_message: message.to_string(),
    session_id: String::new(),
    curl_userinfo: String::new(),
    curl_introspect: String::new(),
    git_hash: env!("GIT_HASH"),
  };
  match t.render() {
    Ok(html) => Html(html).into_response(),
    Err(e) => {
      tracing::error!(%e, "login_result template render failed");
      (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
    }
  }
}

// -- Logout: revoke provider grant so next login requires full re-auth.

#[derive(Deserialize)]
struct LogoutForm {
  session_id: String,
}

async fn logout(State(state): State<Arc<OAuthState>>, Form(form): Form<LogoutForm>) -> impl IntoResponse {
  let session = state.sessions.write().await.remove(&form.session_id);

  let (provider_name, revoke_ok, revoke_detail) = if let Some(session) = session {
    let provider_name = session.provider.display_name().to_string();
    let config = state.providers.get(&session.provider).cloned();

    if let Some(config) = config {
      match session.provider {
        Provider::GitHub => {
          // Revoke the entire OAuth app grant (also deletes all tokens for this user).
          // Must be done in a single call -- revoking the token first would invalidate
          // the access_token reference needed to identify the user for grant revocation.
          match state
            .http_client
            .delete(format!("https://api.github.com/applications/{}/grant", config.client_id))
            .basic_auth(&config.client_id, Some(&config.client_secret))
            .header("Accept", "application/json")
            .header("User-Agent", "homepage-oauth/1.0")
            .json(&serde_json::json!({ "access_token": session.access_token }))
            .send()
            .await
          {
            Ok(resp) => {
              let status = resp.status();
              let body = resp.text().await.unwrap_or_default();
              tracing::info!(%status, %body, "GitHub grant revocation response");
              let ok = status.as_u16() == 204 || status.is_success();
              (provider_name, ok, format!("Grant revoke: {} {}", status, body).trim().to_string())
            }
            Err(e) => {
              tracing::warn!(error = %e, "failed to revoke GitHub grant");
              (provider_name, false, format!("Grant revoke failed: {}", e))
            }
          }
        }
        Provider::Google => {
          match state
            .http_client
            .post(format!(
              "https://oauth2.googleapis.com/revoke?token={}",
              urlencod(&session.access_token)
            ))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await
          {
            Ok(resp) => {
              let status = resp.status();
              tracing::info!(%status, "revoked Google OAuth token");
              (provider_name, status.is_success(), format!("Token revoke: {}", status))
            }
            Err(e) => {
              tracing::warn!(error = %e, "failed to revoke Google OAuth token");
              (provider_name, false, format!("Token revoke: error ({})", e))
            }
          }
        }
        Provider::TopSecret => {
          tracing::info!("cleared topsecret session (no revoke API)");
          (provider_name, true, "Session cleared.".to_string())
        }
      }
    } else {
      // TopSecret uses dynamic client (no entry in providers); just clear session.
      if session.provider == Provider::TopSecret {
        (provider_name, true, "Session cleared.".to_string())
      } else {
        (provider_name, false, "Provider not configured.".to_string())
      }
    }
  } else {
    ("unknown".to_string(), false, "Session not found (expired or already logged out).".to_string())
  };

  let t = LogoutResultTemplate { provider_name, revoke_ok, revoke_detail, git_hash: env!("GIT_HASH") };
  match t.render() {
    Ok(html) => Html(html).into_response(),
    Err(e) => {
      tracing::error!(%e, "logout_result template render failed");
      Redirect::to("/login").into_response()
    }
  }
}

// -- Router.

pub fn router(state: Arc<OAuthState>) -> Router {
  Router::new()
    .route("/login", get(login_page))
    .route("/login/debug", get(login_debug))
    .route("/login/:provider", get(start_oauth))
    .route("/login/:provider/callback", get(oauth_callback))
    .route("/logout", post(logout))
    .with_state(state)
}

// -- Helpers.

fn urlencod(s: &str) -> String {
  let mut result = String::with_capacity(s.len());
  for b in s.bytes() {
    match b {
      b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
        result.push(b as char);
      }
      _ => {
        result.push('%');
        result.push(char::from(HEX[(b >> 4) as usize]));
        result.push(char::from(HEX[(b & 0x0f) as usize]));
      }
    }
  }
  result
}

const HEX: [u8; 16] = *b"0123456789ABCDEF";

/// PKCE S256: returns (code_verifier, code_challenge). Verifier is 43–128 chars from [A-Za-z0-9-._~].
fn pkce_pair() -> (String, String) {
  use base64::Engine;
  use sha2::Digest;
  let verifier: String = (0..64)
    .map(|_| {
      const SET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
      SET[rand::random::<usize>() % SET.len()] as char
    })
    .collect();
  let digest = sha2::Sha256::digest(verifier.as_bytes());
  let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
  (verifier, challenge)
}
