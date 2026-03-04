//! OAuth 2.0 login: manual Authorization Code flow with Google, GitHub and topsecret.

use askama::Template;
use axum::{
  extract::{Path, Query, State},
  http::StatusCode,
  response::{Html, IntoResponse, Redirect},
  routing::get,
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
      "xmemory" => Some(Self::TopSecret),
      _ => None,
    }
  }

  fn slug(&self) -> &'static str {
    match self {
      Self::Google => "google",
      Self::GitHub => "github",
      Self::TopSecret => "xmemory",
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
      Self::TopSecret => "https://dk-oauth2.xmemory.ai/authorize",
    }
  }

  fn token_url(&self) -> &'static str {
    match self {
      Self::Google => "https://oauth2.googleapis.com/token",
      Self::GitHub => "https://github.com/login/oauth/access_token",
      Self::TopSecret => "https://dk-oauth2.xmemory.ai/token",
    }
  }

  fn userinfo_url(&self) -> &'static str {
    match self {
      Self::Google => "https://www.googleapis.com/oauth2/v3/userinfo",
      Self::GitHub => "https://api.github.com/user",
      Self::TopSecret => "https://dk-oauth2.xmemory.ai/userinfo",
    }
  }

  fn scopes(&self) -> &'static str {
    match self {
      Self::Google => "openid email profile",
      Self::GitHub => "read:user user:email",
      Self::TopSecret => "openid read write",
    }
  }
}

// -- State.

struct ProviderConfig {
  client_id: String,
  client_secret: String,
}

struct PendingAuth {
  provider: Provider,
}

pub struct OAuthState {
  providers: HashMap<Provider, ProviderConfig>,
  pending: Arc<RwLock<HashMap<String, PendingAuth>>>,
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

  {
    tracing::info!("OAuth: topsecret configured");
    providers.insert(Provider::TopSecret, ProviderConfig {
      client_id: "default-client".to_string(),
      client_secret: "default-client-secret".to_string(),
    });
  }

  if providers.len() == 1 {
    tracing::info!("OAuth: only topsecret configured (set GOOGLE_CLIENT_ID/SECRET or GITHUB_CLIENT_ID/SECRET for more)");
  }

  Arc::new(OAuthState {
    providers,
    pending: Arc::new(RwLock::new(HashMap::new())),
    http_client: reqwest::Client::new(),
    base_url: base_url.to_string(),
  })
}

// -- Templates.

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
  providers: Vec<ProviderInfo>,
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
}

// -- Route handlers.

async fn login_debug() -> impl IntoResponse {
  let vars = [
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "GITHUB_CLIENT_ID",
    "GITHUB_CLIENT_SECRET",
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
    .filter(|p| state.providers.contains_key(p))
    .map(|p| ProviderInfo { slug: p.slug(), name: p.display_name() })
    .collect();
  let t = LoginTemplate { providers };
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
  let config = match state.providers.get(&provider) {
    Some(c) => c,
    None => return (StatusCode::NOT_FOUND, "provider not configured").into_response(),
  };

  let csrf_state = uuid::Uuid::new_v4().to_string();
  state.pending.write().await.insert(csrf_state.clone(), PendingAuth { provider });

  let redirect_uri = format!("{}/login/{}/callback", state.base_url, provider.slug());
  let url = format!(
    "{}?client_id={}&redirect_uri={}&scope={}&state={}&response_type=code",
    provider.auth_url(),
    urlencod(&config.client_id),
    urlencod(&redirect_uri),
    urlencod(provider.scopes()),
    urlencod(&csrf_state),
  );

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

  // Validate CSRF.
  let pending = state.pending.write().await.remove(&csrf_state);
  match pending {
    Some(p) if p.provider == provider => {}
    _ => return render_error("Invalid or expired state (CSRF check failed)", provider.display_name()),
  }

  let config = match state.providers.get(&provider) {
    Some(c) => c,
    None => return render_error("Provider not configured", provider.display_name()),
  };

  let redirect_uri = format!("{}/login/{}/callback", state.base_url, provider.slug());

  // Exchange code for token.
  let token_res = state
    .http_client
    .post(provider.token_url())
    .header("Accept", "application/json")
    .form(&[
      ("code", code.as_str()),
      ("client_id", config.client_id.as_str()),
      ("client_secret", config.client_secret.as_str()),
      ("redirect_uri", redirect_uri.as_str()),
      ("grant_type", "authorization_code"),
    ])
    .send()
    .await;

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
    .get(provider.userinfo_url())
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

  let t = LoginResultTemplate {
    success: true,
    provider_name: provider.display_name().to_string(),
    user_name: name,
    user_email: email,
    avatar_url: avatar,
    raw_json,
    error_message: String::new(),
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
  };
  match t.render() {
    Ok(html) => Html(html).into_response(),
    Err(e) => {
      tracing::error!(%e, "login_result template render failed");
      (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
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
