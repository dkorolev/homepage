use axum::{
  extract::{Form, Query, Request, State},
  handler::HandlerWithoutStateExt,
  http::{header, uri::Authority, HeaderMap, HeaderValue, Method, StatusCode, Uri},
  middleware,
  response::{Html, IntoResponse, Redirect, Response},
  routing::get,
  Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use percent_encoding::percent_decode_str;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// -- CLI arguments.

#[derive(Parser, Debug)]
#[command(version = "1.0", about = "Homepage HTTP/HTTPS server")]
struct Args {
  /// HTTP port (redirects to HTTPS).
  #[arg(long, default_value = "80")]
  port_http: u16,

  /// HTTPS port.
  #[arg(long, default_value = "443")]
  port_https: u16,

  /// Let's Encrypt directory: FQDN = last path component, must contain fullchain.pem and privkey.pem.
  /// Sibling directories holding the same two files are served too, by SNI, under their own names.
  #[arg(long, required_unless_present = "fqdn")]
  letsencrypt: Option<PathBuf>,

  /// FQDN for redirect (e.g. dima.ai).
  #[arg(long, required_unless_present = "letsencrypt")]
  fqdn: Option<String>,

  /// Path to TLS certificate (PEM).
  #[arg(long, required_unless_present = "letsencrypt")]
  cert: Option<PathBuf>,

  /// Path to TLS private key (PEM).
  #[arg(long, required_unless_present = "letsencrypt")]
  key: Option<PathBuf>,

  /// Path to the JSONL file for registered passkeys.
  #[arg(long)]
  keys_jsonl: PathBuf,
}

// -- TLS certificate resolution, following local_ssl_rust.

fn expand_tilde(p: &Path) -> PathBuf {
  let s = p.to_string_lossy();
  if s.starts_with("~/") {
    if let Some(home) = std::env::var_os("HOME") {
      return PathBuf::from(home).join(s.strip_prefix("~/").unwrap());
    }
  } else if s == "~" {
    if let Some(home) = std::env::var_os("HOME") {
      return PathBuf::from(home);
    }
  }
  p.to_path_buf()
}

fn resolve_fqdn_cert_key(args: &Args) -> Result<(String, PathBuf, PathBuf), Box<dyn std::error::Error + Send + Sync>> {
  if let Some(ref dir) = args.letsencrypt {
    let dir = expand_tilde(dir);
    let fqdn = dir
      .file_name()
      .and_then(|n| n.to_str())
      .ok_or_else(|| {
        std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          format!("--letsencrypt path has no usable directory name: {}", dir.display()),
        )
      })?
      .to_string();
    let cert = dir.join("fullchain.pem");
    let key = dir.join("privkey.pem");
    if !cert.is_file() {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::NotFound,
          format!("missing {} (expected in --letsencrypt dir)", cert.display()),
        )
        .into(),
      );
    }
    if !key.is_file() {
      return Err(
        std::io::Error::new(
          std::io::ErrorKind::NotFound,
          format!("missing {} (expected in --letsencrypt dir)", key.display()),
        )
        .into(),
      );
    }
    return Ok((fqdn, cert, key));
  }

  let fqdn = args.fqdn.clone().ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "either --letsencrypt or all of --fqdn, --cert, --key are required",
    )
  })?;
  let cert = args.cert.clone().ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "either --letsencrypt or all of --fqdn, --cert, --key are required",
    )
  })?;
  let key = args.key.clone().ok_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "either --letsencrypt or all of --fqdn, --cert, --key are required",
    )
  })?;
  Ok((fqdn, cert, key))
}

/// Certificates found next to the `--letsencrypt` directory: every sibling directory holding
/// `fullchain.pem` and `privkey.pem` is served by SNI under the sibling's name (e.g. `current.ai`).
fn sibling_letsencrypt_dirs(args: &Args) -> Vec<(String, PathBuf, PathBuf)> {
  let Some(ref dir) = args.letsencrypt else {
    return Vec::new();
  };
  let dir = expand_tilde(dir);
  let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) else {
    return Vec::new();
  };
  let entries = match std::fs::read_dir(parent) {
    Ok(entries) => entries,
    Err(e) => {
      tracing::warn!("cannot list {} for sibling certificates: {}", parent.display(), e);
      return Vec::new();
    }
  };
  let mut found = Vec::new();
  for entry in entries.flatten() {
    let path = entry.path();
    if entry.file_name() == dir.file_name().unwrap_or_default() || !path.is_dir() {
      continue;
    }
    let (cert, key) = (path.join("fullchain.pem"), path.join("privkey.pem"));
    if !cert.is_file() || !key.is_file() {
      continue;
    }
    if let Some(name) = entry.file_name().to_str() {
      found.push((name.to_string(), cert, key));
    }
  }
  found.sort();
  found
}

fn load_certified_key(cert: &Path, key: &Path) -> Result<CertifiedKey, Box<dyn std::error::Error + Send + Sync>> {
  let chain = CertificateDer::pem_file_iter(cert)
    .map_err(|e| format!("{}: {}", cert.display(), e))?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| format!("{}: {}", cert.display(), e))?;
  if chain.is_empty() {
    return Err(format!("{}: no certificates found", cert.display()).into());
  }
  let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {}", key.display(), e))?;
  let provider = rustls::crypto::CryptoProvider::get_default().ok_or("no default rustls crypto provider")?;
  CertifiedKey::from_der(chain, key, provider).map_err(|e| format!("{}: {}", cert.display(), e).into())
}

// -- SNI certificate resolver: one certificate per hostname, the `--letsencrypt` one otherwise.

#[derive(Debug)]
struct SniCertResolver {
  default: Arc<CertifiedKey>,
  /// Keyed by lowercase hostname.
  by_name: HashMap<String, Arc<CertifiedKey>>,
}

/// Looks a server name up by exact match first, then by its parent domains, so `www.current.ai`
/// gets the `current.ai` entry when there is no closer one.
fn sni_lookup<'a, V>(by_name: &'a HashMap<String, V>, server_name: &str) -> Option<&'a V> {
  let mut candidate = server_name.trim_end_matches('.').to_ascii_lowercase();
  loop {
    if let Some(value) = by_name.get(&candidate) {
      return Some(value);
    }
    match candidate.split_once('.') {
      Some((_, parent)) if !parent.is_empty() => candidate = parent.to_string(),
      _ => return None,
    }
  }
}

impl ResolvesServerCert for SniCertResolver {
  fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
    let chosen = client_hello.server_name().and_then(|name| sni_lookup(&self.by_name, name));
    Some(chosen.unwrap_or(&self.default).clone())
  }
}

fn build_tls_config(default: CertifiedKey, by_name: HashMap<String, Arc<CertifiedKey>>) -> RustlsConfig {
  let resolver = SniCertResolver { default: Arc::new(default), by_name };
  let mut config = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(resolver));
  // Same ALPN list `RustlsConfig::from_pem_file` sets, so HTTP/2 keeps working.
  config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
  RustlsConfig::from_config(Arc::new(config))
}

// -- Profile data, matching the original `content/data.js`.

struct Profile {
  name: &'static str,
  url: &'static str,
}

const NAME: &str = "Dima Korolev";
const GOOGLE_ANALYTICS_CODE: &str = "UA-46065883-1";
const SEGMENT_KEY: &str = "IafwJFqA4vZaVDtStTf7HHUzcOaiFUlV";

const PROFILES: &[Profile] = &[
  Profile { name: "github", url: "https://tinyurl.com/dkorolev-github" },
  Profile { name: "linkedin", url: "https://tinyurl.com/dkorolev-linkedin" },
  Profile { name: "meetup", url: "https://tinyurl.com/dkorolev-dsm" },
  Profile { name: "telegram", url: "https://tinyurl.com/dkorolev-telegram" },
  Profile { name: "facebook", url: "http://on.fb.me/1Q7y09G" },
  Profile { name: "substack", url: "https://tinyurl.com/dkorolev-substack" },
  Profile { name: "youtube", url: "https://tinyurl.com/dkorolev-youtube" },
  Profile { name: "medium", url: "https://tinyurl.com/dkorolev-medium" },
  Profile { name: "twitter", url: "https://tinyurl.com/dkorolev-twitter" },
  Profile { name: "quora", url: "http://bit.ly/1iJQcXN" },
  Profile { name: "email", url: "mailto:dima@current.ai" },
];

// -- Pre-render the homepage HTML at startup.

fn render_home(debug: bool) -> String {
  let mut profile_items = String::new();
  for p in PROFILES {
    let href = if p.url.starts_with("mailto:") { p.url.to_string() } else { format!("/r?url={}", p.url) };
    profile_items.push_str(&format!(
      "    <li><span class=\"headerLine\"><a href=\"{}\" \
             onclick=\"_gaq.push(['_trackEvent', 'Click', 'Link', '{}']);\">\
             {}</a></span></li>\n",
      href, p.url, p.name
    ));
  }

  let mut html = String::new();

  // DOCTYPE and opening tags.
  html.push_str(
    "<!DOCTYPE html>\n\
         <html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\" />\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n\
         <meta name=\"google-site-verification\" content=\"mQFXwDjB1tqPjGWoaUqup5v9b7ZOUZHdL3aAPOfpLic\" />\n",
  );

  // Title.
  html.push_str(&format!("<title>{}</title>\n", NAME));

  // Favicon.
  html.push_str("<link rel=\"icon\" type=\"image/svg+xml\" href=\"/static/favicon.svg\" sizes=\"any\" />\n");

  // CSS.
  html.push_str("<link href=\"static/css.css\" rel=\"stylesheet\" />\n");

  // Google Analytics script.
  html.push_str("<script type=\"text/javascript\">\n");
  html.push_str("  var _gaq = _gaq || [];\n");
  html.push_str(&format!("  _gaq.push(['_setAccount', '{}']);\n", GOOGLE_ANALYTICS_CODE));
  html.push_str("  _gaq.push(['_trackPageview']);\n\n");
  html.push_str(
        "  (function() {\n\
         \x20   var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;\n\
         \x20   ga.src = ('https:' == document.location.protocol ? 'https://' : 'http://') + 'stats.g.doubleclick.net/dc.js';\n\
         \x20   var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);\n\
         \x20 })();\n",
    );
  html.push_str("</script>\n");

  // Segment analytics script.
  html.push_str("<script>\n");
  html.push_str(
    "  !function(){var analytics=window.analytics=window.analytics||[];\
         if(!analytics.initialize)if(analytics.invoked)window.console&&console.error&&\
         console.error(\"Segment snippet included twice.\");else{analytics.invoked=!0;\
         analytics.methods=[\"trackSubmit\",\"trackClick\",\"trackLink\",\"trackForm\",\
         \"pageview\",\"identify\",\"reset\",\"group\",\"track\",\"ready\",\"alias\",\
         \"debug\",\"page\",\"once\",\"off\",\"on\"];\
         analytics.factory=function(t){return function(){\
         var e=Array.prototype.slice.call(arguments);e.unshift(t);analytics.push(e);\
         return analytics}};for(var t=0;t<analytics.methods.length;t++){\
         var e=analytics.methods[t];analytics[e]=analytics.factory(e)}\
         analytics.load=function(t){var e=document.createElement(\"script\");\
         e.type=\"text/javascript\";e.async=!0;e.src=(\"https:\"===document.location.protocol?\
         \"https://\":\"http://\")+\"cdn.segment.com/analytics.js/v1/\"+t+\"/analytics.min.js\";\
         var n=document.getElementsByTagName(\"script\")[0];n.parentNode.insertBefore(e,n)};\
         analytics.SNIPPET_VERSION=\"4.0.0\";\n",
  );
  html.push_str(&format!("  analytics.load(\"{}\");\n", SEGMENT_KEY));
  html.push_str("  analytics.page();\n  }}();\n</script>\n");

  // Close head, open body.
  html.push_str("</head>\n<body>\n");
  html.push_str("<div class=\"outer\">\n<div class=\"wrapper\">\n");

  // Profile links.
  html.push_str("<ul>\n");
  html.push_str(&profile_items);

  // Debug links.
  if debug {
    for (href, name) in [
      ("/passkey", "Passkey"),
      ("/login", "OAuth2"),
      ("/mcpclient", "MCP Client"),
      ("/anthropiclimits", "Anthropic Limits"),
    ] {
      html.push_str(&format!(
        "    <li><span class=\"headerLine\"><a href=\"{}\" class=\"debug\" style=\"color: #ff8c00 !important;\">{}</a></span></li>\n",
        href, name
      ));
    }
    html.push_str(&format!(
      "    <li><span class=\"headerLine\" style=\"font-family:ui-monospace,monospace;font-size:0.75rem;color:rgba(0,0,0,0.35);padding-top:4px;\">{}</span></li>\n",
      env!("GIT_HASH")
    ));
  }

  html.push_str("</ul>\n");

  // Close body.
  html.push_str("</div>\n</div>\n</body>\n</html>\n");

  html
}

// -- Request/response types.

#[derive(Deserialize)]
struct RedirectQuery {
  url: Option<String>,
}

#[derive(Deserialize)]
struct RedirectForm {
  url: Option<String>,
}

#[derive(Deserialize)]
struct IndexQuery {
  debug: Option<String>,
}

#[derive(Clone)]
struct AppState {
  home_html: Arc<String>,
  home_html_debug: Arc<String>,
}

// -- Route handlers.

async fn index(Query(query): Query<IndexQuery>, State(state): State<AppState>) -> impl IntoResponse {
  if query.debug.is_some() {
    Html(state.home_html_debug.as_ref().clone())
  } else {
    Html(state.home_html.as_ref().clone())
  }
}

async fn redirect_get(Query(query): Query<RedirectQuery>) -> impl IntoResponse {
  if let Some(ref url) = query.url {
    Redirect::temporary(url).into_response()
  } else {
    StatusCode::BAD_REQUEST.into_response()
  }
}

async fn redirect_post(Form(form): Form<RedirectForm>) -> impl IntoResponse {
  let url = form.url.unwrap_or_else(|| "http://dimakorolev.com".to_string());
  Redirect::temporary(&url)
}

async fn blog_redirect() -> impl IntoResponse {
  Redirect::temporary("http://medium.com/dima-korolev")
}

async fn blog_chinese_redirect() -> impl IntoResponse {
  Redirect::temporary("http://bit.ly/1kC7fKj")
}

async fn anthropiclimits_page() -> Html<&'static str> {
  Html(include_str!("../../../static/anthropiclimits-probe/index.html"))
}

const ZOOM_URL: &str = "https://us06web.zoom.us/j/2332123321";

async fn zoom_redirect() -> impl IntoResponse {
  Redirect::permanent(ZOOM_URL)
}

// -- current.ai: a landing page pointing at the GitHub repo, then on to dima.ai.

const CURRENT_HOST: &str = "current.ai";
const CURRENT_GITHUB_URL: &str = "https://github.com/c5t/current";
const CURRENT_LANDING_NEXT_URL: &str = "https://dima.ai";
const CURRENT_LANDING_SECONDS: u32 = 3;

fn current_landing_html() -> String {
  format!(
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="{seconds};url={next}">
<title>Current</title>
<style>
  body {{ margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }}
  p {{ font-size: 1.5rem; padding: 0 1rem; text-align: center; }}
</style>
</head>
<body>
<p>This is Current, see <a href="{github}">github.com/c5t/current</a>.</p>
</body>
</html>
"#,
    seconds = CURRENT_LANDING_SECONDS,
    next = CURRENT_LANDING_NEXT_URL,
    github = CURRENT_GITHUB_URL,
  )
}

/// What a hostname other than the FQDN gets from this server. The hostname the caller asked for
/// decides, on both the HTTP and the HTTPS listener.
#[derive(Debug, PartialEq)]
enum HostRule {
  /// Every path goes to this URL.
  Redirect(&'static str),
  /// Served under this canonical hostname; other spellings (`www.` and the like) redirect to it,
  /// keeping the path.
  Serve(&'static str),
}

fn host_rule(hostname: &str) -> Option<HostRule> {
  let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
  if hostname == "zoom.dima.ai" {
    return Some(HostRule::Redirect(ZOOM_URL));
  }
  if hostname == CURRENT_HOST || hostname.ends_with(&format!(".{}", CURRENT_HOST)) {
    return Some(HostRule::Serve(CURRENT_HOST));
  }
  None
}

/// Hostname and port the caller asked for. HTTP/2 carries them in the request URI's authority and
/// sends no `Host` header; HTTP/1.1 requests have a relative URI and a `Host` header.
fn request_host(uri: &Uri, headers: &HeaderMap) -> Option<(String, Option<u16>)> {
  let authority = match uri.authority() {
    Some(authority) => authority.clone(),
    None => headers.get(header::HOST)?.to_str().ok()?.parse::<Authority>().ok()?,
  };
  Some((authority.host().to_string(), authority.port_u16()))
}

/// The same path and query on HTTPS at `host`, with the port only when it is not the default.
fn https_location(host: &str, port: Option<u16>, uri: &Uri) -> String {
  let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
  match port {
    Some(port) if port != 443 => format!("https://{}:{}{}", host, port, path),
    _ => format!("https://{}{}", host, path),
  }
}

/// Middleware for the pad alias, static cache headers, and Host-based redirects.
#[derive(Clone)]
struct RequestMiddlewareState {
  static_dir: PathBuf,
  /// Directory holding the files named by `pad_asset`; the static dir in production.
  pad_dir: PathBuf,
}

/// Maps a `/pad` request path to the file it serves under `pad_dir`, and that file's content type.
/// An allowlist rather than a URL-tail-to-filesystem mapping, so it needs none of the traversal
/// guards `static_etag` carries.
fn pad_asset(path: &str) -> Option<(&'static str, &'static str)> {
  const SHELL: (&str, &str) = ("pad.html", "text/html; charset=utf-8");
  match path {
    "/pad" | "/pad/" => Some(SHELL),
    // Relative to `/pad` the script resolves to `/pad.js`; relative to `/pad/`, to `/pad/pad.js`.
    "/pad.js" | "/pad/pad.js" => Some(("pad.js", "text/javascript; charset=utf-8")),
    // Every other subpath serves the shell, so the pad can route on the client.
    _ => path.starts_with("/pad/").then_some(SHELL),
  }
}

/// Where certbot's webroot mode writes ACME HTTP-01 tokens, relative to the static dir; the URL
/// path is the same, unlike the rest of `/.well-known`, which maps onto the static root.
const ACME_CHALLENGE_DIR: &str = ".well-known/acme-challenge";

fn static_relative_path(path: &str) -> Option<&str> {
  if path.starts_with("/.well-known/acme-challenge/") {
    return path.strip_prefix('/');
  }
  path
    .strip_prefix("/static/")
    .or_else(|| path.strip_prefix("/.well-known/"))
    .or_else(|| (path == "/static" || path == "/.well-known").then_some(""))
}

async fn static_etag(static_dir: &Path, request_path: &str) -> Option<HeaderValue> {
  let relative = static_relative_path(request_path)?;
  let decoded = percent_decode_str(relative).decode_utf8().ok()?;
  if decoded.contains('\\') {
    return None;
  }

  let mut file_path = static_dir.to_path_buf();
  for component in Path::new(decoded.as_ref()).components() {
    match component {
      std::path::Component::Normal(segment) => file_path.push(segment),
      _ => return None,
    }
  }
  if file_path.is_dir() {
    file_path.push("index.html");
  }

  file_etag(&file_path).await
}

async fn file_etag(path: &Path) -> Option<HeaderValue> {
  let metadata = tokio::fs::metadata(path).await.ok()?;
  if !metadata.is_file() {
    return None;
  }
  let modified = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
  let value = format!("W/\"{:x}-{:x}-{:x}\"", metadata.len(), modified.as_secs(), modified.subsec_nanos());
  HeaderValue::from_str(&value).ok()
}

fn if_none_match_matches(headers: &HeaderMap, etag: &HeaderValue) -> bool {
  let Some(condition) = headers.get(header::IF_NONE_MATCH).and_then(|value| value.to_str().ok()) else {
    return false;
  };
  let etag = etag.to_str().unwrap_or_default();
  let etag = etag.strip_prefix("W/").unwrap_or(etag);
  condition.split(',').any(|candidate| {
    let candidate = candidate.trim();
    candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
  })
}

fn add_static_cache_headers(response: &mut Response, etag: Option<&HeaderValue>) {
  response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
  if let Some(etag) = etag {
    response.headers_mut().insert(header::ETAG, etag.clone());
  }
}

fn not_modified(etag: &HeaderValue, last_modified: Option<HeaderValue>) -> Response {
  let mut response = StatusCode::NOT_MODIFIED.into_response();
  add_static_cache_headers(&mut response, Some(etag));
  if let Some(last_modified) = last_modified {
    response.headers_mut().insert(header::LAST_MODIFIED, last_modified);
  }
  response
}

async fn host_redirects(
  State(state): State<RequestMiddlewareState>, headers: HeaderMap, request: Request, next: middleware::Next,
) -> Response {
  if let Some((hostname, port)) = request_host(request.uri(), &headers) {
    match host_rule(&hostname) {
      Some(HostRule::Redirect(target)) => {
        tracing::info!("host redirect: {}{} -> {}", hostname, request.uri().path(), target);
        return Redirect::permanent(target).into_response();
      }
      Some(HostRule::Serve(canonical)) if hostname != canonical => {
        let location = https_location(canonical, port, request.uri());
        tracing::info!("host redirect: {}{} -> {}", hostname, request.uri().path(), location);
        return Redirect::permanent(&location).into_response();
      }
      // ACME HTTP-01 challenges must reach the static files, so certbot's webroot mode can issue
      // and renew this host's certificate while the server keeps running.
      Some(HostRule::Serve(_)) if !request.uri().path().starts_with("/.well-known/") => {
        return Html(current_landing_html()).into_response();
      }
      Some(HostRule::Serve(_)) | None => {}
    }
  }

  if let Some((file_name, content_type)) = pad_asset(request.uri().path()) {
    let pad_path = state.pad_dir.join(file_name);
    return match tokio::fs::read(&pad_path).await {
      Ok(body) => {
        let etag = file_etag(&pad_path).await;
        if matches!(*request.method(), Method::GET | Method::HEAD)
          && etag.as_ref().is_some_and(|etag| if_none_match_matches(&headers, etag))
        {
          return not_modified(etag.as_ref().unwrap(), None);
        }
        let mut response = ([(header::CONTENT_TYPE, content_type)], body).into_response();
        add_static_cache_headers(&mut response, etag.as_ref());
        response
      }
      Err(e) => {
        tracing::error!("failed to serve {} for {}: {}", pad_path.display(), request.uri(), e);
        let mut response = StatusCode::NOT_FOUND.into_response();
        add_static_cache_headers(&mut response, None);
        response
      }
    };
  }

  let static_request = static_relative_path(request.uri().path()).is_some();
  let etag = if static_request { static_etag(&state.static_dir, request.uri().path()).await } else { None };
  let can_revalidate = matches!(*request.method(), Method::GET | Method::HEAD)
    && etag.as_ref().is_some_and(|etag| if_none_match_matches(&headers, etag));

  let mut response = next.run(request).await;
  if static_request {
    if can_revalidate && response.status().is_success() {
      let last_modified = response.headers().get(header::LAST_MODIFIED).cloned();
      return not_modified(etag.as_ref().unwrap(), last_modified);
    }
    add_static_cache_headers(&mut response, etag.as_ref());
  }
  response
}

// -- HTTP -> HTTPS redirect, following local_ssl_rust.

async fn redirect_http_to_https_with_listener(listener: tokio::net::TcpListener, fqdn: String, https_port: u16) {
  let redirect = move |headers: HeaderMap, uri: Uri| {
    let fqdn = fqdn.clone();
    async move { Redirect::permanent(&http_redirect_location(&headers, &uri, &fqdn, https_port)) }
  };

  axum::serve(listener, redirect.into_make_service()).await.expect("HTTP redirect server");
}

/// Where a plain-HTTP request goes: a wholesale-redirected host straight to its target, a host
/// served under a canonical name to that name on HTTPS, anything else to `fqdn` on HTTPS.
fn http_redirect_location(headers: &HeaderMap, uri: &Uri, fqdn: &str, https_port: u16) -> String {
  let hostname = request_host(uri, headers).map(|(hostname, _)| hostname);
  let target_host = match hostname.as_deref().and_then(host_rule) {
    Some(HostRule::Redirect(target)) => return target.to_string(),
    Some(HostRule::Serve(canonical)) => canonical,
    None => fqdn,
  };
  https_location(target_host, Some(https_port), uri)
}

// -- Main.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
  rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");
  tracing_subscriber::registry()
    .with(
      tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| format!("{}=info", env!("CARGO_CRATE_NAME")).into()),
    )
    .with(tracing_subscriber::fmt::layer())
    .init();

  let args = Args::parse();
  let port_http = args.port_http;
  let port_https = args.port_https;

  let (fqdn, cert, key) = resolve_fqdn_cert_key(&args)?;

  let default_certified_key = load_certified_key(&cert, &key).map_err(|e| format!("TLS config: {}", e))?;

  tracing::info!("FQDN: {}", fqdn);
  tracing::info!("cert: {}", cert.display());
  tracing::info!("key:  {}", key.display());

  // A broken sibling certificate is logged and skipped rather than taking the whole server down.
  let mut certs_by_name: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
  for (name, sibling_cert, sibling_key) in sibling_letsencrypt_dirs(&args) {
    match load_certified_key(&sibling_cert, &sibling_key) {
      Ok(certified_key) => {
        tracing::info!("SNI cert: {} from {}", name, sibling_cert.display());
        certs_by_name.insert(name.to_ascii_lowercase(), Arc::new(certified_key));
      }
      Err(e) => tracing::warn!("skipping SNI cert for {}: {}", name, e),
    }
  }
  let tls_config = build_tls_config(default_certified_key, certs_by_name);

  // -- Initialize WebAuthn for /passkey.
  let origin_str =
    if port_https == 443 { format!("https://{}", fqdn) } else { format!("https://{}:{}", fqdn, port_https) };
  let keys_jsonl = args.keys_jsonl;
  let webauthn_state = homepage_webauthn::build_state(&fqdn, &origin_str, keys_jsonl)?;

  // -- Initialize OAuth for /login.
  let oauth_state = homepage_oauth::build_state(&origin_str);

  // -- MCP client UI at /mcpclient.
  let mcpclient_state = homepage_mcpclient::new_state(&origin_str);

  // -- Resolve the static directory.
  // Binary lives in target/release/ or target/debug/, so go two levels up for the project root.
  let project_root = std::env::current_exe()
    .ok()
    .and_then(|exe| exe.parent().and_then(|p| p.parent()).map(|p| p.parent().unwrap_or(p).to_path_buf()));
  // Prefer `./static` next to CWD, then project root (two levels up from binary).
  let static_dir = if Path::new("./static").is_dir() {
    std::fs::canonicalize("./static").unwrap_or_else(|_| PathBuf::from("./static"))
  } else if let Some(ref root) = project_root {
    let candidate = root.join("static");
    if candidate.is_dir() {
      candidate
    } else {
      tracing::error!("static directory not found at ./static or {}", candidate.display());
      tracing::error!(
        "cwd: {}",
        std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_else(|_| "??".into())
      );
      return Err("static directory not found".into());
    }
  } else {
    tracing::error!("static directory not found at ./static and could not determine binary location");
    return Err("static directory not found".into());
  };
  tracing::info!("static dir: {}", static_dir.display());

  let home_html = render_home(false);
  let home_html_debug = render_home(true);
  let state = AppState { home_html: Arc::new(home_html), home_html_debug: Arc::new(home_html_debug) };
  let request_middleware_state = RequestMiddlewareState { static_dir: static_dir.clone(), pad_dir: static_dir.clone() };

  // -- Build the app router.
  let app = Router::new()
    .route("/", get(index))
    .route("/r", get(redirect_get).post(redirect_post))
    .route("/blog", get(blog_redirect))
    .route("/blog/chinese/invited-technical-cofounder", get(blog_chinese_redirect))
    .route("/zoom", get(zoom_redirect))
    .route("/anthropiclimits", get(anthropiclimits_page))
    .nest_service("/static", ServeDir::new(&static_dir))
    .nest_service("/.well-known/acme-challenge", ServeDir::new(static_dir.join(ACME_CHALLENGE_DIR)))
    .nest_service("/.well-known", ServeDir::new(&static_dir))
    .with_state(state)
    .merge(homepage_webauthn::router(webauthn_state))
    .merge(homepage_oauth::router(oauth_state))
    .merge(homepage_mcpclient::router(mcpclient_state))
    .layer(middleware::from_fn_with_state(request_middleware_state, host_redirects));

  // -- HTTP listeners (redirect to HTTPS), bind IPv4 and IPv6.
  let http_addr_v4 = SocketAddr::from(([0, 0, 0, 0], port_http));
  let http_listener_v4 = tokio::net::TcpListener::bind(http_addr_v4)
    .await
    .map_err(|e| format!("bind HTTP on {}: {} (try: sudo lsof -i :{})", http_addr_v4, e, port_http))?;
  tracing::info!("HTTP  (redirect) listening on {}", http_listener_v4.local_addr().unwrap());

  let fqdn_v4 = fqdn.clone();
  tokio::spawn(async move {
    redirect_http_to_https_with_listener(http_listener_v4, fqdn_v4, port_https).await;
  });

  let http_addr_v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port_http));
  match tokio::net::TcpListener::bind(http_addr_v6).await {
    Ok(http_listener_v6) => {
      tracing::info!("HTTP  (redirect) listening on {}", http_listener_v6.local_addr().unwrap());
      let fqdn_v6 = fqdn.clone();
      tokio::spawn(async move {
        redirect_http_to_https_with_listener(http_listener_v6, fqdn_v6, port_https).await;
      });
    }
    Err(e) => {
      tracing::warn!("failed to bind HTTP on {} (IPv6): {}, continuing without it", http_addr_v6, e);
    }
  }

  // -- HTTPS listeners, bind IPv4 and IPv6.
  let addr_v4 = SocketAddr::from(([0, 0, 0, 0], port_https));
  let addr_v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port_https));
  tracing::info!("HTTPS listening on {}", addr_v4);
  tracing::info!("HTTPS listening on {}", addr_v6);

  let tls_config_v6 = tls_config.clone();
  let app_v6 = app.clone();
  tokio::spawn(async move {
    match axum_server::bind_rustls(addr_v6, tls_config_v6).serve(app_v6.into_make_service()).await {
      Ok(()) => {}
      Err(e) => {
        tracing::warn!("failed to bind HTTPS on {} (IPv6): {}, continuing without it", addr_v6, e);
      }
    }
  });

  axum_server::bind_rustls(addr_v4, tls_config).serve(app.into_make_service()).await.map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::body::Body;
  use axum::http::Request;
  use tower::ServiceExt;

  const PAD_SHELL_BODY: &str = "<!doctype html><title>pad</title>";
  const PAD_SCRIPT_BODY: &str = "console.log('pad');";

  fn repo_static_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../static")
  }

  /// The pad files ship with the deployment rather than the repo, so tests serve them from a
  /// scratch directory instead of `static/`.
  fn pad_test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("homepage-pad-test-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pad.html"), PAD_SHELL_BODY).unwrap();
    std::fs::write(dir.join("pad.js"), PAD_SCRIPT_BODY).unwrap();
    dir
  }

  fn test_app(pad_dir: PathBuf) -> Router {
    let static_dir = repo_static_dir();
    let state = RequestMiddlewareState { static_dir: static_dir.clone(), pad_dir: pad_dir.clone() };
    Router::new()
      .nest_service("/static", ServeDir::new(&static_dir))
      // Production keeps ACME tokens under the static dir; tests keep them in scratch.
      .nest_service("/.well-known/acme-challenge", ServeDir::new(pad_dir.join(ACME_CHALLENGE_DIR)))
      .nest_service("/.well-known", ServeDir::new(&static_dir))
      .layer(middleware::from_fn_with_state(state, host_redirects))
  }

  async fn get(app: &Router, path: &str) -> Response {
    app.clone().oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap()
  }

  async fn body_string(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
  }

  #[test]
  fn host_rules_cover_every_current_ai_spelling() {
    assert_eq!(host_rule("current.ai"), Some(HostRule::Serve(CURRENT_HOST)));
    assert_eq!(host_rule("CURRENT.AI"), Some(HostRule::Serve(CURRENT_HOST)));
    assert_eq!(host_rule("www.current.ai"), Some(HostRule::Serve(CURRENT_HOST)));
    assert_eq!(host_rule("current.ai."), Some(HostRule::Serve(CURRENT_HOST)));
    assert_eq!(host_rule("zoom.dima.ai"), Some(HostRule::Redirect(ZOOM_URL)));
    assert_eq!(host_rule("notcurrent.ai"), None);
    assert_eq!(host_rule("dima.ai"), None);
  }

  #[tokio::test]
  async fn current_ai_serves_the_landing_page_and_canonicalizes_other_spellings() {
    let pad_dir = pad_test_dir("current-ai");
    let app = test_app(pad_dir.clone());

    // The bare host gets the landing page on every path, statics and the pad alias included.
    for path in ["/", "/some/path?q=1", "/pad", "/static/favicon.svg", "/.well-known"] {
      let request = Request::get(path).header(header::HOST, "current.ai").body(Body::empty()).unwrap();
      let response = app.clone().oneshot(request).await.unwrap();
      assert_eq!(response.status(), StatusCode::OK, "{path}");
      assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/html; charset=utf-8", "{path}");
      let body = body_string(response).await;
      assert!(body.contains(&format!(r#"<a href="{}">github.com/c5t/current</a>"#, CURRENT_GITHUB_URL)), "{path}");
      assert!(body.contains(&format!(r#"content="3;url={}""#, CURRENT_LANDING_NEXT_URL)), "{path}");
    }

    // Other spellings redirect to the bare host, keeping path, query, and a non-default port.
    for (host, path, location) in [
      ("www.current.ai", "/", "https://current.ai/"),
      ("www.current.ai:443", "/a/b?c=d", "https://current.ai/a/b?c=d"),
      ("www.current.ai:8443", "/pad", "https://current.ai:8443/pad"),
      ("WWW.Current.AI", "/", "https://current.ai/"),
      ("current.ai.", "/", "https://current.ai/"),
    ] {
      let request = Request::get(path).header(header::HOST, host).body(Body::empty()).unwrap();
      let response = app.clone().oneshot(request).await.unwrap();
      assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT, "{host}{path}");
      assert_eq!(response.headers().get(header::LOCATION).unwrap(), location, "{host}{path}");
    }

    // HTTP/2 requests carry the host in the URI authority and no `Host` header at all.
    let request = Request::get("https://www.current.ai:8443/x").body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "https://current.ai:8443/x");
    let request = Request::get("https://current.ai/x").body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // ACME challenges pass through to the static files, so certbot's webroot mode keeps working.
    std::fs::create_dir_all(pad_dir.join(ACME_CHALLENGE_DIR)).unwrap();
    std::fs::write(pad_dir.join(ACME_CHALLENGE_DIR).join("token"), "token.thumbprint").unwrap();
    let request =
      Request::get("/.well-known/acme-challenge/token").header(header::HOST, "current.ai").body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_string(response).await, "token.thumbprint");

    // Other hosts still get their own content, the pad alias included.
    let request = Request::get("/pad").header(header::HOST, "dima.ai").body(Body::empty()).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    std::fs::remove_dir_all(&pad_dir).unwrap();
  }

  #[test]
  fn plain_http_goes_to_https_on_the_canonical_host() {
    let mut headers = HeaderMap::new();
    let uri: Uri = "/anything?x=y".parse().unwrap();

    headers.insert(header::HOST, HeaderValue::from_static("current.ai"));
    assert_eq!(http_redirect_location(&headers, &uri, "dima.ai", 443), "https://current.ai/anything?x=y");
    headers.insert(header::HOST, HeaderValue::from_static("www.current.ai"));
    assert_eq!(http_redirect_location(&headers, &uri, "dima.ai", 443), "https://current.ai/anything?x=y");
    assert_eq!(http_redirect_location(&headers, &uri, "dima.ai", 8443), "https://current.ai:8443/anything?x=y");

    headers.insert(header::HOST, HeaderValue::from_static("dima.ai"));
    assert_eq!(http_redirect_location(&headers, &uri, "dima.ai", 443), "https://dima.ai/anything?x=y");
    let root: Uri = "/".parse().unwrap();
    assert_eq!(http_redirect_location(&headers, &root, "dima.ai", 8443), "https://dima.ai:8443/");

    // No usable Host header at all: still the FQDN.
    headers.remove(header::HOST);
    assert_eq!(http_redirect_location(&headers, &root, "dima.ai", 443), "https://dima.ai/");

    // Plain-HTTP requests for the Zoom hostname used to bounce via https://dima.ai/ instead.
    headers.insert(header::HOST, HeaderValue::from_static("zoom.dima.ai"));
    assert_eq!(http_redirect_location(&headers, &root, "dima.ai", 443), ZOOM_URL);
  }

  #[test]
  fn sni_lookup_falls_back_to_parent_domains() {
    let by_name: HashMap<String, &str> =
      [("current.ai".to_string(), "current"), ("dima.ai".to_string(), "dima")].into_iter().collect();
    assert_eq!(sni_lookup(&by_name, "current.ai"), Some(&"current"));
    assert_eq!(sni_lookup(&by_name, "Current.AI"), Some(&"current"));
    assert_eq!(sni_lookup(&by_name, "www.current.ai"), Some(&"current"));
    assert_eq!(sni_lookup(&by_name, "a.b.dima.ai"), Some(&"dima"));
    assert_eq!(sni_lookup(&by_name, "example.com"), None);
    assert_eq!(sni_lookup(&by_name, "ai"), None);
  }

  #[test]
  fn pad_asset_maps_both_relative_forms_of_the_script() {
    assert_eq!(pad_asset("/pad").unwrap().0, "pad.html");
    assert_eq!(pad_asset("/pad/").unwrap().0, "pad.html");
    // Reached from `/pad` and from `/pad/` respectively.
    assert_eq!(pad_asset("/pad.js").unwrap().0, "pad.js");
    assert_eq!(pad_asset("/pad/pad.js").unwrap().0, "pad.js");
    // Client-side routes fall back to the shell; unrelated paths are left to the router.
    assert_eq!(pad_asset("/pad/whatever").unwrap().0, "pad.html");
    assert!(pad_asset("/padding").is_none());
    assert!(pad_asset("/static/pad.js").is_none());
  }

  #[tokio::test]
  async fn statics_have_cache_headers_and_revalidate() {
    let app = test_app(repo_static_dir());
    let response = get(&app, "/static/favicon.svg").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get(header::CACHE_CONTROL).unwrap(), "no-cache");
    let etag = response.headers().get(header::ETAG).unwrap().clone();

    let not_modified = app
      .oneshot(Request::get("/static/favicon.svg").header(header::IF_NONE_MATCH, etag).body(Body::empty()).unwrap())
      .await
      .unwrap();
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(not_modified.headers().get(header::CACHE_CONTROL).unwrap(), "no-cache");
    assert!(not_modified.headers().contains_key(header::ETAG));
  }

  #[tokio::test]
  async fn pad_serves_the_script_with_its_own_content_type() {
    let pad_dir = pad_test_dir("script");
    let app = test_app(pad_dir.clone());

    for path in ["/pad", "/pad/", "/pad/some/client/route"] {
      let response = get(&app, path).await;
      assert_eq!(response.status(), StatusCode::OK, "{path}");
      assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/html; charset=utf-8", "{path}");
      assert_eq!(body_string(response).await, PAD_SHELL_BODY, "{path}");
    }

    for path in ["/pad.js", "/pad/pad.js"] {
      let response = get(&app, path).await;
      assert_eq!(response.status(), StatusCode::OK, "{path}");
      assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "text/javascript; charset=utf-8", "{path}");
      assert_eq!(response.headers().get(header::CACHE_CONTROL).unwrap(), "no-cache", "{path}");
      // The shell used to be served here, under a `text/html` content type.
      assert_eq!(body_string(response).await, PAD_SCRIPT_BODY, "{path}");
    }

    std::fs::remove_dir_all(&pad_dir).unwrap();
  }

  #[tokio::test]
  async fn pad_script_revalidates() {
    let pad_dir = pad_test_dir("revalidate");
    let app = test_app(pad_dir.clone());

    let response = get(&app, "/pad/pad.js").await;
    let etag = response.headers().get(header::ETAG).unwrap().clone();

    let not_modified = app
      .oneshot(Request::get("/pad/pad.js").header(header::IF_NONE_MATCH, etag).body(Body::empty()).unwrap())
      .await
      .unwrap();
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(not_modified.headers().get(header::CACHE_CONTROL).unwrap(), "no-cache");

    std::fs::remove_dir_all(&pad_dir).unwrap();
  }

  #[tokio::test]
  async fn pad_shell_and_script_have_distinct_etags() {
    let pad_dir = pad_test_dir("etags");
    let app = test_app(pad_dir.clone());

    let shell = get(&app, "/pad").await.headers().get(header::ETAG).unwrap().clone();
    let script = get(&app, "/pad/pad.js").await.headers().get(header::ETAG).unwrap().clone();
    assert_ne!(shell, script);

    std::fs::remove_dir_all(&pad_dir).unwrap();
  }
}
