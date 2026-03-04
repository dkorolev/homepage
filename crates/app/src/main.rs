use axum::{
  extract::{Form, Query, Request, State},
  handler::HandlerWithoutStateExt,
  http::{header, uri::Scheme, HeaderMap, StatusCode, Uri},
  middleware,
  response::{Html, IntoResponse, Redirect, Response},
  routing::get,
  Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

  /// Enable debug endpoints.
  #[arg(short, long)]
  debug: bool,

  /// Let's Encrypt directory: FQDN = last path component, must contain fullchain.pem and privkey.pem.
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
    for (href, name) in [("/piarun", "Passkey"), ("/login", "OAuth2"), ("/mcpclient", "MCP Client")] {
      html.push_str(&format!(
        "    <li><span class=\"headerLine\"><a href=\"{}\" class=\"debug\">{}</a></span></li>\n",
        href, name
      ));
    }
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

#[derive(Clone)]
struct AppState {
  home_html: Arc<String>,
  debug: bool,
}

// -- Route handlers.

async fn index(State(state): State<AppState>) -> impl IntoResponse {
  Html(state.home_html.as_ref().clone())
}

async fn redirect_get(Query(query): Query<RedirectQuery>, State(state): State<AppState>) -> impl IntoResponse {
  if let Some(ref url) = query.url {
    Redirect::temporary(url).into_response()
  } else if state.debug {
    Html("<form method=GET><input type=text name=url /><input type=submit /></form>\n").into_response()
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

const ZOOM_URL: &str = "https://us06web.zoom.us/j/2332123321";

async fn zoom_redirect() -> impl IntoResponse {
  Redirect::permanent(ZOOM_URL)
}

/// Middleware: redirect based on Host header (e.g. zoom.dima.ai -> Zoom).
async fn host_redirects(headers: HeaderMap, request: Request, next: middleware::Next) -> Response {
  if let Some(host) = headers.get(header::HOST) {
    if let Ok(host_str) = host.to_str() {
      let hostname = host_str.split(':').next().unwrap_or(host_str);
      if hostname == "zoom.dima.ai" {
        tracing::info!("host redirect: {} -> {}", host_str, ZOOM_URL);
        return Redirect::permanent(ZOOM_URL).into_response();
      }
    }
  }
  next.run(request).await
}

async fn kill() -> StatusCode {
  std::process::exit(1);
}

// -- HTTP -> HTTPS redirect, following local_ssl_rust.

async fn redirect_http_to_https_with_listener(listener: tokio::net::TcpListener, fqdn: String, https_port: u16) {
  let redirect = move |uri: Uri| {
    let fqdn = fqdn.clone();
    async move {
      match make_https_uri(uri, &fqdn, https_port) {
        Ok(u) => Ok(Redirect::permanent(&u.to_string())),
        Err(_) => {
          tracing::warn!("failed to build HTTPS URI");
          Err(StatusCode::BAD_REQUEST)
        }
      }
    }
  };

  axum::serve(listener, redirect.into_make_service()).await.expect("HTTP redirect server");
}

fn make_https_uri(uri: Uri, authority_host: &str, https_port: u16) -> Result<Uri, StatusCode> {
  let authority =
    if https_port == 443 { authority_host.to_string() } else { format!("{}:{}", authority_host, https_port) };
  let mut parts = uri.into_parts();
  parts.scheme = Some(Scheme::HTTPS);
  parts.authority = Some(authority.parse().map_err(|_| StatusCode::BAD_REQUEST)?);
  if parts.path_and_query.is_none() {
    parts.path_and_query = Some("/".parse().unwrap());
  }
  Uri::from_parts(parts).map_err(|_| StatusCode::BAD_REQUEST)
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
  let debug = args.debug;
  let port_http = args.port_http;
  let port_https = args.port_https;

  let (fqdn, cert, key) = resolve_fqdn_cert_key(&args)?;

  let tls_config = RustlsConfig::from_pem_file(&cert, &key).await.map_err(|e| format!("TLS config: {}", e))?;

  tracing::info!("FQDN: {}", fqdn);
  tracing::info!("cert: {}", cert.display());
  tracing::info!("key:  {}", key.display());

  // -- Initialize WebAuthn for /piarun.
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

  let home_html = render_home(debug);
  let state = AppState { home_html: Arc::new(home_html), debug };

  // -- Build the app router.
  let mut app = Router::new()
    .route("/", get(index))
    .route("/r", get(redirect_get).post(redirect_post))
    .route("/blog", get(blog_redirect))
    .route("/blog/chinese/invited-technical-cofounder", get(blog_chinese_redirect))
    .route("/zoom", get(zoom_redirect));

  if debug {
    app = app.route("/kill", get(kill));
  }

  let app = app
    .nest_service("/static", ServeDir::new(&static_dir))
    .nest_service("/.well-known", ServeDir::new(&static_dir))
    .with_state(state)
    .merge(homepage_webauthn::router(webauthn_state))
    .merge(homepage_oauth::router(oauth_state))
    .merge(homepage_mcpclient::router(mcpclient_state))
    .layer(middleware::from_fn(host_redirects));

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
