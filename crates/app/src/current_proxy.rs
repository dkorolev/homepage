use axum::{
  body::{to_bytes, Body},
  extract::{ConnectInfo, Request},
  http::{header, HeaderMap, HeaderValue, StatusCode},
  response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone)]
pub struct CurrentProxy {
  client: reqwest::Client,
  upstream: String,
}

/// Strip hop-by-hop headers, including names nominated by Connection. Forwarded
/// headers are rebuilt from the actual TLS request, never trusted from a caller.
fn end_to_end(headers: &HeaderMap) -> HeaderMap {
  let mut result = headers.clone();
  for value in headers.get_all(header::CONNECTION) {
    if let Ok(value) = value.to_str() {
      for name in value.split(',') {
        result.remove(name.trim());
      }
    }
  }
  for name in [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "content-length",
    "host",
  ] {
    result.remove(name);
  }
  result
}

impl CurrentProxy {
  pub fn new(upstream: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
    let url = url::Url::parse(upstream)?;
    if url.scheme() != "http"
      || url.host_str() != Some("127.0.0.1")
      || url.path() != "/"
      || url.query().is_some()
      || url.fragment().is_some()
      || !url.username().is_empty()
      || url.password().is_some()
    {
      return Err("CURRENT_DEMOS_UPSTREAM must be an http://127.0.0.1:PORT origin".into());
    }
    let client = reqwest::Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .no_proxy()
      .timeout(Duration::from_secs(25))
      .build()?;
    Ok(Self { client, upstream: upstream.trim_end_matches('/').to_string() })
  }

  pub async fn forward(&self, request: Request, host: &str, port: Option<u16>) -> Response {
    let path = request.uri().path_and_query().map(|path| path.as_str()).unwrap_or("/");
    let destination = format!("{}{}", self.upstream, path);
    let mut headers = end_to_end(request.headers());
    let authority = match port {
      Some(port) if port != 443 => format!("{}:{}", host, port),
      _ => host.to_string(),
    };
    let Ok(authority) = HeaderValue::from_str(&authority) else { return StatusCode::BAD_REQUEST.into_response() };
    headers.insert(header::HOST, authority.clone());
    headers.insert("x-forwarded-host", authority);
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    let ip = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0.ip().to_string());
    if let Some(ip) = ip.and_then(|ip| HeaderValue::from_str(&ip).ok()) {
      headers.insert("x-forwarded-for", ip);
    }
    let method = request.method().clone();
    let body = match to_bytes(request.into_body(), 128 * 1024).await {
      Ok(body) => body,
      Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let response = self.client.request(method, destination).headers(headers).body(body).send().await;
    let Ok(mut upstream) = response else {
      tracing::warn!("Current demos service unavailable");
      return unavailable();
    };
    let status = upstream.status();
    let headers = end_to_end(upstream.headers());
    let mut bytes = Vec::new();
    loop {
      match upstream.chunk().await {
        Ok(Some(chunk)) if bytes.len() + chunk.len() <= 2 * 1024 * 1024 => bytes.extend_from_slice(&chunk),
        Ok(None) => break,
        _ => return StatusCode::BAD_GATEWAY.into_response(),
      }
    }
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
  }
}

pub fn unavailable() -> Response {
  (
    StatusCode::SERVICE_UNAVAILABLE,
    [(header::RETRY_AFTER, "5"), (header::CACHE_CONTROL, "no-store")],
    "Current demos are restarting. Please try again in a moment.",
  )
    .into_response()
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::{routing::post, Router};

  #[tokio::test]
  async fn forwards_auth_bodies_redirects_and_cookies_without_following_or_trusting_forwarded_headers() {
    let upstream = Router::new().route(
      "/oauth/token",
      post(|request: Request| async move {
        assert_eq!(request.headers()["host"], "current.ai");
        assert_eq!(request.headers()["x-forwarded-proto"], "https");
        assert!(!request.headers().contains_key("x-forwarded-for"));
        assert!(!request.headers().contains_key("forwarded"));
        assert!(!request.headers().contains_key("x-remove-me"));
        assert_eq!(request.headers()["authorization"], "Basic test");
        assert_eq!(to_bytes(request.into_body(), 1024).await.unwrap(), "code=test");
        let mut response = StatusCode::SEE_OTHER.into_response();
        response.headers_mut().insert(header::LOCATION, HeaderValue::from_static("https://example.com/callback"));
        response.headers_mut().append(header::SET_COOKIE, HeaderValue::from_static("a=1; HttpOnly; Secure"));
        response.headers_mut().append(header::SET_COOKIE, HeaderValue::from_static("b=2; HttpOnly; Secure"));
        response
      }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let proxy = CurrentProxy::new(&format!("http://{}", address)).unwrap();
    let request = Request::post("/oauth/token")
      .header("authorization", "Basic test")
      .header("x-forwarded-for", "evil")
      .header("forwarded", "host=evil")
      .header("connection", "x-remove-me")
      .header("x-remove-me", "evil")
      .body(Body::from("code=test"))
      .unwrap();
    let response = proxy.forward(request, "current.ai", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "https://example.com/callback");
    assert_eq!(response.headers().get_all(header::SET_COOKIE).iter().count(), 2);
    task.abort();
    let _ = task.await;
  }
}
