//! End-to-end tests running a real axum server and sending raw HTTP requests over TCP.

use std::{net::SocketAddr, num::NonZeroU64, time::Duration};

use axum::{
    extract::Extension,
    routing::{get, post},
    Router,
};
use axum_gcra::{extensions::RateLimiter, gcra::Quota, real_ip::RealIp, RateLimitLayer};
use http::Method;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

type Key = RealIp;

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn app() -> Router {
    Router::new()
        .route("/", get(|ip: RealIp| async move { format!("Hello, {ip}!") }))
        .route("/burst", get(|| async { "burst" }))
        .route("/fast", get(|| async { "fast" }))
        .route(
            "/penalize",
            post(|rl: Extension<RateLimiter<Key>>| async move {
                rl.penalize(Duration::from_secs(60)).await;
            }),
        )
        .route(
            "/reset",
            get(|rl: Extension<RateLimiter<Key>>| async move {
                rl.reset().await;
            }),
        )
        .route_layer(
            RateLimitLayer::<Key>::builder()
                .with_default_quota(Quota::simple(Duration::from_millis(500)))
                .with_route(
                    (Method::GET, "/burst"),
                    Quota::new(Duration::from_secs(10), NonZeroU64::new(3).unwrap()),
                )
                .with_route((Method::GET, "/fast"), Quota::simple(Duration::from_nanos(1)))
                .with_extension(true)
                .default_handle_error(),
        )
}

async fn serve(app: Router, connect_info: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if connect_info {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        } else {
            axum::serve(listener, app).await.unwrap();
        }
    });

    addr
}

async fn request(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)]) -> Response {
    let mut stream = TcpStream::connect(addr).await.unwrap();

    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n");
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();

    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();

    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let mut lines = head.lines();
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();

    Response {
        status,
        headers,
        body: body.to_owned(),
    }
}

async fn get_as(addr: SocketAddr, path: &str, real_ip: &str) -> Response {
    request(addr, "GET", path, &[("x-real-ip", real_ip)]).await
}

#[tokio::test]
async fn throttles_and_recovers() {
    let addr = serve(app(), false).await;

    let res = get_as(addr, "/", "10.0.0.1").await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body, "Hello, 10.0.0.1!");

    let res = get_as(addr, "/", "10.0.0.1").await;
    assert_eq!(res.status, 429);
    assert_eq!(res.header("retry-after"), Some("1"));
    assert_eq!(res.header("ratelimit-remaining"), Some("0"));
    assert!(res.body.starts_with("rate limit exceeded"), "{}", res.body);

    tokio::time::sleep(Duration::from_millis(600)).await;

    assert_eq!(get_as(addr, "/", "10.0.0.1").await.status, 200);
}

#[tokio::test]
async fn burst_quota() {
    let addr = serve(app(), false).await;

    for i in 0..3 {
        assert_eq!(get_as(addr, "/burst", "10.0.0.1").await.status, 200, "request {i}");
    }

    let res = get_as(addr, "/burst", "10.0.0.1").await;
    assert_eq!(res.status, 429);
    let retry: u64 = res.header("retry-after").unwrap().parse().unwrap();
    assert!((9..=10).contains(&retry), "retry-after = {retry}");
}

#[tokio::test]
async fn routes_have_separate_quotas() {
    let addr = serve(app(), false).await;

    assert_eq!(get_as(addr, "/", "10.0.0.1").await.status, 200);
    assert_eq!(get_as(addr, "/", "10.0.0.1").await.status, 429);

    for _ in 0..10 {
        assert_eq!(get_as(addr, "/fast", "10.0.0.1").await.status, 200);
    }
}

#[tokio::test]
async fn clients_are_keyed_by_ip() {
    let addr = serve(app(), false).await;

    assert_eq!(get_as(addr, "/", "10.0.0.1").await.status, 200);
    assert_eq!(get_as(addr, "/", "10.0.0.1").await.status, 429);
    // a different client is unaffected
    assert_eq!(get_as(addr, "/", "10.0.0.2").await.status, 200);
    // the port doesn't change the key
    assert_eq!(get_as(addr, "/", "10.0.0.2:5555").await.status, 429);
}

#[tokio::test]
async fn ipv6_clients() {
    let addr = serve(app(), false).await;

    let res = get_as(addr, "/", "2fa::1").await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body, "Hello, 2fa::1!");

    assert_eq!(get_as(addr, "/", "[2fa::1]:443").await.status, 429);
    assert_eq!(get_as(addr, "/", "[2fa::2]:443").await.status, 200);
    assert_eq!(get_as(addr, "/", "2fa::2").await.status, 429);

    let res = request(addr, "GET", "/", &[("x-forwarded-for", "2fa::3, 10.0.0.1")]).await;
    assert_eq!(res.body, "Hello, 2fa::3!");
}

#[tokio::test]
async fn cloudfront_viewer_address() {
    let addr = serve(app(), false).await;

    let res = request(addr, "GET", "/", &[("cloudfront-viewer-address", "2001:db8::1:443")]).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body, "Hello, 2001:db8::1!");
}

#[tokio::test]
async fn falls_back_to_socket_address() {
    let addr = serve(app(), true).await;

    let res = request(addr, "GET", "/", &[]).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body, "Hello, 127.0.0.1!");

    assert_eq!(request(addr, "GET", "/", &[]).await.status, 429);
}

#[tokio::test]
async fn rejects_requests_without_ip() {
    let addr = serve(app(), false).await;

    assert_eq!(request(addr, "GET", "/", &[]).await.status, 400);
    assert_eq!(get_as(addr, "/", "not-an-ip").await.status, 400);
}

#[tokio::test]
async fn penalize() {
    let addr = serve(app(), false).await;

    let penalize = |ip| async move { request(addr, "POST", "/penalize", &[("x-real-ip", ip)]).await };

    assert_eq!(penalize("10.0.0.1").await.status, 200);

    tokio::time::sleep(Duration::from_millis(600)).await;

    // the penalty outlasts the normal 500ms quota
    let res = penalize("10.0.0.1").await;
    assert_eq!(res.status, 429);
    let retry: u64 = res.header("retry-after").unwrap().parse().unwrap();
    assert!(retry >= 55, "retry-after = {retry}");

    // other clients are unaffected
    assert_eq!(penalize("10.0.0.2").await.status, 200);
}

#[tokio::test]
async fn reset() {
    let addr = serve(app(), false).await;

    // limiter state is per route, so resetting within the handler
    // clears the quota this request just used on `/reset`
    for _ in 0..3 {
        assert_eq!(get_as(addr, "/reset", "10.0.0.1").await.status, 200);
    }
}
