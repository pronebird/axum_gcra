//! Provides a way to get the real IP address of the client, to the best of our ability.
//!
//! This is exposed as [`RealIp`], which is an extractor that can be used in Axum routes,
//! or as a [`Layer`] and [`Service`] that can be used to add the IP address to
//! the request parts extensions. Or both.

use std::{
    fmt::{self, Debug, Display},
    future::Future,
    hash::Hash,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    ops::Deref,
    str::FromStr,
    task::{Context, Poll},
};

use axum::{extract::FromRequestParts, response::IntoResponse};
use http::{header::HeaderName, request::Parts, HeaderValue, Request, StatusCode};
use tower::{Layer, Service};

/// Wrapper around [`std::net::IpAddr`] that can be extracted from the request parts.
///
/// This extractor will try to get the real IP address of the client, using the following headers, in order:
/// - `cf-connecting-ip` (used by Cloudflare sometimes)
/// - `x-cluster-client-ip` (used by AWS sometimes)
/// - `fly-client-ip` (used by Fly.io sometimes)
/// - `fastly-client-ip` (used by Fastly sometimes)
/// - `cloudfront-viewer-address" (used by Cloudfront sometimes)
/// - `x-real-ip`
/// - `x-forwarded-for`
/// - `x-original-forwarded-for` (maybe used by Cloudfront?)
/// - `true-client-ip` (used by some load balancers)
/// - `client-ip` (used by some load balancers)
///
/// If none of these headers are found, it will return a 400 Bad Request via [`IpAddrRejection`],
/// or the error can be handled with a custom rejection handler with
/// [`RateLimitLayerBuilder::handle_error`](crate::RateLimitLayerBuilder::handle_error).
///
/// If the `tokio` feature is enabled AND the `Router` is configured with
/// [`Router::into_make_service_with_connect_info`](axum::Router::into_make_service_with_connect_info),
/// it will also try to get the IP address from the underlying socket via the [`ConnectInfo<SocketAddr>`](axum::extract::ConnectInfo) extension.
/// This is optional as it may not work as expected if the server is behind a reverse proxy.
///
/// The [`RealIpLayer`] can be also used to add the [`RealIp`] extension to the request if available, allowing
/// other services or extractors to reuse it without rescanning the headers every time.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RealIp(pub IpAddr);

/// Like [`RealIp`], but with the last 64 bits of any IPv6 address set to zeroes.
///
/// This is useful for making sure clients with randomized IPv6 interfaces
/// aren't treated as different clients. This can be common in some networks
/// that attempt to preserve privacy.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RealIpPrivacyMask(pub RealIp);

impl From<RealIp> for RealIpPrivacyMask {
    #[inline]
    fn from(ip: RealIp) -> Self {
        RealIpPrivacyMask(match ip.0 {
            IpAddr::V4(ip) => RealIp(IpAddr::V4(ip)),
            IpAddr::V6(ip) => RealIp(IpAddr::V6(From::from(
                ip.to_bits() & 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000,
            ))),
        })
    }
}

impl Debug for RealIp {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Display for RealIp {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Debug for RealIpPrivacyMask {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Display for RealIpPrivacyMask {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Deref for RealIp {
    type Target = IpAddr;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for RealIpPrivacyMask {
    type Target = RealIp;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// IP Address not found, returns a 400 Bad Request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpAddrRejection;

impl IntoResponse for IpAddrRejection {
    fn into_response(self) -> axum::response::Response {
        StatusCode::BAD_REQUEST.into_response()
    }
}

use std::future::ready;

impl<S> FromRequestParts<S> for RealIp {
    type Rejection = IpAddrRejection;

    fn from_request_parts(parts: &mut Parts, _: &S) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        if let Some(ip) = parts.extensions.get::<RealIp>() {
            return ready(Ok(*ip));
        }

        ready(match get_ip_from_parts(parts) {
            Some(ip) => Ok(ip),
            None => Err(IpAddrRejection),
        })
    }
}

impl<S> FromRequestParts<S> for RealIpPrivacyMask {
    type Rejection = IpAddrRejection;

    fn from_request_parts(parts: &mut Parts, _: &S) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        if let Some(&ip) = parts.extensions.get::<RealIp>() {
            return ready(Ok(ip.into()));
        }

        ready(match get_ip_from_parts(parts) {
            Some(ip) => Ok(ip.into()),
            None => Err(IpAddrRejection),
        })
    }
}

/// [`Service`] that adds the [`RealIp`] extension to the request parts if available.
///
/// This extension can be reused by other services or extractors, such as [`RealIp`] itself.
#[derive(Debug, Clone, Copy)]
pub struct RealIpService<I>(I);

/// [`Layer`] that adds the [`RealIp`] extension to the request parts if available.
///
/// This extension can be reused by other services or extractors, such as [`RealIp`] itself.
#[derive(Debug, Clone, Copy)]
pub struct RealIpLayer;

impl<B, I> Service<Request<B>> for RealIpService<I>
where
    I: Service<Request<B>>,
{
    type Response = I::Response;
    type Error = I::Error;
    type Future = I::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let (mut parts, body) = req.into_parts();

        if let Some(ip) = get_ip_from_parts(&parts) {
            parts.extensions.insert(ip);
        }

        self.0.call(Request::from_parts(parts, body))
    }
}

impl<I> Layer<I> for RealIpLayer {
    type Service = RealIpService<I>;

    fn layer(&self, inner: I) -> Self::Service {
        RealIpService(inner)
    }
}

/// Returns the first entry of a comma-separated header value.
fn first_entry(s: &HeaderValue) -> Option<&str> {
    s.to_str().ok()?.split(',').next().map(str::trim)
}

/// Parses `10.0.0.1`, `2fa::1`, `[2fa::1]`, `10.0.0.1:443` or `[2fa::1]:443`.
fn parse_ip(s: &HeaderValue) -> Option<IpAddr> {
    let s = first_entry(s)?;

    if let Ok(ip) = IpAddr::from_str(s) {
        return Some(ip);
    }

    if let Ok(addr) = SocketAddr::from_str(s) {
        return Some(addr.ip());
    }

    let ip = s.strip_prefix('[')?.strip_suffix(']')?;
    Ipv6Addr::from_str(ip).ok().map(IpAddr::V6)
}

/// Parses `cloudfront-viewer-address`, which is always `ip:port`, with IPv6 addresses
/// not enclosed in brackets, e.g. `198.51.100.10:46532` or `2a05:d018::1:46532`.
fn parse_ip_with_port(s: &HeaderValue) -> Option<IpAddr> {
    let (ip, port) = first_entry(s)?.rsplit_once(':')?;
    port.parse::<u16>().ok()?;

    match ip.strip_prefix('[') {
        Some(ip) => Ipv6Addr::from_str(ip.strip_suffix(']')?).ok().map(IpAddr::V6),
        None => ip.parse().ok(),
    }
}

pub(crate) fn get_ip_from_parts(parts: &Parts) -> Option<RealIp> {
    type Parser = fn(&HeaderValue) -> Option<IpAddr>;

    static HEADERS: [(HeaderName, Parser); 10] = [
        (HeaderName::from_static("cf-connecting-ip"), parse_ip), // used by Cloudflare sometimes
        (HeaderName::from_static("x-cluster-client-ip"), parse_ip), // used by AWS sometimes
        (HeaderName::from_static("fly-client-ip"), parse_ip),    // used by Fly.io sometimes
        (HeaderName::from_static("fastly-client-ip"), parse_ip), // used by Fastly sometimes
        (HeaderName::from_static("cloudfront-viewer-address"), parse_ip_with_port), // used by Cloudfront sometimes
        (HeaderName::from_static("x-real-ip"), parse_ip),
        (HeaderName::from_static("x-forwarded-for"), parse_ip),
        (HeaderName::from_static("x-original-forwarded-for"), parse_ip), // maybe used by Cloudfront?
        (HeaderName::from_static("true-client-ip"), parse_ip),           // used by some load balancers
        (HeaderName::from_static("client-ip"), parse_ip),                // used by some load balancers
    ];

    for (header, parse) in &HEADERS {
        if let Some(real_ip) = parts.headers.get(header).and_then(parse) {
            return Some(RealIp(real_ip));
        }
    }

    #[cfg(feature = "tokio")]
    if let Some(info) = parts.extensions.get::<axum::extract::ConnectInfo<SocketAddr>>() {
        return Some(RealIp(info.ip()));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    fn parse(s: &'static str) -> Option<IpAddr> {
        parse_ip(&HeaderValue::from_static(s))
    }

    fn parse_with_port(s: &'static str) -> Option<IpAddr> {
        parse_ip_with_port(&HeaderValue::from_static(s))
    }

    #[test]
    fn parse_ipv4() {
        assert_eq!(parse("10.0.0.1"), ip("10.0.0.1"));
        assert_eq!(parse(" 10.0.0.1 "), ip("10.0.0.1"));
        assert_eq!(parse("10.0.0.1:50000"), ip("10.0.0.1"));
        assert_eq!(parse("10.0.0.1, 10.10.10.10"), ip("10.0.0.1"));
        assert_eq!(parse("10.0.0.1:50000, 10.10.10.10:50000"), ip("10.0.0.1"));
    }

    #[test]
    fn parse_ipv6() {
        assert_eq!(parse("2fa::1"), ip("2fa::1"));
        assert_eq!(parse("[2fa::1]"), ip("2fa::1"));
        assert_eq!(parse("[2fa::1]:50000"), ip("2fa::1"));
        assert_eq!(parse("2fa::1, 2fa::2"), ip("2fa::1"));
        assert_eq!(parse("[2fa::1]:50000, [2fa::2]:50000"), ip("2fa::1"));
        assert_eq!(parse("::ffff:10.0.0.1"), ip("::ffff:10.0.0.1"));
    }

    #[test]
    fn parse_invalid() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("unknown"), None);
        assert_eq!(parse("10.0.0.1:"), None);
        assert_eq!(parse("[2fa::1"), None);
        assert_eq!(parse("2fa::1]"), None);
        assert_eq!(parse("[2fa::1]garbage"), None);
        assert_eq!(parse("[10.0.0.1]"), None);
    }

    #[test]
    fn parse_cloudfront_viewer_address() {
        assert_eq!(parse_with_port("198.51.100.10:46532"), ip("198.51.100.10"));
        assert_eq!(parse_with_port("2a05:d018::1:46532"), ip("2a05:d018::1"));
        // the port would otherwise be mistaken for the last segment of the address
        assert_eq!(parse_with_port("2001:db8::1:443"), ip("2001:db8::1"));
        assert_eq!(parse_with_port("[2001:db8::1]:443"), ip("2001:db8::1"));

        assert_eq!(parse_with_port("198.51.100.10"), None);
        assert_eq!(parse_with_port("198.51.100.10:99999"), None);
    }

    #[test]
    fn header_priority() {
        let req = Request::builder()
            .header("x-forwarded-for", "10.0.0.2")
            .header("cloudfront-viewer-address", "2001:db8::1:443")
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();

        assert_eq!(get_ip_from_parts(&parts).map(|ip| ip.0), ip("2001:db8::1"));
    }
}
