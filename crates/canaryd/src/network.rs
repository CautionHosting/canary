//! DNS resolution and address pinning for target probes (spec §11).
//!
//! A target hostname is resolved afresh for every attempt.  An answer set is
//! usable only when *every* answer is public; selecting one apparently-safe
//! answer from a mixed set would make DNS rebinding protection ineffective.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use thiserror::Error;
use url::Url;

/// Why an address cannot be used as a Canary target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProhibitedAddress {
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Unspecified,
    SharedAddressSpace,
    Benchmarking,
    Broadcast,
}

impl std::fmt::Display for ProhibitedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Loopback => "loopback",
            Self::Private => "private or unique-local",
            Self::LinkLocal => "link-local or metadata",
            Self::Multicast => "multicast",
            Self::Unspecified => "unspecified",
            Self::SharedAddressSpace => "shared address space",
            Self::Benchmarking => "benchmarking",
            Self::Broadcast => "broadcast",
        })
    }
}

/// Classify an address before it is ever handed to the HTTP client.
///
/// IPv4-mapped IPv6 addresses deliberately recurse into the IPv4 policy.
/// This prevents `::ffff:127.0.0.1` and similar aliases from bypassing it.
pub fn prohibited_address(address: IpAddr) -> Option<ProhibitedAddress> {
    match address {
        IpAddr::V4(ip) => prohibited_ipv4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return prohibited_ipv4(mapped);
            }
            if ip.is_loopback() {
                Some(ProhibitedAddress::Loopback)
            } else if ip.is_unspecified() {
                Some(ProhibitedAddress::Unspecified)
            } else if ip.is_multicast() {
                Some(ProhibitedAddress::Multicast)
            } else if ip.is_unicast_link_local() {
                Some(ProhibitedAddress::LinkLocal)
            } else if ip.is_unique_local() {
                Some(ProhibitedAddress::Private)
            } else {
                None
            }
        }
    }
}

fn prohibited_ipv4(ip: Ipv4Addr) -> Option<ProhibitedAddress> {
    let octets = ip.octets();
    if ip.is_loopback() {
        Some(ProhibitedAddress::Loopback)
    } else if ip.is_unspecified() {
        Some(ProhibitedAddress::Unspecified)
    } else if ip.is_private() {
        Some(ProhibitedAddress::Private)
    } else if ip.is_link_local() {
        // This includes AWS's 169.254.169.254 metadata service.
        Some(ProhibitedAddress::LinkLocal)
    } else if ip.is_multicast() {
        Some(ProhibitedAddress::Multicast)
    } else if ip.is_broadcast() {
        Some(ProhibitedAddress::Broadcast)
    } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        // RFC 6598 shared carrier-grade NAT space: 100.64.0.0/10.
        Some(ProhibitedAddress::SharedAddressSpace)
    } else if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        // RFC 2544 benchmarking space, not a public target destination.
        Some(ProhibitedAddress::Benchmarking)
    } else {
        None
    }
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("target URL must be an absolute HTTPS URL without credentials or fragment")]
    UnsafeUrl,
    #[error("target URL has no hostname")]
    MissingHostname,
    #[error("DNS lookup for {host}:{port} failed: {source}")]
    Lookup {
        host: String,
        port: u16,
        #[source]
        source: io::Error,
    },
    #[error("DNS lookup for {host}:{port} returned no addresses")]
    EmptyAnswer { host: String, port: u16 },
    #[error("DNS answer for {host}:{port} included prohibited address {address} ({reason})")]
    ProhibitedAnswer {
        host: String,
        port: u16,
        address: IpAddr,
        reason: ProhibitedAddress,
    },
}

/// A fresh DNS resolver.  It is intentionally generic rather than dynamic so
/// deterministic tests can use a small fake without a runtime dependency.
pub trait Resolver: Send + Sync {
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl std::future::Future<Output = Result<Vec<SocketAddr>, ResolveError>> + Send;
}

/// Resolver backed by the operating system resolver used by Tokio.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
        let host = host.to_owned();
        let addresses = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|source| ResolveError::Lookup {
                host: host.clone(),
                port,
                source,
            })?
            .collect();
        Ok(addresses)
    }
}

/// The original URL/hostname plus the single socket selected from a fresh,
/// wholly-approved DNS answer set.
///
/// HTTP clients must use `url` for the request (therefore Host and TLS SNI)
/// while forcing the TCP connection to `socket`.
#[derive(Debug, Clone)]
pub struct PinnedTarget {
    pub url: Url,
    pub hostname: String,
    pub socket: SocketAddr,
}

/// Resolve and pin one target for one attempt.
///
/// The first answer is selected only after every answer has passed policy. DNS
/// order is retained; no second lookup is made between policy check and TCP
/// connection.
pub async fn resolve_and_pin<R: Resolver>(
    resolver: &R,
    url: &Url,
) -> Result<PinnedTarget, ResolveError> {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ResolveError::UnsafeUrl);
    }
    let hostname = url
        .host_str()
        .ok_or(ResolveError::MissingHostname)?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or(ResolveError::MissingHostname)?;
    let answers = resolver.resolve(&hostname, port).await?;
    select_pinned(url.clone(), hostname, port, answers)
}

/// Apply whole-answer-set policy and select the first permitted address.
/// Exposed separately to make the DNS security boundary hermetically testable.
pub fn select_pinned(
    url: Url,
    hostname: String,
    port: u16,
    answers: Vec<SocketAddr>,
) -> Result<PinnedTarget, ResolveError> {
    let first = *answers.first().ok_or_else(|| ResolveError::EmptyAnswer {
        host: hostname.clone(),
        port,
    })?;
    for answer in &answers {
        if let Some(reason) = prohibited_address(answer.ip()) {
            return Err(ResolveError::ProhibitedAnswer {
                host: hostname,
                port,
                address: answer.ip(),
                reason,
            });
        }
    }
    Ok(PinnedTarget {
        url,
        hostname,
        // `lookup_host` is invoked with this port, but resolver fakes and
        // alternate resolver implementations must not be able to alter it.
        socket: SocketAddr::new(first.ip(), port),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn public_addresses_are_allowed_and_special_ranges_are_rejected() {
        assert_eq!(
            prohibited_address(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            None
        );
        assert_eq!(
            prohibited_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            Some(ProhibitedAddress::Loopback)
        );
        assert_eq!(
            prohibited_address(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            Some(ProhibitedAddress::SharedAddressSpace)
        );
        assert_eq!(
            prohibited_address(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
            Some(ProhibitedAddress::LinkLocal)
        );
        assert_eq!(
            prohibited_address(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some(ProhibitedAddress::Loopback)
        );
        assert_eq!(
            prohibited_address("::ffff:127.0.0.1".parse().unwrap()),
            Some(ProhibitedAddress::Loopback)
        );
        assert_eq!(
            prohibited_address("fc00::1".parse().unwrap()),
            Some(ProhibitedAddress::Private)
        );
    }

    #[test]
    fn one_bad_dns_answer_rejects_the_entire_set() {
        let url = Url::parse("https://target.example/attestation").unwrap();
        let error = select_pinned(
            url,
            "target.example".to_owned(),
            443,
            vec![
                "8.8.8.8:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap(),
            ],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ResolveError::ProhibitedAnswer {
                address: IpAddr::V4(address),
                ..
            } if address == Ipv4Addr::LOCALHOST
        ));
    }

    #[test]
    fn approved_answer_pins_socket_but_keeps_hostname_and_url() {
        let url = Url::parse("https://Target.Example/attestation?x=1").unwrap();
        let pinned = select_pinned(
            url.clone(),
            "target.example".to_owned(),
            443,
            vec!["8.8.8.8:443".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(pinned.socket, "8.8.8.8:443".parse().unwrap());
        assert_eq!(pinned.hostname, "target.example");
        assert_eq!(pinned.url, url);
    }
}
