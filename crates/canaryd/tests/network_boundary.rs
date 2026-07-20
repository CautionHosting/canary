//! Hermetic integration coverage for the DNS/address policy boundary.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use canaryd::network::{
    prohibited_address, resolve_and_pin, select_pinned, ProhibitedAddress, ResolveError, Resolver,
};
use url::Url;

#[derive(Clone)]
struct StaticResolver {
    answers: Vec<SocketAddr>,
}

impl Resolver for StaticResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, ResolveError> {
        Ok(self.answers.clone())
    }
}

#[test]
fn rejects_every_prohibited_ipv4_ipv6_and_mapped_alias_class() {
    let cases = [
        ("127.0.0.1", ProhibitedAddress::Loopback),
        ("0.0.0.0", ProhibitedAddress::Unspecified),
        ("10.0.0.1", ProhibitedAddress::Private),
        ("172.16.0.1", ProhibitedAddress::Private),
        ("192.168.0.1", ProhibitedAddress::Private),
        ("169.254.169.254", ProhibitedAddress::LinkLocal),
        ("224.0.0.1", ProhibitedAddress::Multicast),
        ("255.255.255.255", ProhibitedAddress::Broadcast),
        ("100.64.0.1", ProhibitedAddress::SharedAddressSpace),
        ("198.18.0.1", ProhibitedAddress::Benchmarking),
        ("198.19.255.254", ProhibitedAddress::Benchmarking),
        ("::1", ProhibitedAddress::Loopback),
        ("::", ProhibitedAddress::Unspecified),
        ("ff02::1", ProhibitedAddress::Multicast),
        ("fe80::1", ProhibitedAddress::LinkLocal),
        ("fc00::1", ProhibitedAddress::Private),
        ("fdff::1", ProhibitedAddress::Private),
        ("::ffff:127.0.0.1", ProhibitedAddress::Loopback),
        ("::ffff:10.0.0.1", ProhibitedAddress::Private),
        ("::ffff:169.254.169.254", ProhibitedAddress::LinkLocal),
        ("::ffff:100.64.0.1", ProhibitedAddress::SharedAddressSpace),
    ];

    for (raw, expected) in cases {
        let address: IpAddr = raw.parse().unwrap();
        assert_eq!(prohibited_address(address), Some(expected), "{raw}");
    }
    assert_eq!(prohibited_address("8.8.8.8".parse().unwrap()), None);
    assert_eq!(
        prohibited_address("2606:4700:4700::1111".parse().unwrap()),
        None
    );
}

#[test]
fn mixed_dns_set_is_rejected_and_public_answer_is_pinned_to_url_port() {
    let url = Url::parse("https://canary.example:8443/attestation").unwrap();
    let error = select_pinned(
        url.clone(),
        "canary.example".to_owned(),
        8443,
        vec![
            SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 1),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1),
        ],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ResolveError::ProhibitedAnswer {
            address,
            reason: ProhibitedAddress::Loopback,
            ..
        } if address == IpAddr::V4(Ipv4Addr::LOCALHOST)
    ));

    let target = select_pinned(
        url.clone(),
        "canary.example".to_owned(),
        8443,
        vec![SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 1)],
    )
    .unwrap();
    assert_eq!(target.url, url);
    assert_eq!(target.hostname, "canary.example");
    assert_eq!(target.socket, "8.8.8.8:8443".parse().unwrap());
}

#[tokio::test]
async fn resolve_preserves_hostname_and_rejects_unsafe_url_forms_before_transport() {
    let resolver = StaticResolver {
        answers: vec!["1.1.1.1:443".parse().unwrap()],
    };
    let url = Url::parse("https://target.example/attestation?mode=v0").unwrap();
    let pinned = resolve_and_pin(&resolver, &url).await.unwrap();
    assert_eq!(pinned.url, url);
    assert_eq!(pinned.hostname, "target.example");
    assert_eq!(pinned.socket, "1.1.1.1:443".parse().unwrap());

    for raw in [
        "http://target.example/attestation",
        "https://user@target.example/attestation",
        "https://target.example/attestation#fragment",
    ] {
        let error = resolve_and_pin(&resolver, &Url::parse(raw).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(error, ResolveError::UnsafeUrl), "{raw}");
    }
}
