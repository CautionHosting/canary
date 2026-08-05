//! Opt-in live Nitro/Caddy acceptance test.
//!
//! This test deliberately requires an independently trusted PCR file. It must
//! never derive expected PCRs from the endpoint under test.

use canary_core::config::{E2eMode, ExpectedPcrs, Target};
use canary_core::evidence::ProbeReason;
use canaryd::network::SystemResolver;
use canaryd::probe::{probe_target, ReqwestTransport};
use chrono::Utc;
use serde::Deserialize;

#[derive(Deserialize)]
struct TrustedPcrs {
    pcr0: String,
    pcr1: String,
    pcr2: String,
}

#[tokio::test]
#[ignore = "requires live Nitro endpoint and independently trusted PCR0/1/2"]
async fn live_caddy_attestation_is_bound_to_its_response_leaf() {
    let attestation_url = std::env::var("CADDY_E2E_URL")
        .expect("set CADDY_E2E_URL to the full HTTPS /attestation URL");
    let pcrs_path = std::env::var("CADDY_E2E_PCRS")
        .expect("set CADDY_E2E_PCRS to an independently trusted PCR JSON file");
    let trusted: TrustedPcrs = serde_json::from_slice(
        &std::fs::read(&pcrs_path).expect("read independently trusted PCR file"),
    )
    .expect("parse {pcr0,pcr1,pcr2} PCR file");
    let target = Target {
        id: "caddy-live".to_owned(),
        name: "Caddy live Nitro acceptance".to_owned(),
        attestation_url: attestation_url.clone(),
        e2e_mode: Some(E2eMode::Tls),
        expected_pcrs: ExpectedPcrs {
            pcr0: trusted.pcr0,
            pcr1: trusted.pcr1,
            pcr2: trusted.pcr2,
        },
    };
    let expected_domain = url::Url::parse(&attestation_url)
        .expect("valid attestation URL")
        .host_str()
        .expect("attestation URL hostname")
        .to_owned();

    let attempt = probe_target(&SystemResolver, &ReqwestTransport, &target, Utc::now()).await;
    assert_eq!(attempt.reason, ProbeReason::AllChecksPassed);
    assert!(attempt.evidence.is_some());
    let claims = attempt
        .evidence_claims
        .expect("passing live evidence retains authenticated PCR claims");
    assert!(claims.matches.pcr0 && claims.matches.pcr1 && claims.matches.pcr2);
    let tls = attempt
        .tls
        .expect("passing TLS profile retains its TLS comparison");
    assert!(tls.matches(&expected_domain));
}
