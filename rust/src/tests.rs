use super::*;
use paykit_lib::{
    parse_paykit_app_registry_json, PaymentEndpointIdentifier, PaymentEndpointPayload,
};
use serde_json::{json, Value};
use std::collections::HashMap;

const KEY: &str = "5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";

#[test]
fn test_identity_supported_forms() {
    for text in [
        KEY.to_owned(),
        format!("pubky{KEY}"),
        format!("pubky://{KEY}"),
        format!(" \n pubky{KEY}\t "),
    ] {
        assert_eq!(parse_identity(&text).unwrap().z32(), KEY);
    }
}

#[test]
fn test_identity_rejects_urls_paths_queries_and_invalid_keys() {
    for text in [
        String::new(),
        "not-a-pubky".into(),
        "y".repeat(51),
        "0".repeat(52), // Not a z-base-32 character.
        KEY.to_uppercase(),
        format!("pubky://{KEY}/"),
        format!("pubky{KEY}/pub/paykit/v0/app-registry.json"),
        format!("https://{KEY}"),
        format!("pubky://{KEY}?x=1"),
        format!("pubky://{KEY}#fragment"),
        format!("pubky://someone@{KEY}"),
    ] {
        assert!(
            matches!(parse_identity(&text), Err(Error::InvalidPubky)),
            "{text}"
        );
    }
}

#[tokio::test]
async fn test_lookup_rejects_invalid_identity_before_client_initialization() {
    assert!(matches!(
        get_payment_list("invalid").await,
        Err(Error::InvalidPubky)
    ));
}

#[test]
fn test_discovery_matches_shared_fixture_without_losing_app_attribution() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/discovery.json")).unwrap();
    let registry = parse_paykit_app_registry_json(&fixture["registry"].to_string()).unwrap();
    let mut endpoints = Vec::new();
    for app_id in registry.apps().keys() {
        let prefix = endpoint_prefix(app_id);
        let mut payment_endpoints = HashMap::new();
        for document in fixture["documents"].as_array().unwrap() {
            if let Some(identifier) = document["path"].as_str().unwrap().strip_prefix(&prefix) {
                payment_endpoints.insert(
                    PaymentEndpointIdentifier::new(identifier).unwrap(),
                    PaymentEndpointPayload::new(document["body"].as_str().unwrap()),
                );
            }
        }
        append_payment_list(
            &mut endpoints,
            &registry,
            app_id,
            PaymentList { payment_endpoints },
        );
    }
    let actual: Vec<Value> = order_endpoints(endpoints).into_iter().map(|endpoint| {
        json!({ "app_id": endpoint.app_id, "identifier": endpoint.identifier, "payload": endpoint.payload })
    }).collect();
    assert_eq!(actual, fixture["expected"].as_array().unwrap().clone());
}

#[test]
fn test_discovery_empty_list_stays_empty() {
    let registry = PaykitAppRegistry::new(None);
    let app_id = PaykitAppId::new("empty").unwrap();
    let mut endpoints = Vec::new();
    append_payment_list(
        &mut endpoints,
        &registry,
        &app_id,
        PaymentList {
            payment_endpoints: HashMap::new(),
        },
    );
    assert!(order_endpoints(endpoints).is_empty());
}

#[test]
fn test_discovery_preserves_opaque_payload_and_orders_without_preferences() {
    let registry = PaykitAppRegistry::new(None);
    let mut endpoints = Vec::new();
    let payload = "{\"address\":\"fixture\",\"memo\":\"opaque\"}\n";
    for (app, identifier) in [("zeta", "z"), ("alpha", "b"), ("alpha", "a")] {
        let app_id = PaykitAppId::new(app).unwrap();
        append_payment_list(
            &mut endpoints,
            &registry,
            &app_id,
            PaymentList {
                payment_endpoints: HashMap::from([(
                    PaymentEndpointIdentifier::new(identifier).unwrap(),
                    PaymentEndpointPayload::new(payload),
                )]),
            },
        );
    }
    let result = order_endpoints(endpoints);
    assert_eq!(
        result
            .iter()
            .map(|e| (e.app_id.as_str(), e.identifier.as_str()))
            .collect::<Vec<_>>(),
        [("alpha", "a"), ("alpha", "b"), ("zeta", "z")]
    );
    assert!(result.iter().all(|endpoint| endpoint.payload == payload));
}

#[test]
fn test_discovery_error_retains_underlying_cause() {
    let error = Error::from(paykit_lib::PaykitError::InvalidData {
        context: "malformed App Registry".into(),
        source: None,
    });
    assert!(matches!(
        &error,
        Error::Discovery(paykit_lib::PaykitError::InvalidData { .. })
    ));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn test_identity_bare_key_starting_with_pubky_is_not_stripped() {
    let key = Z32_ALPHABET
        .iter()
        .find_map(|letter| {
            let text = format!("pubky{}{}", char::from(*letter), "y".repeat(46));
            PublicKey::try_from_z32(&text)
                .ok()
                .filter(|key| key.z32() == text)
        })
        .expect("a valid deterministic key with pubky prefix");
    assert_eq!(parse_identity(&key.z32()).unwrap(), key);
}

#[test]
fn test_listing_rejects_other_identities_apps_and_nested_paths() {
    let owner = parse_identity(KEY).unwrap();
    let app = PaykitAppId::new("bitkit").unwrap();
    let prefix = endpoint_prefix(&app);
    let different_owner = pubky::Keypair::from_secret(&[1; 32]).public_key();
    let cases = [
        (different_owner, format!("{prefix}btc-lightning-bolt12")),
        (
            owner.clone(),
            "/pub/paykit/v0/apps/savings/endpoints/btc-lightning-bolt12".into(),
        ),
        (
            owner.clone(),
            format!("{prefix}nested/btc-lightning-bolt12"),
        ),
        (owner.clone(), format!("{prefix}nested/deeper/")),
        (owner.clone(), prefix.clone()),
        (owner.clone(), format!("{prefix}private")),
    ];
    for (resource_owner, path) in cases {
        let resource = PubkyResource::new(resource_owner, &path).unwrap();
        assert!(
            listed_identifier(&resource, &owner, &prefix).is_err(),
            "{path}"
        );
    }
}

#[test]
fn test_listing_accepts_exact_app_child_and_skips_child_directory() {
    let owner = parse_identity(KEY).unwrap();
    let prefix = endpoint_prefix(&PaykitAppId::new("bitkit").unwrap());
    let file = PubkyResource::new(owner.clone(), format!("{prefix}btc-lightning-bolt12")).unwrap();
    assert_eq!(
        listed_identifier(&file, &owner, &prefix)
            .unwrap()
            .unwrap()
            .as_str(),
        "btc-lightning-bolt12"
    );
    let directory = PubkyResource::new(owner.clone(), format!("{prefix}nested/")).unwrap();
    assert!(listed_identifier(&directory, &owner, &prefix)
        .unwrap()
        .is_none());
}

#[test]
fn test_discovery_budget_counts_attempts_and_rejects_overruns() {
    let mut budget = Budget {
        endpoints: 1,
        requests: 2,
        bytes: 4,
    };
    budget.request().unwrap();
    budget.endpoint().unwrap();
    budget.payload(4).unwrap();
    assert!(matches!(budget.request(), Err(Error::ResourceLimit)));
    assert!(matches!(budget.endpoint(), Err(Error::ResourceLimit)));
    assert!(matches!(budget.payload(1), Err(Error::ResourceLimit)));
}

#[test]
fn test_listing_rejects_duplicate_and_backwards_pagination() {
    let owner = parse_identity(KEY).unwrap();
    let a = PubkyResource::new(owner.clone(), "/pub/paykit/v0/apps/bitkit/endpoints/a").unwrap();
    let b = PubkyResource::new(owner, "/pub/paykit/v0/apps/bitkit/endpoints/b").unwrap();
    let mut cursor = None;
    advance_cursor(&mut cursor, &a).unwrap();
    assert!(advance_cursor(&mut cursor, &a).is_err());
    advance_cursor(&mut cursor, &b).unwrap();
    assert!(advance_cursor(&mut cursor, &a).is_err());
}

#[test]
fn test_listing_only_not_found_and_gone_are_empty() {
    for code in [404, 410, 401, 403, 429, 500, 503] {
        let error = pubky::Error::Request(pubky::errors::RequestError::Server {
            status: pubky::StatusCode::from_u16(code).unwrap(),
            message: "fixture".into(),
        });
        assert_eq!(is_missing(&error), code == 404 || code == 410);
    }
}
