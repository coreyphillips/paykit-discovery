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

#[test]
fn test_known_identifiers_match_the_shared_fixture_and_paykit_convention() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/discovery.json")).unwrap();
    let expected: Vec<&str> = fixture["known_identifiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    let known = [
        identifiers::BTC_BITCOIN_P2TR,
        identifiers::BTC_BITCOIN_P2WPKH,
        identifiers::BTC_LIGHTNING_BOLT11,
        identifiers::BTC_LIGHTNING_BOLT12,
        identifiers::EUR_SEPA_IBAN,
        identifiers::GBP_FPS_SORTCODE,
        identifiers::USD_REVOLUT_TAG,
        identifiers::USDC_SOLANA_ADDRESS,
        identifiers::USDT_ETHEREUM_ADDRESS,
        identifiers::USDT_TRON_ADDRESS,
    ];
    assert_eq!(known.as_slice(), expected.as_slice());
    for value in known {
        PaymentEndpointIdentifier::new(value).unwrap();
        let segments: Vec<&str> = value.split('-').collect();
        assert_eq!(segments.len(), 3, "{value}");
        assert!(
            segments.iter().all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9'))
            }),
            "{value}"
        );
    }
}

// Publishing and encrypted Payment Lists.

fn publishing_fixture() -> Value {
    serde_json::from_str(include_str!("../../fixtures/publishing.json")).unwrap()
}

fn endpoint(app_id: &str, identifier: &str, payload: &str) -> PaymentEndpoint {
    PaymentEndpoint {
        app_id: app_id.into(),
        identifier: identifier.into(),
        payload: payload.into(),
    }
}

fn fixture_endpoints(value: &Value) -> Vec<PaymentEndpoint> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            endpoint(
                item["app_id"].as_str().unwrap(),
                item["identifier"].as_str().unwrap(),
                item["payload"].as_str().unwrap(),
            )
        })
        .collect()
}

fn hex32(value: &Value) -> [u8; 32] {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn is_invalid_data(error: &Error) -> bool {
    matches!(
        error,
        Error::Discovery(paykit_lib::PaykitError::InvalidData { .. })
    )
}

#[test]
fn test_mnemonic_and_hex_secret_resolve_to_the_same_pubky() {
    let fixture = publishing_fixture();
    for vector in fixture["secrets"].as_array().unwrap() {
        let expected = hex32(&vector["secret_hex"]);
        for input in [&vector["mnemonic"], &vector["secret_hex"]] {
            let secret = secret::parse_secret(input.as_str().unwrap()).unwrap();
            assert_eq!(*secret, expected);
            assert_eq!(
                pubky::Keypair::from_secret(&secret).public_key().z32(),
                vector["pubky"].as_str().unwrap()
            );
        }
    }
    let first = hex32(&fixture["secrets"][0]["secret_hex"]);
    for input in fixture["equivalent_secret_inputs"].as_array().unwrap() {
        assert_eq!(
            *secret::parse_secret(input.as_str().unwrap()).unwrap(),
            first
        );
    }
}

#[test]
fn test_invalid_secrets_are_rejected_without_echoing_them() {
    for input in publishing_fixture()["invalid_secrets"].as_array().unwrap() {
        let input = input.as_str().unwrap();
        let error = secret::parse_secret(input).unwrap_err();
        assert!(matches!(error, Error::InvalidSecret), "{input}");
        assert!(input.is_empty() || !error.to_string().contains(input));
    }
}

#[test]
fn test_hierarchical_keys_match_pubky_vectors() {
    let fixture = publishing_fixture();
    let keys = &fixture["hierarchical_keys"];
    let secret = hex32(&keys["identity_secret_hex"]);
    for vector in keys["vectors"].as_array().unwrap() {
        let path = vector["path"].as_str().unwrap();
        let key = encrypted::derive_key(&secret, path).unwrap();
        assert_eq!(
            hex::encode(*key),
            vector["key_hex"].as_str().unwrap(),
            "{path}"
        );
    }
}

#[test]
fn test_encrypted_document_matches_shared_vector() {
    let fixture = publishing_fixture();
    let vector = &fixture["encrypted"];
    let secret = hex32(&vector["secret_hex"]);
    let owner = pubky::Keypair::from_secret(&secret).public_key();
    assert_eq!(owner.z32(), vector["owner"].as_str().unwrap());
    let id = vector["id"].as_str().unwrap();
    let path = encrypted::document_path(id);
    assert_eq!(path, vector["path"].as_str().unwrap());

    let key = encrypted::derive_key(&secret, &path).unwrap();
    assert_eq!(hex::encode(*key), vector["key_hex"].as_str().unwrap());
    let list = publish::validate_endpoints(&fixture_endpoints(&vector["endpoints"])).unwrap();
    let plaintext = encrypted::serialize_document(&list.endpoints()).unwrap();
    assert_eq!(
        hex::encode(&plaintext),
        vector["plaintext_hex"].as_str().unwrap()
    );
    let nonce: [u8; 12] = hex::decode(vector["nonce_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sealed = encrypted::seal(&key, &nonce, &owner, &path, &plaintext).unwrap();
    assert_eq!(hex::encode(&sealed), vector["sealed_hex"].as_str().unwrap());
    assert_eq!(
        encrypted::format_access(id, &key),
        vector["access"].as_str().unwrap()
    );

    let access = encrypted::parse_access(vector["access"].as_str().unwrap()).unwrap();
    assert_eq!(access.id, id);
    assert_eq!(*access.key, *key);
    let opened = encrypted::open(&access.key, &owner, &path, &sealed).unwrap();
    assert_eq!(
        encrypted::parse_document(&opened).unwrap(),
        fixture_endpoints(&vector["expected"])
    );
}

#[test]
fn test_encrypted_document_rejects_tampering_wrong_keys_and_relocation() {
    let fixture = publishing_fixture();
    let vector = &fixture["encrypted"];
    let owner = parse_identity(vector["owner"].as_str().unwrap()).unwrap();
    let path = vector["path"].as_str().unwrap();
    let key = hex32(&vector["key_hex"]);
    let sealed = hex::decode(vector["sealed_hex"].as_str().unwrap()).unwrap();
    assert!(encrypted::open(&key, &owner, path, &sealed).is_ok());

    for index in [0, 11, 12, sealed.len() / 2, sealed.len() - 1] {
        let mut tampered = sealed.clone();
        tampered[index] ^= 1;
        let error = encrypted::open(&key, &owner, path, &tampered).unwrap_err();
        assert!(is_invalid_data(&error), "byte {index}");
    }
    let mut wrong_key = key;
    wrong_key[0] ^= 1;
    let other_owner = pubky::Keypair::from_secret(&[1; 32]).public_key();
    let other_path = encrypted::document_path("ffeeddccbbaa99887766554433221100");
    for error in [
        encrypted::open(&wrong_key, &owner, path, &sealed).unwrap_err(),
        encrypted::open(&key, &other_owner, path, &sealed).unwrap_err(),
        encrypted::open(&key, &owner, &other_path, &sealed).unwrap_err(),
        encrypted::open(&key, &owner, path, &sealed[..27]).unwrap_err(),
        encrypted::open(&key, &owner, path, &[]).unwrap_err(),
    ] {
        assert!(is_invalid_data(&error));
    }
}

#[test]
fn test_identifiers_outside_the_known_list_are_accepted() {
    let details = [
        endpoint("my-wallet", "Custom_v1.2", "x"),
        endpoint("my-wallet", "xmr-monero-subaddress", "y"),
    ];
    assert_eq!(
        publish::validate_endpoints(&details).unwrap().endpoints(),
        details
    );
}

#[test]
fn test_missing_encrypted_document_is_not_found_not_empty() {
    for code in [404, 410, 401, 403, 429, 500, 503] {
        let error =
            encrypted::read_error(pubky::Error::Request(pubky::errors::RequestError::Server {
                status: pubky::StatusCode::from_u16(code).unwrap(),
                message: "fixture".into(),
            }));
        if code == 404 || code == 410 {
            assert!(matches!(error, Error::NotFound), "status {code}");
        } else {
            assert!(
                matches!(
                    error,
                    Error::Discovery(paykit_lib::PaykitError::Transport { .. })
                ),
                "status {code}"
            );
        }
    }
}

#[test]
fn test_each_encrypted_document_gets_its_own_path_and_key() {
    let secret = hex32(&publishing_fixture()["encrypted"]["secret_hex"]);
    let owner = pubky::Keypair::from_secret(&secret).public_key();
    let first_id = encrypted::new_document_id();
    let second_id = encrypted::new_document_id();
    assert_ne!(first_id, second_id);
    for id in [&first_id, &second_id] {
        assert_eq!(id.len(), 32);
        assert!(id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
    }
    let first_path = encrypted::document_path(&first_id);
    let second_path = encrypted::document_path(&second_id);
    let first_key = encrypted::derive_key(&secret, &first_path).unwrap();
    let second_key = encrypted::derive_key(&secret, &second_path).unwrap();
    assert_ne!(*first_key, *second_key);

    // Identical details for two recipients still produce unrelated documents.
    let document =
        encrypted::serialize_document(&[endpoint("shop", "btc-bitcoin-p2tr", "same")]).unwrap();
    let nonce = [7; 12];
    let first = encrypted::seal(&first_key, &nonce, &owner, &first_path, &document).unwrap();
    let second = encrypted::seal(&second_key, &nonce, &owner, &second_path, &document).unwrap();
    assert_ne!(first, second);
    assert!(encrypted::open(&first_key, &owner, &second_path, &second).is_err());
    assert!(encrypted::open(&second_key, &owner, &first_path, &first).is_err());
    assert!(encrypted::open(&first_key, &owner, &first_path, &first).is_ok());
}

#[test]
fn test_encrypted_document_parser_is_strict() {
    let valid = r#"{"version":1,"kind":"paykit-discovery.encrypted_payment_list","endpoints":[{"app_id":"bitkit","identifier":"btc","payload":"x"}]}"#;
    assert_eq!(
        encrypted::parse_document(valid.as_bytes()).unwrap(),
        [endpoint("bitkit", "btc", "x")]
    );
    for document in [
        valid.replace(r#""version":1"#, r#""version":2"#),
        valid.replace(r#""version":1"#, r#""version":1.0"#),
        valid.replace(r#""version":1"#, r#""version":1,"version":1"#),
        valid.replace("encrypted_payment_list", "other"),
        valid.replace(r#""payload":"x""#, r#""payload":"x","extra":true"#),
        valid.replace(r#""payload":"x""#, r#""payload":"""#),
        valid.replace(r#""app_id":"bitkit""#, r#""app_id":"Bitkit""#),
        valid.replace(r#""identifier":"btc""#, r#""identifier":"private""#),
        valid.replace(
            r#""endpoints":["#,
            r#""endpoints":[{"app_id":"bitkit","identifier":"btc","payload":"y"},"#,
        ),
        valid.replace(
            r#""endpoints":[{"app_id":"bitkit","identifier":"btc","payload":"x"}]"#,
            r#""endpoints":[]"#,
        ),
        "[]".into(),
        String::new(),
    ] {
        let error = encrypted::parse_document(document.as_bytes()).unwrap_err();
        assert!(is_invalid_data(&error), "{document}");
    }
    assert!(is_invalid_data(
        &encrypted::parse_document(&[0xff]).unwrap_err()
    ));
}

#[test]
fn test_access_strings_are_parsed_strictly() {
    let fixture = publishing_fixture();
    let valid = fixture["encrypted"]["access"].as_str().unwrap();
    assert!(encrypted::parse_access(&format!(" {valid}\n")).is_ok());
    for input in fixture["invalid_access"].as_array().unwrap() {
        let input = input.as_str().unwrap();
        assert!(
            matches!(encrypted::parse_access(input), Err(Error::InvalidInput(_))),
            "{input}"
        );
    }
}

#[test]
fn test_endpoint_validation_matches_discovery_rules() {
    let list = publish::validate_endpoints(&[
        endpoint("zeta", "b", "1"),
        endpoint("alpha", "b", "2"),
        endpoint("alpha", "a", "3"),
        endpoint("zeta", "a", "4"),
    ])
    .unwrap();
    let order: Vec<_> = list
        .endpoints()
        .into_iter()
        .map(|e| (e.app_id, e.identifier, e.payload))
        .collect();
    assert_eq!(
        order,
        [
            ("alpha".into(), "a".into(), "3".into()),
            ("alpha".into(), "b".into(), "2".into()),
            ("zeta".into(), "a".into(), "4".into()),
            ("zeta".into(), "b".into(), "1".into()),
        ]
    );

    let many: Vec<_> = (0..257)
        .map(|i| endpoint("app", &format!("e{i}"), "x"))
        .collect();
    let apps: Vec<_> = (0..65)
        .map(|i| endpoint(&format!("app{i}"), "e", "x"))
        .collect();
    let big = "x".repeat(64 * 1024 + 1);
    let max = "x".repeat(64 * 1024);
    let total: Vec<_> = (0..65)
        .map(|i| endpoint("app", &format!("e{i}"), &max))
        .collect();
    for (case, input) in [
        ("empty", vec![]),
        ("too many", many),
        ("too many apps", apps),
        ("uppercase app", vec![endpoint("Bitkit", "btc", "x")]),
        ("empty app", vec![endpoint("", "btc", "x")]),
        ("long app", vec![endpoint(&"a".repeat(65), "btc", "x")]),
        (
            "reserved identifier",
            vec![endpoint("bitkit", "private", "x")],
        ),
        ("dot identifier", vec![endpoint("bitkit", "..", "x")]),
        ("slash identifier", vec![endpoint("bitkit", "a/b", "x")]),
        ("empty payload", vec![endpoint("bitkit", "btc", "")]),
        ("large payload", vec![endpoint("bitkit", "btc", &big)]),
        ("total payload", total),
        (
            "duplicate",
            vec![
                endpoint("bitkit", "btc", "x"),
                endpoint("bitkit", "btc", "y"),
            ],
        ),
    ] {
        assert!(publish::validate_endpoints(&input).is_err(), "{case}");
    }
    // The same identifier from two Apps is two records, never a duplicate.
    assert!(
        publish::validate_endpoints(&[endpoint("a", "btc", "x"), endpoint("b", "btc", "y")])
            .is_ok()
    );
}

#[test]
fn test_registry_merge_adds_missing_apps_and_preserves_everything_else() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/discovery.json")).unwrap();
    let mut registry_json = fixture["registry"].clone();
    registry_json["key_generation"] = json!(18446744073709551615u64);
    let mut registry = parse_paykit_app_registry_json(&registry_json.to_string()).unwrap();
    let before = registry.clone();

    let existing_only = publish::validate_endpoints(&[endpoint("bitkit", "btc", "x")]).unwrap();
    assert!(!publish::register_missing_apps(&mut registry, &existing_only).unwrap());
    assert!(registry == before);

    let list = publish::validate_endpoints(&[
        endpoint("bitkit", "btc", "x"),
        endpoint("new-app", "btc", "y"),
    ])
    .unwrap();
    assert!(publish::register_missing_apps(&mut registry, &list).unwrap());
    let added = &registry.apps()[&PaykitAppId::new("new-app").unwrap()];
    assert_eq!(added.display_name(), "new-app");
    let capabilities = added.capabilities();
    assert!(
        !capabilities.private_payments
            && !capabilities.payment_requests
            && !capabilities.receipts
            && !capabilities.outgoing_payments
    );
    assert_eq!(registry.apps().len(), 3);
    assert_eq!(registry.key_generation(), u64::MAX);
    assert_eq!(registry.default_app_id(), before.default_app_id());
    assert_eq!(
        registry.default_apps_by_endpoint(),
        before.default_apps_by_endpoint()
    );
    for (app_id, app) in before.apps() {
        assert_eq!(&registry.apps()[app_id], app);
    }
    // The merged registry still serializes under paykit-lib's limits.
    paykit_lib::serialize_paykit_app_registry(&registry).unwrap();
}

#[test]
fn test_registry_merge_refuses_more_than_64_apps() {
    let mut registry = PaykitAppRegistry::new(None);
    let first: Vec<_> = (0..60)
        .map(|i| endpoint(&format!("app{i}"), "e", "x"))
        .collect();
    publish::register_missing_apps(&mut registry, &publish::validate_endpoints(&first).unwrap())
        .unwrap();
    let more: Vec<_> = (60..65)
        .map(|i| endpoint(&format!("app{i}"), "e", "x"))
        .collect();
    assert!(matches!(
        publish::register_missing_apps(&mut registry, &publish::validate_endpoints(&more).unwrap()),
        Err(Error::ResourceLimit)
    ));
    assert_eq!(registry.apps().len(), 60);
}

#[tokio::test]
async fn test_publishing_rejects_invalid_secret_and_input_before_network_access() {
    let fixture = publishing_fixture();
    let mnemonic = fixture["secrets"][0]["mnemonic"].as_str().unwrap();
    let valid = [endpoint("bitkit", "btc", "x")];
    for encrypted in [false, true] {
        assert!(matches!(
            set_payment_list("not a mnemonic", &valid, encrypted).await,
            Err(Error::InvalidSecret)
        ));
        assert!(matches!(
            set_payment_list(mnemonic, &[], encrypted).await,
            Err(Error::InvalidInput(_))
        ));
    }
    assert!(matches!(
        get_encrypted_payment_list("invalid", fixture["encrypted"]["access"].as_str().unwrap())
            .await,
        Err(Error::InvalidPubky)
    ));
    assert!(matches!(
        get_encrypted_payment_list(KEY, "v1.bad").await,
        Err(Error::InvalidInput(_))
    ));
}

#[tokio::test]
async fn test_errors_never_reveal_secrets_or_access_keys() {
    let fixture = publishing_fixture();
    let secret_hex = fixture["secrets"][0]["secret_hex"].as_str().unwrap();
    let mnemonic = fixture["secrets"][0]["mnemonic"].as_str().unwrap();
    let key_hex = fixture["encrypted"]["key_hex"].as_str().unwrap();
    let typo = mnemonic.replace("about", "abound");
    let errors = [
        set_payment_list(&typo, &[], false).await.unwrap_err(),
        set_payment_list(&secret_hex[1..], &[], true)
            .await
            .unwrap_err(),
        set_payment_list(mnemonic, &[endpoint("Bad", "btc", "x")], true)
            .await
            .unwrap_err(),
        encrypted::parse_access(&format!("v1.zz.{key_hex}")).unwrap_err(),
        encrypted::open(&[0; 32], &parse_identity(KEY).unwrap(), "/pub/x", &[0; 40]).unwrap_err(),
    ];
    for error in errors {
        let mut messages = vec![error.to_string(), format!("{error:?}")];
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            messages.push(cause.to_string());
            source = cause.source();
        }
        for message in messages {
            for secret in [secret_hex, &secret_hex[1..], key_hex, "abandon", "abound"] {
                assert!(!message.contains(secret), "{message}");
            }
        }
    }
}

#[test]
fn test_registry_writes_match_paykit_wire_vectors() {
    let fixture = publishing_fixture();
    let vectors = &fixture["registry"];
    let list_for = |app_ids: &Value| {
        let endpoints: Vec<_> = app_ids
            .as_array()
            .unwrap()
            .iter()
            .map(|app_id| endpoint(app_id.as_str().unwrap(), "btc", "x"))
            .collect();
        publish::validate_endpoints(&endpoints).unwrap()
    };

    let mut created = PaykitAppRegistry::new(None);
    publish::register_missing_apps(&mut created, &list_for(&vectors["create"]["app_ids"])).unwrap();
    assert_eq!(
        paykit_lib::serialize_paykit_app_registry(&created).unwrap(),
        vectors["create"]["expected"].as_str().unwrap()
    );

    let merge = &vectors["merge"];
    let mut registry = parse_paykit_app_registry_json(merge["input"].as_str().unwrap()).unwrap();
    assert!(publish::register_missing_apps(&mut registry, &list_for(&merge["app_ids"])).unwrap());
    assert_eq!(
        paykit_lib::serialize_paykit_app_registry(&registry).unwrap(),
        merge["expected"].as_str().unwrap()
    );
}

#[test]
fn test_registry_noise_key_forms_match_shared_fixture() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../fixtures/discovery.json")).unwrap();
    for case in fixture["noise_public_keys"]["cases"].as_array().unwrap() {
        let mut registry = fixture["registry"].clone();
        registry["noise_public_key"] = case["value"].clone();
        let parsed = parse_paykit_app_registry_json(&registry.to_string());
        match case["z32"].as_str() {
            Some(z32) => {
                let parsed = parsed.unwrap_or_else(|error| panic!("{case}: {error}"));
                assert_eq!(parsed.noise_public_key().unwrap().z32(), z32, "{case}");
                let written = paykit_lib::serialize_paykit_app_registry(&parsed).unwrap();
                assert!(written.contains(&format!("\"noise_public_key\":\"{z32}\"")));
            }
            None => assert!(parsed.is_err(), "{case}"),
        }
    }
}

const HOMESERVER: &str = "5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";

fn homegate_body(signup_code: &str, homeserver: &str) -> String {
    json!({ "signupCode": signup_code, "homeserverPubky": homeserver }).to_string()
}

#[test]
fn test_signup_code_accepts_homegate_response() {
    let body = homegate_body("FAKE-CODE", HOMESERVER);
    let parsed = signup::parse_signup_code(pubky::StatusCode::OK, &body).unwrap();
    assert_eq!(parsed.code, "FAKE-CODE");
    assert_eq!(parsed.homeserver.z32(), HOMESERVER);
}

#[test]
fn test_signup_code_rate_limit_has_its_own_error() {
    let result = signup::parse_signup_code(pubky::StatusCode::TOO_MANY_REQUESTS, "limit");
    assert!(matches!(result, Err(Error::SignUpRateLimited)));
}

#[test]
fn test_signup_code_server_errors_are_homegate_errors() {
    let result = signup::parse_signup_code(pubky::StatusCode::INTERNAL_SERVER_ERROR, "down");
    assert!(matches!(result, Err(Error::Homegate(_))));
}

#[test]
fn test_signup_code_rejects_invalid_responses_without_quoting_them() {
    for body in [
        "not json".to_owned(),
        "null".to_owned(),
        "[]".to_owned(),
        json!({ "signupCode": "FAKE-CODE" }).to_string(),
        json!({ "homeserverPubky": HOMESERVER }).to_string(),
        homegate_body("", HOMESERVER),
        homegate_body("FAKE-CODE", "not-a-key"),
        homegate_body("FAKE-CODE", &format!("pubky://{HOMESERVER}")),
    ] {
        let Err(error) = signup::parse_signup_code(pubky::StatusCode::OK, &body) else {
            panic!("accepted {body}");
        };
        assert!(matches!(error, Error::Homegate(_)), "{body}");
        assert!(!error.to_string().contains("FAKE-CODE"), "{body}");
    }
}

#[test]
fn test_relay_answers_decide_whether_a_record_exists() {
    const OK: Option<pubky::StatusCode> = Some(pubky::StatusCode::OK);
    const NOT_FOUND: Option<pubky::StatusCode> = Some(pubky::StatusCode::NOT_FOUND);
    const UNAVAILABLE: Option<pubky::StatusCode> = Some(pubky::StatusCode::SERVICE_UNAVAILABLE);

    for held in [&[OK][..], &[NOT_FOUND, OK], &[None, OK], &[UNAVAILABLE, OK]] {
        assert!(signup::record_on_relays(held).unwrap(), "{held:?}");
    }
    assert!(!signup::record_on_relays(&[NOT_FOUND, NOT_FOUND]).unwrap());
    for unanswered in [
        &[NOT_FOUND, None][..],
        &[None, NOT_FOUND],
        &[NOT_FOUND, UNAVAILABLE],
        &[None, None],
    ] {
        let result = signup::record_on_relays(unanswered);
        assert!(matches!(result, Err(Error::SignUp(_))), "{unanswered:?}");
    }
}

#[test]
fn test_signup_failure_keeps_nothing_that_can_quote_the_code() {
    let quoted = "https://key/auth/grant/signup?signup_token=FAKE-CODE";
    let refused = pubky::Error::Request(pubky::errors::RequestError::Server {
        status: pubky::StatusCode::FORBIDDEN,
        message: format!("refused ({quoted})"),
    });
    let invalid = pubky::Error::Request(pubky::errors::RequestError::Validation {
        message: format!("failed ({quoted})"),
    });
    for (failure, expected) in [
        (&refused, "the homeserver returned status 403 Forbidden"),
        (&invalid, "the signup request failed"),
    ] {
        assert!(failure.to_string().contains("FAKE-CODE"));
        let error = signup::signup_failure(failure);
        assert!(matches!(&error, Error::SignUp(text) if text == expected));
        assert!(!format!("{error} {error:?}").contains("FAKE-CODE"));
    }
}
