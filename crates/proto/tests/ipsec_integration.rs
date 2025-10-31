//! IPSec Integration Tests
//!
//! End-to-end tests for complete IKEv2 + ESP protocol flows.
//! Tests the integration of all components working together.

#![cfg(feature = "ipsec")]

use fynx_proto::ipsec::{
    ikev2::{
        constants::ExchangeType,
        exchange::{IkeAuthExchange, IkeSaContext, IkeSaInitExchange},
        payload::{IdPayload, IdType, TrafficSelector, TrafficSelectorsPayload},
        proposal::{
            DhTransformId, EncrTransformId, PrfTransformId, Proposal, ProtocolId, Transform,
            TransformType,
        },
        state::IkeState,
    },
};

/// Helper function to create test IKE proposals
fn create_test_ike_proposal() -> Proposal {
    Proposal::new(1, ProtocolId::Ike)
        .add_transform(Transform::encr(EncrTransformId::AesGcm128))
        .add_transform(Transform::prf(PrfTransformId::HmacSha256))
        .add_transform(Transform::dh(DhTransformId::Group14))
}

/// Helper function to create test ESP proposals
fn create_test_esp_proposal() -> Proposal {
    Proposal::new(1, ProtocolId::Esp)
        .add_transform(Transform::encr(EncrTransformId::AesGcm128))
        .add_transform(Transform::new(TransformType::Esn, 0)) // No ESN
}

/// Helper function to create test traffic selectors
fn create_test_traffic_selectors() -> TrafficSelectorsPayload {
    TrafficSelectorsPayload {
        selectors: vec![TrafficSelector::ipv4_any()],
    }
}

//
// Test Cases - Basic IKEv2 Handshake Flow
//

#[test]
fn test_basic_ike_sa_init_exchange() {
    // Setup: create initiator and responder contexts
    let mut ctx_i = IkeSaContext::new_initiator([0x01; 8]);
    let mut ctx_r = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);

    // Create proposals
    let proposals = vec![create_test_ike_proposal()];

    // Initiator: create IKE_SA_INIT request
    let dh_i = vec![0xAA; 256];
    let nonce_i = vec![0x11; 32];

    let init_req = IkeSaInitExchange::create_request(
        &mut ctx_i,
        proposals.clone(),
        dh_i.clone(),
        nonce_i.clone(),
        None,
        None,
    )
    .expect("Failed to create IKE_SA_INIT request");

    // Verify initiator state
    assert_eq!(ctx_i.state, IkeState::InitSent);
    assert_eq!(init_req.header.exchange_type, ExchangeType::IkeSaInit);
    assert!(init_req.header.flags.is_initiator());

    // Responder: process request
    IkeSaInitExchange::process_request(&mut ctx_r, &init_req, &proposals)
        .expect("Failed to process IKE_SA_INIT request");

    // Responder: create response
    let dh_r = vec![0xBB; 256];
    let nonce_r = vec![0x22; 32];

    let init_resp = IkeSaInitExchange::create_response(
        &mut ctx_r,
        &init_req.header,
        proposals[0].clone(),
        dh_r.clone(),
        nonce_r.clone(),
        None,
        None,
    )
    .expect("Failed to create IKE_SA_INIT response");

    // Verify responder state
    assert_eq!(ctx_r.state, IkeState::InitDone);

    // Initiator: process response
    IkeSaInitExchange::process_response(&mut ctx_i, &init_resp)
        .expect("Failed to process IKE_SA_INIT response");

    // Verify both contexts are in InitDone state
    assert_eq!(ctx_i.state, IkeState::InitDone);
    assert!(ctx_i.selected_proposal.is_some());
    assert!(ctx_i.nonce_i.is_some());
    assert!(ctx_i.nonce_r.is_some());
}

#[test]
fn test_full_ike_handshake() {
    use fynx_proto::ipsec::crypto::PrfAlgorithm;

    // ===== Phase 1: IKE_SA_INIT =====

    let mut ctx_i = IkeSaContext::new_initiator([0x01; 8]);
    let mut ctx_r = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);

    let proposals = vec![create_test_ike_proposal()];

    // Initiator sends IKE_SA_INIT request
    let init_req = IkeSaInitExchange::create_request(
        &mut ctx_i,
        proposals.clone(),
        vec![0xAA; 256], // DH public key
        vec![0x11; 32],  // Nonce
        None,
        None,
    )
    .expect("Failed to create request");

    let init_req_bytes = init_req.to_bytes();

    // Responder processes and responds
    IkeSaInitExchange::process_request(&mut ctx_r, &init_req, &proposals)
        .expect("Failed to process request");

    let init_resp = IkeSaInitExchange::create_response(
        &mut ctx_r,
        &init_req.header,
        proposals[0].clone(),
        vec![0xBB; 256],
        vec![0x22; 32],
        None,
        None,
    )
    .expect("Failed to create response");

    let init_resp_bytes = init_resp.to_bytes();

    // Initiator processes response
    IkeSaInitExchange::process_response(&mut ctx_i, &init_resp)
        .expect("Failed to process response");

    // Both should be in InitDone state
    assert_eq!(ctx_i.state, IkeState::InitDone);
    assert_eq!(ctx_r.state, IkeState::InitDone);

    // ===== Set up shared secret and derive keys =====

    let shared_secret = vec![0xDD; 256];
    ctx_i.shared_secret = Some(shared_secret.clone());
    ctx_r.shared_secret = Some(shared_secret.clone());

    // Both sides derive keys independently (should get same result)
    ctx_i
        .derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
        .expect("Initiator key derivation failed");

    ctx_r
        .derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
        .expect("Responder key derivation failed");

    // Verify keys are derived
    assert!(ctx_i.sk_d.is_some());
    assert!(ctx_i.sk_ei.is_some());
    assert!(ctx_r.sk_d.is_some());
    assert!(ctx_r.sk_ei.is_some());

    // Verify both sides derived the same keys
    assert_eq!(ctx_i.sk_d, ctx_r.sk_d, "SK_d mismatch");
    assert_eq!(ctx_i.sk_ai, ctx_r.sk_ai, "SK_ai mismatch");
    assert_eq!(ctx_i.sk_ar, ctx_r.sk_ar, "SK_ar mismatch");
    assert_eq!(ctx_i.sk_ei, ctx_r.sk_ei, "SK_ei mismatch");
    assert_eq!(ctx_i.sk_er, ctx_r.sk_er, "SK_er mismatch");
    assert_eq!(ctx_i.sk_pi, ctx_r.sk_pi, "SK_pi mismatch");
    assert_eq!(ctx_i.sk_pr, ctx_r.sk_pr, "SK_pr mismatch");

    // Verify nonces are set correctly
    assert_eq!(ctx_i.nonce_i, ctx_r.nonce_i, "nonce_i mismatch");
    assert_eq!(ctx_i.nonce_r, ctx_r.nonce_r, "nonce_r mismatch");

    // ===== Phase 2: IKE_AUTH =====

    let psk = b"test-psk-12345678";
    let id_i = IdPayload {
        id_type: IdType::Ipv4Addr,
        data: vec![192, 168, 1, 1],
    };
    let id_r = IdPayload {
        id_type: IdType::Ipv4Addr,
        data: vec![192, 168, 1, 2],
    };

    let child_proposals = vec![create_test_esp_proposal()];
    let ts_i = create_test_traffic_selectors();
    let ts_r = create_test_traffic_selectors();

    // Initiator creates IKE_AUTH request
    let auth_req = IkeAuthExchange::create_request(
        &mut ctx_i,
        &init_req_bytes,
        id_i.clone(),
        psk,
        child_proposals.clone(),
        ts_i.clone(),
        ts_r.clone(),
    )
    .expect("Failed to create IKE_AUTH request");

    assert_eq!(ctx_i.state, IkeState::AuthSent);
    assert_eq!(auth_req.header.exchange_type, ExchangeType::IkeAuth);

    // Responder processes request
    let (peer_id_i, selected_child, ts_i_resp, ts_r_resp) = IkeAuthExchange::process_request(
        &mut ctx_r,
        &init_req_bytes,
        &auth_req,
        psk,
        &child_proposals,
    )
    .expect("Failed to process IKE_AUTH request");

    assert_eq!(peer_id_i.data, vec![192, 168, 1, 1]);

    // Responder creates response
    let auth_resp = IkeAuthExchange::create_response(
        &mut ctx_r,
        &init_resp_bytes,
        &auth_req,
        id_r.clone(),
        psk,
        selected_child,
        ts_i_resp,
        ts_r_resp,
    )
    .expect("Failed to create IKE_AUTH response");

    assert_eq!(ctx_r.state, IkeState::Established);

    // Initiator processes response
    let (peer_id_r, _, _, _) = IkeAuthExchange::process_response(
        &mut ctx_i,
        &init_resp_bytes,
        &auth_resp,
        psk,
    )
    .expect("Failed to process IKE_AUTH response");

    assert_eq!(ctx_i.state, IkeState::Established);
    assert_eq!(peer_id_r.data, vec![192, 168, 1, 2]);

    // ===== Verification =====

    // Both sides should be fully established
    assert_eq!(ctx_i.state, IkeState::Established);
    assert_eq!(ctx_r.state, IkeState::Established);

    // Both should have matching SPIs
    assert_eq!(ctx_i.initiator_spi, ctx_r.initiator_spi);
    assert_eq!(ctx_i.responder_spi, ctx_r.responder_spi);

    // Both should have matching proposals
    assert!(ctx_i.selected_proposal.is_some());
    assert!(ctx_r.selected_proposal.is_some());
}

//
// Test Cases - State Machine Validation
//

#[test]
fn test_invalid_state_transitions() {
    let mut ctx = IkeSaContext::new_initiator([0x01; 8]);

    // Cannot go directly to Established from Idle
    assert!(ctx.transition_to(IkeState::Established).is_err());

    // Valid transition
    assert!(ctx.transition_to(IkeState::InitSent).is_ok());
    assert_eq!(ctx.state, IkeState::InitSent);

    // Cannot go back to Idle
    assert!(ctx.transition_to(IkeState::Idle).is_err());
}

#[test]
fn test_message_id_sequencing() {
    let mut ctx = IkeSaContext::new_initiator([0x01; 8]);

    assert_eq!(ctx.message_id, 0);
    assert_eq!(ctx.next_message_id(), 0);
    assert_eq!(ctx.message_id, 1);
    assert_eq!(ctx.next_message_id(), 1);
    assert_eq!(ctx.message_id, 2);
}

//
// Test Cases - Proposal Negotiation
//

#[test]
fn test_proposal_selection() {
    let mut ctx_i = IkeSaContext::new_initiator([0x01; 8]);
    let mut ctx_r = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);

    // Offer multiple proposals
    let proposals = vec![
        // Offer 1: AES-256-GCM
        Proposal::new(1, ProtocolId::Ike)
            .add_transform(Transform::new(TransformType::Encr, 19)) // AES-256-GCM
            .add_transform(Transform::prf(PrfTransformId::HmacSha256))
            .add_transform(Transform::dh(DhTransformId::Group14)),
        // Offer 2: AES-128-GCM
        Proposal::new(2, ProtocolId::Ike)
            .add_transform(Transform::encr(EncrTransformId::AesGcm128))
            .add_transform(Transform::prf(PrfTransformId::HmacSha256))
            .add_transform(Transform::dh(DhTransformId::Group14)),
    ];

    // Create request with multiple proposals
    let init_req = IkeSaInitExchange::create_request(
        &mut ctx_i,
        proposals.clone(),
        vec![0xAA; 256],
        vec![0x11; 32],
        None,
        None,
    )
    .expect("Failed to create request");

    // Responder should select one proposal
    IkeSaInitExchange::process_request(&mut ctx_r, &init_req, &proposals)
        .expect("Failed to process request");

    assert!(ctx_r.selected_proposal.is_some());
}

//
// Test Cases - Error Handling
//

#[test]
fn test_create_request_invalid_state() {
    let mut ctx = IkeSaContext::new_initiator([0x01; 8]);
    ctx.state = IkeState::InitSent; // Wrong state

    let result = IkeSaInitExchange::create_request(
        &mut ctx,
        vec![create_test_ike_proposal()],
        vec![0xAA; 256],
        vec![0x11; 32],
        None,
        None,
    );

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid state"));
}

#[test]
fn test_ike_auth_without_keys() {
    let mut ctx_i = IkeSaContext::new_initiator([0x01; 8]);
    ctx_i.state = IkeState::InitDone;
    ctx_i.responder_spi = [0x02; 8];
    ctx_i.selected_proposal = Some(create_test_ike_proposal());
    ctx_i.nonce_r = Some(vec![0x22; 32]);
    // Missing: derived keys (sk_pi, sk_ei, etc.)

    let id_i = IdPayload {
        id_type: IdType::Ipv4Addr,
        data: vec![192, 168, 1, 1],
    };

    let result = IkeAuthExchange::create_request(
        &mut ctx_i,
        &[0xAA; 100],
        id_i,
        b"test-psk",
        vec![create_test_esp_proposal()],
        create_test_traffic_selectors(),
        create_test_traffic_selectors(),
    );

    assert!(result.is_err());
}

//
// Test Cases - Key Derivation
//

#[test]
fn test_key_derivation() {
    use fynx_proto::ipsec::crypto::PrfAlgorithm;

    let mut ctx = IkeSaContext::new_initiator([0x01; 8]);
    ctx.responder_spi = [0x02; 8];
    ctx.nonce_i = Some(vec![0x11; 32]);
    ctx.nonce_r = Some(vec![0x22; 32]);
    ctx.shared_secret = Some(vec![0xDD; 256]);

    // Derive keys
    ctx.derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
        .expect("Key derivation failed");

    // Verify all keys are derived
    assert!(ctx.sk_d.is_some());
    assert!(ctx.sk_ai.is_some());
    assert!(ctx.sk_ar.is_some());
    assert!(ctx.sk_ei.is_some());
    assert!(ctx.sk_er.is_some());
    assert!(ctx.sk_pi.is_some());
    assert!(ctx.sk_pr.is_some());

    // Keys should have correct lengths (for AES-GCM-128)
    assert_eq!(ctx.sk_ei.as_ref().unwrap().len(), 16);
    assert_eq!(ctx.sk_er.as_ref().unwrap().len(), 16);
}

#[test]
fn test_key_derivation_missing_nonce() {
    use fynx_proto::ipsec::crypto::PrfAlgorithm;

    let mut ctx = IkeSaContext::new_initiator([0x01; 8]);
    ctx.responder_spi = [0x02; 8];
    ctx.nonce_i = Some(vec![0x11; 32]);
    // Missing: nonce_r
    ctx.shared_secret = Some(vec![0xDD; 256]);

    let result = ctx.derive_keys(PrfAlgorithm::HmacSha256, 16, 16);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("nonce not set"));
}

//
// Test Cases - Encryption/Decryption
//

#[test]
fn test_sk_payload_encryption_keys() {
    use fynx_proto::ipsec::crypto::PrfAlgorithm;

    let mut ctx_i = IkeSaContext::new_initiator([0x01; 8]);
    ctx_i.responder_spi = [0x02; 8];
    ctx_i.nonce_i = Some(vec![0x01; 32]);
    ctx_i.nonce_r = Some(vec![0x02; 32]);
    ctx_i.shared_secret = Some(vec![0x03; 256]);

    ctx_i
        .derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
        .expect("Key derivation failed");

    // Initiator should use SK_ei for sending, SK_er for receiving
    let send_key = ctx_i.get_send_encryption_key();
    let recv_key = ctx_i.get_recv_encryption_key();

    assert!(send_key.is_some());
    assert!(recv_key.is_some());
    assert_eq!(send_key.unwrap().len(), 16);
    assert_eq!(recv_key.unwrap().len(), 16);

    // Responder context should use opposite keys
    let mut ctx_r = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);
    ctx_r.nonce_i = Some(vec![0x01; 32]);
    ctx_r.nonce_r = Some(vec![0x02; 32]);
    ctx_r.shared_secret = Some(vec![0x03; 256]);

    ctx_r
        .derive_keys(PrfAlgorithm::HmacSha256, 16, 16)
        .expect("Key derivation failed");

    let resp_send_key = ctx_r.get_send_encryption_key();
    let resp_recv_key = ctx_r.get_recv_encryption_key();

    // Responder's send key should match initiator's recv key
    assert_eq!(resp_send_key, recv_key);
    // Responder's recv key should match initiator's send key
    assert_eq!(resp_recv_key, send_key);
}
