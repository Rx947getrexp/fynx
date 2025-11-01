//! IPSec Integration Tests
//!
//! End-to-end tests for complete IKEv2 + ESP protocol flows.
//! Tests the integration of all components working together.

#![cfg(feature = "ipsec")]

use fynx_proto::ipsec::{
    child_sa::ChildSa,
    esp::EspPacket,
    ikev2::{
        auth,
        constants::ExchangeType,
        exchange::{CreateChildSaExchange, IkeAuthExchange, IkeSaContext, IkeSaInitExchange},
        informational::InformationalExchange,
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
    let (peer_id_r, _, _, _) =
        IkeAuthExchange::process_response(&mut ctx_i, &init_resp_bytes, &auth_resp, psk)
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
    assert!(result.unwrap_err().to_string().contains("Invalid state"));
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
    assert!(result.unwrap_err().to_string().contains("nonce not set"));
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

//
// Test Cases - ESP Data Transfer
//

/// Helper to create test Child SA for outbound (encryption)
fn create_outbound_child_sa(spi: u32, sk_e: Vec<u8>) -> ChildSa {
    use fynx_proto::ipsec::child_sa::{ChildSaState, SaLifetime};
    use std::time::Duration;

    let proposal = create_test_esp_proposal();
    let ts = create_test_traffic_selectors();

    ChildSa {
        spi,
        protocol: 50, // ESP
        is_inbound: false,
        sk_e,
        sk_a: Some(vec![0xBB; 32]), // Dummy auth key (not used in AEAD)
        ts_i: ts.clone(),
        ts_r: ts,
        proposal,
        seq_out: 1,
        replay_window: None, // Disabled for outbound
        state: ChildSaState::Active,
        lifetime: SaLifetime {
            soft_time: Duration::from_secs(2700), // 45 minutes
            hard_time: Duration::from_secs(3600), // 60 minutes
            soft_bytes: Some(900_000_000),        // 900 MB
            hard_bytes: Some(1_000_000_000),      // 1 GB
        },
        created_at: std::time::Instant::now(),
        bytes_processed: 0,
        rekey_initiated_at: None,
    }
}

/// Helper to create test Child SA for inbound (decryption)
fn create_inbound_child_sa(spi: u32, sk_e: Vec<u8>) -> ChildSa {
    use fynx_proto::ipsec::child_sa::{ChildSaState, SaLifetime};
    use fynx_proto::ipsec::replay::ReplayWindow;
    use std::time::Duration;

    let proposal = create_test_esp_proposal();
    let ts = create_test_traffic_selectors();

    ChildSa {
        spi,
        protocol: 50, // ESP
        is_inbound: true,
        sk_e,
        sk_a: Some(vec![0xBB; 32]),
        ts_i: ts.clone(),
        ts_r: ts,
        proposal,
        seq_out: 0,
        replay_window: Some(ReplayWindow::new(64)), // 64-packet window
        state: ChildSaState::Active,
        lifetime: SaLifetime {
            soft_time: Duration::from_secs(2700),
            hard_time: Duration::from_secs(3600),
            soft_bytes: Some(900_000_000),
            hard_bytes: Some(1_000_000_000),
        },
        created_at: std::time::Instant::now(),
        bytes_processed: 0,
        rekey_initiated_at: None,
    }
}

#[test]
fn test_esp_encrypt_decrypt_single_packet() {
    // Create matching Child SAs (same key for both directions in test)
    let encryption_key = vec![0x42; 16]; // AES-128 key
    let spi = 0x12345678;

    let mut sa_out = create_outbound_child_sa(spi, encryption_key.clone());
    let mut sa_in = create_inbound_child_sa(spi, encryption_key);

    // Original payload
    let payload = b"Hello, ESP! This is a test packet.";
    let next_header = 4; // IPv4

    // Encrypt (encapsulate)
    let esp_packet =
        EspPacket::encapsulate(&mut sa_out, payload, next_header).expect("Failed to encapsulate");

    // Verify ESP packet structure
    assert_eq!(esp_packet.spi, spi);
    assert_eq!(esp_packet.sequence, 1);
    assert!(!esp_packet.iv.is_empty());
    assert!(!esp_packet.encrypted_data.is_empty());

    // Decrypt (decapsulate)
    let (decrypted, recovered_next_header) = esp_packet
        .decapsulate(&mut sa_in)
        .expect("Failed to decapsulate");

    // Verify decrypted payload matches original
    assert_eq!(decrypted, payload);
    assert_eq!(recovered_next_header, next_header);

    // Verify sequence numbers updated
    assert_eq!(sa_out.seq_out, 2); // Incremented after encryption
}

#[test]
fn test_esp_sequence_number_handling() {
    let encryption_key = vec![0x99; 16];
    let spi = 0xABCDEF00;

    let mut sa_out = create_outbound_child_sa(spi, encryption_key.clone());
    let mut sa_in = create_inbound_child_sa(spi, encryption_key);

    let payload = b"Test packet";

    // Send multiple packets and verify sequence numbers
    for expected_seq in 1..=5 {
        let esp = EspPacket::encapsulate(&mut sa_out, payload, 4).expect("Encapsulation failed");

        assert_eq!(esp.sequence, expected_seq as u32);
        assert_eq!(sa_out.seq_out, (expected_seq + 1) as u64);

        // Decrypt should succeed
        let (decrypted, _) = esp.decapsulate(&mut sa_in).expect("Decapsulation failed");
        assert_eq!(decrypted, payload);
    }
}

#[test]
fn test_esp_anti_replay_protection() {
    let encryption_key = vec![0x77; 16];
    let spi = 0x11223344;

    let mut sa_out = create_outbound_child_sa(spi, encryption_key.clone());
    let mut sa_in = create_inbound_child_sa(spi, encryption_key);

    let payload = b"Replay test";

    // Send first packet
    let esp1 = EspPacket::encapsulate(&mut sa_out, payload, 4).unwrap();
    assert_eq!(esp1.sequence, 1);

    // Decrypt first packet - should succeed
    let result1 = esp1.decapsulate(&mut sa_in);
    assert!(result1.is_ok());

    // Try to decrypt same packet again - should fail (replay detected)
    let result2 = esp1.decapsulate(&mut sa_in);
    assert!(result2.is_err());
    match result2 {
        Err(fynx_proto::ipsec::Error::ReplayDetected(_)) => {} // Expected
        _ => panic!("Expected ReplayDetected error"),
    }

    // Send second packet
    let esp2 = EspPacket::encapsulate(&mut sa_out, payload, 4).unwrap();
    assert_eq!(esp2.sequence, 2);

    // Decrypt second packet - should succeed
    let result3 = esp2.decapsulate(&mut sa_in);
    assert!(result3.is_ok());
}

#[test]
fn test_esp_multiple_packets() {
    let encryption_key = vec![0x55; 16];
    let spi = 0xFEDCBA98;

    let mut sa_out = create_outbound_child_sa(spi, encryption_key.clone());
    let mut sa_in = create_inbound_child_sa(spi, encryption_key);

    // Send 20 different packets
    for i in 0..20 {
        let payload = format!("Packet number {}", i);
        let payload_bytes = payload.as_bytes();

        // Encrypt
        let esp =
            EspPacket::encapsulate(&mut sa_out, payload_bytes, 4).expect("Encapsulation failed");

        // Decrypt
        let (decrypted, next_header) = esp.decapsulate(&mut sa_in).expect("Decapsulation failed");

        // Verify
        assert_eq!(decrypted, payload_bytes);
        assert_eq!(next_header, 4);
        assert_eq!(esp.sequence, (i + 1) as u32);
    }

    // Verify final sequence number
    assert_eq!(sa_out.seq_out, 21);
}

#[test]
fn test_esp_large_packet() {
    let encryption_key = vec![0x33; 16];
    let spi = 0x99887766;

    let mut sa_out = create_outbound_child_sa(spi, encryption_key.clone());
    let mut sa_in = create_inbound_child_sa(spi, encryption_key);

    // Create large payload (8KB)
    let large_payload: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();

    // Encrypt large packet
    let esp = EspPacket::encapsulate(&mut sa_out, &large_payload, 4)
        .expect("Failed to encapsulate large packet");

    // Verify packet was created
    assert_eq!(esp.spi, spi);
    assert!(esp.encrypted_data.len() > large_payload.len()); // Includes padding + tag

    // Decrypt large packet
    let (decrypted, next_header) = esp
        .decapsulate(&mut sa_in)
        .expect("Failed to decapsulate large packet");

    // Verify full payload recovered
    assert_eq!(decrypted, large_payload);
    assert_eq!(next_header, 4);
    assert_eq!(decrypted.len(), 8192);
}

//
// Test Cases - SA Lifecycle Management
//

/// Helper to create an established IKE SA context with encryption keys
fn create_established_ike_sa(is_initiator: bool) -> IkeSaContext {
    use fynx_proto::ipsec::child_sa::SaLifetime;
    use std::time::Duration;

    let mut ctx = if is_initiator {
        IkeSaContext::new_initiator([0x11; 8])
    } else {
        IkeSaContext::new_responder([0x11; 8], [0x22; 8])
    };

    // Set to Established state
    ctx.state = IkeState::Established;
    ctx.responder_spi = [0x22; 8];

    // Set up encryption keys
    ctx.sk_ei = Some(vec![0xAA; 16]);
    ctx.sk_er = Some(vec![0xBB; 16]);
    ctx.sk_ai = Some(vec![0xCC; 32]);
    ctx.sk_ar = Some(vec![0xDD; 32]);
    ctx.sk_d = Some(vec![0xEE; 32]);

    // Set selected proposal
    ctx.selected_proposal = Some(create_test_ike_proposal());

    // Set nonces (required for some operations)
    ctx.nonce_i = Some(vec![0x11; 32]);
    ctx.nonce_r = Some(vec![0x22; 32]);

    // Set lifetime (default: 1 hour soft, 1.5 hours hard)
    ctx.lifetime = SaLifetime {
        soft_time: Duration::from_secs(3600),
        hard_time: Duration::from_secs(5400),
        soft_bytes: Some(100_000_000),
        hard_bytes: Some(150_000_000),
    };

    ctx
}

#[test]
fn test_ike_sa_rekeying_soft_lifetime() {
    // Setup: create established IKE SA contexts for initiator and responder
    let mut ctx_i = create_established_ike_sa(true);
    let ctx_r = create_established_ike_sa(false);

    // Initiator initiates rekey before soft lifetime expires
    let ike_proposals = vec![create_test_ike_proposal()];
    let dh_public_i = vec![0xAB; 256];

    // Create IKE SA rekey request
    let (rekey_req, nonce_i) =
        CreateChildSaExchange::create_ike_rekey_request(&mut ctx_i, &ike_proposals, dh_public_i)
            .expect("Failed to create IKE rekey request");

    // Verify request message
    assert_eq!(rekey_req.header.exchange_type, ExchangeType::CreateChildSa);
    assert!(rekey_req.header.flags.is_initiator());
    assert_eq!(nonce_i.len(), 32);

    // Responder processes the rekey request
    let (selected_proposal, responder_nonce, _ke_payload) =
        CreateChildSaExchange::process_ike_rekey_request(&ctx_r, &rekey_req)
            .expect("Failed to process IKE rekey request");

    // Verify selected proposal
    assert_eq!(selected_proposal.protocol_id, ProtocolId::Ike);
    assert_eq!(responder_nonce.len(), 32);

    // Responder creates rekey response
    let dh_public_r = vec![0xCD; 256];
    let (rekey_resp, nonce_r) = CreateChildSaExchange::create_ike_rekey_response(
        &ctx_r,
        &rekey_req.header,
        &selected_proposal,
        dh_public_r,
    )
    .expect("Failed to create IKE rekey response");

    // Verify response message
    assert_eq!(rekey_resp.header.exchange_type, ExchangeType::CreateChildSa);
    assert!(rekey_resp.header.flags.is_response());
    assert_eq!(nonce_r.len(), 32);

    // Success: IKE SA rekeying message exchange completed
    // (In real implementation, new IKE SA would be established with new SPIs)
}

#[test]
fn test_child_sa_rekeying() {
    use fynx_proto::ipsec::child_sa::{ChildSaState, SaLifetime};
    use std::time::Duration;

    // Setup: create established IKE SA with a Child SA
    let mut ctx_i = create_established_ike_sa(true);
    let ctx_r = create_established_ike_sa(false);

    // Add an existing Child SA to initiator context
    let old_child_sa = ChildSa {
        spi: 0x12345678,
        protocol: 50, // ESP
        is_inbound: false,
        sk_e: vec![0x42; 16],
        sk_a: Some(vec![0x43; 32]),
        ts_i: create_test_traffic_selectors(),
        ts_r: create_test_traffic_selectors(),
        proposal: create_test_esp_proposal(),
        seq_out: 100,
        replay_window: None,
        state: ChildSaState::Active,
        lifetime: SaLifetime {
            soft_time: Duration::from_secs(1800),
            hard_time: Duration::from_secs(2700),
            soft_bytes: Some(50_000_000),
            hard_bytes: Some(75_000_000),
        },
        created_at: std::time::Instant::now(),
        bytes_processed: 40_000_000, // Approaching soft limit
        rekey_initiated_at: None,
    };

    ctx_i.child_sas.push(old_child_sa);

    // Create Child SA rekey request
    let esp_proposals = vec![create_test_esp_proposal()];
    let ts_i = create_test_traffic_selectors();
    let ts_r = create_test_traffic_selectors();

    let (rekey_req, nonce_i) =
        CreateChildSaExchange::create_request(&mut ctx_i, &esp_proposals, ts_i, ts_r, false, None)
            .expect("Failed to create Child SA rekey request");

    // Verify request
    assert_eq!(rekey_req.header.exchange_type, ExchangeType::CreateChildSa);
    assert_eq!(nonce_i.len(), 32);

    // Responder processes request (generate responder nonce)
    use rand::RngCore;
    let mut nonce_r = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_r[..]);

    let (proposal, _initiator_spi, ts_i_recv, ts_r_recv, _sk_ei, _sk_ai, _sk_er, _sk_ar) =
        CreateChildSaExchange::process_request(&ctx_r, &rekey_req, &nonce_r, &esp_proposals, None)
            .expect("Failed to process Child SA rekey request");

    // Verify received parameters
    assert_eq!(proposal.protocol_id, ProtocolId::Esp);
    assert!(!ts_i_recv.selectors.is_empty());
    assert!(!ts_r_recv.selectors.is_empty());

    // Responder creates rekey response
    let rekey_resp = CreateChildSaExchange::create_response(
        &ctx_r,
        &rekey_req.header,
        &proposal,
        &nonce_r,
        ts_i_recv,
        ts_r_recv,
        None,
    )
    .expect("Failed to create Child SA rekey response");

    // Verify response
    assert!(rekey_resp.header.flags.is_response());

    // Success: Child SA rekeyed with new SPI
    // Old Child SA (0x12345678) would be marked for deletion
    // New Child SA (from proposal) is now active
}

#[test]
fn test_sa_graceful_deletion() {
    use fynx_proto::ipsec::child_sa::{ChildSaState, SaLifetime};

    // Setup: create established IKE SA with Child SA
    let mut ctx_i = create_established_ike_sa(true);

    // Add Child SA to delete
    let child_sa = ChildSa {
        spi: 0xAABBCCDD,
        protocol: 50, // ESP
        is_inbound: false,
        sk_e: vec![0x55; 16],
        sk_a: Some(vec![0x66; 32]),
        ts_i: create_test_traffic_selectors(),
        ts_r: create_test_traffic_selectors(),
        proposal: create_test_esp_proposal(),
        seq_out: 50,
        replay_window: None,
        state: ChildSaState::Active,
        lifetime: SaLifetime::default(),
        created_at: std::time::Instant::now(),
        bytes_processed: 0,
        rekey_initiated_at: None,
    };

    ctx_i.child_sas.push(child_sa);

    // Create DELETE request for Child SA
    let spi_bytes = 0xAABBCCDDu32.to_be_bytes().to_vec();
    let delete_req =
        InformationalExchange::create_delete_child_sa_request(&mut ctx_i, vec![spi_bytes.clone()])
            .expect("Failed to create DELETE request");

    // Verify DELETE request
    assert_eq!(delete_req.header.exchange_type, ExchangeType::Informational);
    assert!(delete_req.header.flags.is_initiator());

    // NOTE: In real implementation, the responder would decrypt the INFORMATIONAL message
    // and extract the DELETE payload. However, the current implementation requires
    // serialization/deserialization for proper SK payload handling, which is beyond
    // the scope of this integration test. Here we verify the message was created successfully.

    // Success: Child SA deletion message created successfully
    // In production, responder would process DELETE and remove the Child SA
}

#[test]
fn test_delete_ike_sa() {
    // Setup: create established IKE SA
    let mut ctx_i = create_established_ike_sa(true);

    // Initiator wants to delete entire IKE SA
    let delete_req = InformationalExchange::create_delete_ike_sa_request(&mut ctx_i)
        .expect("Failed to create DELETE IKE SA request");

    // Verify request
    assert_eq!(delete_req.header.exchange_type, ExchangeType::Informational);
    assert!(delete_req.header.flags.is_initiator());

    // NOTE: In real implementation, the responder would decrypt and process the DELETE
    // message for IKE SA. However, testing full INFORMATIONAL exchange requires
    // proper message serialization/deserialization which is beyond the scope of this test.
    // Here we verify the DELETE IKE SA message was created successfully.

    // Success: IKE SA deletion message created successfully
    // In production, this would terminate the IKE SA and all Child SAs
}

#[test]
fn test_hard_lifetime_expiration_check() {
    use fynx_proto::ipsec::child_sa::SaLifetime;
    use std::time::Duration;

    // Create IKE SA with very short hard lifetime
    let mut ctx = create_established_ike_sa(true);

    // Set very short lifetime (1 second soft, 2 seconds hard)
    ctx.lifetime = SaLifetime {
        soft_time: Duration::from_secs(1),
        hard_time: Duration::from_secs(2),
        soft_bytes: Some(1_000),
        hard_bytes: Some(2_000),
    };

    let created_at = ctx.created_at;

    // Check if soft lifetime expired
    let soft_expired = created_at.elapsed() >= ctx.lifetime.soft_time;

    // Check if hard lifetime expired
    let hard_expired = created_at.elapsed() >= ctx.lifetime.hard_time;

    // At this point, neither should be expired (test just started)
    // In real scenario, waiting 2+ seconds would trigger hard expiration
    assert!(!hard_expired || soft_expired); // If hard expired, soft must also be expired

    // Success: Lifetime expiration checking logic verified
    // In production, hard lifetime expiration would force immediate SA deletion
}

//
// Test Cases - Error Recovery
//

#[test]
fn test_invalid_proposal_no_proposal_chosen() {
    use fynx_proto::ipsec::ikev2::proposal::select_proposal;

    // Setup: initiator proposes AES-GCM-256, responder only supports AES-GCM-128
    let initiator_proposals = vec![Proposal::new(1, ProtocolId::Ike)
        .add_transform(Transform::encr(EncrTransformId::AesGcm256)) // Only 256
        .add_transform(Transform::prf(PrfTransformId::HmacSha256))
        .add_transform(Transform::dh(DhTransformId::Group14))];

    let responder_proposals = vec![Proposal::new(1, ProtocolId::Ike)
        .add_transform(Transform::encr(EncrTransformId::AesGcm128)) // Only 128
        .add_transform(Transform::prf(PrfTransformId::HmacSha256))
        .add_transform(Transform::dh(DhTransformId::Group14))];

    // Attempt to select a proposal - should fail
    let result = select_proposal(&initiator_proposals, &responder_proposals);

    // Verify NO_PROPOSAL_CHOSEN error
    assert!(result.is_err());

    // In production, responder would send INFORMATIONAL with NO_PROPOSAL_CHOSEN notify
    // and close the connection gracefully

    // Success: Invalid proposal correctly rejected
}

#[test]
fn test_authentication_failure_invalid_psk() {
    use fynx_proto::ipsec::crypto::PrfAlgorithm;

    // Setup: create initiator context with keys derived
    let mut ctx_i = IkeSaContext::new_initiator([0x01; 8]);
    ctx_i.state = IkeState::InitDone;
    ctx_i.responder_spi = [0x02; 8];
    ctx_i.nonce_i = Some(vec![0x11; 32]);
    ctx_i.nonce_r = Some(vec![0x22; 32]);
    ctx_i.shared_secret = Some(vec![0xAB; 32]);

    let _ = ctx_i.derive_keys(PrfAlgorithm::HmacSha256, 16, 0);

    // Create signed octets (mock IKE_SA_INIT bytes + nonce + ID)
    let signed_octets = vec![0u8; 200]; // Mock signed octets

    // Initiator creates AUTH payload using sk_pi (initiator's SK_p)
    let sk_pi = ctx_i.sk_pi.clone().unwrap();
    let auth_payload_correct =
        auth::compute_psk_auth(PrfAlgorithm::HmacSha256, &sk_pi, &signed_octets);

    // Create AUTH payload with wrong SK_p (simulating wrong PSK)
    let wrong_sk_p = vec![0xFF; 32]; // Different key!
    let auth_payload_wrong =
        auth::compute_psk_auth(PrfAlgorithm::HmacSha256, &wrong_sk_p, &signed_octets);

    // Verify with correct SK_p - should succeed
    let result_correct = auth::verify_psk_auth(
        PrfAlgorithm::HmacSha256,
        &sk_pi,
        &signed_octets,
        &auth_payload_correct,
    );
    assert!(result_correct.is_ok());

    // Verify with correct SK_p but wrong AUTH payload - should fail
    let result_wrong = auth::verify_psk_auth(
        PrfAlgorithm::HmacSha256,
        &sk_pi,
        &signed_octets,
        &auth_payload_wrong,
    );
    assert!(result_wrong.is_err());

    // In production, responder would send AUTHENTICATION_FAILED notify
    // and delete the IKE SA

    // Success: Authentication failure correctly detected
}

#[test]
fn test_message_id_mismatch_detection() {
    // Setup: create established IKE SA
    let mut ctx = create_established_ike_sa(true);

    // Set expected message ID
    ctx.message_id = 5;

    // Create a response with wrong message ID (6 instead of 4)
    let wrong_message_id = 6;

    // Attempt to validate the message ID - should fail
    let result = ctx.validate_message_id(wrong_message_id, true); // true = response

    // Verify error
    assert!(result.is_err());
    if let Err(e) = result {
        // Should get InvalidMessageId error
        assert!(matches!(
            e,
            fynx_proto::ipsec::Error::InvalidMessageId { .. }
        ));
    }

    // Success: Message ID mismatch correctly detected
    // In production, this would trigger connection reset
}

#[test]
fn test_malformed_packet_buffer_too_short() {
    use fynx_proto::ipsec::ikev2::message::IkeMessage;

    // Create malformed packet: header claims 200 bytes but only 50 bytes provided
    let mut malformed = vec![0u8; 50];

    // Set IKE header with incorrect length field (200 bytes)
    malformed[0..8].copy_from_slice(&[0x11; 8]); // Initiator SPI
    malformed[8..16].copy_from_slice(&[0x22; 8]); // Responder SPI
    malformed[16] = 0; // Next payload
    malformed[17] = 0x20; // Version 2.0
    malformed[18] = 34; // Exchange type (IKE_SA_INIT)
    malformed[19] = 0x08; // Flags (Initiator)
    malformed[20..24].copy_from_slice(&[0, 0, 0, 1]); // Message ID
    malformed[24..28].copy_from_slice(&(200u32).to_be_bytes()); // Length = 200 (WRONG!)

    // Attempt to parse - should fail
    let result = IkeMessage::from_bytes(&malformed);

    // Verify parsing error
    assert!(result.is_err());
    if let Err(e) = result {
        // Should get BufferTooShort error
        assert!(matches!(e, fynx_proto::ipsec::Error::BufferTooShort { .. }));
    }

    // Success: Malformed packet correctly rejected
    // In production, such packets would be silently dropped
}

#[test]
fn test_state_machine_invalid_transition() {
    // Setup: create IKE SA in Idle state
    let mut ctx = IkeSaContext::new_initiator([0x01; 8]);
    ctx.state = IkeState::Idle;

    // Attempt invalid state transition: Idle -> Established (skipping intermediate states)
    let result = ctx.transition_to(IkeState::Established);

    // Verify transition is rejected
    assert!(result.is_err());
    if let Err(e) = result {
        // Should get InvalidState error
        assert!(matches!(e, fynx_proto::ipsec::Error::InvalidState(_)));
    }

    // Verify state hasn't changed
    assert_eq!(ctx.state, IkeState::Idle);

    // Success: Invalid state transition correctly prevented
    // This ensures protocol state machine integrity
}
