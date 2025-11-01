//! IPSec Performance Benchmarks
//!
//! Benchmarks for IKEv2 handshake latency, ESP throughput, and memory usage.
//!
//! Run with: `cargo bench --features ipsec --bench ipsec_bench`

#![cfg(feature = "ipsec")]

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use fynx_proto::ipsec::{
    child_sa::{ChildSa, ChildSaState, SaLifetime},
    crypto::PrfAlgorithm,
    esp::EspPacket,
    ikev2::{
        exchange::{IkeAuthExchange, IkeSaContext, IkeSaInitExchange},
        payload::{IdPayload, IdType, TrafficSelector, TrafficSelectorsPayload},
        proposal::{
            DhTransformId, EncrTransformId, PrfTransformId, Proposal, ProtocolId, Transform,
            TransformType,
        },
    },
};
use std::time::Duration;

/// Create test IKE proposal
fn create_test_ike_proposal() -> Proposal {
    Proposal::new(1, ProtocolId::Ike)
        .add_transform(Transform::encr(EncrTransformId::AesGcm128))
        .add_transform(Transform::prf(PrfTransformId::HmacSha256))
        .add_transform(Transform::dh(DhTransformId::Group14))
}

/// Create test ESP proposal
fn create_test_esp_proposal() -> Proposal {
    Proposal::new(1, ProtocolId::Esp)
        .add_transform(Transform::encr(EncrTransformId::AesGcm128))
        .add_transform(Transform::new(TransformType::Esn, 0))
}

/// Create test traffic selectors
fn create_test_traffic_selectors() -> TrafficSelectorsPayload {
    TrafficSelectorsPayload {
        selectors: vec![TrafficSelector::ipv4_any()],
    }
}

/// Create a Child SA with derived keys for benchmarking
fn create_test_child_sa() -> ChildSa {
    let prf_alg = PrfAlgorithm::HmacSha256;
    let sk_d = vec![0xABu8; 32];
    let nonce_i = vec![0x11u8; 32];
    let nonce_r = vec![0x22u8; 32];

    let (sk_ei, sk_ai, _sk_er, _sk_ar) = fynx_proto::ipsec::child_sa::derive_child_sa_keys(
        prf_alg, &sk_d, &nonce_i, &nonce_r, None, 16, 0,
    );

    ChildSa {
        spi: 0x12345678,
        protocol: 50,
        is_inbound: false,
        sk_e: sk_ei,
        sk_a: Some(sk_ai),
        ts_i: create_test_traffic_selectors(),
        ts_r: create_test_traffic_selectors(),
        proposal: create_test_esp_proposal(),
        seq_out: 1,
        replay_window: None,
        state: ChildSaState::Active,
        lifetime: SaLifetime::default(),
        created_at: std::time::Instant::now(),
        bytes_processed: 0,
        rekey_initiated_at: None,
    }
}

/// Benchmark IKE_SA_INIT message creation
fn bench_ike_sa_init_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("ike_sa_init");

    group.bench_function("create_request", |b| {
        let mut ctx = IkeSaContext::new_initiator([0x01; 8]);
        let proposals = vec![create_test_ike_proposal()];
        let dh_public = vec![0xAA; 256];
        let nonce = vec![0x11; 32];

        b.iter(|| {
            black_box(
                IkeSaInitExchange::create_request(
                    &mut ctx,
                    proposals.clone(),
                    dh_public.clone(),
                    nonce.clone(),
                    None,
                    None,
                )
                .unwrap(),
            )
        });
    });

    group.finish();
}

/// Benchmark IKE_SA_INIT message processing
fn bench_ike_sa_init_process(c: &mut Criterion) {
    let mut group = c.benchmark_group("ike_sa_init");

    // Create a request to process
    let mut ctx_i = IkeSaContext::new_initiator([0x01; 8]);
    let proposals = vec![create_test_ike_proposal()];
    let init_req = IkeSaInitExchange::create_request(
        &mut ctx_i,
        proposals.clone(),
        vec![0xAA; 256],
        vec![0x11; 32],
        None,
        None,
    )
    .unwrap();

    group.bench_function("process_request", |b| {
        b.iter(|| {
            let mut ctx_r = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);
            black_box(
                IkeSaInitExchange::process_request(&mut ctx_r, &init_req, &proposals).unwrap(),
            )
        });
    });

    group.finish();
}

/// Benchmark key derivation
fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");

    group.bench_function("derive_ike_keys", |b| {
        let mut ctx = IkeSaContext::new_initiator([0x01; 8]);
        ctx.nonce_i = Some(vec![0x11; 32]);
        ctx.nonce_r = Some(vec![0x22; 32]);
        ctx.shared_secret = Some(vec![0xDD; 256]);
        ctx.selected_proposal = Some(create_test_ike_proposal());

        b.iter(|| {
            black_box(ctx.derive_keys(PrfAlgorithm::HmacSha256, 16, 16).unwrap());
            // Reset keys for next iteration
            ctx.sk_d = None;
            ctx.sk_ei = None;
            ctx.sk_er = None;
        });
    });

    group.bench_function("derive_child_sa_keys", |b| {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_d = vec![0xAB; 32];
        let nonce_i = vec![0x11; 32];
        let nonce_r = vec![0x22; 32];

        b.iter(|| {
            black_box(fynx_proto::ipsec::child_sa::derive_child_sa_keys(
                prf_alg, &sk_d, &nonce_i, &nonce_r, None, 16, 0,
            ))
        });
    });

    group.finish();
}

/// Benchmark ESP encryption throughput
fn bench_esp_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("esp_encryption");

    // Small packets (64 bytes)
    group.throughput(Throughput::Bytes(64));
    group.bench_function("encrypt_64bytes", |b| {
        let mut sa = create_test_child_sa();
        let data = vec![0x42u8; 64];

        b.iter(|| {
            let packet = black_box(EspPacket::encapsulate(&mut sa, &data, 4).unwrap());
            packet
        });
    });

    // Medium packets (512 bytes)
    group.throughput(Throughput::Bytes(512));
    group.bench_function("encrypt_512bytes", |b| {
        let mut sa = create_test_child_sa();
        let data = vec![0x42u8; 512];

        b.iter(|| {
            let packet = black_box(EspPacket::encapsulate(&mut sa, &data, 4).unwrap());
            packet
        });
    });

    // Large packets (1500 bytes - typical MTU)
    group.throughput(Throughput::Bytes(1500));
    group.bench_function("encrypt_1500bytes", |b| {
        let mut sa = create_test_child_sa();
        let data = vec![0x42u8; 1500];

        b.iter(|| {
            let packet = black_box(EspPacket::encapsulate(&mut sa, &data, 4).unwrap());
            packet
        });
    });

    group.finish();
}

/// Benchmark ESP decryption throughput
fn bench_esp_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("esp_decryption");

    // Small packets (64 bytes)
    group.throughput(Throughput::Bytes(64));
    group.bench_function("decrypt_64bytes", |b| {
        let mut sa_enc = create_test_child_sa();
        let mut sa_dec = create_test_child_sa();
        sa_dec.is_inbound = true;
        let data = vec![0x42u8; 64];
        let encrypted = EspPacket::encapsulate(&mut sa_enc, &data, 4).unwrap();

        b.iter(|| {
            let decrypted = black_box(encrypted.decapsulate(&mut sa_dec).unwrap());
            decrypted
        });
    });

    // Large packets (1500 bytes)
    group.throughput(Throughput::Bytes(1500));
    group.bench_function("decrypt_1500bytes", |b| {
        let mut sa_enc = create_test_child_sa();
        let mut sa_dec = create_test_child_sa();
        sa_dec.is_inbound = true;
        let data = vec![0x42u8; 1500];
        let encrypted = EspPacket::encapsulate(&mut sa_enc, &data, 4).unwrap();

        b.iter(|| {
            let decrypted = black_box(encrypted.decapsulate(&mut sa_dec).unwrap());
            decrypted
        });
    });

    group.finish();
}

/// Benchmark ESP serialization/deserialization
fn bench_esp_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("esp_serialization");

    let mut sa = create_test_child_sa();
    let data = vec![0x42u8; 1500];
    let packet = EspPacket::encapsulate(&mut sa, &data, 4).unwrap();

    group.bench_function("to_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(packet.to_bytes());
            bytes
        });
    });

    let packet_bytes = packet.to_bytes();
    group.bench_function("from_bytes", |b| {
        b.iter(|| {
            let parsed = black_box(EspPacket::from_bytes(&packet_bytes, 8, 16).unwrap());
            parsed
        });
    });

    group.finish();
}

/// Benchmark full IKE handshake
fn bench_full_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_handshake");
    group.sample_size(50); // Fewer samples due to complexity
    group.measurement_time(Duration::from_secs(10));

    group.bench_function("ike_sa_init_and_auth", |b| {
        b.iter(|| {
            // Setup
            let mut ctx_i = IkeSaContext::new_initiator([0x01; 8]);
            let mut ctx_r = IkeSaContext::new_responder([0x01; 8], [0x02; 8]);
            let proposals = vec![create_test_ike_proposal()];
            let child_proposals = vec![create_test_esp_proposal()];
            let psk = b"test-psk-secret";

            // IKE_SA_INIT
            let init_req = IkeSaInitExchange::create_request(
                &mut ctx_i,
                proposals.clone(),
                vec![0xAA; 256],
                vec![0x11; 32],
                None,
                None,
            )
            .unwrap();

            let init_req_bytes = init_req.to_bytes();

            IkeSaInitExchange::process_request(&mut ctx_r, &init_req, &proposals).unwrap();

            let init_resp = IkeSaInitExchange::create_response(
                &mut ctx_r,
                &init_req.header,
                proposals[0].clone(),
                vec![0xBB; 256],
                vec![0x22; 32],
                None,
                None,
            )
            .unwrap();

            IkeSaInitExchange::process_response(&mut ctx_i, &init_resp).unwrap();

            // Key derivation
            ctx_i.shared_secret = Some(vec![0xDD; 256]);
            ctx_r.shared_secret = Some(vec![0xDD; 256]);
            ctx_i.derive_keys(PrfAlgorithm::HmacSha256, 16, 16).unwrap();
            ctx_r.derive_keys(PrfAlgorithm::HmacSha256, 16, 16).unwrap();

            // IKE_AUTH
            let id_i = IdPayload {
                id_type: IdType::Ipv4Addr,
                data: vec![192, 168, 1, 1],
            };

            let ts = create_test_traffic_selectors();

            let auth_req = IkeAuthExchange::create_request(
                &mut ctx_i,
                &init_req_bytes,
                id_i,
                psk,
                child_proposals.clone(),
                ts.clone(),
                ts.clone(),
            )
            .unwrap();

            let _result = IkeAuthExchange::process_request(
                &mut ctx_r,
                &init_req_bytes,
                &auth_req,
                psk,
                &child_proposals,
            );

            black_box(_result)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ike_sa_init_create,
    bench_ike_sa_init_process,
    bench_key_derivation,
    bench_esp_encryption,
    bench_esp_decryption,
    bench_esp_serialization,
    bench_full_handshake,
);

criterion_main!(benches);
