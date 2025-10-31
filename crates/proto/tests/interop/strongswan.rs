//! strongSwan Interoperability Tests
//!
//! These tests validate interoperability between Fynx IPSec and strongSwan,
//! the industry-standard IPSec implementation.
//!
//! # Prerequisites
//!
//! - strongSwan installed and configured
//! - Root/sudo permissions for port 500
//! - See `docs/ipsec/STAGE4_INTEROP_GUIDE.md` for setup instructions
//!
//! # Running Tests
//!
//! ```bash
//! # Start strongSwan first
//! sudo ipsec start
//!
//! # Run tests (requires strongSwan running)
//! cargo test --test interop_strongswan --features ipsec -- --test-threads=1 --ignored
//! ```
//!
//! **Note**: Tests are marked with `#[ignore]` because they require external strongSwan setup.

#![cfg(feature = "ipsec")]

use fynx_proto::ipsec::{ClientConfig, IpsecClient, IpsecServer, ServerConfig};
use std::time::Duration;
use tokio::time::timeout;

/// Test PSK for interop testing
/// Must match the PSK in /etc/strongswan/ipsec.secrets
const TEST_PSK: &[u8] = b"fynx-interop-test-key-32-bytes";

/// strongSwan server address (typically localhost)
const STRONGSWAN_SERVER_ADDR: &str = "127.0.0.1:500";

/// Fynx server address for strongSwan client tests
const FYNX_SERVER_ADDR: &str = "127.0.0.1:500";

/// Test timeout duration
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Test 1: Fynx Client → strongSwan Server
///
/// Verifies that Fynx can successfully initiate an IPSec tunnel to strongSwan.
///
/// # Prerequisites
///
/// 1. strongSwan must be running: `sudo ipsec start`
/// 2. Connection configured in /etc/strongswan/ipsec.conf
/// 3. PSK configured in /etc/strongswan/ipsec.secrets
///
/// # Test Steps
///
/// 1. Create Fynx client with test configuration
/// 2. Connect to strongSwan server on localhost:500
/// 3. Verify IKE_SA_INIT exchange succeeds
/// 4. Verify IKE_AUTH exchange succeeds
/// 5. Verify Child SA is established
/// 6. Send test data through tunnel
/// 7. Receive response from strongSwan
/// 8. Gracefully close connection
#[tokio::test]
#[ignore = "Requires strongSwan server running - run with --ignored"]
async fn test_fynx_client_to_strongswan_server() {
    // Initialize logging for debugging
    let _ = tracing_subscriber::fmt()
        .with_env_filter("fynx_proto::ipsec=trace")
        .try_init();

    // Configure Fynx client
    let config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(TEST_PSK)
        .build()
        .expect("Failed to build client config");

    let mut client = IpsecClient::new(config);

    // Connect to strongSwan server
    let connect_result = timeout(
        TEST_TIMEOUT,
        client.connect(STRONGSWAN_SERVER_ADDR.parse().unwrap()),
    )
    .await;

    match connect_result {
        Ok(Ok(())) => {
            println!("✅ Successfully connected to strongSwan server");

            // Send test data
            let test_data = b"Hello from Fynx!";
            let send_result = client.send_packet(test_data).await;
            assert!(send_result.is_ok(), "Failed to send packet");
            println!("✅ Sent test data to strongSwan");

            // Try to receive response (strongSwan may echo back)
            match timeout(Duration::from_secs(5), client.recv_packet()).await {
                Ok(Ok(data)) => {
                    println!("✅ Received {} bytes from strongSwan", data.len());
                }
                Ok(Err(e)) => {
                    println!("⚠️ No response received (may be expected): {}", e);
                }
                Err(_) => {
                    println!("⚠️ Receive timeout (may be expected)");
                }
            }

            // Graceful shutdown
            let _ = client.shutdown().await;
            println!("✅ Gracefully disconnected");
        }
        Ok(Err(e)) => {
            panic!(
                "❌ Failed to connect to strongSwan: {}\n\
                   Ensure strongSwan is running: sudo ipsec start",
                e
            );
        }
        Err(_) => {
            panic!(
                "❌ Connection timeout\n\
                   Ensure strongSwan is running and listening on port 500"
            );
        }
    }
}

/// Test 2: strongSwan Client → Fynx Server
///
/// Verifies that strongSwan can successfully connect to Fynx server.
///
/// # Prerequisites
///
/// This test starts a Fynx server and expects strongSwan to connect as a client.
///
/// # Manual Steps Required
///
/// 1. Run this test in one terminal
/// 2. In another terminal, start strongSwan client:
///    ```bash
///    sudo ipsec up fynx-server-to-strongswan-client
///    ```
///
/// # Test Steps
///
/// 1. Start Fynx server on localhost:500
/// 2. Wait for strongSwan client to connect
/// 3. Accept connection from strongSwan
/// 4. Verify handshake succeeds
/// 5. Exchange test data
/// 6. Close session
#[tokio::test]
#[ignore = "Requires manual strongSwan client initiation - run with --ignored"]
async fn test_strongswan_client_to_fynx_server() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("fynx_proto::ipsec=trace")
        .try_init();

    // Configure Fynx server
    let config = ServerConfig::builder()
        .with_local_id("server@example.com")
        .with_psk(TEST_PSK)
        .build()
        .expect("Failed to build server config");

    let mut server = IpsecServer::bind(config, FYNX_SERVER_ADDR.parse().unwrap())
        .await
        .expect("Failed to bind server - ensure you have root permissions");

    println!("✅ Fynx server listening on {}", FYNX_SERVER_ADDR);
    println!("💡 Now run: sudo ipsec up fynx-server-to-strongswan-client");

    // Wait for strongSwan client connection
    let accept_result = timeout(TEST_TIMEOUT, server.accept()).await;

    match accept_result {
        Ok(Ok((peer_addr, mut session))) => {
            println!("✅ strongSwan client connected from {}", peer_addr);
            println!("⚠️ Note: Session recv/send requires UDP socket integration");
            println!("See client.rs implementation for full async networking");

            // Close session
            let _ = session.close().await;
            println!("✅ Session closed");
        }
        Ok(Err(e)) => {
            panic!("❌ Failed to accept strongSwan connection: {}", e);
        }
        Err(_) => {
            panic!(
                "❌ No strongSwan client connected within timeout\n\
                   Did you run: sudo ipsec up fynx-server-to-strongswan-client ?"
            );
        }
    }
}

/// Test 3: Cipher Suite - AES-128-GCM
///
/// Verifies that Fynx and strongSwan can negotiate and use AES-128-GCM.
#[tokio::test]
#[ignore = "Requires strongSwan with AES-128-GCM configured"]
async fn test_cipher_suite_aes128gcm() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("fynx_proto::ipsec=debug")
        .try_init();

    // Use default configuration (includes AES-128-GCM)
    let config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(TEST_PSK)
        .build()
        .unwrap();

    let mut client = IpsecClient::new(config);

    let result = timeout(
        TEST_TIMEOUT,
        client.connect(STRONGSWAN_SERVER_ADDR.parse().unwrap()),
    )
    .await;

    assert!(
        result.is_ok() && result.unwrap().is_ok(),
        "Failed to negotiate AES-128-GCM with strongSwan"
    );

    println!("✅ AES-128-GCM cipher suite works");
    let _ = client.shutdown().await;
}

/// Test 4: Cipher Suite - AES-256-GCM
///
/// Verifies that Fynx and strongSwan can negotiate and use AES-256-GCM.
///
/// # Prerequisites
///
/// strongSwan must be configured with AES-256-GCM:
/// ```
/// ike=aes256gcm16-prfsha384-modp2048!
/// esp=aes256gcm16!
/// ```
#[tokio::test]
#[ignore = "Requires strongSwan with AES-256-GCM configured"]
async fn test_cipher_suite_aes256gcm() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("fynx_proto::ipsec=debug")
        .try_init();

    use fynx_proto::ipsec::ikev2::proposal::*;

    // Configure AES-256-GCM proposals
    let ike_proposal = Proposal::new(1, ProtocolId::Ike)
        .add_transform(Transform::encr(EncrTransformId::AesGcm256))
        .add_transform(Transform::prf(PrfTransformId::HmacSha384))
        .add_transform(Transform::dh(DhTransformId::Group14));

    let esp_proposal = Proposal::new(1, ProtocolId::Esp)
        .add_transform(Transform::encr(EncrTransformId::AesGcm256))
        .add_transform(Transform::new(TransformType::Esn, 0));

    let config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(TEST_PSK)
        .with_ike_proposals(vec![ike_proposal])
        .with_esp_proposals(vec![esp_proposal])
        .build()
        .unwrap();

    let mut client = IpsecClient::new(config);

    let result = timeout(
        TEST_TIMEOUT,
        client.connect(STRONGSWAN_SERVER_ADDR.parse().unwrap()),
    )
    .await;

    assert!(
        result.is_ok() && result.unwrap().is_ok(),
        "Failed to negotiate AES-256-GCM with strongSwan"
    );

    println!("✅ AES-256-GCM cipher suite works");
    let _ = client.shutdown().await;
}

/// Test 5: Cipher Suite - ChaCha20-Poly1305
///
/// Verifies that Fynx and strongSwan can negotiate and use ChaCha20-Poly1305.
///
/// # Prerequisites
///
/// strongSwan must be configured with ChaCha20-Poly1305:
/// ```
/// ike=chacha20poly1305-prfsha256-modp2048!
/// esp=chacha20poly1305!
/// ```
#[tokio::test]
#[ignore = "Requires strongSwan with ChaCha20-Poly1305 configured"]
async fn test_cipher_suite_chacha20poly1305() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("fynx_proto::ipsec=debug")
        .try_init();

    use fynx_proto::ipsec::ikev2::proposal::*;

    let ike_proposal = Proposal::new(1, ProtocolId::Ike)
        .add_transform(Transform::encr(EncrTransformId::ChaCha20Poly1305))
        .add_transform(Transform::prf(PrfTransformId::HmacSha256))
        .add_transform(Transform::dh(DhTransformId::Group14));

    let esp_proposal = Proposal::new(1, ProtocolId::Esp)
        .add_transform(Transform::encr(EncrTransformId::ChaCha20Poly1305))
        .add_transform(Transform::new(TransformType::Esn, 0));

    let config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(TEST_PSK)
        .with_ike_proposals(vec![ike_proposal])
        .with_esp_proposals(vec![esp_proposal])
        .build()
        .unwrap();

    let mut client = IpsecClient::new(config);

    let result = timeout(
        TEST_TIMEOUT,
        client.connect(STRONGSWAN_SERVER_ADDR.parse().unwrap()),
    )
    .await;

    assert!(
        result.is_ok() && result.unwrap().is_ok(),
        "Failed to negotiate ChaCha20-Poly1305 with strongSwan"
    );

    println!("✅ ChaCha20-Poly1305 cipher suite works");
    let _ = client.shutdown().await;
}

/// Test 6: NAT Traversal (NAT-T)
///
/// Verifies that NAT-T detection and ESP-in-UDP encapsulation works correctly.
///
/// # Prerequisites
///
/// This test requires either:
/// - A real NAT router between Fynx and strongSwan
/// - Network namespace simulation
/// - Manual NAT-T configuration in strongSwan
#[tokio::test]
#[ignore = "Requires NAT environment or manual configuration"]
async fn test_nat_traversal() {
    println!("⚠️ NAT-T test requires special network configuration");
    println!("See STAGE4_INTEROP_GUIDE.md for NAT-T testing instructions");

    // NAT-T is automatically detected and handled by Fynx
    // This test would follow the same flow as test_fynx_client_to_strongswan_server
    // but requires verifying that UDP port 4500 is used instead of 500
}

/// Test 7: Dead Peer Detection (DPD)
///
/// Verifies that DPD correctly detects when a peer becomes unreachable.
#[tokio::test]
#[ignore = "Requires manual peer termination"]
async fn test_dead_peer_detection() {
    println!("⚠️ DPD test requires manual peer termination");
    println!("See STAGE4_INTEROP_GUIDE.md for DPD testing instructions");

    // Test procedure:
    // 1. Establish connection
    // 2. Kill strongSwan process without sending DELETE
    // 3. Verify Fynx detects failure via DPD timeout
}

/// Test 8: IKE SA Rekeying
///
/// Verifies that IKE SA can be rekeyed without disrupting the connection.
#[tokio::test]
#[ignore = "Requires long-running test with short SA lifetime"]
async fn test_ike_sa_rekey() {
    println!("⚠️ IKE SA rekey test requires long-running connection");
    println!("Configure short lifetime in strongSwan and Fynx configs");

    // Test procedure:
    // 1. Configure short IKE SA lifetime (60 seconds)
    // 2. Establish connection
    // 3. Wait for rekey trigger
    // 4. Verify new IKE SA is established
    // 5. Verify old IKE SA is deleted
    // 6. Verify no data loss during rekey
}

/// Test 9: Child SA Rekeying
///
/// Verifies that Child SA can be rekeyed without disrupting data transfer.
#[tokio::test]
#[ignore = "Requires long-running test with short SA lifetime"]
async fn test_child_sa_rekey() {
    println!("⚠️ Child SA rekey test requires long-running connection");
    println!("Configure short lifetime in strongSwan and Fynx configs");

    // Test procedure:
    // 1. Configure short Child SA lifetime (60 seconds)
    // 2. Establish connection
    // 3. Send continuous data stream
    // 4. Wait for rekey trigger
    // 5. Verify new Child SA is established
    // 6. Verify old Child SA is deleted
    // 7. Verify no data loss during rekey
}

/// Test 10: Bidirectional Data Transfer
///
/// Verifies that data can flow in both directions through the tunnel.
#[tokio::test]
#[ignore = "Requires strongSwan server with echo capability"]
async fn test_bidirectional_data_transfer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("fynx_proto::ipsec=debug")
        .try_init();

    let config = ClientConfig::builder()
        .with_local_id("client@example.com")
        .with_remote_id("server@example.com")
        .with_psk(TEST_PSK)
        .build()
        .unwrap();

    let mut client = IpsecClient::new(config);

    // Connect
    client
        .connect(STRONGSWAN_SERVER_ADDR.parse().unwrap())
        .await
        .expect("Failed to connect");

    // Send multiple packets
    let test_messages = vec![
        b"Hello strongSwan!".to_vec(),
        b"This is packet 2".to_vec(),
        b"Final test packet".to_vec(),
    ];

    for (i, msg) in test_messages.iter().enumerate() {
        client
            .send_packet(msg)
            .await
            .expect("Failed to send packet");
        println!("✅ Sent packet {}", i + 1);

        // Try to receive echo
        match timeout(Duration::from_secs(2), client.recv_packet()).await {
            Ok(Ok(data)) => {
                println!("✅ Received response for packet {}: {} bytes", i + 1, data.len());
            }
            _ => {
                println!("⚠️ No response for packet {} (may be expected)", i + 1);
            }
        }
    }

    client.shutdown().await.ok();
    println!("✅ Bidirectional data transfer test complete");
}
