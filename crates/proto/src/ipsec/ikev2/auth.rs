//! IKEv2 Authentication
//!
//! Implements authentication logic as defined in RFC 7296 Section 2.15.

use super::payload::{AuthMethod, AuthPayload};
use crate::ipsec::crypto::PrfAlgorithm;
use crate::ipsec::{Error, Result};

/// Key pad for IKEv2 (RFC 7296 Section 2.15)
const KEY_PAD_IKEV2: &[u8] = b"Key Pad for IKEv2";

/// Compute AUTH payload for PSK authentication (RFC 7296 Section 2.15)
///
/// ```text
/// AUTH = prf(prf(SK_p, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
/// ```
///
/// For initiator: SK_p = SK_pi
/// For responder: SK_p = SK_pr
///
/// # Arguments
///
/// * `prf_alg` - PRF algorithm to use
/// * `sk_p` - SK_pi (initiator) or SK_pr (responder)
/// * `signed_octets` - Data to be signed
///
/// # Returns
///
/// Returns AUTH payload with PSK method
pub fn compute_psk_auth(
    prf_alg: PrfAlgorithm,
    sk_p: &[u8],
    signed_octets: &[u8],
) -> AuthPayload {
    // Step 1: prf(SK_p, "Key Pad for IKEv2")
    let prf1 = prf_alg.compute(sk_p, KEY_PAD_IKEV2);

    // Step 2: prf(result, <SignedOctets>)
    let auth_data = prf_alg.compute(&prf1, signed_octets);

    AuthPayload::new(AuthMethod::SharedKeyMic, auth_data)
}

/// Verify AUTH payload for PSK authentication
///
/// # Arguments
///
/// * `prf_alg` - PRF algorithm to use
/// * `sk_p` - SK_pi (initiator) or SK_pr (responder)
/// * `signed_octets` - Data to verify
/// * `received_auth` - Received AUTH payload
///
/// # Returns
///
/// Returns Ok(()) if authentication succeeds, error otherwise
pub fn verify_psk_auth(
    prf_alg: PrfAlgorithm,
    sk_p: &[u8],
    signed_octets: &[u8],
    received_auth: &AuthPayload,
) -> Result<()> {
    // Check auth method
    if received_auth.auth_method != AuthMethod::SharedKeyMic {
        return Err(Error::AuthenticationFailed(format!(
            "Expected PSK auth, got {:?}",
            received_auth.auth_method
        )));
    }

    // Compute expected AUTH
    let expected = compute_psk_auth(prf_alg, sk_p, signed_octets);

    // Constant-time comparison
    if expected.auth_data.len() != received_auth.auth_data.len() {
        return Err(Error::AuthenticationFailed(
            "AUTH data length mismatch".to_string(),
        ));
    }

    // Use constant-time comparison to prevent timing attacks
    let mut diff = 0u8;
    for (a, b) in expected.auth_data.iter().zip(received_auth.auth_data.iter()) {
        diff |= a ^ b;
    }

    if diff != 0 {
        return Err(Error::AuthenticationFailed(
            "AUTH verification failed".to_string(),
        ));
    }

    Ok(())
}

/// Construct initiator signed octets (RFC 7296 Section 2.15)
///
/// ```text
/// InitiatorSignedOctets = RealMessage1 | NonceR | prf(SK_pi, IDi')
/// ```
///
/// Where:
/// - RealMessage1 = IKE_SA_INIT request (from first octet to last octet)
/// - NonceR = Responder's nonce payload data
/// - IDi' = IDi payload data (excluding header)
///
/// # Arguments
///
/// * `prf_alg` - PRF algorithm
/// * `real_message1` - Complete IKE_SA_INIT request bytes
/// * `nonce_r` - Responder's nonce
/// * `sk_pi` - Initiator's SK_pi key
/// * `id_i_data` - IDi payload data (without header)
///
/// # Returns
///
/// Returns signed octets
pub fn construct_initiator_signed_octets(
    prf_alg: PrfAlgorithm,
    real_message1: &[u8],
    nonce_r: &[u8],
    sk_pi: &[u8],
    id_i_data: &[u8],
) -> Vec<u8> {
    let mut signed_octets = Vec::new();

    // RealMessage1
    signed_octets.extend_from_slice(real_message1);

    // NonceR
    signed_octets.extend_from_slice(nonce_r);

    // prf(SK_pi, IDi')
    let id_hash = prf_alg.compute(sk_pi, id_i_data);
    signed_octets.extend_from_slice(&id_hash);

    signed_octets
}

/// Construct responder signed octets (RFC 7296 Section 2.15)
///
/// ```text
/// ResponderSignedOctets = RealMessage2 | NonceI | prf(SK_pr, IDr')
/// ```
///
/// Where:
/// - RealMessage2 = IKE_SA_INIT response (from first octet to last octet)
/// - NonceI = Initiator's nonce payload data
/// - IDr' = IDr payload data (excluding header)
///
/// # Arguments
///
/// * `prf_alg` - PRF algorithm
/// * `real_message2` - Complete IKE_SA_INIT response bytes
/// * `nonce_i` - Initiator's nonce
/// * `sk_pr` - Responder's SK_pr key
/// * `id_r_data` - IDr payload data (without header)
///
/// # Returns
///
/// Returns signed octets
pub fn construct_responder_signed_octets(
    prf_alg: PrfAlgorithm,
    real_message2: &[u8],
    nonce_i: &[u8],
    sk_pr: &[u8],
    id_r_data: &[u8],
) -> Vec<u8> {
    let mut signed_octets = Vec::new();

    // RealMessage2
    signed_octets.extend_from_slice(real_message2);

    // NonceI
    signed_octets.extend_from_slice(nonce_i);

    // prf(SK_pr, IDr')
    let id_hash = prf_alg.compute(sk_pr, id_r_data);
    signed_octets.extend_from_slice(&id_hash);

    signed_octets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_psk_auth() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_p = vec![0x01; 32];
        let signed_octets = vec![0x02; 128];

        let auth = compute_psk_auth(prf_alg, &sk_p, &signed_octets);

        assert_eq!(auth.auth_method, AuthMethod::SharedKeyMic);
        assert_eq!(auth.auth_data.len(), 32); // HMAC-SHA256 output
    }

    #[test]
    fn test_psk_auth_deterministic() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_p = vec![0xAA; 32];
        let signed_octets = vec![0xBB; 64];

        let auth1 = compute_psk_auth(prf_alg, &sk_p, &signed_octets);
        let auth2 = compute_psk_auth(prf_alg, &sk_p, &signed_octets);

        assert_eq!(auth1.auth_data, auth2.auth_data);
    }

    #[test]
    fn test_verify_psk_auth_success() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_p = vec![0x03; 32];
        let signed_octets = vec![0x04; 100];

        let auth = compute_psk_auth(prf_alg, &sk_p, &signed_octets);

        let result = verify_psk_auth(prf_alg, &sk_p, &signed_octets, &auth);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_psk_auth_wrong_data() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_p = vec![0x05; 32];
        let signed_octets = vec![0x06; 100];
        let wrong_octets = vec![0x07; 100];

        let auth = compute_psk_auth(prf_alg, &sk_p, &signed_octets);

        let result = verify_psk_auth(prf_alg, &sk_p, &wrong_octets, &auth);
        assert!(matches!(result, Err(Error::AuthenticationFailed(_))));
    }

    #[test]
    fn test_verify_psk_auth_wrong_key() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_p = vec![0x08; 32];
        let wrong_sk_p = vec![0x09; 32];
        let signed_octets = vec![0x0A; 100];

        let auth = compute_psk_auth(prf_alg, &sk_p, &signed_octets);

        let result = verify_psk_auth(prf_alg, &wrong_sk_p, &signed_octets, &auth);
        assert!(matches!(result, Err(Error::AuthenticationFailed(_))));
    }

    #[test]
    fn test_verify_psk_auth_wrong_method() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let sk_p = vec![0x0B; 32];
        let signed_octets = vec![0x0C; 100];

        let wrong_auth = AuthPayload::new(AuthMethod::RsaSig, vec![0xFF; 32]);

        let result = verify_psk_auth(prf_alg, &sk_p, &signed_octets, &wrong_auth);
        assert!(matches!(result, Err(Error::AuthenticationFailed(_))));
    }

    #[test]
    fn test_construct_initiator_signed_octets() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let real_message1 = vec![0x01; 200];
        let nonce_r = vec![0x02; 32];
        let sk_pi = vec![0x03; 32];
        let id_i_data = vec![0x04; 20];

        let signed_octets = construct_initiator_signed_octets(
            prf_alg,
            &real_message1,
            &nonce_r,
            &sk_pi,
            &id_i_data,
        );

        // Length should be: message + nonce + prf_output
        assert_eq!(signed_octets.len(), 200 + 32 + 32);

        // Should start with real_message1
        assert_eq!(&signed_octets[0..200], &real_message1[..]);
    }

    #[test]
    fn test_construct_responder_signed_octets() {
        let prf_alg = PrfAlgorithm::HmacSha384;
        let real_message2 = vec![0x05; 250];
        let nonce_i = vec![0x06; 32];
        let sk_pr = vec![0x07; 48];
        let id_r_data = vec![0x08; 25];

        let signed_octets = construct_responder_signed_octets(
            prf_alg,
            &real_message2,
            &nonce_i,
            &sk_pr,
            &id_r_data,
        );

        // Length should be: message + nonce + prf_output (SHA384 = 48 bytes)
        assert_eq!(signed_octets.len(), 250 + 32 + 48);

        // Should start with real_message2
        assert_eq!(&signed_octets[0..250], &real_message2[..]);
    }

    #[test]
    fn test_signed_octets_deterministic() {
        let prf_alg = PrfAlgorithm::HmacSha256;
        let real_message = vec![0xAA; 100];
        let nonce = vec![0xBB; 32];
        let sk_p = vec![0xCC; 32];
        let id_data = vec![0xDD; 15];

        let signed1 = construct_initiator_signed_octets(
            prf_alg,
            &real_message,
            &nonce,
            &sk_p,
            &id_data,
        );

        let signed2 = construct_initiator_signed_octets(
            prf_alg,
            &real_message,
            &nonce,
            &sk_p,
            &id_data,
        );

        assert_eq!(signed1, signed2);
    }
}
