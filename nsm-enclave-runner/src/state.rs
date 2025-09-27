use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct PublicState {
    /// Self-signed TLS certificate (DER) the server presents.
    pub cert_der: Arc<[u8]>,
    /// SPKI (DER) of the TLS cert's public key; bind this in NSM attestation.
    pub spki_der: Arc<[u8]>,
    // If you don't actually use a sealed store elsewhere, delete it entirely.
    // pub store: Arc<sealed_state::MemStore>,
}

#[derive(serde::Serialize)]
pub struct AttestationResponse {
    /// Fields coming from the fresh NSM attestation (built per verifier nonce).
    pub attestation: AttestationFields,
    /// The server's TLS leaf certificate (DER, base64) to pin after validation.
    pub cert_der_b64: String,
}

#[derive(serde::Serialize)]
pub struct AttestationFields {
    /// Raw NSM COSE_Sign1 attestation (base64).
    pub quote_b64: String,
    /// Echo of the verifier-supplied nonce (base64).
    pub nonce_b64: String,
    /// SPKI (DER) the enclave included in the attestation (base64).
    pub spki_der_b64: String,
    /// Static policy tag for clarity (e.g., "aws-nitro-nsm").
    pub policy: String,
    /// Runner version string.
    pub runner_version: String,
    /// CABundle returned by NSM (base64 DER, leaf excluded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cabundle_der_b64: Option<Vec<String>>,
    /// Hex-encoded PCR values keyed by PCR index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcrs_hex: Option<BTreeMap<String, String>>,
    /// Convenience alias for PCR0 (measurement) if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement_hex: Option<String>,
    /// Module identifier emitted by NSM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_id: Option<String>,
    /// Digest algorithm used by NSM for PCR bank.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Timestamp of the attestation document (ms since Unix epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
    /// Optional user data (base64) bound into the attestation document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data_b64: Option<String>,
    /// Attestation signing certificate DER emitted by NSM (base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_cert_der_b64: Option<String>,
}
