use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use log::debug;
use rand::RngCore;
use ring::signature;
use rustls_pemfile as pemfile;
use serde::Deserialize;
use serde_cbor::Value as CborValue;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

#[derive(Deserialize)]
struct AttestationResponse {
    attestation: AttestationFields,
    cert_der_b64: String,
}
#[derive(Deserialize)]
struct AttestationFields {
    quote_b64: String,
    nonce_b64: String,
    spki_der_b64: String,
    policy: String,
    runner_version: String,
    #[serde(default)]
    cabundle_der_b64: Option<Vec<String>>,
    #[serde(default)]
    attestation_cert_der_b64: Option<String>,
    #[serde(default)]
    pcr0_hex: Option<String>,
    #[serde(default)]
    pcrs_hex: Option<BTreeMap<String, String>>,
    #[serde(default)]
    measurement_hex: Option<String>,
    #[serde(default)]
    module_id: Option<String>,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    timestamp_ms: Option<u64>,
    #[serde(default)]
    user_data_b64: Option<String>,
}

// -------- helpers --------
fn pem_to_der_many(pem_str: &str) -> Result<Vec<Vec<u8>>> {
    debug!("Parsing PEM payload for certificates");
    let mut cursor = std::io::Cursor::new(pem_str.as_bytes());
    let mut ders = Vec::new();
    loop {
        match pemfile::read_one(&mut cursor) {
            Ok(Some(pemfile::Item::X509Certificate(der))) => ders.push(der.to_vec()),
            Ok(Some(_other)) => continue, // skip keys/CSRs/etc.
            Ok(None) => break,
            Err(e) => return Err(anyhow!("PEM parse error: {e}")),
        }
    }
    if ders.is_empty() {
        debug!("PEM payload did not contain any certificates");
        return Err(anyhow!("no certificates found in PEM"));
    }
    debug!("Parsed {} certificate(s) from PEM", ders.len());
    Ok(ders)
}

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn read_file_from_env(var: &str) -> Result<(String, String)> {
    let path = env::var(var).with_context(|| format!("env var {var} not set"))?;
    debug!("Reading file for {var} from {path}");
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("failed to read file from {var}='{}'", path))?;
    Ok((path, contents))
}

fn load_json_from_env(var: &str) -> Result<(String, JsonValue)> {
    let (path, contents) = read_file_from_env(var)?;
    debug!("Parsing JSON configuration for {var} from {path}");
    let json = serde_json::from_str(&contents)
        .with_context(|| format!("parse JSON from {var} file '{}':", path))?;
    debug!("Loaded JSON configuration for {var}");
    Ok((path, json))
}

// Basic sanity check on x5c using x509-parser:
// - leaf & intermediates parse
// - leaf validity window covers "now"
fn basic_chain_sanity(leaf: &[u8], inters: &[Vec<u8>]) -> Result<()> {
    debug!(
        "Performing basic chain sanity checks (leaf + {})",
        inters.len()
    );
    let (_, leaf_cert) = X509Certificate::from_der(leaf).context("parse leaf der")?;
    let now = unix_secs_now() as i64;

    // validity check
    debug!("Validating leaf certificate time window");
    let not_before = leaf_cert.validity().not_before.timestamp();
    let not_after = leaf_cert.validity().not_after.timestamp();
    if now < not_before || now > not_after {
        return Err(anyhow!(
            "leaf cert not valid at current time (nb={} na={} now={})",
            not_before,
            not_after,
            now
        ));
    }
    debug!("Leaf certificate is valid for current time");

    // parse all intermediates (structure sanity only)
    for (i, der) in inters.iter().enumerate() {
        debug!("Parsing intermediate certificate #{i} for structural sanity");
        let _ =
            X509Certificate::from_der(der).with_context(|| format!("parse intermediate #{i}"))?;
    }

    debug!(
        "Successfully parsed {} intermediate certificate(s)",
        inters.len()
    );

    Ok(())
}

fn ensure_trust_anchor(x5c: &[Vec<u8>], trust_roots: &[Vec<u8>]) -> Result<()> {
    debug!(
        "Validating attestation chain root against {} configured trust root(s)",
        trust_roots.len()
    );
    if trust_roots.is_empty() {
        debug!("Trusted root set is empty; cannot validate trust anchor");
        return Err(anyhow!("trusted root set is empty"));
    }

    let chain_root = x5c.last().ok_or_else(|| anyhow!("x5c chain empty"))?;

    let matches = trust_roots
        .iter()
        .any(|trusted| trusted.as_slice() == chain_root.as_slice());

    if matches {
        debug!("Attestation chain root matches a configured trust root");
        Ok(())
    } else {
        debug!("Attestation chain root did not match any configured trust root");
        Err(anyhow!("x5c root does not match trusted root"))
    }
}

fn cbor_to_json(value: &CborValue) -> Result<JsonValue> {
    Ok(match value {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(b) => JsonValue::Bool(*b),
        CborValue::Integer(i) => serde_json::Number::from_i128(*i)
            .map(JsonValue::Number)
            .ok_or_else(|| anyhow!("CBOR integer out of range for JSON"))?,
        CborValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(JsonValue::Number)
            .ok_or_else(|| anyhow!("invalid float value"))?,
        CborValue::Bytes(b) => JsonValue::String(hex::encode(b)),
        CborValue::Text(s) => JsonValue::String(s.clone()),
        CborValue::Array(items) => {
            JsonValue::Array(items.iter().map(cbor_to_json).collect::<Result<Vec<_>>>()?)
        }
        CborValue::Map(entries) => {
            let mut obj = serde_json::Map::with_capacity(entries.len());
            for (k, v) in entries.iter() {
                let key = match k {
                    CborValue::Text(s) => s.clone(),
                    CborValue::Integer(i) => i.to_string(),
                    CborValue::Bytes(b) => hex::encode(b),
                    other => return Err(anyhow!("unsupported CBOR map key type: {:?}", other)),
                };
                obj.insert(key, cbor_to_json(v)?);
            }
            JsonValue::Object(obj)
        }
        CborValue::Tag(_, inner) => cbor_to_json(inner)?,
        CborValue::__Hidden => return Err(anyhow!("unsupported CBOR value")),
    })
}

fn is_hexish(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn ensure_subset(actual: &JsonValue, expected: &JsonValue, path: &str) -> Result<()> {
    let display_path = if path.is_empty() { "<root>" } else { path };
    debug!("Ensuring payload matches expectations at path {display_path}");
    match expected {
        JsonValue::Null => {
            if actual.is_null() {
                debug!("Verified null value at {display_path}");
                Ok(())
            } else {
                Err(anyhow!("expected null at {path}"))
            }
        }
        JsonValue::Bool(b) => match actual {
            JsonValue::Bool(b_actual) if b_actual == b => {
                debug!("Verified bool value at {display_path}");
                Ok(())
            }
            _ => Err(anyhow!("bool mismatch at {path}")),
        },
        JsonValue::Number(num_expected) => match actual {
            JsonValue::Number(num_actual) if num_actual == num_expected => {
                debug!("Verified number at {display_path}");
                Ok(())
            }
            _ => Err(anyhow!("number mismatch at {path}")),
        },
        JsonValue::String(expected_str) => {
            let actual_str = actual
                .as_str()
                .ok_or_else(|| anyhow!("expected string at {path}"))?;
            let matches = if is_hexish(expected_str) && is_hexish(actual_str) {
                actual_str.eq_ignore_ascii_case(expected_str)
            } else {
                actual_str == expected_str
            };
            if matches {
                debug!("Verified string at {display_path}");
                Ok(())
            } else {
                Err(anyhow!("string mismatch at {path}"))
            }
        }
        JsonValue::Array(expected_arr) => match actual {
            JsonValue::Array(actual_arr) if actual_arr.len() == expected_arr.len() => {
                for (idx, (act, exp)) in actual_arr.iter().zip(expected_arr).enumerate() {
                    let child_path = format!("{path}[{idx}]");
                    ensure_subset(act, exp, &child_path)?;
                }
                debug!("Verified array at {display_path}");
                Ok(())
            }
            _ => Err(anyhow!("array mismatch at {path}")),
        },
        JsonValue::Object(expected_map) => {
            let actual_obj = actual
                .as_object()
                .ok_or_else(|| anyhow!("expected object at {path}"))?;
            for (key, expected_val) in expected_map {
                let actual_val = actual_obj
                    .get(key)
                    .ok_or_else(|| anyhow!("missing key '{key}' at {path}"))?;
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                ensure_subset(actual_val, expected_val, &child_path)?;
            }
            debug!("Verified object at {display_path}");
            Ok(())
        }
    }
}

// -------- main --------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .format_timestamp_secs()
        .try_init()
        .ok();
    debug!("Starting attestation verification run");

    let (root_pem_path, root_source) = match env::var("NITRO_ROOT_PEM_PATH") {
        Ok(path) => (path, "env NITRO_ROOT_PEM_PATH"),
        Err(_) => (
            env::args().nth(1).ok_or_else(|| {
                anyhow!("provide root PEM path as first argument or set NITRO_ROOT_PEM_PATH")
            })?,
            "CLI argument",
        ),
    };
    debug!("Using trust root PEM from {root_source}: {root_pem_path}");

    debug!("Reading trust root PEM from disk");
    let root_pem = std::fs::read_to_string(&root_pem_path)
        .with_context(|| format!("read root pem from {root_pem_path}"))?;
    let trust_roots = pem_to_der_many(&root_pem)
        .with_context(|| format!("parse root pem from {root_pem_path}"))?;
    let (_measurements_path, expected_measurements) =
        load_json_from_env("NITRO_MEASUREMENTS_PATH")?;
    let (_pcrs_path, expected_pcrs) = load_json_from_env("NITRO_EXPECTED_PCRS_PATH")?;

    // 1) fresh nonce
    let mut nonce = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce);
    debug!(
        "Generated fresh {}-byte nonce for attestation request",
        nonce.len()
    );

    // 2) fetch attestation
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // we'll pin via attestation
        .timeout(Duration::from_secs(15))
        .build()?;
    debug!("Built reqwest client for attestation request");

    debug!("Sending attestation request to https://127.0.0.1:8443/attestation");
    let resp: AttestationResponse = client
        .post("https://127.0.0.1:8443/attestation")
        .json(&serde_json::json!({ "nonce_b64": nonce_b64 }))
        .send()
        .await
        .context("POST /attestation")?
        .error_for_status()
        .context("HTTP status")?
        .json()
        .await
        .context("read json")?;
    debug!("Received attestation response from server");

    // 3) decode fields
    let b64 = &base64::engine::general_purpose::STANDARD;
    debug!("Decoding attestation payload fields");
    let quote = b64.decode(resp.attestation.quote_b64.as_bytes())?;
    let nonce_echo = b64.decode(resp.attestation.nonce_b64.as_bytes())?;
    let spki_attest = b64.decode(resp.attestation.spki_der_b64.as_bytes())?;
    let server_cert_der = b64.decode(resp.cert_der_b64.as_bytes())?;
    debug!(
        "Decoded quote ({} bytes), nonce echo ({} bytes), attested SPKI ({} bytes), and server cert ({} bytes)",
        quote.len(),
        nonce_echo.len(),
        spki_attest.len(),
        server_cert_der.len()
    );

    if nonce_echo != nonce {
        return Err(anyhow!("nonce mismatch"));
    }
    debug!("Nonce echo matches generated nonce");

    // 4) decode attestation certificate and cabundle from response
    let attestation_cert_der_b64 = resp
        .attestation
        .attestation_cert_der_b64
        .as_ref()
        .ok_or_else(|| anyhow!("attestation response missing attestation_cert_der_b64"))?;
    let attestation_cert_der = b64
        .decode(attestation_cert_der_b64.as_bytes())
        .context("decode attestation_cert_der_b64")?;
    debug!(
        "Decoded attestation certificate ({} bytes)",
        attestation_cert_der.len()
    );

    let mut intermediates_der: Vec<Vec<u8>> = Vec::new();
    if let Some(bundle_b64s) = resp.attestation.cabundle_der_b64.as_ref() {
        for (idx, cert_b64) in bundle_b64s.iter().enumerate() {
            let cert_der = b64
                .decode(cert_b64.as_bytes())
                .with_context(|| format!("decode cabundle_der_b64[{idx}]"))?;
            intermediates_der.push(cert_der);
        }
    }
    debug!(
        "Decoded {} intermediate certificate(s) from cabundle",
        intermediates_der.len()
    );
    let mut attestation_chain = Vec::with_capacity(1 + intermediates_der.len());
    attestation_chain.push(attestation_cert_der.clone());
    attestation_chain.extend(intermediates_der.iter().cloned());

    // 5) basic sanity checks on chain + time (lightweight)
    // (If you want strict path validation to Nitro root, say the word and I'll switch this to webpki/openssl.)
    debug!("Running basic certificate chain sanity checks");
    basic_chain_sanity(&attestation_cert_der, &intermediates_der)?;
    debug!("Basic certificate chain sanity checks passed");
    debug!("Ensuring attestation chain terminates in trusted root");
    ensure_trust_anchor(&attestation_chain, &trust_roots)?;
    debug!("Attestation chain trust anchor validated");

    // 6) parse COSE_Sign1
    debug!("Parsing attestation quote as COSE_Sign1 structure");
    let sign1 = match CoseSign1::from_tagged_slice(&quote) {
        Ok(v) => v,
        Err(_) => CoseSign1::from_slice(&quote)
            .map_err(|e| anyhow::anyhow!("COSE parse failed: {e:?}"))?,
    };
    debug!("Parsed COSE_Sign1 structure successfully");

    // 6) verify COSE signature with leaf public key
    // Empty AAD is equivalent to None in the old helper
    // Load leaf SPKI (for ring verifier)
    debug!("Extracting public key from leaf certificate for COSE verification");
    let (_, leaf_cert) = X509Certificate::from_der(attestation_cert_der.as_slice())
        .context("parse attestation leaf cert")?;
    let spki = leaf_cert.tbs_certificate.subject_pki.raw.to_vec();
    if spki.as_slice() != spki_attest.as_slice() {
        return Err(anyhow!(
            "attestation certificate SPKI != attestation.spki_der_b64"
        ));
    }
    debug!("Attestation certificate SPKI matches attested SPKI");

    // Decide alg (unchanged)
    let alg = sign1
        .protected
        .header
        .alg
        .as_ref()
        .ok_or_else(|| anyhow!("COSE alg missing"))?;

    let (alg_fixed, desc) = match alg {
        coset::Algorithm::Assigned(coset::iana::Algorithm::ES256) => {
            (&signature::ECDSA_P256_SHA256_FIXED, "ES256")
        }
        coset::Algorithm::Assigned(coset::iana::Algorithm::ES384) => {
            (&signature::ECDSA_P384_SHA384_FIXED, "ES384")
        }
        other => return Err(anyhow!("unsupported COSE alg: {:?}", other)),
    };
    debug!("Using COSE algorithm {desc} for signature verification");

    let pubkey = signature::UnparsedPublicKey::new(alg_fixed, &spki);
    sign1
        .verify_signature(&[], |data, sig| pubkey.verify(data, sig))
        .map_err(|_| anyhow!("COSE signature verification failed ({desc})"))?;
    debug!("COSE signature verified using {desc}");

    // 7) check CBOR payload bindings (nonce + public_key)
    let payload_bytes = sign1
        .payload
        .as_ref()
        .ok_or_else(|| anyhow!("COSE missing payload"))?;
    let payload: CborValue = serde_cbor::from_slice(payload_bytes).context("parse CBOR payload")?;

    let mut payload_nonce_ok = false;
    let mut payload_pk_ok = false;
    let mut payload_user_data: Option<Vec<u8>> = None;

    debug!("Inspecting CBOR payload bindings for nonce and public_key");
    if let CborValue::Map(m) = &payload {
        for (k, v) in m {
            if let (CborValue::Text(s), CborValue::Bytes(b)) = (k, v) {
                if s == "nonce" {
                    payload_nonce_ok = b.as_slice() == nonce.as_slice();
                }
            }
            if let (CborValue::Text(s), CborValue::Bytes(b)) = (k, v) {
                if s == "public_key" {
                    payload_pk_ok = b.as_slice() == spki_attest.as_slice();
                }
            }
            if let (CborValue::Text(s), CborValue::Bytes(b)) = (k, v) {
                if s == "user_data" {
                    payload_user_data = Some(b.clone());
                }
            }
        }
    }

    if !payload_nonce_ok {
        return Err(anyhow!("payload nonce mismatch (CBOR)"));
    }
    debug!("CBOR payload nonce matches generated nonce");
    if !payload_pk_ok {
        return Err(anyhow!(
            "payload public_key mismatch (CBOR vs attestation.spki_der_b64)"
        ));
    }
    debug!("CBOR payload public_key matches attested SPKI");

    if let Some(user_data_b64) = resp.attestation.user_data_b64.as_ref() {
        let user_data = b64
            .decode(user_data_b64.as_bytes())
            .context("decode attestation.user_data_b64")?;
        let payload_user_data =
            payload_user_data.ok_or_else(|| anyhow!("attestation payload missing user_data"))?;
        if payload_user_data.as_slice() != user_data.as_slice() {
            return Err(anyhow!(
                "payload user_data mismatch (CBOR vs attestation.user_data_b64)"
            ));
        }
        debug!("CBOR payload user_data matches response binding");
    }

    let payload_json =
        cbor_to_json(&payload).context("convert attestation payload to comparable JSON")?;
    let mut measurement_json = payload_json.clone();
    if let JsonValue::Object(ref mut obj) = measurement_json {
        if let Some(measurement_hex) = resp.attestation.measurement_hex.clone() {
            obj.insert(
                "measurement_hex".to_string(),
                JsonValue::String(measurement_hex),
            );
        }
        if let Some(module_id) = resp.attestation.module_id.clone() {
            obj.insert("module_id".to_string(), JsonValue::String(module_id));
        }
        if let Some(digest) = resp.attestation.digest.clone() {
            obj.insert("digest".to_string(), JsonValue::String(digest));
        }
        if let Some(timestamp_ms) = resp.attestation.timestamp_ms {
            obj.insert(
                "timestamp_ms".to_string(),
                JsonValue::String(timestamp_ms.to_string()),
            );
        }
    }
    debug!("Validating attestation payload measurements against expectations");
    ensure_subset(&measurement_json, &expected_measurements, "measurements")?;
    let actual_pcrs = payload_json
        .get("pcrs")
        .ok_or_else(|| anyhow!("attestation payload missing pcrs field"))?;
    debug!("Validating attestation payload PCRs against expectations");
    ensure_subset(actual_pcrs, &expected_pcrs, "pcrs")?;

    if let Some(pcr0_hex) = resp.attestation.pcr0_hex.as_ref() {
        let actual_pcr0 = actual_pcrs
            .get("0")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("attestation payload missing pcrs[0]"))?;
        if !actual_pcr0.eq_ignore_ascii_case(pcr0_hex) {
            return Err(anyhow!(
                "pcr0 mismatch between payload and attestation.pcr0_hex"
            ));
        }
        debug!("PCR0 matches attestation.pcr0_hex field");
    }
    if let Some(measurement_hex) = resp.attestation.measurement_hex.as_ref() {
        let actual_pcr0 = actual_pcrs
            .get("0")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("attestation payload missing pcrs[0]"))?;
        if !actual_pcr0.eq_ignore_ascii_case(measurement_hex) {
            return Err(anyhow!(
                "pcr0 mismatch between payload and attestation.measurement_hex"
            ));
        }
        debug!("PCR0 matches attestation.measurement_hex field");
    }
    if let Some(pcrs_hex) = resp.attestation.pcrs_hex.as_ref() {
        let actual_obj = actual_pcrs
            .as_object()
            .ok_or_else(|| anyhow!("attestation payload pcrs field is not an object"))?;
        for (idx, expected_hex) in pcrs_hex {
            let actual_hex = actual_obj
                .get(idx)
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("attestation payload missing pcrs[{idx}]"))?;
            if !actual_hex.eq_ignore_ascii_case(expected_hex) {
                return Err(anyhow!("pcrs[{idx}] mismatch between payload and response"));
            }
        }
        debug!(
            "Validated {} PCR entries against attestation.pcrs_hex",
            pcrs_hex.len()
        );
    }

    // 8) pin: server TLS cert SPKI == attested SPKI
    let (_, server_cert) =
        X509Certificate::from_der(&server_cert_der).context("parse server cert der")?;
    let server_spki = server_cert.tbs_certificate.subject_pki.raw.to_vec();
    if server_spki != spki_attest {
        return Err(anyhow!("server TLS SPKI != attested SPKI"));
    }
    debug!("Server TLS certificate SPKI matches attested SPKI");

    debug!("All attestation checks passed");

    println!("✅ Attestation verified:");
    println!("  policy         : {}", resp.attestation.policy);
    println!("  runner_version : {}", resp.attestation.runner_version);
    println!("  chain len     : {} certs", attestation_chain.len());
    println!("  COSE alg       : {:?}", alg);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VALID_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUA56oEXa5MXydxzfR+FNzU8CSDKswDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjUwOTI2MTc0OTM2WhcNMzUw
OTI0MTc0OTM2WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANP5frQEQPuZgCp6vZG4L8n89kvgkCJV+5E4x2/G
KAuUgL36XPKgRqBqEIVsUeVzrN+Wnn7UloxDKunrXiAfv9sk9DYz3H1oHJVOI7yA
WMsPyLSUhVXtObE/M6TvSB51qCQuw1bUtKeDBysPpNQyZNbkrYocLgD1+nkoBwOD
AnWXXCenHEP4z2TEA1uEVPmsI6YCfPhjxhi9AhE+yjnds2/l+UTdqLGU9osRdREr
U0aCFrgJAVw8o23S4negNrh3Bt4FQvwfGEnBh4r9+93z8sJRmCaPzaK+/5Q2JiEd
35vJ2R1lfO2zfnriUUBbkVFWFCAw51bbNQ8aOaTz6Fjjz40CAwEAAaNTMFEwHQYD
VR0OBBYEFCUtxJfJuIaraiCaZ3qwazJZJWLiMB8GA1UdIwQYMBaAFCUtxJfJuIar
aiCaZ3qwazJZJWLiMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AGoK9zYIgzqOwh7dJCQC8G0zldA4KTSlEEcITTLB8Mt2+v5+aDNXpxreVxtVLIVG
/ccRZQhoBgA+8IDTNZbj+e9iazrLlS1KQnljtNRWreAvvsySuE9SQrM7c95WD3ru
NW02/HO6U7t8J1RoiFYaGbmkuiCVU9rFrtauYieMl89EX2HaHpZ2AsgDMkIXtcUR
LGpiHZxRsXBYRyRBwHJcKHXaWMPzWdcSlDRKNOsbJ7VxJx+RpPXxZHCsbJxVFApg
LKuNsASRkaNY6GWLx9FkTHv2J6j4BSQRs2VL8dK1p8ZHwj1qt34TDqk8a6gUUp3p
s0PsjMvSNmVGS1Kyv9RmQj4=
-----END CERTIFICATE-----
"#;

    const VALID_CERT_DER_BASE64: &str = "MIIDDTCCAfWgAwIBAgIUA56oEXa5MXydxzfR+FNzU8CSDKswDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjUwOTI2MTc0OTM2WhcNMzUwOTI0MTc0OTM2WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANP5frQEQPuZgCp6vZG4L8n89kvgkCJV+5E4x2/GKAuUgL36XPKgRqBqEIVsUeVzrN+Wnn7UloxDKunrXiAfv9sk9DYz3H1oHJVOI7yAWMsPyLSUhVXtObE/M6TvSB51qCQuw1bUtKeDBysPpNQyZNbkrYocLgD1+nkoBwODAnWXXCenHEP4z2TEA1uEVPmsI6YCfPhjxhi9AhE+yjnds2/l+UTdqLGU9osRdRErU0aCFrgJAVw8o23S4negNrh3Bt4FQvwfGEnBh4r9+93z8sJRmCaPzaK+/5Q2JiEd35vJ2R1lfO2zfnriUUBbkVFWFCAw51bbNQ8aOaTz6Fjjz40CAwEAAaNTMFEwHQYDVR0OBBYEFCUtxJfJuIaraiCaZ3qwazJZJWLiMB8GA1UdIwQYMBaAFCUtxJfJuIaraiCaZ3qwazJZJWLiMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGoK9zYIgzqOwh7dJCQC8G0zldA4KTSlEEcITTLB8Mt2+v5+aDNXpxreVxtVLIVG/ccRZQhoBgA+8IDTNZbj+e9iazrLlS1KQnljtNRWreAvvsySuE9SQrM7c95WD3ruNW02/HO6U7t8J1RoiFYaGbmkuiCVU9rFrtauYieMl89EX2HaHpZ2AsgDMkIXtcURLGpiHZxRsXBYRyRBwHJcKHXaWMPzWdcSlDRKNOsbJ7VxJx+RpPXxZHCsbJxVFApgLKuNsASRkaNY6GWLx9FkTHv2J6j4BSQRs2VL8dK1p8ZHwj1qt34TDqk8a6gUUp3ps0PsjMvSNmVGS1Kyv9RmQj4=";

    const FUTURE_CERT_DER_BASE64: &str = "MIIC5TCCAc2gAwIBAgIUU9vs9bM9GVdxhmM27KuuwH0H41YwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwOZnV0dXJlLmV4YW1wbGUwIhgPMzAwMTAxMDEwMDAwMDBaGA8zMDAyMDEwMTAwMDAwMFowGTEXMBUGA1UEAwwOZnV0dXJlLmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2hQQoor2HD8R0f4wyEL+o2FgGx9XqApo6hVj5T2Y+5jeybDgq2keqYvIW8CPJs1efBHzZx57Q2nqB7vSojuYz3Y8uOeDG3W1TyjjX9pKyRUwehZWP3in1apA8Q2ul68yiveUpLmyf71BeKFGmschuMHJ09LcIoYgXa3IbEoLKRNBAQu96Z99I0TprU63owGBE+ljr+wvdSz/nBm49CgjS0tQtNUbyvnjLQzn2kJFk8YpicaurphS3AWdYjKH6nCR2GWgkks9+jiFPrTSxThbVfKJ7/iefylU56jGlHHPyvp1q6y91S+SATHgGVHZmdrAk8eNku7HXU5fQS3sE01tZAgMBAAGjITAfMB0GA1UdDgQWBBTthUULw+S7t7JldNsidKU2TBNIhTANBgkqhkiG9w0BAQsFAAOCAQEAr9/7IhLSAdVM8o0yG3s6icMM/+VOqVD1W106gscKtbPyMeoDZ/uaBmr95QalcSNFNYvC9rWME4OYSytTv9kbK6UFY8oPxCODasXkvBxV2Gg2Wuwv8h2mxBrvpAvXv/wtF71ghcKTckc6f42491dPgjjPsfO3F7nDAMdVCGooTiM11da+4WpURXyqaN+aDSE63Qrx7sS1ybRH3VRzKFumt+PSjHAOLiF8V2SjO7ZQHjRd4gq95UiYQbwTJMM0WutvDI4zYVLrmEoidU56tJE4TtW1XkxoZAaOnbjsgrKJ/PSi1NkoZyYpxEEhiPNV8X2pKsX34RCGJ3reSSNjRzfPvA==";

    #[test]
    fn pem_to_der_many_parses_single_certificate() {
        let ders = pem_to_der_many(VALID_CERT_PEM).expect("valid pem parses");
        assert_eq!(ders.len(), 1);
        let expected = base64::engine::general_purpose::STANDARD
            .decode(VALID_CERT_DER_BASE64)
            .expect("valid base64");
        assert_eq!(ders[0], expected);
    }

    #[test]
    fn pem_to_der_many_errors_when_no_certificate_present() {
        let err = pem_to_der_many("").expect_err("empty pem should error");
        assert!(err.to_string().contains("no certificates"));
    }

    #[test]
    fn ensure_trust_anchor_accepts_matching_root() {
        let leaf = vec![1u8];
        let root = vec![2u8, 3u8];
        let chain = vec![leaf, root.clone()];
        let trust_roots = vec![root];

        ensure_trust_anchor(&chain, &trust_roots).expect("matching root should pass");
    }

    #[test]
    fn ensure_trust_anchor_rejects_unknown_root() {
        let chain = vec![vec![1u8], vec![2u8]];
        let trust_roots = vec![vec![9u8]];

        let err =
            ensure_trust_anchor(&chain, &trust_roots).expect_err("non-matching root should error");
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn cbor_to_json_converts_bytes_to_hex_strings() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(
            CborValue::Text("0".into()),
            CborValue::Bytes(vec![0xCA, 0xFE]),
        );

        let mut root = BTreeMap::new();
        root.insert(
            CborValue::Text("module_id".into()),
            CborValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        );
        root.insert(CborValue::Text("pcrs".into()), CborValue::Map(pcrs));

        let cbor = CborValue::Map(root);

        let json = cbor_to_json(&cbor).expect("conversion should succeed");
        assert_eq!(json["module_id"].as_str(), Some("deadbeef"));
        assert_eq!(json["pcrs"]["0"].as_str(), Some("cafe"));
    }

    #[test]
    fn ensure_subset_handles_hex_case_insensitively() {
        let actual = json!({
            "module_id": "deadbeef",
            "pcrs": {"0": "cafe"},
        });
        let expected = json!({
            "module_id": "DEADBEEF",
        });

        ensure_subset(&actual, &expected, "module_id")
            .expect("hex comparison should be case insensitive");
    }

    #[test]
    fn ensure_subset_errors_on_missing_key() {
        let actual = json!({"module_id": "dead"});
        let expected = json!({"nonce": "beef"});

        let err =
            ensure_subset(&actual, &expected, "payload").expect_err("missing key should error");
        assert!(err.to_string().contains("missing key 'nonce'"));
    }

    #[test]
    fn basic_chain_sanity_accepts_currently_valid_certificate() {
        let leaf = base64::engine::general_purpose::STANDARD
            .decode(VALID_CERT_DER_BASE64)
            .expect("valid base64");
        basic_chain_sanity(&leaf, &[]).expect("valid certificate should pass");
    }

    #[test]
    fn basic_chain_sanity_rejects_not_yet_valid_certificate() {
        let leaf = base64::engine::general_purpose::STANDARD
            .decode(FUTURE_CERT_DER_BASE64)
            .expect("valid base64");
        let err = basic_chain_sanity(&leaf, &[]).expect_err("future certificate should fail");
        assert!(err.to_string().contains("not valid at current time"));
    }
}
