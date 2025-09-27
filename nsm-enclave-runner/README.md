# Enclave Runner

A small Rust service that demonstrates **RA-TLS (Remote Attestation with TLS)**,  
public attestation endpoints, and an optional **mutual TLS (mTLS) host channel**.

---

## Quickstart

### 1. Configure
Copy the sample `.env`:
```bash
cp .env.example .env
````

Edit `.env` to your liking. Defaults bind to:

* Public (attestation) listener: `127.0.0.1:8443`
* Host (mTLS) listener: `127.0.0.1:9443` (disabled unless you set `RUNNER_HOST_CA_PEM_PATH`)

---

### 2. Run the runner

```bash
cargo run -p runner
```

Logs will show bound addresses:

```
INFO  binding public listener at 127.0.0.1:8443
INFO  HOST CA not set -> host mTLS listener will NOT start (dev mode)
```

---

### 3. Public endpoints (RA-TLS)

Health:

```bash
curl -k https://127.0.0.1:8443/health
```

Ready:

```bash
curl -k https://127.0.0.1:8443/ready
```

Attestation (includes cert + quote in base64):

```bash
curl -k https://127.0.0.1:8443/attestation | jq
```

The response contract now surfaces everything a verifier needs to reproduce the
Nitro checks without decoding CBOR manually:

- `attestation.quote_b64` – raw NSM COSE_Sign1 attestation (still AWS-signed).
- `attestation.cabundle_der_b64[]` / `attestation.attestation_cert_der_b64` –
  DER certificates (base64) forming the signing chain, leaf first.
- `attestation.pcrs_hex{}` / `attestation.measurement_hex` – hex-encoded PCR
  values straight from the document (PCR0 is the canonical measurement).
- `attestation.module_id`, `attestation.digest`, `attestation.timestamp_ms` –
  document metadata.
- `attestation.nonce_b64`, `attestation.spki_der_b64`, `attestation.user_data_b64`
  – bindings that must match the verifier challenge and enclave SPKI.
- `cert_der_b64` – TLS leaf certificate presented on the HTTPS connection;
  its SPKI is identical to `attestation.spki_der_b64` to enable pinning.

---

### 4. Enable host mTLS

Generate a CA + client cert (dev only):

```bash
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout ca.key -out ca.pem -subj "/CN=Test CA"

openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr -subj "/CN=Host"

openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key \
  -CAcreateserial -out client.pem -days 365 \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth")
```

Update `.env`:

```dotenv
RUNNER_HOST_CA_PEM_PATH=./ca.pem
```

Restart runner.

---

### 5. Host endpoints (require client cert)

Status:

```bash
curl -vk --cert client.pem --key client.key \
  https://127.0.0.1:9443/_host/status
```

Reload policy:

```bash
curl -vk --cert client.pem --key client.key \
  -X POST https://127.0.0.1:9443/_host/reload_policy
```

> Add `--cacert ca.pem` if you want **client→server validation** too (not just server→client).

---

## Development

Lint + test:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --all-features
```

