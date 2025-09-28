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

### 6. Build the enclave container image

The Nitro build scripts expect an image tagged `enclave-runner:enclave` that
contains the compiled binary and AF_VSOCK support.

```bash
docker build -f Dockerfile.enclave -t enclave-runner:enclave .
```

When testing the container locally (outside a Nitro enclave microVM) you **must**
grant the `NET_ADMIN` capability so the process can bind the VSOCK listener:

```bash
docker run --rm --cap-add=NET_ADMIN enclave-runner:enclave
```

Without that capability the process exits immediately with `Operation not
permitted` once it tries to create the VSOCK socket.

---

## Nitro Enclave Workflow

The helper scripts now live in the repository-level `scripts/` directory. Run them
from the repo root so they can find this crate and the verifier automatically.
They assume `docker`, `nitro-cli`, `jq`, `socat`, and `sudo` are installed on the host.

1. **Build artifacts**
   ```bash
   ./scripts/build_enclave.sh
   ```
   - Produces the Docker image `enclave-runner:enclave`
   - Emits `nsm-enclave-runner/target/enclave/enclave-runner.eif`
   - Saves `nsm-enclave-runner/target/enclave/enclave-runner-measurements.json`
   - Saves `nsm-enclave-runner/target/enclave/enclave-runner-expected-pcrs.json`
   - Stages the bundled Nitro root cert (`assets/aws-nitro-root.pem`) to `nsm-enclave-runner/target/enclave/nitro-root.pem`
   > Verifies the SHA-256 fingerprint equals `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`

2. **Launch the enclave**
   ```bash
   ./scripts/run_enclave.sh
   ```
   - Terminates any existing enclave, then runs the EIF headlessly
   - Stores the `nitro-cli run-enclave` output in `nsm-enclave-runner/target/enclave/enclave-run.json`
   - Prints the new Enclave ID and CID

3. **(Optional) Watch the console**
   ```bash
   ./scripts/open_enclave_console.sh
   ```
   Uses the saved Enclave ID to attach to the serial console.

4. **Expose the HTTPS endpoint to the host**
   ```bash
   ./scripts/start_socat_bridge.sh
   ```
   Forwards host TCP port `8443` → enclave CID/port `8443` using `socat`.

5. **Run attestation verification from the host**
   ```bash
   ./scripts/run_attestation_verifier.sh
   ```
   Runs the companion verifier (`attestation-verifier`) with the measurements
   produced in step 1. The script sets the required env vars so the verifier can
   compare PCRs and trust roots automatically.

All intermediate files live under `nsm-enclave-runner/target/enclave/`, making it easy to archive
or feed into external tooling.

6. **Reset workspace before re-applying a patch**
   ```bash
   ./scripts/cleanup_workspace.sh
   ```
   Removes extracted artifacts (including this directory) so you can unpack a fresh archive.

---

## Development

Lint + test:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --all-features
```
