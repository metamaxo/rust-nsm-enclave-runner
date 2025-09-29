# Nitro Enclave Workflow

This repository contains two major pieces:

- `nsm-enclave-runner`: the enclave application that serves attestation material
  over HTTPS.
- `attestation-verifier` (`nitro_verifier` crate): a reusable library + CLI for
  validating AWS Nitro Enclave attestation responses.

The scripts under `scripts/` orchestrate the full build → run → verify loop with
opinionated defaults so you can iterate quickly on a workstation.

## Prerequisites

Install the following on the parent instance:

- Docker with Nitro Enclaves support
- `nitro-cli` and the Nitro kernel modules (`sudo nitro-cli configure-enclave`)
- `jq`, `socat`, `curl`, and `sudo`

## Typical Flow

```bash
# 1. Build the enclave image, EIF, measurements, and expected PCR policy
./scripts/build_enclave.sh

# 2. Launch the enclave (writes run metadata to nsm-enclave-runner/target/enclave)
./scripts/run_enclave.sh

# 3. (Optional) watch the enclave console
./scripts/open_enclave_console.sh

# 4. Forward host TCP port 8443 → enclave vsock 8443 for HTTPS access
./scripts/start_socat_bridge.sh

# 5. Verify attestation using the nitro_verifier CLI (library backed)
./scripts/run_attestation_verifier.sh

# 6. Reset extracted artifacts if you want a clean slate
./scripts/cleanup_workspace.sh
```

All generated artifacts (EIF, measurements, PCR policy JSON, Nitro root cert,
run metadata) live under `nsm-enclave-runner/target/enclave/` for easy archival
or external tooling.

## Verifier Library Usage

The `attestation-verifier` crate exposes `nitro_verifier::attestation`, which you
can embed in other projects. Minimal example:

```rust
use nitro_verifier::attestation::{Verifier, VerifierConfig};
use std::time::Duration;

let mut cfg = VerifierConfig::default();
cfg.root_pem_paths.push("assets/aws-nitro-root.pem".into());
cfg.freshness = Duration::from_secs(300);
// populate cfg.expected_pcrs / expected_measurement as needed

let verifier = Verifier::new(cfg)?;
let response_body = /* JSON from /attestation */;
let expected_nonce = "...base64 nonce...";
let attn = verifier.verify_json(&response_body, expected_nonce)?;
println!("module {} attested with root {}", attn.module_id, attn.root_fingerprint_sha256);
```

The CLI located in `attestation-verifier/src/main.rs` is built on top of this
API and remains the quickest way to validate responses produced by the helper
scripts.

## Project Layout

- `nsm-enclave-runner/`: enclave runtime, REST API, and Docker context
- `attestation-verifier/`: library + CLI for attestation verification
- `scripts/`: convenience scripts for building/running/verifying the enclave
- `assets/`: bundled Nitro root certificate and other static assets
