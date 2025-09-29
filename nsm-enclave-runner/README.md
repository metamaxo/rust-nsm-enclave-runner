# nsm-enclave-runner

`nsm-enclave-runner` packages the AWS Nitro Secure Module (NSM) API server into
an enclave image. It exposes a small HTTPS API listening on `0.0.0.0:8443`
inside the enclave so verifiers can request fresh attestation documents, read
platform constraints, and inspect metadata.

## Runtime Overview

- Developer-supplied TLS keypair is generated at boot (self-signed); trust is
  derived from attestation.
- `/attestation` accepts `{"nonce_b64": "..."}` and responds with:
  - the raw NSM `AttestationDocument` (COSE_Sign1, base64 encoded)
  - the attestation signing certificate and cabundle (base64 DER)
  - convenience JSON fields (PCRs, measurement shortcut, module ID, digest,
    timestamp, user data, enclave TLS SPKI)
  - the enclave TLS leaf certificate (DER, base64) for SPKI binding

All canonical data remains inside the COSE document so third-party verifiers can
parse it independently.

## Building & Running

Use the helper scripts from the repository root:

```bash
./scripts/build_enclave.sh      # builds Docker image + EIF + measurements
./scripts/run_enclave.sh        # launches the enclave and records run info
./scripts/start_socat_bridge.sh # forwards host 8443 → enclave vsock 8443
```

Optional helpers:

- `./scripts/open_enclave_console.sh` – attach to the enclave serial console
- `./scripts/cleanup_workspace.sh` – remove generated artifacts

Artifacts for this crate are emitted under `nsm-enclave-runner/target/enclave/`
(EIF, measurement JSON, PCR policy, Nitro root certificate, run metadata).

## Companion Verifier

The `attestation-verifier` crate (`nitro_verifier` library / CLI) validates
responses emitted by `/attestation`. The script
`./scripts/run_attestation_verifier.sh` drives the CLI with the correct PCR
policy and root certificate to provide an end-to-end sanity check.
