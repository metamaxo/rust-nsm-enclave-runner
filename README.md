## Nitro Enclave Workflow

The scripts in `scripts/` hard-code the paths and tags used by the project, so
you can walk the entire enclave build → run → verify loop without extra flags.
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

