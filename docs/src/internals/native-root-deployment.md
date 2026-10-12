# Explicit native-root deployment

The default installer remains the nonroot `aenv` service. The native guest currently requires UID/GID0 for protected profiles, relay peer credentials, broker credentials and spool custody. Enabling a native profile in the default nonroot service does not satisfy those guards.

`AENV_DEPLOYMENT_MODE=native-root` selects a separate **fresh-only**, root-owned service and state tree. It fixes `User=root`, `Group=root`, KVM supplementary group, only NET_ADMIN/SYS_ADMIN capability bounds, locked NOROOT and NoNewPrivileges. It adds no DAC/SETUID/CHOWN capabilities or setuid wrapper. Shared `aenv` service/data/config are not overwritten or stopped. Native mode refuses existing installation destinations and does not download dependencies or execute legacy host setup. Prepare `/dev/kvm` access separately; the installer does not mutate host networking/ublk for this mode.

Run the repository installer as root with an explicit protected native profile, its matching VMM path, and an explicitly pinned native-capable server source:

```sh
AENV_DEPLOYMENT_MODE=native-root \
AENV_NATIVE_PROFILE=/srv/codex-guest-416/FRESH_NONCE/agentenv-profile.json \
AENV_NATIVE_VMM=/usr/local/bin/firecracker \
AENV_NATIVE_SERVER_SOURCE=/root/protected-stage/server \
AENV_NATIVE_SERVER_SHA256=ACTUAL_SHA256 \
bash scripts/install.sh
```

Use the actual profile namespace and SHA, not these placeholder values. Profile/credentials remain in their original root-private namespace; they are not copied, exposed or consumed by installation. Server source must be protected root-owned0755 single-link; profile must be root-owned0600 single-link. Both have protected ancestors. The installer creates separate root700 home/work/runtime/state/snapshot directories and a root600 global config/env/unit. Read-only `server --check-native-deployment` verifies the native-only policy before writing the unit; failure preserves the partial owned installation for inspection, never recursively cleans or starts it. Review it before explicitly starting `aenv-native-root`.

Runtime native-root validation requires actual Linux UID/GID0, KVM, protected root600 global config, protected native profile and matching VMM, private home/work/runtime directories, no legacy resource pools/P2P/extensions/proxy domains/snapshot tracking, private snapshot paths, and fresh state. It skips legacy dependency download, network preparation, ublk startup and VM prewarm. Default legacy behavior is unchanged. Native setup is not a root exception to `server --setup-host --runtime-user aenv`: that existing path still requires a nonroot runtime account.

The API rejects legacy template/image/snapshot/auto-resume/network effect routes before handlers. Only health/metrics, native capability/control, read-only sandbox metadata and delete are admitted. Existing native-create reports worker authority unavailable until its independent authority integration is qualified; installation does not fabricate that authority or make unsupported CLI operations work. Factory request validation still rejects foreign images, envd/MMDS/extensions/custom network/disk contexts and snapshots. Native protocol filesystem/command operations retain their existing supported capability bounds. Recursive directories and other unfinished migrations remain unsupported.

`Restart=no` avoids silently repeating consumed profiles. A stopped service with persisted state is not auto-resumable; supply a new explicit protected state/profile ownership arrangement after genuine original-owner cleanup. `KillMode=process` matches retained child ownership: stopping/reaping the server alone does not prove child/device/debt absence. Actual lifecycle acceptance and external retirement checks are required.

Pure verification (no service/filesystem provisioning):

```sh
bash scripts/tests/verify-native-root-install-service.sh
```

These render/refusal checks do **not** prove a boot, readiness, execution or cleanup. Exact installed-unit capability acceptance, native Factory→VMM→authenticated READY→Executor/files→stop, ownership debt and full client/API migration must be run separately against fresh owned inputs.
