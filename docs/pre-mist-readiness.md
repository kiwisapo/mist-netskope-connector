# Pre-Mist implementation readiness

Reviewed against the local implementation on 20 September 2026. This document
separates offline-verifiable engineering from deployment and vendor acceptance.
The older API and codebase assessments contain historical observations; they
are not current production certification.

## Implemented and locally verified

| Area | Implemented behavior | Evidence |
|---|---|---|
| Template preservation | Journal a hash of unrelated template configuration before provisioning/cleanup PUTs; verify readback and retain the guard across uncertain responses and restarts. Ignore only top-level server metadata (`id`, `org_id`, `created_time`, `modified_time`) and normalise empty ancestors of owned paths. | Replacement-style PUT, unrelated loss, restart, cleanup refusal and pre-write concurrent-edit tests. |
| Recovery | Preserve create uncertainty; converge after lost PATCH/DELETE responses, lagging deletion visibility and interruption between vendor key updates. | Synthetic state-machine tests in `tests/test_prework.py`, in addition to existing lifecycle tests. |
| Operational status | Persist pass start/finish, duration, mode, success timestamps, request counts, error count when available and aggregate health. Persist connection health observation timestamps. Service JSON includes an `operational` summary. | Success/failure/preview and health-unknown tests; existing service shutdown test. |
| Inbox retention | Prune completed events older than seven days on scheduled passes as well as new deliveries. Never expire pending work. | Retention test with old completed and unresolved events. |
| Backup/restore | Back up SQLite consistently under the worker lock and copy private PSK files. Checksum the snapshot. Restore only into a new directory, verify checksums, database integrity and tenant binding, and preserve installation identity. | Round-trip convergence without duplicate provisioning; corruption, wrong-binding, path-traversal, symlink, existing-target and lock tests. |
| Earlier fixes | CI workflow, bounded receiver, private state, POP roles/uniqueness, masked secrets in lists and fresh cleanup ownership checks are already implemented. | Existing assessment, contract, optimisation and review regression suites. |

The local suite currently has **168 tests**, with **89% combined statement/branch
coverage** on Python 3.12. Ruff passes. These are mocked and loopback checks;
they are not evidence of a deployed service or a functioning IPsec tunnel.

## Operational commands

Stop the service before maintenance. Keep the lifecycle configuration and all
five API environment variables available: the CLI validates configuration and
tenant binding even though these commands make no vendor calls.

```sh
.venv/bin/python netskope_mist_connector.py --lifecycle-config lifecycle.local.json \
  --state-dir ./state --operational-status
.venv/bin/python netskope_mist_connector.py --lifecycle-config lifecycle.local.json \
  --state-dir ./state --backup-state /secure/backups/connector-20260920
.venv/bin/python netskope_mist_connector.py --lifecycle-config lifecycle.local.json \
  --state-dir /secure/restore/connector-20260920 \
  --restore-state /secure/backups/connector-20260920
```

Create the protected parent directories first; the backup and restore leaf
directories must not exist. Store backups outside the checkout: they contain
PSKs and are **not encrypted**. Checksums detect corruption, not malicious
replacement of both data and manifest. Apply storage encryption, access and
retention controls appropriate to the deployment.

A backup must include every active connection's secret. It also retains valid
orphan and retired secret files. Restore never overwrites existing state and
refuses a different organisation/API-origin binding. Stop the original writer
before activating a restored copy; matching installation identity must never
be active in two directories at once. Inspect `--status`, run a read-only
preview, and verify the intended state-directory path before enabling apply.

During service operation, collect the existing JSON output with the deployment's
log/monitoring agent. Alert separately on stale `last_apply_success_at`, pass
errors, persistent down/unknown health, and growing pending work. Preview
success does not advance the applied-success timestamp. A successful pass does
not imply healthy tunnels. `--operational-status` is a stopped-service inspection
command, not a concurrent metrics endpoint. A crash can leave the last pass
marked `running`; use its start time and external process supervision to detect
staleness. Alert delivery and thresholds require deployment testing.

## Remaining qualification gates

1. **Mist PUT semantics and hidden fields.** Preservation checks detect observed
   unrelated changes after a write; they cannot prevent the first destructive
   write or detect fields that were already omitted on GET. Qualify partial PUT
   semantics and masked/omitted secret behavior before applying. Other connections sharing a template cannot write while a preservation guard
   remains unresolved. A failed guard requires investigation and repair, not journal deletion or automatic replay
   of an old whole-template snapshot.
2. **Real delivery and forwarding.** Capture signed audit/ping requests through
   the intended HTTPS proxy. Verify signature encoding, body fidelity, retry
   behavior, request limits, shutdown and durable recovery.
3. **SRX and SSR acceptance.** Qualify actual platform/firmware mappings, identity,
   PSKs, both POP roles, steering/policy references, traffic and failover.
4. **Shared templates and automatic onboarding.** Variable substitution in every
   custom-IPsec field, settings merge semantics, authoritative WAN discovery,
   template assignment recovery and secret placement are not yet qualified.
   Current profiles still require dedicated assigned templates and site inputs.
5. **Optional read optimisations.** Variable search and targeted Netskope reads
   have documented shapes, but are not enabled. Search completeness/freshness,
   source filters and continuation validation need qualification; complete
   inventories remain authoritative for retirement and ownership collisions.
6. **Concurrency and production restore.** Conditional writes/deletes are
   unverified. Fresh reads narrow but cannot eliminate the final race. Validate
   one-writer operation, service/proxy load, disk faults and restoration on the
   actual deployment filesystem. Multi-host HA is outside this design.

No Mist or Netskope mutations were used to validate this prework.
