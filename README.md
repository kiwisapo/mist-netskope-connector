# Mist-driven Netskope tunnel provisioning

An unofficial connector that keeps Netskope IPsec tunnels in step with Juniper Mist sites. It receives Mist organisation **audit** webhooks, reconciles enrolled sites on a schedule, creates and updates the tunnels it owns, writes the matching entries into each site's Mist gateway template, and retires tunnels only after a site's deletion is confirmed. SRX and SSR are driven by configurable profiles; the service contains no hard-coded vendor payloads.

**Status.** This is an implementation foundation with a mocked regression suite. Repository notes record Netskope development-tenant checks and Mist OpenAPI schema checks from September 2026. These are historical evidence, not current tenant certification. No end-to-end tunnel validation is recorded, and normal-path automation is incomplete: each enrolled site still needs its variables set and a dedicated gateway template assigned in advance. Complete the profile mappings from a working lab configuration before enabling writes.

## How it works

1. **Enrolment.** A site opts in by setting the site variable `netskope_profile` to a profile name (`srx`, `ssr`, or another you define). The service lists the organisation's sites and reads each site's settings. Site listings are cross-checked against Mist's `X-Page-Total` header when present.
2. **Triggers.** In `--serve` mode, audit webhooks validate the topic and organisation, enqueue event hashes in SQLite, and wake the reconciler. Raw event bodies are not persisted and event contents do not directly command resource changes. A pass runs at start-up; after each pass the service waits up to `reconcile_interval_seconds` (default 600), interruptible by a webhook, then pauses another 10 seconds. Pass duration adds to this interval. Without `--serve`, the command runs once.
3. **Preflight.** For each enrolled connection the service checks the assigned template, resolves the profile against the two selected POPs (accepting, bandwidth tier, phase 1/2 crypto, IKEv2, lifetimes) and rejects invalid inputs before provisioning that connection. This is a per-connection check, not an atomic transaction across all sites or connections.
4. **Ownership.** Each connection has a stable key (org + site + connection ID), a deterministic tunnel name, an installation-specific marker in the Netskope `notes` field and a generated PSK held in a private file. Site names are never used for ownership.
5. **Writes.** The service persists create intent, configuration state, and pending Mist entry hashes before the corresponding mutations. Writes are single-attempt at the HTTP layer; later passes may repeat idempotent updates. Readback checks visible configuration and journalled hashes of unrelated template sections, including recovery after an uncertain PUT. Netskope PSKs are excluded from comparison, and masked Mist PSKs cannot prove peer agreement. A later pass recovers partial work.
6. **Retirement.** A site must be missing from a complete inventory, return a site-specific 404, stay missing for `deletion_grace_seconds` (default 3600) and be re-checked before its owned Mist entries and tunnel are removed. Cleanup is off until `cleanup_enabled` is `true`. Removing the profile variable, a device going offline or an API error never triggers deletion.

## Install and configure

Python 3.9+ on Linux or macOS with an OpenSSL-backed interpreter (`python3 -c 'import ssl; print(ssl.OPENSSL_VERSION)'`; some macOS system Python installations use LibreSSL; check the actual interpreter before use). The only direct runtime dependency is `requests`, which installs its own dependencies. POSIX file locking is used, so Windows is not supported.

```sh
uv venv --python 3.12 .venv            # or: python3 -m venv .venv
uv pip install -r requirements.txt     # or: .venv/bin/python -m pip install -r requirements.txt
cp examples/lifecycle.example.json lifecycle.local.json
```

`.mise.toml` selects Python 3.12 and the latest available `uv` and Ruff. `pyproject.toml` holds Ruff and coverage settings.

Export credentials into the process environment through a secrets manager or a protected environment file loaded by your service manager. The CLI does not automatically load `.env` files. Do not pass credentials as command-line arguments:

| Variable | Purpose |
|---|---|
| `NETSKOPE_TENANT_URL` | HTTPS tenant origin only; no API path, credentials, query, or fragment |
| `NETSKOPE_API_TOKEN` | Token with the `ip_sec` API group, read/write (`Netskope-Api-Token` header) |
| `MIST_BASE_URL` | Regional HTTPS API origin only; do not append `/api/v1` |
| `MIST_API_TOKEN` | Read sites, settings and gateway templates; write gateway templates |
| `MIST_ORG_ID` | Target organisation ID |
| `MIST_WEBHOOK_SECRET` | At least 32 characters; required for `--serve` |

The permissions above cover apply mode; preview needs only the corresponding read permissions. `--profile-digest` needs no credentials.

The state directory (`--state-dir`, default `./state`) holds the SQLite journal and the per-connection PSK files. Keep it on persistent local storage, mode `0700`, owned by the service account, and back the two up together while the service is stopped or using a consistent SQLite-aware backup. Run one installation per organisation; the file lock only serialises workers sharing the same directory.

## Profiles

`examples/lifecycle.example.json` contains an SRX and an SSR profile. Each profile has one or more connections with a stable `id`, the Netskope tunnel payload, explicit phase 1/2 crypto, the Mist entries to own, and optional health checks.

- **Netskope payload.** `pops` selects two distinct tenant POPs, primary first and secondary second. IDs and names are resolved before checking uniqueness; readback uses the POP `primary` flag so response ordering does not hide a role change. `sourcetype` must be one of `User`, `Machine`, `IoT`, `Guest Wifi`, `Mixed`, `Private App Support`. `options.xff.iplist` may only be present when `xff.enable` is true. `Null` encryption is refused even though POPs advertise it. PATCH includes all required tunnel fields and the options explicitly supplied by the profile. Repository tenant observations report that omitted fields can reset to defaults; set intended options explicitly.
- **Mist entries.** Each entry names a JSON key path of at least two levels inside the gateway template and the value to place there. The example uses the `tunnel_configs` → `provider: custom-ipsec` schema from Juniper's OpenAPI document (`local_id`, `psk`, `ike_proposals`, `primary.hosts`, `primary.remote_ids`, `primary.probe_ips`, `primary.wan_names`, `networks`), used by both example profiles. Schema alignment does not establish support on a particular SRX/SSR platform or firmware. The mappings are not lab-validated: `remote_ids` = POP gateway is an assumption, and `networks` is left as a `REPLACE_WITH_` placeholder because it is deployment-specific. Include every connection-owned entry, including any steering or policy references that must disappear on retirement.
- **Placeholders.** A whole-value `${...}` token is replaced with the referenced value and keeps its JSON type; interpolation inside a string is rejected. Initial contexts are `site`, `setting`, `vars`, `tunnel.name` and `owner`. Payload rendering also exposes `secret` and `crypto`; selected POP contexts `primary` and `secondary` become available for Mist entries after POP resolution. Tokens in path-list elements are rendered, but dictionary keys are not.
- **Template scope.** The site's `gatewaytemplate_id` must equal the profile's resolved `template_id`, and that template must not be assigned to any other site. Several connections on the same site may own distinct entries in it. Changing a connection's template or owned paths is refused; migrate explicitly.
- **Secret readback.** `secret_readback` is `exact` by default. Set `masked` only once the lab shows Mist masks the PSK on read; then only the PSK fields are normalised (including those nested inside lists) and every other field must still match.
- **Health checks.** Predicates over the Netskope tunnel response, for example `{"path": ["pops", "0", "status"], "equals": "up"}`. Health is reported as `up`, `down`, `unknown` or `not_verified`, separately from configuration state. List indices refer to API response order, not primary/secondary roles. A `configured` result or zero exit code does not establish tunnel health or traffic flow.

Example site variables:

```json
{
  "netskope_profile": "srx",
  "netskope_identity": "branch1.example.invalid",
  "netskope_wan_ip": "192.0.2.10",
  "netskope_wan_name": "wan0",
  "netskope_primary_pop": "bne1",
  "netskope_secondary_pop": "syd1"
}
```

Replace these illustrative site values with deployment-specific values. Site variables and profiles hold configuration only; use `${secret}` for the generated PSK, never a literal PSK or token.

## Run

Preview with no vendor writes (authenticated reads and local state only). It validates prerequisites but does not show a complete diff, prove vendor acceptance, or generate a real PSK for a new connection:

```sh
.venv/bin/python netskope_mist_connector.py --lifecycle-config lifecycle.local.json --state-dir ./state
```

Applying requires an attestation in the config: set `validation.evidence` to your lab evidence reference and `validation.profiles_sha256` to the output of `--profile-digest`. The digest covers only the `profiles` object, not site variables or other policy settings. Changes to profiles invalidate it, and literal `REPLACE_WITH_` markers remaining in that object block `--apply`. The evidence reference is an operator attestation; the program does not inspect the evidence or certify the configuration.

```sh
.venv/bin/python netskope_mist_connector.py --lifecycle-config lifecycle.local.json --profile-digest
.venv/bin/python netskope_mist_connector.py --lifecycle-config lifecycle.local.json --state-dir ./state --apply
.venv/bin/python netskope_mist_connector.py --lifecycle-config lifecycle.local.json --state-dir ./state --apply --serve
```

`--serve` listens on `127.0.0.1:8080` (`--listen`, `--port`) at `/webhooks/mist`. Put it behind an HTTPS reverse proxy with request-size limits, and configure a Mist organisation webhook (HTTP Post, topic `audits`) with the same secret. The receiver verifies `X-Mist-Signature-v2` over the raw body, accepts `202` only after a durable enqueue, rejects events for other organisations, answers signed `ping` requests, and bounds itself to eight worker threads with a 10-second socket timeout and 10,000 pending events. On `SIGTERM`, the loop notices shutdown during waits or between provisioning sites; in-flight work and retirement may continue before exit. Events are marked done only after a pass returns without connection errors; unacknowledged events remain pending.

In `--serve` mode each pass prints a JSON line containing either `results` or an error, request counts, and any budget warning. The service also emits an `operational` summary with persisted pass freshness, mode, duration, health counts and pending work. One-shot mode prints an indented results array and exits nonzero for reconciliation errors; it also persists pass status. The warning uses `mist_hourly_request_budget` (default 5000) and the configured wait interval; it is an estimate, not a rate limiter. A steady-state applied pass costs approximately one Mist settings read per site plus five Mist calls per enrolled connection, plus inventory pagination. Webhooks, retries and cleanup add calls. Netskope requests are spaced by at least 0.25 seconds using a four-requests/second assumption from prior tenant observations. Verify current tenant limits and account for other API clients.

`examples/mist-netskope-connector.service` is a Debian systemd unit for `/opt/mist-netskope-connector` with a private `/var/lib/mist-netskope-connector` state directory and sandboxing directives. Before starting it, create the named service user/group, install the checkout and virtual environment at the specified paths, and provide protected `service.env` and validated `lifecycle.json` files under `/etc/mist-netskope-connector/`. Its `ExecStart` enables `--apply --serve`. The unit does not install these prerequisites or provide a reverse proxy or TLS.

## Recovery

Stop the service first; these commands need the state lock. Both require the credential environment and a readable lifecycle configuration. `--status` makes no vendor calls; its object keys supply `CONNECTION_KEY` for recovery.

```sh
.venv/bin/python netskope_mist_connector.py --lifecycle-config lifecycle.local.json --state-dir ./state --status
.venv/bin/python netskope_mist_connector.py --lifecycle-config lifecycle.local.json --state-dir ./state \
  --resolve-create CONNECTION_KEY --confirm-no-remote-tunnel
```

- A lost create response is recovered on the next pass through the ownership marker. If no tunnel ever appears, the service will not POST again; confirm with the tenant that nothing was created, then run `--resolve-create`, which resets local state without writing to either vendor.
- A lost Mist PUT response is recovered through the hashes journalled before the write. A preservation mismatch blocks subsequent provisioning/cleanup until investigated and repaired; detection does not undo the first write or prove vendor merge semantics. An owned entry changed outside the service blocks further writes until you reconcile it; do not clear the journal to get past the check.
- If the state directory will not open (corrupt database, symlinked file, different tenant), restore the matching backup. A fresh state directory is a new installation and cannot adopt existing resources.
- Cleanup refreshes tunnel ownership before removing Mist entries and again immediately before Netskope deletion. Conditional DELETE support is unverified, so a residual race remains between the final ownership read and deletion; coordinate external edits during retirement.
- The connector sends `If-Match` when Mist returns an ETag and performs a second read before PUT. Conditional-write enforcement has not been established for the target deployment, so a residual read/write race remains. Make this service the only automated writer for the organisation.
- `--list-pops` prints tenant POPs read-only. Run it separately from `--lifecycle-config`; the current CLI requires all five API environment variables even for this Netskope-only diagnostic.

### Operational status and state backup

`--operational-status` reports last-pass freshness, apply/preview mode, aggregate
health and pending events while the service is stopped. `--status` retains its
connection-record output and now includes recorded health observations.

Use `--backup-state NEW_DIRECTORY` to snapshot the locked SQLite journal and
private secrets. Use `--restore-state BACKUP_DIRECTORY` with a new `--state-dir`
to restore a checksum-verified snapshot with matching tenant binding. Both need
the lifecycle configuration and credential environment but make no vendor calls.
Never run the original and restored installations simultaneously.

Backups contain **unencrypted PSKs**. Keep them outside the repository on protected
storage. See [Pre-Mist readiness and recovery commands](docs/pre-mist-readiness.md)
for the restore sequence, monitoring fields and remaining acceptance gates.

## Development

```sh
uv pip install ruff 'coverage[toml]'
.venv/bin/ruff check .
.venv/bin/python -m coverage run -m unittest discover -s tests -v
.venv/bin/python -m coverage report
```

Tests use mocked vendor APIs and a loopback webhook receiver; they are local correctness checks, not interoperability evidence. `.github/workflows/tests.yml` runs `ruff check` and the suite under coverage (85% combined statement/branch coverage threshold from `pyproject.toml`, not an independent branch-only floor) on Python 3.9, 3.12 and 3.13 for pull requests and pushes to `main`; `examples/github-actions-tests.yml` is an identical copy for installation elsewhere.

Before production, capture evidence for creation, duplicate and delayed events, updates, restarts, missed-webhook recovery, deletion, API outages, partial inventories, secret masking, tunnel health and failover for each platform you enable.

## References

- [Juniper Mist OpenAPI specification](https://github.com/mistsys/mist_openapi)
- [Juniper Mist webhook topics](https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/concept/webhook-topics.html) and [webhook configuration](https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/task/webhooks-add-portal.html)
- [Juniper Mist REST API pagination](https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/concept/rest-api-pagination.html) and [rate limiting](https://www.mist.com/documentation/api-rate-limiting/)
- [Netskope steering APIs](https://www.netskope.com/blog/harness-netskope-steering-apis-for-scalable-sd-wan-deployments); the full IPsec API reference is the Swagger document in your tenant (Tools → REST API v2)
