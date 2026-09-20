#!/usr/bin/env python3
"""Mist-driven Netskope IPsec lifecycle connector (unofficial integration).

SERVICE MODEL
-------------
Organisation-level Mist audits trigger current-state reconciliation. A signed
HTTP receiver durably queues event hashes in SQLite before acknowledging them;
a scheduled pass also discovers new/deleted sites and recovers interrupted work.
No exact site-created/deleted event names are assumed. Duplicate or delayed
notifications cannot directly create/delete a resource.

Select a configured SRX or SSR profile through the Mist site variable
netskope_profile. Profiles supply lab-validated vendor payload mappings and
explicit crypto proposals. Each connection uses a stable org/site/WAN key,
a deterministic tunnel name and an installation-specific ownership marker.
Per-tunnel PSKs are generated into private files and never depend on API
readback. The journal stores IDs and hashes, not secret payloads.

The service preflights assigned templates and both POPs, creates/updates only
owned tunnels, merges owned Mist paths, and verifies configuration readback.
HTTP mutations are not retried at the transport layer; later reconciliation
passes may repeat idempotent updates. An uncertain create is recovered by
ownership marker; if no tunnel appears, operator confirmation is required
before another POST. Pending Mist entry hashes allow recovery after a lost
PUT response. One process lock serialises all work for a state directory.

CLEANUP
-------
Only confirmed site removal initiates retirement. A complete inventory read,
site-specific 404, persistent grace period and a second absence check precede
deletion. Offline devices, removed profile variables, API failures and
incomplete inventories do not authorise cleanup. Only journalled Mist paths
and ownership-marked Netskope tunnels are removed. Externally modified entries
stop cleanup; deleted records and private keys are retained for audit/recovery.
Cleanup must be explicitly enabled in configuration.

VALIDATION BOUNDARIES AND WORKAROUNDS
------------------------------------
- Raw Mist SEC payloads differ by deployment. Supply captured JSON paths and
  values in a profile; example mappings still require deployment validation. Apply
  requires a lab evidence reference and the matching profile digest.
- Per-site literal values require a dedicated, assigned gateway template.
  Shared template assignments are rejected; prepare dedicated templates before
  enrolment. Template migration and adopting manual resources are not automatic.
- Exact secret readback is the default. A profile can declare masked readback;
  only declared PSK fields are normalised, and last-submitted key hashes prevent
  update loops. Hidden secrets cannot prove peer agreement: verify tunnel health.
- Optional health predicates report observed Netskope health separately from
  configured state. A lab dataplane/failover test is still required for acceptance.
- Mist writes send only affected top-level sections, preserving other entries.
  ETags are used when returned, and a second read detects intervening edits.
  Without enforced conditional writes there is still a race: designate one
  writer per organisation and coordinate administrator changes.
- Mist site pages are cross-checked against X-Page-Total when the header is
  returned. Netskope inventories must reconcile exactly with their total; a
  larger total is followed with offset/limit continuation and fails closed on
  repeated, missing or shifting pages. Verify the tenant contract in /apidocs.
- Each pass reports its vendor request counts and warns when the projected
  hourly Mist call rate approaches the configured budget (documented Mist
  limit: 5000 calls/hour). This is observation, not service-wide rate limiting.
- This is a POSIX single-host service (Debian/macOS), not an HA controller. Keep
  its private state and secrets together, back them up, and never run independent
  state directories for the same managed resources.

USAGE
-----
See README.md for profiles, enrolment, lab gates, deployment and recovery.

    python3 netskope_mist_connector.py --lifecycle-config lifecycle.local.json
    python3 netskope_mist_connector.py --lifecycle-config lifecycle.local.json --apply
    python3 netskope_mist_connector.py --lifecycle-config lifecycle.local.json --apply --serve

Lifecycle mode defaults to a read-only vendor plan. --serve listens on loopback
port 8080; expose /webhooks/mist through an HTTPS reverse proxy and set a strong
MIST_WEBHOOK_SECRET. Config.from_env() defines API credentials. Lifecycle mode
generates its own keys; no PSK is ever read from the environment.

The CSV/single-site prototype and its guessed Mist payload builder were retired.
--list-pops remains as a read-only diagnostic and uses the same strict transport
as the service. Dry-runs still perform authenticated API reads and open local
private state.

Repository: https://github.com/kiwisapo/mist-netskope-connector. Never commit credentials,
private state or tenant exports.

REFERENCES (REVIEWED 2026-09-18)
-------------------------------
https://github.com/mistsys/mist_openapi
https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/concept/webhook-topics.html
https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/task/webhooks-add-portal.html
https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/concept/rest-api-pagination.html
https://www.netskope.com/blog/harness-netskope-steering-apis-for-scalable-sd-wan-deployments
"""

import argparse
import contextlib
import copy
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import signal
import sqlite3
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 30
READ_ATTEMPTS = 3                 # GET only; mutations are single-attempt by design.
MAX_RETRY_AFTER_SECONDS = 30
MIST_PAGE_LIMIT = 1000            # Documented Mist maximum for limit=.
MIST_DEFAULT_HOURLY_BUDGET = 5000  # Documented Mist limit, reset on the hour boundary.
NETSKOPE_MAX_PAGES = 1000
INBOX_CAPACITY = 10000
INBOX_RETENTION_SECONDS = 604800
WEBHOOK_MAX_BODY_BYTES = 1048576
WEBHOOK_SOCKET_TIMEOUT = 10
WEBHOOK_MAX_WORKERS = 8           # Bounds receiver threads; excess connections are closed.
MIN_PASS_PAUSE_SECONDS = 10       # Dampens audit loops caused by the service's own writes.
NETSKOPE_MIN_SPACING_SECONDS = 0.25  # Observed tenant limit: 4 requests/second (X-RateLimit-Limit-Second).
NETSKOPE_MAX_RESET_WAIT = 5
NETSKOPE_SOURCETYPES = ('User', 'Machine', 'IoT', 'Guest Wifi', 'Mixed', 'Private App Support')  # Tenant-enforced enum.
# Fields a Netskope PATCH must always carry. The tenant resets omitted fields
# to defaults, and the default cipher is "Null" (observed 18 Sep 2026).
NETSKOPE_FULL_PAYLOAD_KEYS = ('site', 'pops', 'bandwidth', 'encryption', 'psk', 'srcidentity', 'srcipidentity',
                              'sourcetype', 'vendor', 'template', 'enable')


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

@dataclass
class Config:
    netskope_tenant_url: str
    netskope_api_token: str
    mist_base_url: str
    mist_api_token: str
    mist_org_id: str

    def __repr__(self) -> str:
        # Tokens must never reach logs or tracebacks through a default repr.
        return ("Config(netskope_tenant_url=%r, mist_base_url=%r, mist_org_id=%r, tokens=<redacted>)"
                % (self.netskope_tenant_url, self.mist_base_url, self.mist_org_id))

    @classmethod
    def from_env(cls) -> "Config":
        required = [
            "NETSKOPE_TENANT_URL",
            "NETSKOPE_API_TOKEN",
            "MIST_BASE_URL",
            "MIST_API_TOKEN",
            "MIST_ORG_ID",
        ]
        missing = [v for v in required if not os.environ.get(v)]
        if missing:
            raise ReconcileError("Missing required environment variables: " + ", ".join(missing))
        return cls(
            netskope_tenant_url=os.environ["NETSKOPE_TENANT_URL"].rstrip("/"),
            netskope_api_token=os.environ["NETSKOPE_API_TOKEN"],
            mist_base_url=os.environ["MIST_BASE_URL"].rstrip("/"),
            mist_api_token=os.environ["MIST_API_TOKEN"],
            mist_org_id=os.environ["MIST_ORG_ID"],
        )


# --------------------------------------------------------------------------
# Parsers for Netskope POP advertisement strings
# --------------------------------------------------------------------------
# POPs advertise comma-separated crypto options, duration strings such as "8h"
# and bandwidth tiers such as "50 mbps, 100 mbps". These parsers only support
# preflight comparison against an explicit, lab-selected profile; nothing here
# selects a proposal on the operator's behalf.

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_csv_options(raw: str) -> List[str]:
    """'AES128-CBC, AES256-CBC' -> ['AES128-CBC', 'AES256-CBC']"""
    if not isinstance(raw, str):
        raise ValueError("Crypto options must be a string")
    return [item.strip() for item in raw.split(",") if item.strip()]


def parse_duration_to_seconds(raw: str) -> int:
    """'8h' -> 28800, '90m' -> 5400; a bare integer string is already seconds."""
    if not isinstance(raw, str):
        raise ValueError("Duration advertisement must be a string")
    raw = raw.strip().lower()
    if raw and raw[-1] in _DURATION_UNITS and raw[:-1].isdigit():
        return int(raw[:-1]) * _DURATION_UNITS[raw[-1]]
    if raw.isdigit():
        return int(raw)
    raise ValueError("Could not parse duration; expected e.g. '8h', '90m' or integer seconds")


_BANDWIDTH_UNITS = {"": 1, "mbps": 1, "gbps": 1000}
_BANDWIDTH_PATTERN = re.compile(r"(\d+)\s*([a-z]*)")


def parse_bandwidth_tiers(raw: str) -> List[int]:
    """'50 mbps, 1 gbps' -> [50, 1000] (Mbps). Unknown units fail closed."""
    if not isinstance(raw, str):
        raise ValueError("Bandwidth advertisement must be a string")
    tiers = []
    for item in raw.split(","):
        item = item.strip().lower()
        if not item:
            continue
        match = _BANDWIDTH_PATTERN.fullmatch(item)
        if not match or match.group(2) not in _BANDWIDTH_UNITS:
            raise ValueError("Unrecognised bandwidth advertisement")
        tiers.append(int(match.group(1)) * _BANDWIDTH_UNITS[match.group(2)])
    return tiers


# --------------------------------------------------------------------------
# Durable event-driven reconciliation. Vendor JSON is supplied by a lab profile.
# --------------------------------------------------------------------------

class ReconcileError(Exception):
    """A safe, non-secret diagnostic suitable for the service status output."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def lookup(value, path):
    for part in path:
        if isinstance(value, list) and str(part).isdigit() and int(part) < len(value):
            value = value[int(part)]
        elif isinstance(value, dict) and part in value:
            value = value[part]
        else:
            raise ReconcileError("Required configuration field is missing")
    return value


def render(value, context):
    """Resolve whole-value ${path.to.field} tokens, preserving JSON types."""
    if isinstance(value, dict):
        return {k: render(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, context) for v in value]
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        return lookup(context, value[2:-1].split("."))
    if isinstance(value, str) and "${" in value:
        raise ReconcileError("Use whole-value placeholders, not interpolation")
    return value


def path_value(document, path):
    current = document
    for key in path:
        if not isinstance(current, dict):
            raise ReconcileError("Mist entry parent is not an object")
        if key not in current:
            return False, None
        current = current[key]
    return True, current


def put_path(document, path, value, delete=False):
    current = document
    for key in path[:-1]:
        if isinstance(current, list) and type(key) is int and 0 <= key < len(current):
            current = current[key]
        elif isinstance(current, dict) and isinstance(key, str):
            current = current.setdefault(key, {})
        else:
            raise ReconcileError("Mist entry path does not match its container")
    if isinstance(current, list):
        if type(path[-1]) is not int or not 0 <= path[-1] < len(current) or delete:
            raise ReconcileError("Invalid managed secret list index")
        current[path[-1]] = copy.deepcopy(value)
        return
    if not isinstance(current, dict) or not isinstance(path[-1], str):
        raise ReconcileError("Mist entry parent is not an object")
    if delete:
        current.pop(path[-1], None)
    else:
        current[path[-1]] = copy.deepcopy(value)


def secret_paths(value, secret, prefix=()):
    """Locate whole-value keys carrying our PSK, for explicitly masked readback."""
    if value == secret:
        return [list(prefix)]
    if isinstance(value, dict):
        return [p for key, child in value.items() for p in secret_paths(child, secret, prefix + (key,))]
    if isinstance(value, list):
        return [p for index, child in enumerate(value) for p in secret_paths(child, secret, prefix + (index,))]
    return []


def entry_hash(value, paths):
    # A validated masked-readback contract cannot detect out-of-band key changes.
    # Track the last submitted key separately and verify actual tunnel health.
    normalized = copy.deepcopy(value)
    for path in paths:
        if not path:
            normalized = '<managed-secret>'
        else:
            put_path(normalized, path, '<managed-secret>')
    return fingerprint(normalized)


def validate_crypto(crypto, pops):
    """Validate explicit, lab-selected proposals against both POP advertisements."""
    if not isinstance(crypto, dict):
        raise ReconcileError("An explicit crypto profile is required")
    for phase in ('phase1', 'phase2'):
        desired = crypto.get(phase, {})
        if not isinstance(desired, dict):
            raise ReconcileError("Crypto phase must be an object")
        for pop in pops:
            options = pop.get('options')
            if not isinstance(options, dict) or not isinstance(options.get(phase), dict):
                raise ReconcileError("POP crypto advertisement is not an object")
            offered = options[phase]
            for key in ('encryptionalgo', 'integrityalgo', 'dhgroup'):
                if desired.get(key) not in parse_csv_options(offered.get(key, '')):
                    raise ReconcileError("Crypto profile is not offered by both POPs: " + phase + '.' + key)
            if str(desired.get('encryptionalgo')).lower() == 'null':
                raise ReconcileError("Null encryption is not permitted")
            lifetime = desired.get('lifetime_seconds')
            if not isinstance(lifetime, int) or not 180 <= lifetime <= 86400:
                raise ReconcileError("Crypto lifetime must be an integer from 180 to 86400")
            if lifetime > parse_duration_to_seconds(offered.get('salifetime', '0')):
                raise ReconcileError("Crypto lifetime exceeds a POP advertisement")
            if phase == 'phase1' and (str(desired.get('ikeversion')) != '2' or str(offered.get('ikeversion')) != '2'):
                raise ReconcileError("IKEv2 must be supported and selected")
            if phase == 'phase2' and (not isinstance(desired.get('pfs'), bool) or desired['pfs'] != offered.get('pfs')):
                raise ReconcileError("PFS profile does not match the POP advertisement")


def ascii_digits(value):
    """True only for ASCII decimal strings; str.isdigit() also accepts e.g. superscripts that int() rejects."""
    return isinstance(value, str) and re.fullmatch(r'[0-9]{1,18}', value) is not None


def checked_id(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"[A-Za-z0-9_-]+", str(value)):
        raise ReconcileError("Invalid API resource identifier")
    return str(value)


class LifecycleAPI:
    """Strict transport; mutations are never blindly retried.

    Netskope inventory must be complete, as indicated by its total field.
    Unexpected envelopes fail closed rather than masquerading as an empty list.
    Mist reads use documented page/limit pagination, reject repeated IDs and
    reconcile with X-Page-Total when that header is returned.
    """
    def __init__(self, cfg):
        self.cfg = cfg
        self.request_counts = {'mist': 0, 'netskope': 0}
        self.tunnel_capacity = None  # {'total', 'maxsites'} from the last complete tunnel listing.
        self._netskope_next_allowed = 0.0
        for url in (cfg.mist_base_url, cfg.netskope_tenant_url):
            parsed = urlparse(url)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
                raise ReconcileError("API base URLs must use HTTPS without credentials or query strings")
        self.mist = requests.Session()
        self.mist.headers['Authorization'] = 'Token ' + cfg.mist_api_token
        self.netskope = requests.Session()
        self.netskope.headers['Netskope-Api-Token'] = cfg.netskope_api_token

    def close(self):
        self.mist.close()
        self.netskope.close()

    def reset_request_counts(self):
        counts, self.request_counts = self.request_counts, {'mist': 0, 'netskope': 0}
        return counts

    def request(self, vendor, method, path, payload=None, missing_ok=False, headers=None, params=None):
        session = self.mist if vendor == 'mist' else self.netskope
        base = self.cfg.mist_base_url if vendor == 'mist' else self.cfg.netskope_tenant_url
        attempts = READ_ATTEMPTS if method == 'GET' else 1
        for attempt in range(attempts):
            last = attempt == attempts - 1
            if vendor == 'netskope':
                self.pace_netskope()
            self.request_counts[vendor] += 1
            try:
                response = session.request(method, base + path, json=payload, headers=headers,
                                           params=params, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            except requests.RequestException:
                if not last:
                    time.sleep(2 ** attempt)
                    continue
                detail = " transport failure" if method == 'GET' else " transport failure; mutation outcome may be uncertain"
                raise ReconcileError(vendor + detail) from None
            if vendor == 'netskope':
                self.note_netskope_limits(getattr(response, 'headers', None) or {})
            if (response.status_code == 429 or response.status_code >= 500) and not last:
                retry = response.headers.get('Retry-After', '')
                time.sleep(min(MAX_RETRY_AFTER_SECONDS, int(retry)) if ascii_digits(retry) else 2 ** attempt)
                continue
            if missing_ok and response.status_code == 404:
                return None, {}
            if vendor == 'netskope' and response.status_code == 409:
                raise ReconcileError("netskope HTTP 409: a tunnel with this site name already exists; reconcile by ownership marker")
            if vendor == 'netskope' and response.status_code == 405:
                # Reported tenant behaviour when tunnels are also managed in the web UI.
                raise ReconcileError("netskope HTTP 405; check that IPsec tunnels are API-managed only")
            if not 200 <= response.status_code < 300:
                raise ReconcileError(vendor + " HTTP " + str(response.status_code))
            if not response.content:
                if method == 'GET':
                    raise ReconcileError(vendor + " returned an empty read response")
                return None, dict(response.headers)
            try:
                data = response.json()
            except ValueError:
                raise ReconcileError(vendor + " returned invalid JSON") from None
            if method == 'GET' and data is None:
                raise ReconcileError(vendor + " returned a null read response")
            return data, dict(response.headers)
        raise ReconcileError("Read retry budget exhausted")  # pragma: no cover

    def pace_netskope(self):
        """Client-side pacing for the tenant's per-second allowance.

        Reads retry on 429, but a mutation does not, so a burst inside one pass
        would otherwise turn into a failed connection. Spacing plus honouring
        an exhausted window keeps the service under the limit by construction."""
        wait = self._netskope_next_allowed - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._netskope_next_allowed = time.monotonic() + NETSKOPE_MIN_SPACING_SECONDS

    def note_netskope_limits(self, headers):
        remaining, reset = self.header(headers, 'RateLimit-Remaining'), self.header(headers, 'RateLimit-Reset')
        if ascii_digits(remaining) and int(remaining) == 0:
            hold = min(NETSKOPE_MAX_RESET_WAIT, int(reset)) if ascii_digits(reset) else 1
            self._netskope_next_allowed = max(self._netskope_next_allowed, time.monotonic() + hold)

    @staticmethod
    def header(headers, name):
        return next((v for k, v in headers.items() if k.lower() == name.lower()), None)

    def sites(self):
        result, seen, total = [], set(), None
        for page in range(1, 10001):
            data, headers = self.request('mist', 'GET', '/api/v1/orgs/' + checked_id(self.cfg.mist_org_id) + '/sites',
                                         params={'limit': MIST_PAGE_LIMIT, 'page': page})
            if not isinstance(data, list):
                raise ReconcileError("Mist site inventory is not a list")
            advertised = self.header(headers, 'X-Page-Total')
            if advertised is not None:
                if not ascii_digits(advertised) or (total is not None and int(advertised) != total):
                    raise ReconcileError("Mist inventory total is invalid or changed between pages")
                total = int(advertised)
            # If Mist applied a smaller page size than requested, a "short" page
            # must be judged against the size actually served.
            served = self.header(headers, 'X-Page-Limit')
            page_limit = int(served) if ascii_digits(served) and 0 < int(served) <= MIST_PAGE_LIMIT else MIST_PAGE_LIMIT
            for site in data:
                if not isinstance(site, dict) or not site.get('id'):
                    raise ReconcileError("Mist inventory has invalid or repeated site IDs")
                identifier = checked_id(site['id'])
                if identifier in seen:
                    raise ReconcileError("Mist inventory has invalid or repeated site IDs")
                if site.get('org_id') != self.cfg.mist_org_id:
                    raise ReconcileError("Mist site organisation mismatch")
                seen.add(identifier)
                result.append(site)
            if len(data) < page_limit:
                # A short page normally ends the listing; the advertised total,
                # when present, must agree before absence can mean anything.
                if total is not None and total != len(result):
                    raise ReconcileError("Mist inventory is incomplete against X-Page-Total")
                return result
        raise ReconcileError("Mist inventory pagination limit reached")

    def site(self, site_id):
        data, _ = self.request('mist', 'GET', '/api/v1/sites/' + checked_id(site_id), missing_ok=True)
        if data is not None and (not isinstance(data, dict) or data.get('id') != site_id or data.get('org_id') != self.cfg.mist_org_id):
            raise ReconcileError("Mist site readback mismatch")
        return data

    def setting(self, site_id):
        data, _ = self.request('mist', 'GET', '/api/v1/sites/' + checked_id(site_id) + '/setting')
        if not isinstance(data, dict):
            raise ReconcileError("Mist settings are not an object")
        if data.get('vars') is None:
            data['vars'] = {}
        if not isinstance(data['vars'], dict):
            raise ReconcileError("Mist site variables are not an object")
        return data

    def template(self, template_id):
        data, headers = self.request('mist', 'GET', '/api/v1/orgs/' + checked_id(self.cfg.mist_org_id)
                                     + '/gatewaytemplates/' + checked_id(template_id), missing_ok=True)
        if data is not None and not isinstance(data, dict):
            raise ReconcileError("Mist template is not an object")
        return data, self.header(headers, 'ETag')

    def put_template(self, template_id, payload, etag):
        self.request('mist', 'PUT', '/api/v1/orgs/' + checked_id(self.cfg.mist_org_id)
                     + '/gatewaytemplates/' + checked_id(template_id), payload,
                     headers={'If-Match': etag} if etag else None)

    def inventory(self, resource):
        """Return a complete Netskope list or fail closed.

        The first request carries no paging parameters. When total exceeds the
        returned rows, offset/limit continuation (as used by Netskope's own API
        client) is attempted; any repeated ID, empty page or shifting total
        aborts the read. Verify the tenant contract in /apidocs before relying
        on continuation in production."""
        path = '/api/v2/steering/ipsec/' + resource
        rows, seen, total, page_size = [], set(), None, None
        for _ in range(NETSKOPE_MAX_PAGES):
            params = {'offset': len(rows), 'limit': page_size} if rows else None
            data, _headers = self.request('netskope', 'GET', path, params=params)
            if not isinstance(data, dict) or not isinstance(data.get('result'), list):
                raise ReconcileError("Netskope inventory envelope is unverified")
            page = data['result']
            if type(data.get('total')) is not int or data['total'] < 0 or (total is not None and data['total'] != total):
                raise ReconcileError("Netskope inventory is incomplete or total is missing")
            total = data['total']
            if resource == 'tunnels':
                maxsites = data.get('maxsites')
                self.tunnel_capacity = {'total': total, 'maxsites': maxsites if type(maxsites) is int else None}
            if any(not isinstance(row, dict) or 'id' not in row for row in page):
                raise ReconcileError("Netskope inventory contains invalid records")
            for row in page:
                identifier = checked_id(row['id'])
                if identifier in seen:
                    raise ReconcileError("Netskope inventory contains duplicate IDs")
                seen.add(identifier)
            rows.extend(page)
            if len(rows) == total:
                return rows
            if len(rows) > total or not page:
                raise ReconcileError("Netskope inventory is incomplete or total is missing")
            page_size = page_size or len(page)
        raise ReconcileError("Netskope inventory pagination limit reached")

    def create(self, payload):
        # The reconciler writes create_pending before this call and recovers
        # by ownership marker. The POST response shape is deliberately unused.
        self.request('netskope', 'POST', '/api/v2/steering/ipsec/tunnels', payload)

    def update(self, tunnel_id, payload):
        missing = [k for k in NETSKOPE_FULL_PAYLOAD_KEYS if k not in payload]
        if missing:
            # A partial PATCH resets omitted fields; encryption falls back to Null.
            raise ReconcileError("Refusing partial Netskope PATCH; missing " + ", ".join(missing))
        self.request('netskope', 'PATCH', '/api/v2/steering/ipsec/tunnels/' + checked_id(tunnel_id), payload)

    def delete(self, tunnel_id):
        self.request('netskope', 'DELETE', '/api/v2/steering/ipsec/tunnels/' + checked_id(tunnel_id), missing_ok=True)


class LifecycleState:
    """SQLite journal and coalescing inbox; payloads and PSKs are never stored.

    A process-wide flock serialises workers sharing this directory. Deploy one
    active writer per organisation; this is not a distributed locking scheme.
    Because the lock guarantees a single writer, connection records are cached
    in memory and written through, avoiding a full table parse per lookup.
    """
    def __init__(self, directory, binding):
        self.root = Path(directory)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or self.root.stat().st_mode & 0o077:
            raise ReconcileError("State directory must be private (mode 0700)")
        self.db = None
        self.mutex = threading.RLock()
        self.lock_file = self._open_private(self.root / 'worker.lock')
        try:
            try:
                fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ReconcileError("Another worker owns this state directory") from None
            db_path = self.root / 'state.sqlite3'
            for artefact in (db_path, Path(str(db_path) + '-wal'), Path(str(db_path) + '-shm')):
                if artefact.is_symlink():
                    raise ReconcileError("State database files must not be symlinks")
            # Create the database file privately before SQLite opens it.
            self._open_private(db_path).close()
            try:
                self.db = sqlite3.connect(str(db_path), check_same_thread=False)
                self.db.executescript('''
                    PRAGMA journal_mode=WAL;
                    PRAGMA synchronous=FULL;
                    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS connections (key TEXT PRIMARY KEY, body TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS inbox (digest TEXT PRIMARY KEY, created REAL NOT NULL, done INTEGER NOT NULL DEFAULT 0);
                    CREATE INDEX IF NOT EXISTS inbox_done ON inbox (done, created);
                ''')
                existing = self.db.execute("SELECT value FROM meta WHERE key='binding'").fetchone()
                if existing and existing[0] != canonical(binding):
                    raise ReconcileError("State belongs to a different tenant or organisation")
                self.db.execute("INSERT OR IGNORE INTO meta VALUES ('binding', ?)", (canonical(binding),))
                self.db.execute("INSERT OR IGNORE INTO meta VALUES ('installation', ?)", (str(uuid.uuid4()),))
                self.installation = self.db.execute("SELECT value FROM meta WHERE key='installation'").fetchone()[0]
                self.db.commit()
                self._records = {key: json.loads(body) for key, body in self.db.execute('SELECT key, body FROM connections')}
            except (sqlite3.Error, ValueError):
                raise ReconcileError("State database is unreadable; restore the matching backup") from None
        except BaseException:
            self.close()  # Never leave the lock or database handle behind a failed start.
            raise

    @staticmethod
    def _open_private(path):
        """Open (creating if needed) a 0600 file without following symlinks."""
        fd = None
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, 'a')
        except OSError:
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
            raise ReconcileError("State file is unavailable or is a symlink") from None

    def close(self):
        with self.mutex:  # Let an in-flight webhook enqueue finish before the handle goes away.
            if self.db is not None:
                self.db.close()
                self.db = None
            if not self.lock_file.closed:
                self.lock_file.close()

    def _open_db(self):
        if self.db is None:
            raise ReconcileError("State is closed")  # Receiver maps this to a retryable 503.
        return self.db

    def records(self):
        with self.mutex:
            return copy.deepcopy(self._records)

    def record(self, key):
        with self.mutex:
            return copy.deepcopy(self._records.get(key, {}))

    def template_records(self, template_id, exclude_key=None):
        """Live (non-retired) records sharing a template, excluding one key."""
        with self.mutex:
            return {key: copy.deepcopy(record) for key, record in self._records.items()
                    if key != exclude_key and record.get('template_id') == template_id and record.get('status') != 'deleted'}

    def save(self, key, record):
        body = canonical(record)
        with self.mutex:
            with self.db:
                self.db.execute('INSERT OR REPLACE INTO connections VALUES (?, ?)', (key, body))
            self._records[key] = json.loads(body)  # Cache only what was durably committed.

    def enqueue(self, digest):
        self.enqueue_many([digest])

    def enqueue_many(self, digests):
        """All-or-nothing enqueue so a rejected aggregate leaves no partial work."""
        with self.mutex, self._open_db():
            self.db.execute('DELETE FROM inbox WHERE done=1 AND created<?', (time.time() - INBOX_RETENTION_SECONDS,))
            pending = self.db.execute('SELECT COUNT(*) FROM inbox WHERE done=0').fetchone()[0]
            for digest in digests:
                if self.db.execute('SELECT 1 FROM inbox WHERE digest=?', (digest,)).fetchone():
                    continue
                # Bound disk use if the worker is failing or the endpoint is flooded.
                if pending >= INBOX_CAPACITY:
                    raise ReconcileError("Webhook inbox is full")
                self.db.execute('INSERT INTO inbox (digest, created) VALUES (?, ?)', (digest, time.time()))
                pending += 1

    def pending(self):
        with self.mutex:
            return [row[0] for row in self._open_db().execute('SELECT digest FROM inbox WHERE done=0')]

    def acknowledge(self, digests):
        with self.mutex, self.db:
            self.db.executemany('UPDATE inbox SET done=1 WHERE digest=?', [(x,) for x in digests])

    def secret(self, key, create=False):
        if not re.fullmatch(r'[0-9a-f]{64}', key):
            raise ReconcileError("Invalid connection key")
        directory = self.root / 'secrets'
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or directory.stat().st_mode & 0o077:
            raise ReconcileError("Secret directory must be private")
        path = directory / (key + '.psk')
        if create and not path.exists() and not path.is_symlink():
            # Exclusive file creation prevents rotation on retries and restarts.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as handle:
                handle.write(secrets.token_urlsafe(32))
                handle.flush()
                os.fsync(handle.fileno())
            # Persist the directory entry too; a key lost in a crash after the
            # tunnel POST would otherwise be unrecoverable.
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise ReconcileError("Per-tunnel secret is unavailable or not private")
        value = path.read_text().strip()
        if len(value) < 32:
            raise ReconcileError("Per-tunnel secret is invalid")
        return value


def valid_key_path(path, minimum):
    """A JSON key path: a list of at least `minimum` nonempty strings."""
    return isinstance(path, list) and len(path) >= minimum and all(isinstance(p, str) and p for p in path)


def validate_lifecycle_config(config):
    """Reject malformed local policy before reads, state changes or vendor writes."""
    if not isinstance(config, dict) or type(config.get('version')) is not int or config['version'] != 1 or not isinstance(config.get('profiles'), dict):
        raise ReconcileError("Expected lifecycle config version 1 and profiles object")
    for field_name, default, minimum in (('reconcile_interval_seconds', 600, 10), ('deletion_grace_seconds', 3600, 60)):
        value = config.get(field_name, default)
        if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
            raise ReconcileError(field_name + " must be finite and >= " + str(minimum))
    budget = config.get('mist_hourly_request_budget', MIST_DEFAULT_HOURLY_BUDGET)
    if type(budget) is not int or budget < 1:
        raise ReconcileError("mist_hourly_request_budget must be a positive integer")
    if 'cleanup_enabled' in config and not isinstance(config['cleanup_enabled'], bool):
        raise ReconcileError("cleanup_enabled must be boolean")
    if not isinstance(config.get('validation', {}), dict):
        raise ReconcileError("validation must be an object")
    if not isinstance(config.get('profile_variable', 'netskope_profile'), str) or not config.get('profile_variable', 'netskope_profile'):
        raise ReconcileError("profile_variable must be a nonempty string")
    for profile in config['profiles'].values():
        if not isinstance(profile, dict) or not isinstance(profile.get('connections'), list):
            raise ReconcileError("Each profile needs connections")
        ids = [c.get('id') for c in profile['connections'] if isinstance(c, dict)]
        if len(ids) != len(profile['connections']) or not ids:
            raise ReconcileError("Connections need distinct stable IDs")
        for identifier in ids:
            checked_id(identifier)
        if len(set(ids)) != len(ids):
            raise ReconcileError("Connections need distinct stable IDs")
        for connection in profile['connections']:
            checked_id(connection['id'])
            for field_name in ('template_id', 'netskope', 'mist_entries'):
                if field_name not in connection:
                    raise ReconcileError("Profile is missing " + field_name)
            if not isinstance(connection['netskope'], dict) or not isinstance(connection['mist_entries'], list) or not connection['mist_entries']:
                raise ReconcileError("Invalid payload profile")
            if connection.get('secret_readback', 'exact') not in ('exact', 'masked'):
                raise ReconcileError("secret_readback must be exact or masked")
            for entry in connection['mist_entries']:
                if not isinstance(entry, dict) or not valid_key_path(entry.get('path'), 2) or 'value' not in entry:
                    raise ReconcileError("Mist entries need a path of at least two keys and a value")
            checks = connection.get('health_checks', [])
            if not isinstance(checks, list) or any(not isinstance(check, dict) or not valid_key_path(check.get('path'), 1)
                                                   or 'equals' not in check for check in checks):
                raise ReconcileError("Health checks need a nonempty key path and equals value")


def load_lifecycle_config(path):
    try:
        config = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        raise ReconcileError("Cannot read lifecycle configuration JSON") from None
    validate_lifecycle_config(config)
    return config


class Reconciler:
    """Converge owned resources from Mist site variables and validated profiles."""
    def __init__(self, api, state, config, apply=False, clock=time.time, should_stop=None):
        self.api, self.state, self.config = api, state, config
        self.apply, self.clock = apply, clock
        self.should_stop = should_stop or (lambda: False)
        self.site_snapshot = []

    def marker(self, key):
        return 'mist-netskope-connector:' + self.state.installation + ':' + key

    def key(self, site_id, connection_id):
        return fingerprint([self.api.cfg.mist_org_id, site_id, connection_id])

    def owned_tunnel(self, rows, key, record):
        matches = [r for r in rows if r.get('notes') == self.marker(key)]
        if len(matches) > 1:
            raise ReconcileError("Multiple tunnels have the same ownership marker")
        if matches and matches[0].get('site') != 'mist-' + key[:24]:
            raise ReconcileError("Owned tunnel name changed")
        if matches and record.get('tunnel_id') is not None and str(matches[0]['id']) != str(record['tunnel_id']):
            raise ReconcileError("Owned tunnel ID changed")
        if record.get('tunnel_id') is not None:
            other = [r for r in rows if str(r['id']) == str(record['tunnel_id'])]
            if other and other[0].get('notes') != self.marker(key):
                raise ReconcileError("Tunnel ownership marker was changed")
        return matches[0] if matches else None

    def check_entries(self, entries, key, record, current):
        paths = []
        previous = {tuple(item['path']): item['hash'] for item in record.get('entries', [])}
        pending = {tuple(item['path']): item['hash'] for item in record.get('pending_entries', [])}
        other_paths = []
        for other in self.state.template_records(record['template_id'], exclude_key=key).values():
            other_paths.extend(tuple(e['path']) for e in other.get('entries', []) + other.get('pending_entries', []))
        for entry in entries:
            path = entry.get('path')
            if not valid_key_path(path, 2) or 'value' not in entry:
                raise ReconcileError("Mist entries need a path of at least two keys and a value")
            path = tuple(path)
            if any(path[:len(p)] == p or p[:len(path)] == path for p in paths + other_paths):
                raise ReconcileError("Mist ownership paths overlap")
            paths.append(path)
            exists, value = path_value(current, path)
            # A crash after PUT is recoverable using hashes journalled before it.
            if exists and entry_hash(value, entry.get('secret_paths', [])) not in {previous.get(path), pending.get(path)}:
                raise ReconcileError("Mist entry is unowned or externally modified")
        if (previous and set(previous) != set(paths)) or (pending and set(pending) != set(paths)):
            raise ReconcileError("Owned Mist paths changed; migrate explicitly before changing the profile")

    def write_sections(self, document, template_id, sections, exclude_key=None):
        """Restore our own masked keys; never replay an unowned masked secret."""
        payload = {section: copy.deepcopy(document[section]) for section in sections}
        if 'name' in document and 'name' not in payload:
            payload['name'] = document['name']  # The official PUT schema requires name.
        for other_key, record in self.state.template_records(template_id, exclude_key=exclude_key).items():
            paths = {}
            for entry in record.get('entries', []) + record.get('pending_entries', []):
                paths.setdefault(tuple(entry['path']), []).append(entry)
            for path, candidates in paths.items():
                if path[0] not in sections or not any(e.get('secret_paths') for e in candidates):
                    continue
                exists, value = path_value(payload, path)
                if not exists:
                    continue
                # A lost PUT response can leave either the previous or pending
                # version remotely. Match before restoring a key, once per path.
                entry = next((e for e in candidates if entry_hash(value, e.get('secret_paths', [])) == e['hash']), None)
                if entry is None:
                    raise ReconcileError("Another managed entry changed; refusing a section write")
                secret = self.state.secret(other_key)
                for secret_path in entry.get('secret_paths', []):
                    put_path(payload, list(path) + secret_path, secret)
        def check(value):
            if isinstance(value, dict):
                for child in value.values():
                    check(child)
            elif isinstance(value, list):
                for child in value:
                    check(child)
            elif isinstance(value, str) and (re.fullmatch(r'[*•]{4,}', value) or value.lower() in ('<redacted>', '***redacted***', '[redacted]')):
                raise ReconcileError("Preserved configuration contains a masked value; cannot safely replay it")
        check(payload)
        return payload

    def plan(self, site, setting, connection, pops, rows):
        key = self.key(site['id'], connection['id'])
        record = self.state.record(key)
        if record.get('status') == 'deleted':
            raise ReconcileError("Connection was retired; use a new connection ID to reprovision")
        context = {'site': site, 'vars': setting.get('vars', {}), 'setting': setting,
                   'tunnel': {'name': 'mist-' + key[:24]}, 'owner': self.marker(key)}
        template_id = checked_id(render(connection['template_id'], context))
        if site.get('gatewaytemplate_id') != template_id:
            raise ReconcileError("Profile template does not match the site's assigned gateway template")
        if any(s['id'] != site['id'] and s.get('gatewaytemplate_id') == template_id for s in self.site_snapshot):
            raise ReconcileError("Per-site literal tunnel values require a dedicated gateway template")
        if record.get('template_id', template_id) != template_id:
            raise ReconcileError("Template migration requires explicit removal of the old owned entries")
        record.update(site_id=site['id'], connection_id=connection['id'], template_id=template_id)
        current, _ = self.api.template(template_id)
        if current is None:
            raise ReconcileError("Target Mist template is missing")
        # Secret creation occurs only after structural preflight in upsert().
        try:
            secret = self.state.secret(key)
        except ReconcileError:
            if record.get('tunnel_id') or record.get('status'):
                raise
            secret = 'DRY-RUN-NOT-A-REAL-TUNNEL-SECRET-0000'  # noqa: S105 - placeholder for read-only planning
        context['secret'] = secret
        context['crypto'] = connection.get('crypto', {})
        payload = render(connection['netskope'], context)
        for required in ('pops', 'srcidentity', 'srcipidentity', 'vendor', 'template', 'bandwidth', 'encryption', 'sourcetype'):
            if not payload.get(required):
                raise ReconcileError("Missing Netskope prerequisite: " + required)
        if not isinstance(payload['pops'], list) or len(payload['pops']) != 2 or len(set(payload['pops'])) != 2:
            raise ReconcileError("Select two distinct Netskope POPs")
        if payload['sourcetype'] not in NETSKOPE_SOURCETYPES:
            raise ReconcileError("sourcetype must be one of: " + ", ".join(NETSKOPE_SOURCETYPES))
        xff = payload.get('options', {}).get('xff') if isinstance(payload.get('options'), dict) else None
        if isinstance(xff, dict) and xff.get('enable') is not True and 'iplist' in xff:
            raise ReconcileError("options.xff.iplist is only accepted when xff.enable is true; omit it")
        if str(payload['encryption']).lower() == 'null':
            raise ReconcileError("Null encryption is not permitted")
        selected = []
        for pop_ref in payload['pops']:
            # The tenant addresses POPs by name in tunnel payloads; accept an ID
            # in the profile too, but always send the name.
            found = [p for p in pops if p.get('name') == pop_ref or p.get('id') == pop_ref]
            if len(found) != 1 or found[0].get('acceptingtunnels') is not True or not found[0].get('gateway') or not found[0].get('name'):
                raise ReconcileError("Selected POP is unavailable or has an unverified response")
            if payload['bandwidth'] not in parse_bandwidth_tiers(found[0].get('bandwidth', '')):
                raise ReconcileError("Requested bandwidth is not offered by both POPs")
            options = found[0].get('options')
            if not isinstance(options, dict) or not isinstance(options.get('phase2'), dict):
                raise ReconcileError("POP crypto advertisement is not an object")
            offered = options['phase2'].get('encryptionalgo', '')
            if payload['encryption'] not in parse_csv_options(offered):
                raise ReconcileError("Encryption is not offered by both POPs")
            selected.append(found[0])
        if len({checked_id(p['id']) for p in selected}) != 2 or len({p['name'] for p in selected}) != 2:
            raise ReconcileError("Select two distinct Netskope POPs after resolving IDs and names")
        payload['pops'] = [p['name'] for p in selected]
        # POP data are available to the captured Mist mapping; don't guess leaf names.
        crypto = connection.get('crypto')
        validate_crypto(crypto, selected)
        if payload['encryption'] != crypto['phase2']['encryptionalgo']:
            raise ReconcileError("Netskope encryption differs from the selected IPsec proposal")
        context.update(primary=selected[0], secondary=selected[1], crypto=crypto)
        payload.update(site=context['tunnel']['name'], notes=self.marker(key), psk=secret, enable=True)
        entries = render(connection['mist_entries'], context)
        if not any(secret in canonical(e['value']) for e in entries):
            raise ReconcileError("Mist profile must include the authoritative ${secret}")
        for entry in entries:
            if connection.get('secret_readback', 'exact') not in ('exact', 'masked'):
                raise ReconcileError("secret_readback must be exact or masked")
            entry['secret_paths'] = secret_paths(entry['value'], secret) if connection.get('secret_readback') == 'masked' else []
        self.check_entries(entries, key, record, current)
        preview = copy.deepcopy(current)
        for entry in entries:
            put_path(preview, entry['path'], entry['value'])
        self.write_sections(preview, template_id, {e['path'][0] for e in entries}, exclude_key=key)
        tunnel = self.owned_tunnel(rows, key, record)
        if not tunnel and any(t.get('site') == payload['site'] for t in rows):
            raise ReconcileError("An unowned tunnel uses the deterministic name")
        return key, record, payload, entries, tunnel

    @staticmethod
    def observed_options(actual, desired):
        """Project the read-side options onto the desired keys, mapping enabled->enable."""
        if not isinstance(actual, dict) or not isinstance(desired, dict):
            return actual
        projected = {}
        for key, wanted in desired.items():
            if key == 'enable' and 'enable' not in actual and 'enabled' in actual:
                projected[key] = actual['enabled']
            elif isinstance(wanted, dict):
                projected[key] = Reconciler.observed_options(actual.get(key), wanted)
            else:
                projected[key] = actual.get(key)
        return projected

    @staticmethod
    def tunnel_matches(actual, desired, pop_names=None):
        """Compare a tunnel as read against the desired write payload.

        The tenant OpenAPI document shows the read shape differs from the
        write shape: reads report ``enabled`` (writes send ``enable``), the
        XFF option reads as ``enabled``, and ``pops`` read back as objects
        ``{name, gateway, primary, status, ...}`` with no id. Without this
        normalisation every pass would PATCH and then fail its readback."""
        pop_names = pop_names or {}
        for key, value in desired.items():
            if key == 'psk':
                continue  # Secrets may be omitted or masked on reads.
            if key == 'enable':
                observed = actual.get('enable', actual.get('enabled'))
            elif key == 'pops':
                observed = actual.get('pops')
                if not isinstance(observed, list) or not isinstance(value, list):
                    return False
                if any(isinstance(p, dict) for p in observed):
                    if (len(observed) != 2 or not all(isinstance(p, dict) and type(p.get('primary')) is bool for p in observed)
                            or sum(p['primary'] for p in observed) != 1):
                        return False
                    observed = [p.get('name') for p in sorted(observed, key=lambda p: not p['primary'])]
                else:
                    # Legacy scalar responses use configured order: primary first.
                    observed = [str(pop_names.get(p, p)) for p in observed]
                value = [str(pop_names.get(p, p)) for p in value]
            elif key == 'options' and isinstance(value, dict):
                # The tenant adds defaults (qos, ctap, xff.iplist) on reads; only
                # the keys the profile sets are compared, recursively.
                observed = Reconciler.observed_options(actual.get('options'), value)
            else:
                observed = actual.get(key)
            if observed != value:
                return False
        return True

    def upsert(self, site, setting, connection, pops, rows):
        key, record, payload, entries, tunnel = self.plan(site, setting, connection, pops, rows)
        if not self.apply:
            return {'site_id': site['id'], 'connection': connection['id'], 'action': 'reconcile' if tunnel else 'create', 'dry_run': True}
        fresh_site = self.api.site(site['id'])
        if fresh_site is None or any(fresh_site.get(k) != v for k, v in site.items()) or self.api.setting(site['id']) != setting:
            raise ReconcileError("Site configuration changed during preflight; retry later")
        self.state.secret(key, create=True)
        key, record, payload, entries, tunnel = self.plan(site, setting, connection, pops, rows)
        record.pop('missing_since', None)
        if not tunnel:
            if record.get('status') == 'create_pending':
                raise ReconcileError("Create outcome unresolved; refusing another POST until the owned tunnel appears")
            if record.get('tunnel_id') is not None:
                raise ReconcileError("Previously managed tunnel disappeared; investigate before reprovisioning")
            capacity = getattr(self.api, 'tunnel_capacity', None)
            if isinstance(capacity, dict) and isinstance(capacity.get('maxsites'), int) and capacity.get('total', 0) >= capacity['maxsites']:
                raise ReconcileError("Tenant IPsec tunnel capacity (maxsites) is exhausted; no create attempted")
            record['status'] = 'create_pending'
            self.state.save(key, record)
            self.api.create(payload)
            rows[:] = self.api.inventory('tunnels')
            tunnel = self.owned_tunnel(rows, key, record)
            if not tunnel:
                raise ReconcileError("Created tunnel not visible yet; journal retained for recovery")
        record.update(tunnel_id=tunnel['id'], status='configuring')
        self.state.save(key, record)
        pop_names = {checked_id(p['id']): p['name'] for p in pops if isinstance(p, dict) and p.get('id') and p.get('name')}
        # Persist the key's digest only, never the key or payload. If an API hides
        # the key, a successful acknowledged PATCH is the limit of verification.
        if not self.tunnel_matches(tunnel, payload, pop_names) or record.get('secret_hash') != fingerprint(payload['psk']):
            self.api.update(tunnel['id'], payload)
            rows[:] = self.api.inventory('tunnels')
            tunnel = self.owned_tunnel(rows, key, record)
            if not tunnel or not self.tunnel_matches(tunnel, payload, pop_names):
                raise ReconcileError("Netskope configuration readback differs from desired state")
            record['secret_hash'] = fingerprint(payload['psk'])
            self.state.save(key, record)
        current, etag = self.api.template(record['template_id'])
        if current is None:
            raise ReconcileError("Mist template disappeared during provisioning")
        self.check_entries(entries, key, record, current)
        merged = copy.deepcopy(current)
        for entry in entries:
            put_path(merged, entry['path'], entry['value'])
        owned = [{'path': e['path'], 'hash': entry_hash(e['value'], e['secret_paths']), 'secret_paths': e['secret_paths']} for e in entries]
        same = all(path_value(current, e['path'])[0] and
                   entry_hash(path_value(current, e['path'])[1], e['secret_paths']) == e['hash'] for e in owned)
        masked = any(e['secret_paths'] for e in owned)
        key_changed = record.get('mist_secret_hash') != fingerprint(payload['psk'])
        pending_key_matches = record.get('pending_secret_hash') == fingerprint(payload['psk'])
        # Masked readback cannot prove an uncertain key write succeeded. Repeat
        # that idempotent PUT until acknowledged; exact readback can prove it.
        if not same or (key_changed and (masked or not pending_key_matches)):
            record['pending_entries'] = owned
            record['pending_secret_hash'] = fingerprint(payload['psk'])
            self.state.save(key, record)
            # A second read catches intervening edits. Without ETag support there
            # remains a race: operators must designate this service as sole writer.
            latest, latest_etag = self.api.template(record['template_id'])
            if latest != current:
                raise ReconcileError("Mist template changed during reconciliation; retry later")
            sections = {e['path'][0] for e in entries}
            self.api.put_template(record['template_id'], self.write_sections(merged, record['template_id'], sections, exclude_key=key),
                                  latest_etag or etag)
            record['mist_secret_hash'] = fingerprint(payload['psk'])
            self.state.save(key, record)
            actual, _ = self.api.template(record['template_id'])
        else:
            actual = current  # Read moments ago and unchanged by us: no second GET needed.
        if actual is None or any(not path_value(actual, e['path'])[0] or
                                 entry_hash(path_value(actual, e['path'])[1], e['secret_paths']) != e['hash'] for e in owned):
            raise ReconcileError("Mist readback differs (including hidden secrets); validate the readback contract")
        record.update(entries=owned, mist_secret_hash=fingerprint(payload['psk']), status='configured', last_success=self.clock())
        record.pop('pending_entries', None)
        record.pop('pending_secret_hash', None)
        self.state.save(key, record)
        checks = connection.get('health_checks', [])
        health = 'not_verified'
        if checks:
            try:
                health = 'up' if all(lookup(tunnel, check['path']) == check['equals'] for check in checks) else 'down'
            except ReconcileError:
                health = 'unknown'
        return {'site_id': site['id'], 'connection': connection['id'], 'status': 'configured', 'health': health}

    def retire(self, key, record, rows):
        if self.api.site(record['site_id']) is not None:
            if self.apply and 'missing_since' in record:
                record.pop('missing_since')
                self.state.save(key, record)
            return {'site_id': record['site_id'], 'status': 'present'}
        if not self.apply:
            return {'site_id': record['site_id'], 'action': 'retire_after_confirmation', 'dry_run': True}
        if 'missing_since' not in record:
            record['missing_since'] = self.clock()
            self.state.save(key, record)
        grace = self.config.get('deletion_grace_seconds', 3600)
        if self.clock() - record['missing_since'] < grace:
            return {'site_id': record['site_id'], 'status': 'retirement_pending'}
        # Explicitly opt into automatic deletion only after lab cleanup validation.
        if self.config.get('cleanup_enabled') is not True:
            return {'site_id': record['site_id'], 'status': 'cleanup_disabled'}
        # A retired site's template may have been repurposed. Do not remove
        # entries now serving a different site, even when their hashes match.
        if any(site.get('gatewaytemplate_id') == record['template_id'] for site in self.api.sites()):
            raise ReconcileError("Retirement template is assigned to a current site; cleanup stopped")
        # Never authorise cleanup using the pass-level snapshot.
        rows[:] = self.api.inventory('tunnels')
        tunnel = self.owned_tunnel(rows, key, record)
        if not tunnel and record.get('tunnel_id') is not None:
            # A row can slip between pages of a changing listing. Require a second
            # complete read before concluding that a journalled tunnel is already gone.
            rows[:] = self.api.inventory('tunnels')
            tunnel = self.owned_tunnel(rows, key, record)
        if not tunnel and record.get('status') == 'create_pending':
            raise ReconcileError("Unresolved creation cannot be declared retired")
        current, etag = self.api.template(record['template_id'])
        if current is not None:
            merged = copy.deepcopy(current)
            paths = {}
            for entry in record.get('entries', []) + record.get('pending_entries', []):
                paths.setdefault(tuple(entry['path']), []).append(entry)
            for path, saved_entries in paths.items():
                exists, value = path_value(current, path)
                if exists and not any(entry_hash(value, e.get('secret_paths', [])) == e['hash'] for e in saved_entries):
                    raise ReconcileError("Owned Mist entry changed externally; cleanup stopped")
                if exists:
                    put_path(merged, path, None, delete=True)
            if merged != current:
                latest, latest_etag = self.api.template(record['template_id'])
                if latest != current:
                    raise ReconcileError("Mist template changed during cleanup")
                sections = {path[0] for path in paths}
                self.api.put_template(record['template_id'], self.write_sections(merged, record['template_id'], sections, exclude_key=key),
                                      latest_etag or etag)
                readback, _ = self.api.template(record['template_id'])
                if readback is not None and any(path_value(readback, path)[0] for path in paths):
                    raise ReconcileError("Mist cleanup readback failed")
        # Check site absence again immediately before deleting the tunnel.
        if self.api.site(record['site_id']) is not None:
            raise ReconcileError("Site reappeared during cleanup; retry reconciliation")
        # Mist cleanup can take several requests; recheck ownership at the
        # destructive boundary too. The API has no verified conditional DELETE.
        rows[:] = self.api.inventory('tunnels')
        tunnel = self.owned_tunnel(rows, key, record)
        if not tunnel and record.get('status') == 'create_pending':
            raise ReconcileError("Unresolved creation cannot be declared retired")
        if tunnel:
            self.api.delete(tunnel['id'])
            rows[:] = self.api.inventory('tunnels')
            if self.owned_tunnel(rows, key, record):
                raise ReconcileError("Netskope deletion not yet visible")
        record.update(status='deleted', deleted_at=self.clock())
        self.state.save(key, record)
        return {'site_id': record['site_id'], 'status': 'deleted'}

    def reconcile(self):
        validate_lifecycle_config(self.config)
        if self.apply and (not self.config.get('validation', {}).get('evidence') or
                           self.config['validation'].get('profiles_sha256') != fingerprint(self.config['profiles'])):
            raise ReconcileError("Apply requires lab evidence and a matching profiles_sha256")
        if self.apply and 'REPLACE_WITH_' in canonical(self.config['profiles']):
            raise ReconcileError("Replace all example placeholders before applying")
        sites = self.api.sites()  # Nothing mutates until the complete read succeeds.
        self.site_snapshot = sites
        rows, pops = self.api.inventory('tunnels'), self.api.inventory('pops')
        results, site_ids = [], {s['id'] for s in sites}
        for site in sites:
            if self.should_stop():
                # Stop between sites, never mid-connection; the journal resumes the rest.
                raise ReconcileError("Shutdown requested; pass abandoned between sites")
            try:
                setting = self.api.setting(site['id'])
                name = setting.get('vars', {}).get(self.config.get('profile_variable', 'netskope_profile'))
                if not name:
                    continue
                if name not in self.config['profiles']:
                    raise ReconcileError("Site selects an unknown provisioning profile")
                for connection in self.config['profiles'][name]['connections']:
                    try:
                        results.append(self.upsert(site, setting, connection, pops, rows))
                    except ReconcileError as exc:
                        results.append({'site_id': site['id'], 'connection': connection['id'], 'status': 'error', 'detail': str(exc)})
                    except (ValueError, TypeError, KeyError):
                        results.append({'site_id': site['id'], 'connection': connection['id'], 'status': 'error', 'detail': 'Invalid site or profile schema'})
            except ReconcileError as exc:
                results.append({'site_id': site['id'], 'status': 'error', 'detail': str(exc)})
            except (ValueError, TypeError, KeyError):
                results.append({'site_id': site['id'], 'status': 'error', 'detail': 'Invalid site or profile schema'})
        for key, record in self.state.records().items():
            if record['site_id'] in site_ids:
                # Absence must be continuous, even when eligibility is removed.
                if self.apply and 'missing_since' in record:
                    record.pop('missing_since')
                    self.state.save(key, record)
                continue
            if record.get('status') != 'deleted':
                try:
                    results.append(self.retire(key, record, rows))
                except ReconcileError as exc:
                    results.append({'site_id': record['site_id'], 'status': 'error', 'detail': str(exc)})
        return results


def webhook_handler(state, org_id, secret, wake):
    class Handler(BaseHTTPRequestHandler):
        # Applied in setup(), so it also covers the request line and headers;
        # a silent connection cannot hold a worker slot beyond this per-read limit.
        timeout = WEBHOOK_SOCKET_TIMEOUT

        def log_message(self, *args):
            pass  # Do not log webhook bodies, signatures or untrusted paths.

        def do_POST(self):
            try:
                if self.path != '/webhooks/mist' or self.headers.get('Transfer-Encoding'):
                    self.send_error(400)
                    return
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= WEBHOOK_MAX_BODY_BYTES:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
                supplied = self.headers.get('X-Mist-Signature-v2', '')
                if len(body) != length or not hmac.compare_digest(expected.encode(), supplied.encode('utf-8', 'replace')):
                    self.send_error(401)
                    return
                data = json.loads(body)
                if isinstance(data, dict) and data.get('topic') == 'ping':
                    self.send_response(200)
                    self.end_headers()
                    return
                events = data.get('events')
                if data.get('topic') != 'audits' or not isinstance(events, list) or not events or any(
                    not isinstance(e, dict) or e.get('org_id') != org_id for e in events
                ):
                    self.send_error(400)
                    return
                # Store hashes only. Every audit prompts current-state convergence;
                # no dependence on guessed site-created/site-deleted event names.
                # The aggregate is enqueued atomically: a 503 never leaves part of it.
                state.enqueue_many([fingerprint(event) for event in events])
                wake.set()
                self.send_response(202)
                self.end_headers()
            except (ValueError, TypeError, AttributeError):
                self.send_error(400)
            except (OSError, sqlite3.Error, ReconcileError):
                with contextlib.suppress(OSError):
                    self.send_error(503)
    return Handler


class BoundedWebhookServer(ThreadingHTTPServer):
    """Threaded receiver with a hard worker cap.

    One slow or stalled client can no longer block other deliveries, while the
    cap (plus per-socket timeouts and the reverse proxy's limits) bounds
    resource use. Connections beyond the cap are closed; Mist's retry or the
    scheduled pass recovers the missed hint."""
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, handler, max_workers=WEBHOOK_MAX_WORKERS):
        super().__init__(address, handler)
        self._slots = threading.BoundedSemaphore(max_workers)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def reconcile_cycle(reconciler, state):
    """Acknowledge only inbox items present before a successful full pass."""
    digests = state.pending()
    result = reconciler.reconcile()
    if not any(r.get('status') == 'error' for r in result):
        state.acknowledge(digests)
    return result


def request_budget_warning(counts, interval, budget):
    """Project one pass's Mist calls onto an hour of back-to-back scheduled passes.

    Observation only: webhook-triggered passes add to the real rate, and other
    API users share the organisation's allowance."""
    projected = counts.get('mist', 0) * 3600.0 / (interval + MIN_PASS_PAUSE_SECONDS)
    if projected > 0.8 * budget:
        return ("Projected %d Mist calls/hour exceeds 80%% of the %d budget; lengthen "
                "reconcile_interval_seconds or reduce enrolled scope" % (projected, budget))
    return None


def run_list_pops(api):
    """Read-only diagnostic using the strict lifecycle transport."""
    print("%-10s %-12s %-10s %-10s %s" % ('ID', 'NAME', 'REGION', 'ACCEPTING', 'LOCATION'))
    for pop in sorted(api.inventory('pops'), key=lambda p: str(p.get('name', ''))):
        print("%-10s %-12s %-10s %-10s %s" % (pop.get('id', ''), pop.get('name', ''), pop.get('region', ''),
                                              pop.get('acceptingtunnels', ''), pop.get('location', '')))
    return 0


def run_lifecycle(args):
    config = load_lifecycle_config(args.lifecycle_config)
    if args.profile_digest:
        print(fingerprint(config['profiles']))
        return 0
    if args.apply and args.dry_run:
        raise ReconcileError("Choose --apply or --dry-run")
    cfg = Config.from_env()
    interval = config.get('reconcile_interval_seconds', 600)
    budget = config.get('mist_hourly_request_budget', MIST_DEFAULT_HOURLY_BUDGET)
    api = LifecycleAPI(cfg)  # Validate base URLs before persisting the tenant binding.
    stopping = []  # Appended to by the signal handler; list.append takes no lock.
    with contextlib.ExitStack() as stack:
        stack.callback(api.close)
        state = LifecycleState(args.state_dir, {'org': cfg.mist_org_id, 'netskope': cfg.netskope_tenant_url,
                                                'mist': cfg.mist_base_url})
        stack.callback(state.close)
        reconciler = Reconciler(api, state, config, apply=args.apply, should_stop=lambda: bool(stopping))
        if args.status:
            print(json.dumps(state.records(), indent=2))
            return 0
        if args.resolve_create:
            if not args.confirm_no_remote_tunnel or args.apply or args.serve:
                raise ReconcileError("Resolution needs --confirm-no-remote-tunnel and a stopped service; do not combine with apply/serve")
            key = args.resolve_create
            record = state.record(key)
            if not record or record.get('status') != 'create_pending' or record.get('tunnel_id'):
                raise ReconcileError("Only an unresolved create_pending record can be reset")
            rows = reconciler.api.inventory('tunnels')
            if reconciler.owned_tunnel(rows, key, record) or any(t.get('site') == 'mist-' + key[:24] for t in rows):
                raise ReconcileError("A remote tunnel exists; run reconciliation to recover it")
            record.update(status='ready', create_resolution_at=time.time())
            state.save(key, record)
            print('Pending create reset after operator confirmation and complete inventory read; no vendor write performed.')
            return 0
        if not args.serve:
            result = reconciler.reconcile()
            print(json.dumps(result, indent=2))
            return int(any(r.get('status') == 'error' for r in result))
        secret = os.environ.get('MIST_WEBHOOK_SECRET', '')
        if len(secret) < 32:
            raise ReconcileError("MIST_WEBHOOK_SECRET must contain at least 32 characters")
        wake = threading.Event()

        def request_stop(*_):
            # SIGTERM/SIGINT: finish the connection in flight, then exit cleanly.
            # Deliberately touches no Event: their internal lock is not re-entrant
            # and the handler may interrupt the main thread while it holds one.
            stopping.append(True)

        def pause(seconds, event=None):
            """Sleep in one-second slices so a stop request is noticed promptly."""
            deadline = time.monotonic() + seconds
            while not stopping and time.monotonic() < deadline:
                remaining = min(1.0, max(0.0, deadline - time.monotonic()))
                if event is not None:
                    if event.wait(remaining):
                        return
                else:
                    time.sleep(remaining)
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, request_stop)
        server = BoundedWebhookServer((args.listen, args.port), webhook_handler(state, cfg.mist_org_id, secret, wake))
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.5}, daemon=True)
        thread.start()
        try:
            while not stopping:
                api.reset_request_counts()
                try:
                    result = reconcile_cycle(reconciler, state)
                    output = {'time': time.time(), 'results': result}
                except ReconcileError as exc:
                    output = {'time': time.time(), 'status': 'error', 'detail': str(exc)}
                output['requests'] = api.reset_request_counts()
                warning = request_budget_warning(output['requests'], interval, budget)
                if warning:
                    output['warning'] = warning
                print(json.dumps(output), flush=True)
                # Minimum delay prevents the connector's own audit events from
                # causing a busy loop; failed work retries on the same schedule.
                pause(interval, wake)
                wake.clear()
                pause(MIN_PASS_PAUSE_SECONDS)
            return 0
        finally:
            server.shutdown()
            thread.join(timeout=WEBHOOK_SOCKET_TIMEOUT + 2)
            server.server_close()


def run(args: argparse.Namespace) -> int:
    if args.lifecycle_config:
        if args.list_pops:
            raise ReconcileError("--list-pops cannot be combined with --lifecycle-config")
        return run_lifecycle(args)
    if args.serve or args.apply or args.dry_run or args.profile_digest or args.status or args.resolve_create or args.confirm_no_remote_tunnel:
        raise ReconcileError("Lifecycle options require --lifecycle-config")
    if args.list_pops:
        api = LifecycleAPI(Config.from_env())
        try:
            return run_list_pops(api)
        finally:
            api.close()
    raise ReconcileError("Nothing to do: supply --lifecycle-config or --list-pops (see --help)")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--lifecycle-config', help='Validated JSON payload profiles and reconciliation policy')
    parser.add_argument('--state-dir', default='./state', help='Private durable state directory (0700)')
    parser.add_argument('--apply', action='store_true', help='Enable lifecycle writes after profile validation')
    parser.add_argument('--dry-run', action='store_true', help='Explicit read-only plan (the default); cannot be combined with --apply')
    parser.add_argument('--serve', action='store_true', help='Receive Mist audit webhooks and reconcile periodically')
    parser.add_argument('--listen', default='127.0.0.1', help='Receiver bind address; put behind an HTTPS reverse proxy')
    parser.add_argument('--port', type=int, default=8080, help='Receiver port (default 8080)')
    parser.add_argument('--profile-digest', action='store_true', help='Print the profiles SHA256 for the lab validation record; no credentials needed')
    parser.add_argument('--status', action='store_true', help='Read persisted non-secret connection status while the service is stopped')
    parser.add_argument('--resolve-create', metavar='CONNECTION_KEY', help='Reset an unresolved POST only after independent confirmation it created no tunnel')
    parser.add_argument('--confirm-no-remote-tunnel', action='store_true', help='Operator confirms the uncertain POST did not create a tunnel')
    parser.add_argument('--list-pops', action='store_true', help='Read-only diagnostic: print Netskope IPsec POPs and exit')
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    try:
        return run(parse_args(argv))
    except ReconcileError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
