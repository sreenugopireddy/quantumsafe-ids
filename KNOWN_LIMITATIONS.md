# Known Limitations

## R08 (handshake-exhaustion, rate + resource correlation)

The project spec describes R08 as: "High handshake rate correlates with
high server CPU or handshake latency."

**Only the latency half is currently implemented.**
`src/rules/exhaustion_rules.py::check_r08_rate_correlates_with_latency`
flags a source-IP window where the handshake rate exceeds the same
threshold used by R06 *and* the mean handshake latency in that window
exceeds `ServicePolicy.max_handshake_duration_ms`.

The CPU-correlation half is deferred because:
- Server CPU/telemetry data is collected independently in
  `data/raw/telemetry/endpoint_telemetry.csv` (via
  `docker/telemetry/collector.py`), on its own polling interval.
- There is no reliable per-session or per-window key to join telemetry
  samples to a specific `SourceWindowStats` bucket - only an approximate
  nearest-timestamp match is possible, and that join logic has not been
  implemented yet.

**To close this gap**, a future task should:
1. Implement a nearest-timestamp (or interval-overlap) join between a
   window's `[window_start, window_end)` and telemetry rows for the
   relevant container.
2. Extend `SourceWindowStats` with a `mean_cpu_percent` (or similar)
   field, computed the same way `mean_handshake_duration_ms` is now.
3. Extend `check_r08_rate_correlates_with_latency` (or add a distinct
   `check_r08b_rate_correlates_with_cpu`) to also/instead check CPU.

## R07 (failed-handshake threshold is a count, not a ratio)

The project spec's wording is "excessive failed-handshake **ratio**."
The implementation checks `failed_handshake_count` against
`ServicePolicy.max_failed_handshakes_per_source_per_minute`, which is an
**absolute per-window count**, matching the field's actual name/units in
`configs/pqc_policy.yaml`. `ServicePolicy` has no ratio-based threshold
field today. If a true ratio (e.g. failed/total > 0.5) is wanted instead,
add a new field such as `max_failed_handshake_ratio: float` to
`ServicePolicy` and update `check_r07_failed_handshake_ratio_exceeded`
accordingly.

## R03 / R05 cannot trigger on real (non-synthetic) parsed data

See `src/parsers/zeek_parser.py` module docstring. Stock Zeek `ssl.log`
does not expose the ClientHello's offered key-exchange groups or the
negotiated key-share length without a custom Zeek script extension.
Until `configs/zeek/local.zeek` is extended to extract these fields,
every `TLSSessionRecord` produced by the real parser has
`offered_groups=[]` and `key_share_length=None`, so R03 and R05 will
never fire on real lab traffic - only on synthetic test fixtures.

## Malformed-handshake traffic is synthetic and narrow

`scripts/generate_malformed_cases.sh` (via `scripts/send_malformed_tls.py`)
produces only three deliberately hand-crafted byte patterns: a truncated
ClientHello, an internally inconsistent extension length, and random
garbage following a plausible-looking record header. This is **not**
representative of the full space of real-world malformed TLS traffic
(fuzzed field combinations, protocol-version confusion, malformed
certificate chains, oversized/undersized extensions across many TLS
message types, etc.) - it exists to produce *some* labeled
`malformed_handshake` training data, not a comprehensive corpus.

**More importantly:** because these payloads are not valid TLS records
(or are truncated before completion), Zeek's SSL analyzer frequently
fails to log them in `ssl.log` at all - only `conn.log` will show the
raw TCP connection. Since `src/parsers/zeek_parser.py::build_session_records`
only builds `TLSSessionRecord` objects from `ssl.log` rows, a meaningful
fraction of `generate_malformed_cases.sh`'s traffic may **never become a
labeled training row** at all. `scripts/label_sessions.py` logs a warning
when a manifest (especially `exp-005-malformed-handshake`) matches zero
parsed sessions - this is expected, not necessarily a bug.

**To close this gap**, a future task should either extend
`configs/zeek/local.zeek` to log incomplete/failed SSL negotiations from
`conn.log` alone (so malformed traffic that never reaches a valid
ClientHello still produces a session record), or add a second, less
strict session record builder that operates on `conn.log` directly for
connections with no matching `ssl.log` entry.

## Downgrade traffic may be indistinguishable from PQC-fallback traffic

`scripts/generate_downgrade_cases.sh` forces a classical-only group
against the PQC-required lab server. If `tls-pqc` is currently running
its default classical-fallback stub (`PQC_ALLOW_CLASSICAL_FALLBACK=true`,
no real PQC-capable `PQC_BASE_IMAGE` configured - see Phase 1), then
`exp-002-benign-hybrid-pqc` traffic (which *intends* to be PQC) and
`exp-003-downgrade-violation` traffic (which *intends* to force a
downgrade) will be wire-identical: both actually negotiate a classical
group. `scripts/label_sessions.py` cross-checks each matched session
against the rule engine and logs a warning when this disagreement is
detected, but does not override the manifest's label - trusting
experimental intent rather than silently relabeling. Real, distinguishable
`benign_hybrid_pqc` data requires a genuinely PQC-capable `PQC_BASE_IMAGE`.
