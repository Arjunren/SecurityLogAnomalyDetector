# Security review

## Threat model

An adversary can inject malformed or oversized log records, poison reviewed labels or historical rates, probe anomaly scores, or replace a writable artifact. Sensitive principals and host IDs exist in raw upstream logs. Protect availability, model integrity, privacy, and API credentials.

## Attack surface, trust boundaries, and controls

- Five explicit parser mappings accept structured JSONL, bound source bytes, event count, and line length, and discard free-form messages. Output contains numeric windows and a per-run keyed source hash; no raw principal, host, or message is written.
- Pydantic rejects missing, extra, out-of-range, NaN, and infinite window values. Group-disjoint splits keep sources isolated. Scaling and PCA fit benign training rows only; validation sets the threshold. Review labels and historical fields for poisoning or future leakage.
- API body, batch, worker, queue, and timeout limits reduce exhaustion. Production requires a strong key checked in constant time. A gateway supplies TLS, per-client rate limits, identity, and server-side tenant/object/function authorization. Opaque IDs are not authorization.
- Model artifacts are fixed-schema JSON with finite numeric tensors, size cap, feature order, and checksum. No pickle is loaded. Use reviewed, trusted artifact storage for authenticity.
- Logs include route template, status, and latency only. They exclude message bodies, principals, hosts, IDs, keys, and predictions. Docker runs non-root with read-only filesystem and dropped capabilities. CI runs Ruff, mypy, pytest, Bandit, and pip-audit.

## OWASP considerations and residual risks

No user-driven shell, SQL query, URL fetch, or uploaded executable is used. Errors are generic. Timed-out inference workers can complete after the HTTP response but remain counted until done. Shared-key mode lacks tenant roles. Poisoning, parser drift, baseline contamination, score probing, false positives, and false negatives remain. Use gateway controls, monitored rollouts, and analyst decisions.
