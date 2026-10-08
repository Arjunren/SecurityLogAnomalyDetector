# Dataset handling

No logs are bundled. The [Loghub academic collection](https://github.com/logpai/loghub) and [LANL ARCS portal](https://csr.lanl.gov/data/) are research starting points; review each source's terms, privacy, schema, and labels. Prepare one JSON object per line in `data/raw/`, then run `scripts/prepare_logs.py --format linux|windows|cloud|application|authentication`. The parser does not download data or retain message bodies.

All formats require `baseline_expected_events_per_minute` (positive historical value), `reviewed_label` (`benign` or `anomalous`), and optional booleans `is_error`, `auth_failed`, `access_denied`, `off_hours`, `rare_template`, and `privileged_action`. Historical fields must use only information available before the event window. Source-specific required fields:

| Format | Timestamp | Group source | Event code | Principal | Host | Severity |
| --- | --- | --- | --- | --- | --- | --- |
| `linux` | `timestamp` | `host` | `event_code` | `principal` | `host` | `severity` |
| `windows` | `TimeCreated` | `Computer` | `EventID` | `TargetUserName` | `Computer` | `Level` |
| `cloud` | `eventTime` | `sourceIPAddress` | `eventName` | `userIdentity.principalId` | `eventSource` | `severity` |
| `application` | `timestamp` | `service` | `event_code` | `principal` | `host` | `severity` |
| `authentication` | `timestamp` | `provider` | `event_code` | `principal` | `host` | `severity` |

Timestamps must be timezone-aware ISO strings. Source IDs and event codes are bounded strings; severity is an integer from 0 to 10. Upstream adapters must map source-specific outcomes and severity to these fields consistently. The output CSV contains only bounded numeric features, reviewed label, and a per-run keyed source hash. Do not concatenate separately prepared CSVs without reassigning consistent `group_id` values. Raw and processed files are Git ignored. The synthetic fixture is only for smoke tests.
