# Model card — SecurityLogAnomalyDetector 1.0.0

| Field | Description |
| --- | --- |
| Purpose | Surface unusual security-log windows for analyst investigation. |
| Model type | StandardScaler plus PCA reconstruction error, fitted on benign training windows only. |
| Training dataset | Operator-prepared, reviewed structured log windows; no external data bundled. |
| Feature set | 15 bounded input fields, including source category expanded to five indicators, plus 3 deterministic rates. |
| Evaluation metrics | Held-out precision, recall, F1, ROC-AUC, PR-AUC, FPR, FNR, confusion matrix, and support per run. No default benchmark score. |
| Known limitations | Aggregate linear baseline, no sequence modeling, source-schema and historical-rate dependence. |
| Bias considerations | Uneven source coverage, roles, schedules, and logging levels can cause unequal false-positive rates. |
| Security considerations | Protect labels and baselines from poisoning, review parser mappings and artifact provenance, and keep raw messages out of logs. |
| Intended use | Investigation prioritization and SIEM enrichment. |
| Out-of-scope use | Confirmed attack attribution or automatic blocking. |
| Version | JSON format `security-log-pca-anomaly-v1`; semantic model version supplied at training. |

`anomaly_score` is reconstruction error. `baseline_percentile` and `risk_score` locate a window relative to benign validation scores, not a probability of maliciousness. Feature deviations are squared residuals, not causal explanations.
