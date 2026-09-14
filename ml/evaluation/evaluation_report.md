# Intelligent IDS evaluation report

Generated: 2026-09-14T14:30:58+00:00

Trained on a development/test labeled dataset. These metrics are for pipeline verification only and are not a production IDS evaluation.

| Metric | Result |
| --- | --- |
| Accuracy | 1.0000 |
| Precision (macro) | 1.0000 |
| Recall (macro) | 1.0000 |
| F1-score (macro) | 1.0000 |
| Malicious precision | 1.0000 |
| Malicious recall | 1.0000 |
| Malicious F1 | 1.0000 |
| False positive rate (malicious ovr) | 0.0000 |
| False negative rate (malicious ovr) | 0.0000 |
| Avg ML latency (ms) | 14.3006 |
| Median ML latency (ms) | 14.3023 |
| Max ML latency (ms) | 15.1705 |
| Avg pipeline with XAI (ms) | 41.6160 |
| Avg pipeline without XAI (ms) | 14.4221 |
| Throughput (events/sec) | 15.8660 |
| Test cases passed | 166 |
| Test cases failed | 0 |
| Test cases skipped | 0 |
| Coverage percent | 79.7184 |

## Confusion matrix (hold-out test split)

Rows are actual classes, columns are predicted classes (normal, suspicious, malicious).

```
{
  "labels": [
    "normal",
    "suspicious",
    "malicious"
  ],
  "matrix": [
    [
      6,
      0,
      0
    ],
    [
      0,
      6,
      0
    ],
    [
      0,
      0,
      6
    ]
  ]
}
```

## Limitations

- Metrics use the synthetic development labeled CSV unless another dataset was passed.
- Hold-out accuracy on that file is pipeline verification, not a real-world IDS score.
- Latencies were measured on the local development machine.
