from __future__ import annotations

import statistics
from typing import Any


def summarize_ms(samples: list[float]) -> dict[str, Any]:
    if not samples:
        return {"count": 0, "min_ms": None, "max_ms": None, "mean_ms": None, "median_ms": None}
    return {
        "count": len(samples),
        "min_ms": round(min(samples), 4),
        "max_ms": round(max(samples), 4),
        "mean_ms": round(statistics.mean(samples), 4),
        "median_ms": round(statistics.median(samples), 4),
    }
