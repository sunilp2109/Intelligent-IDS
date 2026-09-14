from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.preprocessing.feature_schema import FEATURE_NAMES


def build_preprocessor() -> Pipeline:
    """Reusable numeric preprocessing for training and inference."""
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )


def features_to_frame(features: dict[str, object]) -> pd.DataFrame:
    row = {name: features.get(name) for name in FEATURE_NAMES}
    frame = pd.DataFrame([row], columns=list(FEATURE_NAMES))
    numeric = frame.apply(pd.to_numeric, errors="coerce")
    return numeric.replace([np.inf, -np.inf], np.nan)
