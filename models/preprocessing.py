"""ML feature preprocessing and cleaning.

Ensures that identical feature processing is applied during training
and streaming inference. Handles NaNs, infinite values, scaling,
and feature selection.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# Core numeric features generated from parse_conn_log
FEATURE_COLUMNS = [
    "duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts",
    "orig_ip_bytes", "resp_ip_bytes", "missed_bytes", "total_bytes",
    "total_pkts", "total_ip_bytes", "packets_per_sec", "bytes_per_sec",
    "orig_packets_per_sec", "resp_packets_per_sec", "avg_pkt_size_orig",
    "avg_pkt_size_resp", "avg_pkt_size", "byte_ratio", "pkt_ratio",
    "ip_byte_ratio", "is_tcp", "is_udp",
    "hist_syn_count", "hist_syn_ack_count", "hist_ack_count", "hist_data_count",
    "hist_fin_count", "hist_rst_count", "hist_length",
    "conn_state_S0", "conn_state_S1", "conn_state_SF", "conn_state_REJ",
    "conn_state_RSTO", "conn_state_RSTR", "conn_state_OTH",
]


class FlowFeaturePreprocessor:
    """Preprocessor for scaling and cleaning connection level features."""

    def __init__(self, feature_cols: List[str] | None = None) -> None:
        self.feature_cols = feature_cols or FEATURE_COLUMNS
        self.scaler = StandardScaler()
        self._is_fitted = False

    def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Perform validation and cleaning on input DataFrame.

        Replaces NaNs with 0.0, replaces infinite values with large numbers/0.0.

        Args:
            df: Raw or partially processed flow DataFrame.

        Returns:
            Cleaned DataFrame.
        """
        df_clean = df.copy()

        # Add missing feature columns with default 0.0
        for col in self.feature_cols:
            if col not in df_clean.columns:
                df_clean[col] = 0.0

        # Select only our target feature columns to prevent leakage of columns
        df_clean = df_clean[self.feature_cols]

        # Handle inf/nan
        df_clean = df_clean.replace([np.inf, -np.inf], np.nan)
        df_clean = df_clean.fillna(0.0)

        return df_clean

    def fit(self, df: pd.DataFrame) -> FlowFeaturePreprocessor:
        """Fit scaler on the cleaned feature DataFrame.

        Args:
            df: DataFrame containing the training features.
        """
        df_clean = self.clean_dataframe(df)
        self.scaler.fit(df_clean)
        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Clean and scale features in the input DataFrame.

        Args:
            df: Input DataFrame.

        Returns:
            Scaled features as a 2D numpy array.
        """
        if not self._is_fitted:
            raise RuntimeError("Preprocessor has not been fitted, call fit() first")

        df_clean = self.clean_dataframe(df)
        return self.scaler.transform(df_clean)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        """Fit scaler and transform input DataFrame."""
        return self.fit(df).transform(df)

    def save(self, path: str | Path) -> None:
        """Save fitted preprocessor to a file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, p)
        logger.info("Saved preprocessor to %s", p)

    @classmethod
    def load(cls, path: str | Path) -> FlowFeaturePreprocessor:
        """Load preprocessor from a file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Preprocessor file not found: {p}")
        obj = joblib.load(p)
        if not isinstance(obj, cls):
            raise TypeError(f"Loaded object is not a {cls.__name__}")
        return obj
