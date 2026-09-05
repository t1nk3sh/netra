"""Model inference implementation.

Loads trained models, validates features, applies matching preprocessing,
and makes threat probability/confidence predictions.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd

from models.training import ModelTrainer

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path("models/artifacts/default_rf.joblib")


class ThreatPredictor:
    """Predicts threat likelihood from precalculated connection-level features."""

    def __init__(self, model_path: str | Path | None = None) -> None:
        if model_path is None:
            model_path = DEFAULT_MODEL_PATH

        self.model_path = Path(model_path)
        logger.info("Initializing ThreatPredictor with model: %s", self.model_path)
        
        # Load the ModelTrainer containing model and fitted preprocessor
        self.trainer = ModelTrainer.load(self.model_path)
        self.model = self.trainer.model
        self.preprocessor = self.trainer.preprocessor

    def predict(self, df: pd.DataFrame, threshold: float | None = None) -> List[Dict[str, Any]]:
        """Predict threat classifications and confidence for a DataFrame of flows.

        Args:
            df: DataFrame containing the connection features.
            threshold: Optional custom confidence threshold for binary threat classification.

        Returns:
            List of prediction dicts containing:
                - threat_predicted: bool
                - confidence: float (probability or anomaly score)
                - model_type: str
        """
        if df.empty:
            return []

        # 1. Align features and apply fitted scaling
        X = self.preprocessor.transform(df)

        # 2. Run inference
        preds = self.model.predict(X)

        # 3. Retrieve confidence/probability where supported
        has_proba = hasattr(self.model, "predict_proba")
        if has_proba:
            # Classification probability for class 1 (Malicious)
            probas = self.model.predict_proba(X)
            confidences = probas[:, 1]
        else:
            if self.trainer.model_type == "isolation_forest":
                # For IsolationForest, decision_function returns anomaly score (negative is anomaly, positive is normal)
                scores = self.model.decision_function(X)
                # Map scores to a [0, 1] range: lower score -> higher anomaly confidence
                confidences = 1.0 / (1.0 + np.exp(scores))
            else:
                confidences = np.where(preds == 1, 1.0, 0.0)

        # Convert prediction labels (for IsolationForest, map outlier -1 to 1, normal 1 to 0)
        if self.trainer.model_type == "isolation_forest":
            threat_preds = (preds == -1).astype(int)
        else:
            threat_preds = preds.astype(int)

        results = []
        for i in range(len(df)):
            conf = float(confidences[i])
            if threshold is not None:
                is_threat = bool(conf >= threshold)
            else:
                is_threat = bool(threat_preds[i] == 1)

            results.append({
                "threat_predicted": is_threat,
                "confidence": conf,
                "model_type": self.trainer.model_type,
            })

        return results

    def predict_single(self, flow_features: Dict[str, Any], threshold: float | None = None) -> Dict[str, Any]:
        """Predict threat profile for a single flow.

        Args:
            flow_features: Dict containing features of a single flow.
            threshold: Optional custom confidence threshold.

        Returns:
            Dict containing threat forecast and confidence.
        """
        df = pd.DataFrame([flow_features])
        res = self.predict(df, threshold=threshold)
        return res[0]

    def classify_threat_type(self, flow: Dict[str, Any]) -> str:
        """Classify flow into a recognized threat category based on feature fingerprints.

        Args:
            flow: Connection flow dictionary with features.

        Returns:
            Threat type label (e.g. 'port_scan', 'dos_flood', 'c2_beacon', 'unknown_anomaly', 'benign').
        """
        syn_count = float(flow.get("hist_syn_count", 0.0) or 0.0)
        rst_count = float(flow.get("hist_rst_count", 0.0) or 0.0)
        pps = float(flow.get("packets_per_sec", 0.0) or 0.0)
        bps = float(flow.get("bytes_per_sec", 0.0) or 0.0)
        duration = float(flow.get("duration", 0.0) or 0.0)
        orig_bytes = float(flow.get("orig_bytes", 0.0) or 0.0)
        total_pkts = float(flow.get("total_pkts", 0.0) or 0.0)
        conn_state = str(flow.get("conn_state", ""))
        data_count = float(flow.get("hist_data_count", 0.0) or 0.0)
        byte_ratio = float(flow.get("byte_ratio", 0.0) or 0.0)

        # 1. Port scan: high SYN/RST with low or zero payload bytes / rejected states
        if (syn_count >= 3.0 or rst_count >= 3.0) and orig_bytes == 0.0 and duration < 5.0:
            return "port_scan"
        if conn_state in ["REJ", "RSTO", "S0"] and total_pkts < 10.0 and orig_bytes < 100.0:
            return "port_scan"

        # 2. DoS / DDoS flood: excessive packets/sec or bytes/sec
        if pps > 100.0 or bps > 1_000_000.0 or (total_pkts > 500.0 and duration < 2.0):
            return "dos_flood"

        # 3. C2 Beaconing: periodic small exchanges, low byte ratio, extended duration with intermittent data
        if duration > 120.0 and data_count >= 20.0 and byte_ratio < 0.1:
            return "c2_beacon"

        return "unknown_anomaly"
