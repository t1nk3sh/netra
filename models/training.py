"""ML model training pipeline.

Trains Random Forest, XGBoost and Isolation Forest models on flow features.
Implements temporal train/test split to prevent leakage.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
import xgboost as xgb

from models.preprocessing import FlowFeaturePreprocessor

logger = logging.getLogger(__name__)


@dataclass
class EvaluationMetrics:
    """Standard evaluation metrics for a trained classifier."""

    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    confusion_matrix: list[list[int]]
    report: str
    inference_latency_ms: float
    validation_strategy: str = "Temporal split (chronological split on timestamp)"


class ModelTrainer:
    """ML Model Trainer supporting Random Forest, XGBoost, and Isolation Forest."""

    def __init__(
        self,
        model_type: str = "random_forest",
        preprocessor: FlowFeaturePreprocessor | None = None,
        model_params: Dict[str, Any] | None = None,
    ) -> None:
        self.model_type = model_type.lower()
        self.preprocessor = preprocessor or FlowFeaturePreprocessor()
        self.model_params = model_params or {}
        self.model: Any = None
        self._is_trained = False

        self._initialize_model()

    def _initialize_model(self) -> None:
        if self.model_type == "random_forest":
            params = {"n_estimators": 100, "random_state": 42, "class_weight": "balanced"}
            params.update(self.model_params)
            self.model = RandomForestClassifier(**params)
        elif self.model_type == "xgboost":
            params = {"n_estimators": 100, "random_state": 42, "eval_metric": "logloss"}
            params.update(self.model_params)
            self.model = xgb.XGBClassifier(**params)
        elif self.model_type == "isolation_forest":
            params = {"contamination": 0.05, "random_state": 42}
            params.update(self.model_params)
            self.model = IsolationForest(**params)
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")

    def temporal_split(
        self, df: pd.DataFrame, test_size: float = 0.25, time_col: str = "ts"
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Perform chronological temporal split to prevent data leakage.

        Sorts df by time_col and splits into training and testing sets.

        Args:
            df: Input DataFrame containing features, labels, and timestamp.
            test_size: Ratio of data used for testing (0.0 to 1.0).
            time_col: Columns to sort chronologically before split.

        Returns:
            Tuple of (train_df, test_df).
        """
        if time_col not in df.columns:
            logger.warning("Time column %s not found. Falling back to index-based split", time_col)
            sorted_df = df.copy()
        else:
            sorted_df = df.sort_values(by=time_col).reset_index(drop=True)

        split_idx = int(len(sorted_df) * (1 - test_size))
        train_df = sorted_df.iloc[:split_idx]
        test_df = sorted_df.iloc[split_idx:]
        return train_df, test_df

    def train(self, train_df: pd.DataFrame, label_col: str = "label") -> ModelTrainer:
        """Fit preprocessor and train model.

        Args:
            train_df: Training DataFrame containing features and labels.
            label_col: Label column name.

        Returns:
            Self.
        """
        logger.info("Starting training of %s model", self.model_type)

        # Fit and transform features
        X_train = self.preprocessor.fit_transform(train_df)

        if self.model_type == "isolation_forest":
            # Unsupervised: train only on benign logs (where label == 0) if labels exist,
            # or train on all logs generally.
            if label_col in train_df.columns:
                benign_df = train_df[train_df[label_col] == 0]
                if len(benign_df) > 10:
                    X_train = self.preprocessor.transform(benign_df)
            self.model.fit(X_train)
        else:
            if label_col not in train_df.columns:
                raise ValueError(f"Label column '{label_col}' not found in training DataFrame")
            y_train = train_df[label_col].values
            self.model.fit(X_train, y_train)

        self._is_trained = True
        logger.info("Training complete")
        return self

    def evaluate(self, test_df: pd.DataFrame, label_col: str = "label") -> EvaluationMetrics:
        """Evaluate the model and preprocessor on a test set.

        Args:
            test_df: Unseen validation/test DataFrame.
            label_col: Label column name.

        Returns:
            EvaluationMetrics object.
        """
        if not self._is_trained:
            raise RuntimeError("Model has not been trained yet")

        if label_col not in test_df.columns:
            raise ValueError(f"Label column '{label_col}' not found in test DataFrame")

        y_test = test_df[label_col].values
        X_test = self.preprocessor.transform(test_df)

        # Measure latency
        start_time = time.perf_counter()
        if self.model_type == "isolation_forest":
            # IsolationForest outputs -1 for outliers (anomaly) and 1 for inliers (normal).
            # Convert to standard 0/1 indicator: anomaly=1, normal=0.
            preds_raw = self.model.predict(X_test)
            preds = np.where(preds_raw == -1, 1, 0)
        else:
            preds = self.model.predict(X_test)
        end_time = time.perf_counter()

        inference_latency_ms = ((end_time - start_time) / len(test_df)) * 1000.0

        cm = confusion_matrix(y_test, preds)
        
        # Calculate rates
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, preds, average="binary", zero_division=0
        )

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        report = classification_report(y_test, preds, zero_division=0)

        return EvaluationMetrics(
            precision=float(precision),
            recall=float(recall),
            f1_score=float(f1),
            false_positive_rate=float(fpr),
            false_negative_rate=float(fnr),
            confusion_matrix=cm.tolist(),
            report=report,
            inference_latency_ms=float(inference_latency_ms),
        )

    def save(self, path: str | Path) -> None:
        """Save entire ModelTrainer containing model and preprocessor."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, p)
        logger.info("Saved model trainer to %s", p)

    @classmethod
    def load(cls, path: str | Path) -> ModelTrainer:
        """Load ModelTrainer from a file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Model file not found: {p}")
        obj = joblib.load(p)
        if not isinstance(obj, cls):
            raise TypeError(f"Loaded object is not a {cls.__name__}")
        return obj
