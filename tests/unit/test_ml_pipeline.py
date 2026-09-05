"""Unit tests for ML training and preprocessing pipeline."""

import os
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from models.preprocessing import FlowFeaturePreprocessor, FEATURE_COLUMNS
from models.training import ModelTrainer, EvaluationMetrics

DATA_PATH = Path("data/samples/labeled_flows.csv")


@pytest.fixture(scope="module")
def dataset() -> pd.DataFrame:
    if not DATA_PATH.exists():
        from scripts.generate_training_data import generate
        generate()
    return pd.read_csv(DATA_PATH)


class TestFlowFeaturePreprocessor:
    def test_clean_dataframe_fills_missing(self, dataset: pd.DataFrame):
        preprocessor = FlowFeaturePreprocessor()
        # Create a DF missing some columns
        df_incomplete = dataset[["duration", "orig_bytes"]].copy()
        
        cleaned = preprocessor.clean_dataframe(df_incomplete)
        assert cleaned.shape[1] == len(FEATURE_COLUMNS)
        assert "packets_per_sec" in cleaned.columns
        assert (cleaned["packets_per_sec"] == 0.0).all()

    def test_clean_dataframe_replaces_nans_and_infs(self):
        preprocessor = FlowFeaturePreprocessor()
        df = pd.DataFrame({
            col: [np.nan, np.inf, -np.inf, 1.5] for col in FEATURE_COLUMNS
        })
        cleaned = preprocessor.clean_dataframe(df)
        assert not cleaned.isna().any().any()
        assert not np.isinf(cleaned.values).any()
        assert cleaned.iloc[0, 0] == 0.0
        assert cleaned.iloc[1, 0] == 0.0
        assert cleaned.iloc[2, 0] == 0.0
        assert cleaned.iloc[3, 0] == 1.5

    def test_fit_transform(self, dataset: pd.DataFrame):
        preprocessor = FlowFeaturePreprocessor()
        scaled = preprocessor.fit_transform(dataset)
        assert isinstance(scaled, np.ndarray)
        assert scaled.shape == (len(dataset), len(FEATURE_COLUMNS))
        # Scaled values mean should be close to 0, std close to 1
        assert np.allclose(scaled.mean(axis=0), 0.0, atol=1e-2)

    def test_save_load(self, dataset: pd.DataFrame, tmp_path: Path):
        path = tmp_path / "scaler.joblib"
        preprocessor = FlowFeaturePreprocessor()
        preprocessor.fit(dataset)
        preprocessor.save(path)

        assert path.exists()

        loaded = FlowFeaturePreprocessor.load(path)
        assert isinstance(loaded, FlowFeaturePreprocessor)
        assert loaded.feature_cols == preprocessor.feature_cols
        assert loaded._is_fitted is True

        scaled_orig = preprocessor.transform(dataset)
        scaled_loaded = loaded.transform(dataset)
        assert np.array_equal(scaled_orig, scaled_loaded)


class TestModelTrainer:
    def test_temporal_split(self, dataset: pd.DataFrame):
        trainer = ModelTrainer()
        train_df, test_df = trainer.temporal_split(dataset, test_size=0.20)
        
        # Test size check
        assert len(test_df) == pytest.approx(len(dataset) * 0.20, abs=1)
        assert len(train_df) + len(test_df) == len(dataset)

        # Monotonic time check to prevent leakage
        assert train_df["ts"].max() <= test_df["ts"].min()

    def test_random_forest_training_and_eval(self, dataset: pd.DataFrame, tmp_path: Path):
        trainer = ModelTrainer(model_type="random_forest")
        train_df, test_df = trainer.temporal_split(dataset, test_size=0.30)
        
        trainer.train(train_df)
        assert trainer._is_trained is True

        metrics = trainer.evaluate(test_df)
        assert isinstance(metrics, EvaluationMetrics)
        assert 0.0 <= metrics.precision <= 1.0
        assert 0.0 <= metrics.recall <= 1.0
        assert 0.0 <= metrics.f1_score <= 1.0
        assert 0.0 <= metrics.false_positive_rate <= 1.0
        assert 0.0 <= metrics.false_negative_rate <= 1.0
        assert metrics.inference_latency_ms > 0
        assert "Temporal split" in metrics.validation_strategy
        assert len(metrics.confusion_matrix) == 2

        # Save & load check
        model_path = tmp_path / "rf_model.joblib"
        trainer.save(model_path)
        assert model_path.exists()
        
        loaded = ModelTrainer.load(model_path)
        assert loaded.model_type == "random_forest"
        assert loaded._is_trained is True

    def test_xgb_training_and_eval(self, dataset: pd.DataFrame):
        trainer = ModelTrainer(model_type="xgboost")
        train_df, test_df = trainer.temporal_split(dataset, test_size=0.30)
        
        trainer.train(train_df)
        assert trainer._is_trained is True
        
        metrics = trainer.evaluate(test_df)
        assert isinstance(metrics, EvaluationMetrics)
        assert 0.0 <= metrics.f1_score <= 1.0

    def test_isolation_forest_training_and_eval(self, dataset: pd.DataFrame):
        trainer = ModelTrainer(model_type="isolation_forest", model_params={"contamination": 0.1})
        # Isolation Forest is unsupervised.
        train_df, test_df = trainer.temporal_split(dataset, test_size=0.30)
        
        # Train (trainer isolates benign for training inside trainer.train())
        trainer.train(train_df)
        assert trainer._is_trained is True
        
        metrics = trainer.evaluate(test_df)
        assert isinstance(metrics, EvaluationMetrics)
        assert 0.0 <= metrics.f1_score <= 1.0
