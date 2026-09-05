"""Unit tests for inference/predictor.py"""

from pathlib import Path
import pandas as pd
import pytest

from inference.predictor import ThreatPredictor, DEFAULT_MODEL_PATH


@pytest.fixture(scope="module")
def model_file() -> Path:
    # Ensure default model is trained before running tests
    if not DEFAULT_MODEL_PATH.exists():
        from scripts.train_default_model import train_default
        train_default()
    return DEFAULT_MODEL_PATH


class TestThreatPredictor:
    def test_predictor_load_and_init(self, model_file: Path):
        predictor = ThreatPredictor(model_file)
        assert predictor.model is not None
        assert predictor.preprocessor is not None
        assert predictor.trainer._is_trained is True

    def test_predict_batch_returns_correct_fields(self, model_file: Path):
        predictor = ThreatPredictor(model_file)
        # Create small flow features df
        dummy_df = pd.DataFrame([
            {"duration": 1.2, "orig_bytes": 100, "resp_bytes": 200, "is_tcp": 1},
            {"duration": 0.0, "orig_bytes": 40, "resp_bytes": 0, "is_tcp": 1, "conn_state_S0": 1, "hist_syn_count": 1}
        ])

        results = predictor.predict(dummy_df)
        assert len(results) == 2
        for r in results:
            assert isinstance(r, dict)
            assert "threat_predicted" in r
            assert "confidence" in r
            assert "model_type" in r
            assert isinstance(r["threat_predicted"], bool)
            assert isinstance(r["confidence"], float)
            assert 0.0 <= r["confidence"] <= 1.0

    def test_predict_single_flow(self, model_file: Path):
        predictor = ThreatPredictor(model_file)
        flow = {"duration": 1.2, "orig_bytes": 100, "resp_bytes": 200, "is_tcp": 1}
        
        res = predictor.predict_single(flow)
        assert isinstance(res, dict)
        assert "threat_predicted" in res
        assert "confidence" in res
        assert "model_type" in res

    def test_predict_empty_df(self, model_file: Path):
        predictor = ThreatPredictor(model_file)
        res = predictor.predict(pd.DataFrame())
        assert res == []

    def test_invalid_file_raises(self):
        with pytest.raises(FileNotFoundError):
            ThreatPredictor("/nonexistent/file.joblib")
