"""Models page detailing ML pipeline configuration and training evaluation metrics."""

from pathlib import Path
import streamlit as st
import pandas as pd
from models.training import ModelTrainer

import logging

logger = logging.getLogger(__name__)

DATA_PATH = Path("data/samples/labeled_flows.csv")
MODEL_PATH = Path("models/artifacts/default_rf.joblib")


def render_models_page() -> None:
    """Render the machine learning models overview page."""
    st.markdown("## 🧠 Machine Learning Engine Registry")
    st.markdown("Overview of the trained classifiers and validation partition metrics.")

    if not MODEL_PATH.exists():
        st.warning("ML Inference Offline: Trained model files were not found in models/artifacts/.")
        st.info("Please execute scripts/train_default_model.py first.")
        return

    # Load from disk
    trainer = ModelTrainer.load(MODEL_PATH)
    
    # Check if dataset is available to compute actual validation metrics
    metrics = None
    if DATA_PATH.exists():
        try:
            df = pd.read_csv(DATA_PATH)
            # Evaluate test partition using temporal split defined inside training scripts
            train_df, test_df = trainer.temporal_split(df, test_size=0.20)
            metrics = trainer.evaluate(test_df)
        except Exception as e:
            logger.warning("Failed to evaluate loaded classifier metrics: %s", e)

    # Status indicators natively displayed
    with st.container(border=True):
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown("**Active Classifier**")
            st.markdown("Random Forest")
        with col2:
            st.markdown("**Registry Status**")
            st.markdown("🟢 Live & Loaded")
        with col3:
            st.markdown("**Model Type**")
            st.markdown("Supervised Ensemble")
        with col4:
            st.markdown("**Model Path**")
            st.code("models/artifacts/default_rf.joblib")

    st.markdown("<br>", unsafe_allow_html=True)

    if metrics:
        st.markdown("### Model Evaluation Metrics (Temporal Holdout Test Set)")
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        with col_m1:
            st.metric("F1-Score", f"{metrics.f1_score * 100:.2f}%")
        with col_m2:
            st.metric("Precision", f"{metrics.precision * 100:.2f}%")
        with col_m3:
            st.metric("Recall", f"{metrics.recall * 100:.2f}%")
        with col_m4:
            st.metric("Inference Latency", f"{metrics.inference_latency_ms:.4f} ms")
            
        # Display confusion matrix and reports
        st.markdown("<br>", unsafe_allow_html=True)
        col_report, col_cm = st.columns([2, 1])
        with col_report:
            st.markdown("**Classification Report**")
            st.code(metrics.report)
        with col_cm:
            st.markdown("**Validation Matrix**")
            c_matrix = metrics.confusion_matrix
            if len(c_matrix) == 2 and len(c_matrix[0]) == 2:
                cm_df = pd.DataFrame(
                    c_matrix, 
                    index=["Actual Benign (0)", "Actual Malicious (1)"], 
                    columns=["Predicted Benign (0)", "Predicted Malicious (1)"]
                )
            else:
                # Safely fallback to unlabelled matrix when testing single-class predictions
                cm_df = pd.DataFrame(c_matrix)
            st.dataframe(cm_df)
    else:
        st.markdown("### Model Evaluation Metrics")
        st.info("Evaluation metrics not present. Please place labeled_flows.csv in data/samples/ to display validation scores.")

    st.markdown("---")
    st.markdown("### Feature Extraction Input Profiles")
    st.write("Below are the standard features scaled, cleaned, and evaluated by the ML preprocessor pipeline.")
    
    # Feature columns display
    features = trainer.preprocessor.feature_cols
    col_feat1, col_feat2 = st.columns(2)
    half = len(features) // 2 + 1
    
    with col_feat1:
        st.dataframe(pd.DataFrame(features[:half], columns=["Numeric Feature Dimension"]), use_container_width=True)
    with col_feat2:
        st.dataframe(pd.DataFrame(features[half:], columns=["Numeric Feature Dimension"]), use_container_width=True)
