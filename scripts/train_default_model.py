"""Train and save a threat detection classifier model with custom dataset support."""

import argparse
from pathlib import Path
import pandas as pd
from models.training import ModelTrainer

DEFAULT_DATA_PATH = "data/samples/labeled_flows.csv"
DEFAULT_MODEL_PATH = "models/artifacts/default_rf.joblib"


def train_model(data_path: str, model_type: str, output_path: str) -> None:
    """Train a classifier on the target dataset CSV and save model weights."""
    p_data = Path(data_path)
    if not p_data.exists():
        if data_path == DEFAULT_DATA_PATH:
            print(f"Predefined dataset not found. Generating default training samples...")
            from scripts.generate_training_data import generate
            generate()
        else:
            raise FileNotFoundError(f"Input dataset CSV file not found: {data_path}")

    print(f"Loading dataset from: {p_data}")
    if p_data.suffix.lower() == ".parquet":
        df = pd.read_parquet(p_data)
    else:
        df = pd.read_csv(p_data)
    
    # Standardize column headers (strip spaces, resolve casing)
    df.columns = [str(c).strip() for c in df.columns]
    
    # Map common external label attributes (e.g. CIC-IDS2017 'Label' column) to standardized 'label'
    label_mapped = False
    for col in df.columns:
        if col.lower() in ["label", "class", "threat", "is_attacker", "intrusion_label"]:
            df = df.rename(columns={col: "label"})
            label_mapped = True
            break
        # Handle various label naming conventions for CIC-IDS2017
        if col == "Label":
            df = df.rename(columns={"Label": "label"})
            label_mapped = True
            break

    # If the model is supervised but no label/target is mapped, prompt user
    if model_type.lower() != "isolation_forest" and "label" not in df.columns:
        # Check standard binary classification label targets
        raise ValueError(
            f"Dataset does not contain a classification label target column ('label' or 'Label'). "
            f"Available headers: {list(df.columns[:10])}..."
        )

    # Coerce label values to integer standards: map strings like 'BENIGN'/'Benign' to 0, anything else to 1
    if "label" in df.columns and str(df["label"].dtype).lower().startswith(("object", "str", "category")):
        df["label"] = df["label"].apply(
            lambda val: 0 if str(val).strip().lower() == "benign" else 1
        )

    print(f"Dataset loaded. Total connection records: {len(df)}")
    print(f"Initializing {model_type} training engine...")
    trainer = ModelTrainer(model_type=model_type)
    
    # Perform temporal holdout split to prevent data leakage in training evaluation
    train_df, test_df = trainer.temporal_split(df, test_size=0.20)
    
    # Train model
    print("Fitting features preprocessor and training classifier...")
    trainer.train(train_df)
    
    # Evaluate performance
    print("Evaluating classifier on holdout validation partition...")
    metrics = trainer.evaluate(test_df)
    
    print("==================================================")
    print(f"🚀 Model trained successfully!")
    print(f"  Accuracy Statistics:")
    print(f"  F1 Score:  {metrics.f1_score * 100:.2f}%")
    print(f"  Precision: {metrics.precision * 100:.2f}%")
    print(f"  Recall:    {metrics.recall * 100:.2f}%")
    print(f"  Inference Latency: {metrics.inference_latency_ms:.6f} ms/flow")
    print("==================================================")
    
    # Save model weights to target path
    p_output = Path(output_path)
    p_output.parent.mkdir(parents=True, exist_ok=True)
    trainer.save(p_output)
    print(f"Saved trained classifier weights to: {p_output}\n")


def main():
    parser = argparse.ArgumentParser(description="NETra ML Threat Classifier Model Trainer")
    parser.add_argument(
        "--data", "-d", default=DEFAULT_DATA_PATH,
        help=f"Path to input dataset CSV (default: {DEFAULT_DATA_PATH})"
    )
    parser.add_argument(
        "--model-type", "-m", default="random_forest",
        choices=["random_forest", "xgboost", "isolation_forest"],
        help="Type of threat detection model to train (default: random_forest)"
    )
    parser.add_argument(
        "--output", "-o", default=DEFAULT_MODEL_PATH,
        help=f"Target output file path to save weights (default: {DEFAULT_MODEL_PATH})"
    )
    args = parser.parse_args()

    train_model(
        data_path=args.data,
        model_type=args.model_type,
        output_path=args.output
    )


if __name__ == "__main__":
    main()
