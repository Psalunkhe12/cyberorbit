import os
import time
import random
from pathlib import Path
from typing import Dict, Any, List, Tuple
from backend.config.settings import settings
from backend.ml.features import FeatureExtractor, FEATURE_NAMES

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server/script rendering
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import OneClassSVM
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)


def generate_experiment_dataset(num_samples: int = 2000, random_seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates an empirical network telemetry dataset with ground truth labels.
    - Class 0: Normal operational network traffic (90%)
    - Class 1: Anomalous network traffic (10%)
    """
    random.seed(random_seed)
    np.random.seed(random_seed)

    features_list: List[List[float]] = []
    labels: List[int] = []

    # 1. Normal Traffic (Class 0) - 1800 samples
    num_normal = int(num_samples * 0.90)
    for _ in range(num_normal):
        duration = float(random.uniform(0.1, 15.0))
        pkts = float(random.randint(2, 50))
        bytes_cnt = float(random.randint(120, 5000))

        pps = pkts / duration
        bps = bytes_cnt / duration
        dest_port = float(random.choice([80, 443, 53, 8080, 5432, 22]))
        uniq_dest = float(random.choice([1, 1, 1, 2]))
        failed_cnt = float(random.choice([0, 0, 0, 0, 1]))
        dns_cnt = float(random.choice([0, 1, 1, 2]))

        features_list.append([pps, bps, duration, dest_port, uniq_dest, failed_cnt, dns_cnt])
        labels.append(0)

    # 2. Anomalous Traffic (Class 1) - 200 samples
    num_anomalous = num_samples - num_normal
    for i in range(num_anomalous):
        anomaly_type = i % 4
        if anomaly_type == 0:
            # High Packet Rate Surge
            duration = float(random.uniform(0.1, 2.0))
            pkts = float(random.randint(800, 5000))
            bytes_cnt = float(random.randint(20000, 100000))
            pps = pkts / duration
            bps = bytes_cnt / duration
            dest_port = 80.0
            uniq_dest = 1.0
            failed_cnt = 0.0
            dns_cnt = 0.0
        elif anomaly_type == 1:
            # Port Scanning
            duration = float(random.uniform(0.5, 5.0))
            pkts = float(random.randint(20, 100))
            bytes_cnt = float(random.randint(1000, 5000))
            pps = pkts / duration
            bps = bytes_cnt / duration
            dest_port = float(random.choice([4444, 3389, 23, 1433, 5900]))
            uniq_dest = float(random.randint(10, 50))
            failed_cnt = float(random.randint(5, 20))
            dns_cnt = 0.0
        elif anomaly_type == 2:
            # Failed Connection Brute Force
            duration = float(random.uniform(1.0, 10.0))
            pkts = float(random.randint(50, 300))
            bytes_cnt = float(random.randint(2000, 15000))
            pps = pkts / duration
            bps = bytes_cnt / duration
            dest_port = 443.0
            uniq_dest = 1.0
            failed_cnt = float(random.randint(15, 60))
            dns_cnt = 0.0
        else:
            # Abnormal Outbound Exfiltration / DNS Tunneling
            duration = float(random.uniform(2.0, 20.0))
            pkts = float(random.randint(100, 1000))
            bytes_cnt = float(random.randint(200000, 1000000))
            pps = pkts / duration
            bps = bytes_cnt / duration
            dest_port = 53.0
            uniq_dest = 5.0
            failed_cnt = 0.0
            dns_cnt = float(random.randint(50, 300))

        features_list.append([pps, bps, duration, dest_port, uniq_dest, failed_cnt, dns_cnt])
        labels.append(1)

    return np.array(features_list), np.array(labels)


def run_model_comparison_experiment() -> pd.DataFrame:
    """
    Executes empirical model comparison across 5 machine learning architectures:
    1. Isolation Forest (Unsupervised Anomaly Detection)
    2. One-Class SVM (Unsupervised Anomaly Detection)
    3. Random Forest (Supervised Ensemble)
    4. Gradient Boosting (Supervised Boosting)
    5. Logistic Regression (Linear Classifier Baseline)

    Measures: Accuracy, Precision, Recall, F1, ROC-AUC, Training Time, and Inference Time.
    Saves results to ml/reports/model_comparison.csv and ml/reports/model_comparison.png.
    """
    print("[Experiment] Generating ground-truth dataset (2000 samples)...")
    X, y = generate_experiment_dataset(num_samples=2000)

    # Train / Test split (70% train, 30% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Models dictionary
    models = {
        "Isolation Forest": IsolationForest(n_estimators=100, contamination=0.10, random_state=42),
        "One-Class SVM": OneClassSVM(kernel="rbf", gamma="scale", nu=0.10),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    }

    results: List[Dict[str, Any]] = []

    for name, model in models.items():
        print(f"[Experiment] Evaluating model: {name}...")

        # 1. Measure Training Time
        t_start_train = time.perf_counter()
        if name in ["Isolation Forest", "One-Class SVM"]:
            # Unsupervised models train only on normal class in training set
            X_train_normal = X_train_scaled[y_train == 0]
            model.fit(X_train_normal)
        else:
            model.fit(X_train_scaled, y_train)
        t_end_train = time.perf_counter()
        training_time = t_end_train - t_start_train

        # 2. Measure Inference Time (on test set)
        t_start_inf = time.perf_counter()
        if name in ["Isolation Forest", "One-Class SVM"]:
            raw_pred = model.predict(X_test_scaled)
            # sklearn unsupervised models predict -1 for anomaly, 1 for normal
            y_pred = np.where(raw_pred == -1, 1, 0)
            y_scores = -model.decision_function(X_test_scaled)
        else:
            y_pred = model.predict(X_test_scaled)
            if hasattr(model, "predict_proba"):
                y_scores = model.predict_proba(X_test_scaled)[:, 1]
            else:
                y_scores = model.decision_function(X_test_scaled)
        t_end_inf = time.perf_counter()
        inference_time = t_end_inf - t_start_inf

        # 3. Calculate Empirical Metrics
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))

        try:
            auc = float(roc_auc_score(y_test, y_scores))
        except Exception:
            auc = 0.0

        results.append({
            "model_name": name,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "training_time_sec": round(training_time, 6),
            "inference_time_sec": round(inference_time, 6),
        })

    df = pd.DataFrame(results)

    # Output Paths
    root_reports_dir = Path("ml/reports")
    backend_reports_dir = Path("backend/ml/reports")

    root_reports_dir.mkdir(parents=True, exist_ok=True)
    backend_reports_dir.mkdir(parents=True, exist_ok=True)

    csv_path_root = root_reports_dir / "model_comparison.csv"
    csv_path_backend = backend_reports_dir / "model_comparison.csv"

    png_path_root = root_reports_dir / "model_comparison.png"
    png_path_backend = backend_reports_dir / "model_comparison.png"

    # Save CSV
    df.to_csv(csv_path_root, index=False)
    df.to_csv(csv_path_backend, index=False)
    print(f"[Experiment] Saved comparison CSV to {csv_path_root}")

    # Generate Visualization Plot
    plt.figure(figsize=(12, 8), dpi=300)
    plt.style.use("ggplot")

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("CyberOrbit Security Machine Learning Model Comparison", fontsize=16, fontweight="bold", y=0.98)

    models_list = df["model_name"].tolist()
    colors = ["#334d4a", "#d49b28", "#2d9d78", "#1976d2", "#d94b4b"]

    # 1. F1 Score Comparison
    axes[0, 0].bar(models_list, df["f1_score"], color=colors)
    axes[0, 0].set_title("F1-Score Comparison", fontsize=12, fontweight="bold")
    axes[0, 0].set_ylim(0, 1.1)
    axes[0, 0].set_ylabel("F1 Score")
    for i, val in enumerate(df["f1_score"]):
        axes[0, 0].text(i, val + 0.02, f"{val:.3f}", ha="center", fontsize=9, fontweight="bold")
    axes[0, 0].tick_params(axis="x", rotation=25)

    # 2. ROC-AUC Comparison
    axes[0, 1].bar(models_list, df["roc_auc"], color=colors)
    axes[0, 1].set_title("ROC-AUC Score", fontsize=12, fontweight="bold")
    axes[0, 1].set_ylim(0, 1.1)
    axes[0, 1].set_ylabel("ROC-AUC")
    for i, val in enumerate(df["roc_auc"]):
        axes[0, 1].text(i, val + 0.02, f"{val:.3f}", ha="center", fontsize=9, fontweight="bold")
    axes[0, 1].tick_params(axis="x", rotation=25)

    # 3. Training Time (seconds)
    axes[1, 0].bar(models_list, df["training_time_sec"] * 1000, color=colors)
    axes[1, 0].set_title("Training Time (ms)", fontsize=12, fontweight="bold")
    axes[1, 0].set_ylabel("Time (milliseconds)")
    for i, val in enumerate(df["training_time_sec"] * 1000):
        axes[1, 0].text(i, val + (max(df["training_time_sec"] * 1000) * 0.02), f"{val:.1f} ms", ha="center", fontsize=9, fontweight="bold")
    axes[1, 0].tick_params(axis="x", rotation=25)

    # 4. Inference Time (ms for 600 test samples)
    axes[1, 1].bar(models_list, df["inference_time_sec"] * 1000, color=colors)
    axes[1, 1].set_title("Inference Time (ms per 600 samples)", fontsize=12, fontweight="bold")
    axes[1, 1].set_ylabel("Time (milliseconds)")
    for i, val in enumerate(df["inference_time_sec"] * 1000):
        axes[1, 1].text(i, val + (max(df["inference_time_sec"] * 1000) * 0.02), f"{val:.2f} ms", ha="center", fontsize=9, fontweight="bold")
    axes[1, 1].tick_params(axis="x", rotation=25)

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])

    # Save PNG
    plt.savefig(png_path_root, dpi=300)
    plt.savefig(png_path_backend, dpi=300)
    plt.close()
    print(f"[Experiment] Saved comparison plot to {png_path_root}")

    return df


if __name__ == "__main__":
    df_results = run_model_comparison_experiment()
    print("\nEmpirical Model Comparison Results:")
    print(df_results.to_string(index=False))
