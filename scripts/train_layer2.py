"""Submission-Grade Training Pipeline for CANARY Layer 2 AI-Aided Kalman Filter IDS.

Fuses 4WD wheel encoders and 6-DOF IMU through the Kinematic Kalman Filter,
generates a realistic, balanced 2400-sample dataset, and trains a RandomForestClassifier.
"""
import os
import sys
import json
import random
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
import joblib

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from simulation.sensor_simulator import (
    SensorSimulator, PhysicalAttack,
    ATTACK_IMU_YAW_OFFSET, ATTACK_WHEEL_OFFSET, ATTACK_SIDE_OFFSET,
)
from simulation import scenarios
from simulation.kalman_filter import RoverKalmanFilter
from simulation.layer2_ids import (
    FEATURE_NAMES, extract_features, features_to_vector,
    MODELS_DIR, FEATURES_PATH, MODEL_PATH
)
from simulation.vehicle_model import TRACK_WIDTH

RANDOM_SEED = 42
TOTAL_SAMPLES = 2400
NORMAL_SAMPLES = 1200
ANOMALY_SAMPLES = 1200


def generate_robust_dataset():
    rng = random.Random(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    X_list = []
    y_list = []

    print("[1/4] Simulating normal driving with Kalman state estimation & wheel slip...")
    sim_normal = SensorSimulator(dt=0.01, seed=RANDOM_SEED)
    sim_normal.timeline = scenarios.DEFAULT_TIMELINE * 25
    kf_normal = RoverKalmanFilter(track_width=TRACK_WIDTH, dt=0.01)

    while len(y_list) < NORMAL_SAMPLES:
        sample = sim_normal.step()
        enc = dict(sample["encoders"])
        imu = dict(sample["imu"])

        # Inject realistic skid-steer lateral wheel slip during turns
        yaw_rate = imu["gyro_z"]
        if abs(yaw_rate) > 0.1:
            slip = rng.gauss(0.0, 1.2)
            enc["fl_rpm"] += slip
            enc["rl_rpm"] += slip
            enc["fr_rpm"] -= slip
            enc["rr_rpm"] -= slip

        feats = extract_features(enc, imu, kf=kf_normal)
        X_list.append(features_to_vector(feats))
        y_list.append(0)  # 0 = NORMAL

    print(f"      -> Generated {len(y_list)} normal samples.")

    print("[2/4] Simulating multi-tier physical attacks through Kalman filter...")
    sim_atk = SensorSimulator(dt=0.01, seed=RANDOM_SEED + 999)
    sim_atk.timeline = scenarios.DEFAULT_TIMELINE * 35
    kf_atk = RoverKalmanFilter(track_width=TRACK_WIDTH, dt=0.01)

    attack_categories = [
        "IMU_STEALTHY",   # 0.35 - 0.75 rad/s bias
        "IMU_BLATANT",    # 1.00 - 2.20 rad/s spoof
        "IMU_FREEZE",     # IMU reports 0 yaw while turning
        "WHEEL_SINGLE",   # Single wheel encoder offset
        "WHEEL_FREEZE",   # Single wheel reports 0 while moving
        "SIDE_ASYMMETRY", # Asymmetric side speed manipulation
    ]

    while len(y_list) < TOTAL_SAMPLES:
        cat = rng.choice(attack_categories)
        duration = rng.uniform(1.2, 2.5)
        steps = int(round(duration / sim_atk.dt))

        target_wheel = rng.choice(["fl", "fr", "rl", "rr"])
        target_side = rng.choice(["left", "right"])
        sign = rng.choice([-1.0, 1.0])

        for _ in range(steps):
            if len(y_list) >= TOTAL_SAMPLES:
                break
            sample = sim_atk.step()
            enc = dict(sample["encoders"])
            imu = dict(sample["imu"])

            if cat == "IMU_STEALTHY":
                imu["gyro_z"] += sign * rng.uniform(0.35, 0.75)
            elif cat == "IMU_BLATANT":
                imu["gyro_z"] += sign * rng.uniform(1.0, 2.2)
            elif cat == "IMU_FREEZE":
                if abs(imu["gyro_z"]) > 0.2:
                    imu["gyro_z"] = rng.gauss(0.0, 0.02)
                else:
                    imu["gyro_z"] += sign * 0.9
            elif cat == "WHEEL_SINGLE":
                enc[f"{target_wheel}_rpm"] += sign * rng.uniform(50.0, 140.0)
            elif cat == "WHEEL_FREEZE":
                enc[f"{target_wheel}_rpm"] = 0.0
            elif cat == "SIDE_ASYMMETRY":
                offset = sign * rng.uniform(40.0, 110.0)
                if target_side == "left":
                    enc["fl_rpm"] += offset
                    enc["rl_rpm"] += offset
                else:
                    enc["fr_rpm"] += offset
                    enc["rr_rpm"] += offset

            feats = extract_features(enc, imu, kf=kf_atk)
            X_list.append(features_to_vector(feats))
            y_list.append(1)  # 1 = ANOMALY

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)
    print(f"      -> Total dataset ready: X shape = {X.shape}, y shape = {y.shape}")

    return X, y


def train():
    X, y = generate_robust_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y
    )

    print("\n[3/4] Training RandomForestClassifier (100 trees, max_depth=8)...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    acc = accuracy_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    print("\n[4/4] Evaluation on Held-Out Test Set (480 samples):")
    print(f"      Accuracy: {acc * 100:.2f}%")
    print(f"      ROC-AUC Score: {roc:.4f}")
    print("\nConfusion Matrix:")
    print(f"  [[TN={cm[0,0]:<3}  FP={cm[0,1]:<3}]  -> Normal driving correctly classified: {cm[0,0]}/{cm[0,0]+cm[0,1]}")
    print(f"   [FN={cm[1,0]:<3}  TP={cm[1,1]:<3}]] -> Injected physical attacks caught: {cm[1,1]}/{cm[1,0]+cm[1,1]}")

    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["NORMAL (0)", "ANOMALY (1)"], digits=4))

    print("Learned Feature Importances:")
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for idx in sorted_idx:
        bar = "#" * int(round(importances[idx] * 40))
        print(f"  {FEATURE_NAMES[idx]:<20} : {importances[idx]*100:5.2f}%  {bar}")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    spec = {
        "features": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "n_estimators": 100,
        "max_depth": 8,
        "random_state": RANDOM_SEED,
        "classes": ["NORMAL", "ANOMALY"],
        "threshold": 0.5,
        "metrics": {
            "accuracy": round(float(acc), 4),
            "roc_auc": round(float(roc), 4),
            "test_samples": len(y_test)
        }
    }
    with open(FEATURES_PATH, "w") as f:
        json.dump(spec, f, indent=2)

    joblib.dump(model, MODEL_PATH)
    print(f"\nArtifacts successfully written to:")
    print(f"  -> {FEATURES_PATH}")
    print(f"  -> {MODEL_PATH}")


if __name__ == "__main__":
    train()
