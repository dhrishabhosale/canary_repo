"""CANARY Layer 2: AI-Aided Kalman Filter Physical Intrusion Detection System.

Fuses 4-wheel encoder streams with 6-DOF IMU data using a Kinematic Kalman Filter
and evaluates physical plausibility with a trained Random Forest classifier.
"""
import json
from pathlib import Path
import numpy as np
import joblib

try:
    from .vehicle_model import rpm_to_velocity, TRACK_WIDTH
    from .kalman_filter import RoverKalmanFilter
except ImportError:
    from vehicle_model import rpm_to_velocity, TRACK_WIDTH
    from kalman_filter import RoverKalmanFilter

REPO_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = REPO_ROOT / "models"
FEATURES_PATH = MODELS_DIR / "layer2_features.json"
MODEL_PATH = MODELS_DIR / "layer2_random_forest.pkl"

FEATURE_NAMES = [
    "fl_speed",
    "fr_speed",
    "rl_speed",
    "rr_speed",
    "left_speed",
    "right_speed",
    "vehicle_speed",
    "acceleration",
    "observed_yaw_rate",
    "expected_yaw_rate",
    "yaw_residual",
]


def extract_features(enc, imu, kf=None):
    """Extract the 11 kinematic & physical consistency features from raw sensor data.

    Args:
        enc: dict with keys 'fl_rpm', 'fr_rpm', 'rl_rpm', 'rr_rpm'
        imu: dict with keys 'accel_x', 'accel_y', 'accel_z', 'gyro_x', 'gyro_y', 'gyro_z'
        kf: optional RoverKalmanFilter instance for state filtering and innovation tracking

    Returns:
        dict mapping feature_name -> float value
    """
    fl_speed = float(rpm_to_velocity(enc["fl_rpm"]))
    fr_speed = float(rpm_to_velocity(enc["fr_rpm"]))
    rl_speed = float(rpm_to_velocity(enc["rl_rpm"]))
    rr_speed = float(rpm_to_velocity(enc["rr_rpm"]))

    left_speed = (fl_speed + rl_speed) / 2.0
    right_speed = (fr_speed + rr_speed) / 2.0

    acceleration = float(imu["accel_x"])
    observed_yaw_rate = float(imu["gyro_z"])

    if kf is not None:
        kf.predict()
        kf_res = kf.update(left_speed, right_speed, acceleration, observed_yaw_rate)
        vehicle_speed = kf_res["fused_velocity"]
        expected_yaw_rate = kf_res["expected_yaw_rate"]
        yaw_residual = kf_res["yaw_residual"]
    else:
        vehicle_speed = (left_speed + right_speed) / 2.0
        expected_yaw_rate = (right_speed - left_speed) / TRACK_WIDTH
        yaw_residual = observed_yaw_rate - expected_yaw_rate

    return {
        "fl_speed": fl_speed,
        "fr_speed": fr_speed,
        "rl_speed": rl_speed,
        "rr_speed": rr_speed,
        "left_speed": left_speed,
        "right_speed": right_speed,
        "vehicle_speed": vehicle_speed,
        "acceleration": acceleration,
        "observed_yaw_rate": observed_yaw_rate,
        "expected_yaw_rate": expected_yaw_rate,
        "yaw_residual": yaw_residual,
    }


def features_to_vector(features_dict):
    """Convert feature dict to a list ordered according to FEATURE_NAMES."""
    return [features_dict[name] for name in FEATURE_NAMES]


class Layer2IDS:
    """AI-Aided Kalman Filter Physical Intrusion Detection System."""

    def __init__(self, model, threshold=0.5, track_width=TRACK_WIDTH, dt=0.01):
        self.model = model
        self.threshold = threshold
        self.kf = RoverKalmanFilter(track_width=track_width, dt=dt)

    @classmethod
    def load(cls, model_path=MODEL_PATH, features_path=FEATURES_PATH, threshold=0.5):
        """Load trained model and verify feature specification."""
        if not Path(model_path).exists():
            raise FileNotFoundError(f"Model file not found at {model_path}")
        if not Path(features_path).exists():
            raise FileNotFoundError(f"Features specification not found at {features_path}")

        with open(features_path, "r") as f:
            spec = json.load(f)

        saved_features = spec.get("features", [])
        if saved_features != FEATURE_NAMES:
            raise ValueError(f"Feature mismatch: code={FEATURE_NAMES}, json={saved_features}")

        model = joblib.load(model_path)
        return cls(model=model, threshold=threshold)

    def reset_filter(self):
        """Reset the internal Kalman filter state."""
        self.kf.reset()

    def evaluate_features(self, feat_dict):
        """Run inference on extracted feature dictionary."""
        vec = np.array([features_to_vector(feat_dict)], dtype=np.float32)
        proba = self.model.predict_proba(vec)[0]
        # Class 1 is ANOMALY, Class 0 is NORMAL
        anomaly_score = float(proba[1]) if len(proba) > 1 else float(proba[0])
        prediction = "ANOMALY" if anomaly_score >= self.threshold else "NORMAL"

        return {
            "prediction": prediction,
            "anomaly_score": anomaly_score,
            "features": feat_dict,
        }

    def evaluate_state(self, enc, imu):
        """Pass sensor readings through the Kalman filter and evaluate with Random Forest."""
        feat_dict = extract_features(enc, imu, kf=self.kf)
        res = self.evaluate_features(feat_dict)
        res["kalman_state"] = {
            "fused_velocity": float(self.kf.x[0, 0]),
            "fused_yaw_rate": float(self.kf.x[1, 0]),
            "fused_acceleration": float(self.kf.x[2, 0]),
        }
        return res
