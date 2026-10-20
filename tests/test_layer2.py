"""Unit tests for CANARY Layer 2: AI-Aided Kalman Filter Physical Intrusion Detection System."""
import unittest
import numpy as np
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from simulation.layer2_ids import (
    Layer2IDS, extract_features, FEATURE_NAMES, MODEL_PATH, FEATURES_PATH
)
from simulation.kalman_filter import RoverKalmanFilter
from simulation.vehicle_model import velocity_to_rpm, TRACK_WIDTH


class TestLayer2IDS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ids = Layer2IDS.load()

    def setUp(self):
        self.ids.reset_filter()

    def test_feature_names(self):
        self.assertEqual(len(FEATURE_NAMES), 11)
        self.assertIn("yaw_residual", FEATURE_NAMES)
        self.assertIn("observed_yaw_rate", FEATURE_NAMES)
        self.assertIn("expected_yaw_rate", FEATURE_NAMES)

    def test_kalman_filter_steps(self):
        kf = RoverKalmanFilter(track_width=TRACK_WIDTH, dt=0.01)
        x_pred = kf.predict()
        self.assertEqual(x_pred.shape, (3, 1))

        # Update with straight driving measurements: v=0.5 m/s, yaw=0.0
        res = kf.update(v_left=0.5, v_right=0.5, a_imu=0.0, omega_imu=0.0)
        self.assertIn("fused_velocity", res)
        self.assertIn("fused_yaw_rate", res)
        self.assertIn("yaw_residual", res)
        self.assertAlmostEqual(res["expected_yaw_rate"], 0.0, places=4)
        self.assertAlmostEqual(res["yaw_residual"], 0.0, places=4)

    def test_extract_features(self):
        enc = {"fl_rpm": 120.0, "fr_rpm": 120.0, "rl_rpm": 120.0, "rr_rpm": 120.0}
        imu = {
            "accel_x": 0.0, "accel_y": 0.0, "accel_z": 9.81,
            "gyro_x": 0.0, "gyro_y": 0.0, "gyro_z": 0.0
        }
        feats = extract_features(enc, imu)
        for name in FEATURE_NAMES:
            self.assertIn(name, feats)

        # Straight driving: expected yaw rate and residual should be ~0
        self.assertAlmostEqual(feats["expected_yaw_rate"], 0.0, places=4)
        self.assertAlmostEqual(feats["yaw_residual"], 0.0, places=4)

    def test_normal_straight_driving(self):
        enc = {"fl_rpm": 150.0, "fr_rpm": 150.0, "rl_rpm": 150.0, "rr_rpm": 150.0}
        imu = {
            "accel_x": 0.02, "accel_y": 0.0, "accel_z": 9.81,
            "gyro_x": 0.0, "gyro_y": 0.0, "gyro_z": 0.01
        }
        res = self.ids.evaluate_state(enc, imu)
        self.assertEqual(res["prediction"], "NORMAL")
        self.assertLess(res["anomaly_score"], 0.5)
        self.assertIn("kalman_state", res)

    def test_normal_turning_left(self):
        # In a left turn: right wheels spin faster than left wheels
        v_left = 0.5 - (0.8 * TRACK_WIDTH / 2.0)
        v_right = 0.5 + (0.8 * TRACK_WIDTH / 2.0)
        rpm_l = velocity_to_rpm(v_left)
        rpm_r = velocity_to_rpm(v_right)

        enc = {"fl_rpm": rpm_l, "fr_rpm": rpm_r, "rl_rpm": rpm_l, "rr_rpm": rpm_r}
        imu = {
            "accel_x": 0.0, "accel_y": 0.4, "accel_z": 9.81,
            "gyro_x": 0.0, "gyro_y": 0.0, "gyro_z": 0.8  # matches wheel kinematics!
        }
        res = self.ids.evaluate_state(enc, imu)
        self.assertEqual(res["prediction"], "NORMAL")
        self.assertLess(res["anomaly_score"], 0.5)

    def test_normal_turning_right(self):
        # In a right turn: left wheels spin faster than right wheels
        v_left = 0.5 + (0.8 * TRACK_WIDTH / 2.0)
        v_right = 0.5 - (0.8 * TRACK_WIDTH / 2.0)
        rpm_l = velocity_to_rpm(v_left)
        rpm_r = velocity_to_rpm(v_right)

        enc = {"fl_rpm": rpm_l, "fr_rpm": rpm_r, "rl_rpm": rpm_l, "rr_rpm": rpm_r}
        imu = {
            "accel_x": 0.0, "accel_y": -0.4, "accel_z": 9.81,
            "gyro_x": 0.0, "gyro_y": 0.0, "gyro_z": -0.8  # matches wheel kinematics!
        }
        res = self.ids.evaluate_state(enc, imu)
        self.assertEqual(res["prediction"], "NORMAL")
        self.assertLess(res["anomaly_score"], 0.5)

    def test_attack_imu_yaw_spoof(self):
        # Wheels say straight driving, but IMU reports strong spin (+1.8 rad/s)
        enc = {"fl_rpm": 150.0, "fr_rpm": 150.0, "rl_rpm": 150.0, "rr_rpm": 150.0}
        imu = {
            "accel_x": 0.0, "accel_y": 0.0, "accel_z": 9.81,
            "gyro_x": 0.0, "gyro_y": 0.0, "gyro_z": 1.8  # physically impossible without wheel speed diff!
        }
        res = self.ids.evaluate_state(enc, imu)
        self.assertEqual(res["prediction"], "ANOMALY")
        self.assertGreaterEqual(res["anomaly_score"], 0.5)

    def test_attack_single_wheel_offset(self):
        # Wheel encoder attacked: FL reported 280 RPM while all other wheels report 120 RPM
        enc = {"fl_rpm": 280.0, "fr_rpm": 120.0, "rl_rpm": 120.0, "rr_rpm": 120.0}
        imu = {
            "accel_x": 0.0, "accel_y": 0.0, "accel_z": 9.81,
            "gyro_x": 0.0, "gyro_y": 0.0, "gyro_z": 0.0
        }
        res = self.ids.evaluate_state(enc, imu)
        self.assertEqual(res["prediction"], "ANOMALY")
        self.assertGreaterEqual(res["anomaly_score"], 0.5)

    def test_attack_side_offset(self):
        # Left side attacked: both FL and RL report 250 RPM, right side reports 100 RPM
        enc = {"fl_rpm": 250.0, "fr_rpm": 100.0, "rl_rpm": 250.0, "rr_rpm": 100.0}
        imu = {
            "accel_x": 0.0, "accel_y": 0.0, "accel_z": 9.81,
            "gyro_x": 0.0, "gyro_y": 0.0, "gyro_z": 0.0
        }
        res = self.ids.evaluate_state(enc, imu)
        self.assertEqual(res["prediction"], "ANOMALY")
        self.assertGreaterEqual(res["anomaly_score"], 0.5)


if __name__ == "__main__":
    unittest.main()
