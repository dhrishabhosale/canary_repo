"""Kinematic Kalman Filter for CANARY 4WD Skid-Steer Rover.

Fuses 4-wheel encoder velocities and 6-DOF IMU (accelerometer + gyroscope)
into an optimal estimate of vehicle state:
  State Vector x = [v, omega, a]^T
    v: forward longitudinal velocity (m/s)
    omega: yaw rate / angular velocity around vertical axis (rad/s)
    a: forward longitudinal acceleration (m/s^2)

Measurement Vector z = [v_left, v_right, a_imu, omega_imu]^T
  v_left: average left-side wheel velocity (m/s)
  v_right: average right-side wheel velocity (m/s)
  a_imu: IMU longitudinal acceleration (m/s^2)
  omega_imu: IMU measured yaw rate (rad/s)
"""
import numpy as np

try:
    from .vehicle_model import TRACK_WIDTH, rpm_to_velocity
except ImportError:
    from vehicle_model import TRACK_WIDTH, rpm_to_velocity


class RoverKalmanFilter:
    """Discrete-time linear Kalman filter for skid-steer rover sensor fusion."""

    def __init__(self, track_width=TRACK_WIDTH, dt=0.01):
        self.W = float(track_width)
        self.dt = float(dt)

        # State vector x = [v, omega, a]^T
        self.x = np.zeros((3, 1), dtype=np.float64)

        # State covariance matrix P (initial uncertainty)
        self.P = np.diag([0.1, 0.1, 0.5]).astype(np.float64)

        # Process noise covariance Q (vehicle dynamics uncertainty)
        self.Q = np.diag([0.02, 0.05, 0.1]).astype(np.float64)

        # Measurement noise covariance R (sensor noise)
        # [v_left_noise, v_right_noise, accel_noise, gyro_noise]
        self.R = np.diag([0.01, 0.01, 0.05, 0.005]).astype(np.float64)

        # Measurement matrix H (maps state x -> measurement z)
        # v_left  = v - (W/2)*omega
        # v_right = v + (W/2)*omega
        # a_imu   = a
        # gz_imu  = omega
        self.H = np.array([
            [1.0, -self.W / 2.0, 0.0],
            [1.0,  self.W / 2.0, 0.0],
            [0.0,  0.0,          1.0],
            [0.0,  1.0,          0.0],
        ], dtype=np.float64)

        # Most recent innovation (residual) and innovation covariance
        self.y = np.zeros((4, 1), dtype=np.float64)
        self.S = np.zeros((4, 4), dtype=np.float64)
        self.K = np.zeros((3, 4), dtype=np.float64)

    def reset(self):
        """Reset state and covariance to initial stationary conditions."""
        self.x = np.zeros((3, 1), dtype=np.float64)
        self.P = np.diag([0.1, 0.1, 0.5]).astype(np.float64)
        self.y = np.zeros((4, 1), dtype=np.float64)

    def predict(self, dt=None):
        """State extrapolation (prediction step): x_{k|k-1} = F * x_{k-1}."""
        if dt is None:
            dt = self.dt

        # State transition matrix F
        # v_{k} = v_{k-1} + a_{k-1} * dt
        # omega_{k} = omega_{k-1}
        # a_{k} = a_{k-1}
        F = np.array([
            [1.0, 0.0, dt],
            [0.0, 1.0, 0.0],
            [0.0, 0.0, 1.0],
        ], dtype=np.float64)

        self.x = F @ self.x
        self.P = F @ self.P @ F.T + self.Q
        return self.x

    def update(self, v_left, v_right, a_imu, omega_imu):
        """Measurement update step: fuse encoders and IMU readings.

        Args:
            v_left: left-side wheel linear velocity (m/s)
            v_right: right-side wheel linear velocity (m/s)
            a_imu: IMU longitudinal acceleration (m/s^2)
            omega_imu: IMU observed yaw rate (rad/s)

        Returns:
            dict containing filtered states and innovation residuals.
        """
        z = np.array([[v_left], [v_right], [a_imu], [omega_imu]], dtype=np.float64)

        # Innovation: y = z - H * x_pred
        z_pred = self.H @ self.x
        self.y = z - z_pred

        # Innovation covariance: S = H * P * H^T + R
        self.S = self.H @ self.P @ self.H.T + self.R

        # Kalman gain: K = P * H^T * S^-1
        self.K = self.P @ self.H.T @ np.linalg.inv(self.S)

        # State update: x = x + K * y
        self.x = self.x + self.K @ self.y

        # Covariance update (Joseph form for numerical stability)
        I = np.eye(3, dtype=np.float64)
        IKH = I - self.K @ self.H
        self.P = IKH @ self.P @ IKH.T + self.K @ self.R @ self.K.T

        # Expected kinematic yaw rate from wheel speeds
        expected_yaw_rate = (v_right - v_left) / self.W
        yaw_residual = omega_imu - expected_yaw_rate

        return {
            "fused_velocity": float(self.x[0, 0]),
            "fused_yaw_rate": float(self.x[1, 0]),
            "fused_acceleration": float(self.x[2, 0]),
            "expected_yaw_rate": float(expected_yaw_rate),
            "observed_yaw_rate": float(omega_imu),
            "yaw_residual": float(yaw_residual),
            "innovation_yaw": float(self.y[3, 0]),
            "innovation_v_left": float(self.y[0, 0]),
            "innovation_v_right": float(self.y[1, 0]),
            "innovation_accel": float(self.y[2, 0]),
        }
