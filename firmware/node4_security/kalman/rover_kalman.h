#ifndef ROVER_KALMAN_H
#define ROVER_KALMAN_H

#include <stdint.h>

/**
 * 4WD Skid-Steer Rover Kinematic Kalman Filter for ESP32 (Node 4 Security ECU).
 *
 * State Vector:
 *   x[0] = v (forward velocity, m/s)
 *   x[1] = omega (yaw rate, rad/s)
 *   x[2] = a (longitudinal acceleration, m/s^2)
 *
 * Fuses wheel encoders (left/right) with IMU (accel_x, gyro_z).
 */
class RoverKalmanFilter {
public:
    RoverKalmanFilter(float track_width = 0.180f, float dt = 0.01f);

    void reset();
    void predict(float dt = -1.0f);

    // Updates state with sensor measurements.
    // Returns the yaw residual (omega_imu - expected_yaw).
    float update(float v_left, float v_right, float a_imu, float omega_imu);

    float getVelocity() const { return x[0]; }
    float getYawRate() const { return x[1]; }
    float getAcceleration() const { return x[2]; }
    float getExpectedYawRate() const { return expected_yaw; }
    float getYawResidual() const { return yaw_residual; }

private:
    float track_width;
    float default_dt;

    float x[3];       // State vector
    float P[3][3];    // State covariance
    float Q[3][3];    // Process noise covariance
    float R[4];       // Measurement noise variances

    float expected_yaw;
    float yaw_residual;
};

#endif // ROVER_KALMAN_H
