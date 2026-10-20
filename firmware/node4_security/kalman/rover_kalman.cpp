#include "rover_kalman.h"
#include <math.h>
#include <string.h>

RoverKalmanFilter::RoverKalmanFilter(float track_width, float dt)
    : track_width(track_width), default_dt(dt), expected_yaw(0.0f), yaw_residual(0.0f) {
    reset();
}

void RoverKalmanFilter::reset() {
    x[0] = 0.0f; // v
    x[1] = 0.0f; // omega
    x[2] = 0.0f; // a

    memset(P, 0, sizeof(P));
    P[0][0] = 0.1f;
    P[1][1] = 0.1f;
    P[2][2] = 0.5f;

    memset(Q, 0, sizeof(Q));
    Q[0][0] = 0.02f;
    Q[1][1] = 0.05f;
    Q[2][2] = 0.1f;

    R[0] = 0.01f;  // v_left
    R[1] = 0.01f;  // v_right
    R[2] = 0.05f;  // a_imu
    R[3] = 0.005f; // omega_imu

    expected_yaw = 0.0f;
    yaw_residual = 0.0f;
}

void RoverKalmanFilter::predict(float dt) {
    if (dt <= 0.0f) dt = default_dt;

    // x_{k|k-1}:
    // v = v + a * dt
    x[0] += x[2] * dt;
    // omega = omega
    // a = a

    // P = F * P * F^T + Q
    // F = [1, 0, dt; 0, 1, 0; 0, 0, 1]
    float p00 = P[0][0] + dt * (P[2][0] + P[0][2] + dt * P[2][2]) + Q[0][0];
    float p01 = P[0][1] + dt * P[2][1];
    float p02 = P[0][2] + dt * P[2][2];

    float p10 = P[1][0] + dt * P[1][2];
    float p11 = P[1][1] + Q[1][1];
    float p12 = P[1][2];

    float p20 = P[2][0] + dt * P[2][2];
    float p21 = P[2][1];
    float p22 = P[2][2] + Q[2][2];

    P[0][0] = p00; P[0][1] = p01; P[0][2] = p02;
    P[1][0] = p10; P[1][1] = p11; P[1][2] = p12;
    P[2][0] = p20; P[2][1] = p21; P[2][2] = p22;
}

float RoverKalmanFilter::update(float v_left, float v_right, float a_imu, float omega_imu) {
    float half_w = track_width / 2.0f;

    // Predicted measurements:
    float z0_pred = x[0] - half_w * x[1]; // v_left
    float z1_pred = x[0] + half_w * x[1]; // v_right
    float z2_pred = x[2];                 // a_imu
    float z3_pred = x[1];                 // omega_imu

    // Innovations (y = z - z_pred):
    float y0 = v_left - z0_pred;
    float y1 = v_right - z1_pred;
    float y2 = a_imu - z2_pred;
    float y3 = omega_imu - z3_pred;

    expected_yaw = (v_right - v_left) / track_width;
    yaw_residual = omega_imu - expected_yaw;

    // Measurement update using sequential scalar updates for speed & zero matrix inversion
    // Measurement 0: v_left (H = [1, -half_w, 0])
    {
        float s = P[0][0] - 2.0f * half_w * P[0][1] + half_w * half_w * P[1][1] + R[0];
        if (s > 1e-6f) {
            float k0 = (P[0][0] - half_w * P[0][1]) / s;
            float k1 = (P[1][0] - half_w * P[1][1]) / s;
            float k2 = (P[2][0] - half_w * P[2][1]) / s;

            x[0] += k0 * y0;
            x[1] += k1 * y0;
            x[2] += k2 * y0;
        }
    }

    // Measurement 1: v_right (H = [1, +half_w, 0])
    {
        float s = P[0][0] + 2.0f * half_w * P[0][1] + half_w * half_w * P[1][1] + R[1];
        if (s > 1e-6f) {
            float k0 = (P[0][0] + half_w * P[0][1]) / s;
            float k1 = (P[1][0] + half_w * P[1][1]) / s;
            float k2 = (P[2][0] + half_w * P[2][1]) / s;

            x[0] += k0 * y1;
            x[1] += k1 * y1;
            x[2] += k2 * y1;
        }
    }

    // Measurement 2: a_imu (H = [0, 0, 1])
    {
        float s = P[2][2] + R[2];
        if (s > 1e-6f) {
            float k0 = P[0][2] / s;
            float k1 = P[1][2] / s;
            float k2 = P[2][2] / s;

            x[0] += k0 * y2;
            x[1] += k1 * y2;
            x[2] += k2 * y2;
        }
    }

    // Measurement 3: omega_imu (H = [0, 1, 0])
    {
        float s = P[1][1] + R[3];
        if (s > 1e-6f) {
            float k0 = P[0][1] / s;
            float k1 = P[1][1] / s;
            float k2 = P[2][1] / s;

            x[0] += k0 * y3;
            x[1] += k1 * y3;
            x[2] += k2 * y3;
        }
    }

    return yaw_residual;
}
