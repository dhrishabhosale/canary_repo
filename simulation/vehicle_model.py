"""Ground-truth model of a 4-wheel skid-steer rover (2D kinematics)."""
import math

WHEEL_DIAMETER = 0.080  # m
TRACK_WIDTH = 0.180     # m
WHEEL_RADIUS = WHEEL_DIAMETER / 2.0


def rpm_to_velocity(rpm):
    """Wheel RPM -> wheel linear velocity (m/s)."""
    return rpm * 2.0 * math.pi * WHEEL_RADIUS / 60.0


def velocity_to_rpm(v):
    """Wheel linear velocity (m/s) -> RPM."""
    return v * 60.0 / (2.0 * math.pi * WHEEL_RADIUS)


class VehicleModel:
    def __init__(self):
        self.x = 0.0
        self.y = 0.0
        self.yaw = 0.0           # rad, 0 = +x axis, CCW positive
        self.velocity = 0.0      # m/s forward
        self.acceleration = 0.0  # m/s^2 forward
        self.yaw_rate = 0.0      # rad/s, CCW positive

    def step(self, dt, target_accel, target_yaw_rate, max_speed=1.0):
        """Advance the state by dt using commanded accel and yaw rate."""
        new_v = self.velocity + target_accel * dt
        # clamp speed to [0, max_speed]
        new_v = max(0.0, min(max_speed, new_v))
        self.acceleration = (new_v - self.velocity) / dt
        self.velocity = new_v
        self.yaw_rate = target_yaw_rate

        self.yaw += self.yaw_rate * dt
        self.x += self.velocity * math.cos(self.yaw) * dt
        self.y += self.velocity * math.sin(self.yaw) * dt

    def wheel_velocities(self):
        """Return (v_left, v_right) in m/s from the skid-steer relationship."""
        v_left = self.velocity - self.yaw_rate * TRACK_WIDTH / 2.0
        v_right = self.velocity + self.yaw_rate * TRACK_WIDTH / 2.0
        return v_left, v_right

    def state(self):
        return {
            "x": self.x,
            "y": self.y,
            "yaw": self.yaw,
            "velocity": self.velocity,
            "acceleration": self.acceleration,
            "yaw_rate": self.yaw_rate,
        }
