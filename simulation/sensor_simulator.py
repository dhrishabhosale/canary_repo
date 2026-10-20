"""Simulated encoders + MPU6050 for the CANARY rover with attack injection support.

Run:  python3 -m simulation.sensor_simulator   (from the parent folder)
  or: python3 sensor_simulator.py              (from inside simulation/)
"""
import random
import math

try:
    from .vehicle_model import VehicleModel, velocity_to_rpm, rpm_to_velocity, TRACK_WIDTH
    from . import scenarios
except ImportError:  # running as a plain script
    from vehicle_model import VehicleModel, velocity_to_rpm, rpm_to_velocity, TRACK_WIDTH
    import scenarios

GRAVITY = 9.81

# Physical attack constants
ATTACK_IMU_YAW_OFFSET = "imu_yaw_offset"
ATTACK_WHEEL_OFFSET = "wheel_offset"
ATTACK_SIDE_OFFSET = "side_offset"

# Noise standard deviations (all configurable)
DEFAULT_NOISE = {
    "encoder_rpm": 1.5,     # RPM
    "accel": 0.05,          # m/s^2
    "gyro": 0.01,           # rad/s
    "accel_bias": 0.02,     # constant offset per axis (m/s^2)
    "gyro_bias": 0.003,     # constant offset per axis (rad/s)
}


class PhysicalAttack:
    """Represents a physical sensor perturbation injected into the simulation."""
    def __init__(self, kind, value, target=None, t_start=0.0, t_end=float("inf")):
        self.kind = kind
        self.value = value
        self.target = target
        self.t_start = t_start
        self.t_end = t_end

    def is_active(self, t):
        return self.t_start <= t <= self.t_end


class SensorSimulator:
    def __init__(self, dt=0.01, noise=None, timeline=None, seed=None):
        self.dt = dt
        self.noise = dict(DEFAULT_NOISE)
        if noise:
            self.noise.update(noise)
        self.timeline = timeline or scenarios.DEFAULT_TIMELINE
        self.rng = random.Random(seed)
        self.vehicle = VehicleModel()
        self.time = 0.0
        self.attack = None

        # fixed per-run sensor biases, like a real MPU6050
        g = self.rng.gauss
        self.accel_bias = [g(0, self.noise["accel_bias"]) for _ in range(3)]
        self.gyro_bias = [g(0, self.noise["gyro_bias"]) for _ in range(3)]

    def set_attack(self, attack):
        self.attack = attack

    def clear_attack(self):
        self.attack = None

    def _encoders(self):
        v_left, v_right = self.vehicle.wheel_velocities()
        rpm_l = velocity_to_rpm(v_left)
        rpm_r = velocity_to_rpm(v_right)
        n = self.noise["encoder_rpm"]
        g = self.rng.gauss

        fl = rpm_l + g(0, n)
        fr = rpm_r + g(0, n)
        rl = rpm_l + g(0, n)
        rr = rpm_r + g(0, n)

        # Apply attack if active
        if self.attack and self.attack.is_active(self.time):
            if self.attack.kind == ATTACK_WHEEL_OFFSET:
                target = self.attack.target or "fl"
                if target == "fl": fl += self.attack.value
                elif target == "fr": fr += self.attack.value
                elif target == "rl": rl += self.attack.value
                elif target == "rr": rr += self.attack.value
            elif self.attack.kind == ATTACK_SIDE_OFFSET:
                target = self.attack.target or "left"
                if target == "left":
                    fl += self.attack.value
                    rl += self.attack.value
                elif target == "right":
                    fr += self.attack.value
                    rr += self.attack.value

        return {
            "fl_rpm": fl,
            "fr_rpm": fr,
            "rl_rpm": rl,
            "rr_rpm": rr,
        }

    def _imu(self):
        s = self.vehicle
        g = self.rng.gauss
        na, ng = self.noise["accel"], self.noise["gyro"]
        gz = s.yaw_rate + self.gyro_bias[2] + g(0, ng)

        # Apply attack if active
        if self.attack and self.attack.is_active(self.time):
            if self.attack.kind == ATTACK_IMU_YAW_OFFSET:
                gz += self.attack.value

        return {
            "accel_x": s.acceleration + self.accel_bias[0] + g(0, na),
            "accel_y": (s.velocity * s.yaw_rate) + self.accel_bias[1] + g(0, na),  # centripetal
            "accel_z": GRAVITY + self.accel_bias[2] + g(0, na),
            "gyro_x": self.gyro_bias[0] + g(0, ng),
            "gyro_y": self.gyro_bias[1] + g(0, ng),
            "gyro_z": gz,
        }

    def _scenario_at(self, t):
        elapsed = 0.0
        for name, duration in self.timeline:
            elapsed += duration
            if t < elapsed:
                return name
        return self.timeline[-1][0]

    def step(self):
        """Advance one timestep and return one sample dict."""
        scenario = self._scenario_at(self.time)
        accel, yaw_rate = scenarios.get_command(scenario, self.vehicle.velocity)
        self.vehicle.step(self.dt, accel, yaw_rate)

        active_attack = self.attack.kind if (self.attack and self.attack.is_active(self.time)) else None

        sample = {
            "timestamp": round(self.time, 6),
            "scenario": scenario,
            "attack": active_attack,
            "ground_truth": self.vehicle.state(),
            "encoders": self._encoders(),
            "imu": self._imu(),
        }
        self.time += self.dt
        return sample

    def run(self, duration):
        n = int(round(duration / self.dt))
        return [self.step() for _ in range(n)]

    def total_duration(self):
        return sum(d for _, d in self.timeline)


def expected_yaw_rate_from_encoders(enc):
    """yaw_rate = (v_right - v_left) / track_width, using avg left/right wheels."""
    v_left = rpm_to_velocity((enc["fl_rpm"] + enc["rl_rpm"]) / 2.0)
    v_right = rpm_to_velocity((enc["fr_rpm"] + enc["rr_rpm"]) / 2.0)
    return (v_right - v_left) / TRACK_WIDTH


if __name__ == "__main__":
    sim = SensorSimulator(dt=0.01, seed=42)
    data = sim.run(sim.total_duration())
    print("Generated %d samples (%.1f s @ %d Hz)\n" % (len(data), sim.total_duration(), round(1 / sim.dt)))
