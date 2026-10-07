"""Simulated encoders + MPU6050 for the CANARY rover.

Run:  python3 -m simulation.sensor_simulator   (from the parent folder)
  or: python3 sensor_simulator.py              (from inside simulation/)
"""
import random

try:
    from .vehicle_model import VehicleModel, velocity_to_rpm, rpm_to_velocity, TRACK_WIDTH
    from . import scenarios
except ImportError:  # running as a plain script
    from vehicle_model import VehicleModel, velocity_to_rpm, rpm_to_velocity, TRACK_WIDTH
    import scenarios

GRAVITY = 9.81

# Noise standard deviations (all configurable)
DEFAULT_NOISE = {
    "encoder_rpm": 1.5,     # RPM
    "accel": 0.05,          # m/s^2
    "gyro": 0.01,           # rad/s
    "accel_bias": 0.02,     # constant offset per axis (m/s^2)
    "gyro_bias": 0.003,     # constant offset per axis (rad/s)
}


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

        # fixed per-run sensor biases, like a real MPU6050
        g = self.rng.gauss
        self.accel_bias = [g(0, self.noise["accel_bias"]) for _ in range(3)]
        self.gyro_bias = [g(0, self.noise["gyro_bias"]) for _ in range(3)]

    def _encoders(self):
        v_left, v_right = self.vehicle.wheel_velocities()
        rpm_l = velocity_to_rpm(v_left)
        rpm_r = velocity_to_rpm(v_right)
        n = self.noise["encoder_rpm"]
        g = self.rng.gauss
        return {
            "fl_rpm": rpm_l + g(0, n),
            "fr_rpm": rpm_r + g(0, n),
            "rl_rpm": rpm_l + g(0, n),
            "rr_rpm": rpm_r + g(0, n),
        }

    def _imu(self):
        s = self.vehicle
        g = self.rng.gauss
        na, ng = self.noise["accel"], self.noise["gyro"]
        # body frame: x forward, y left, z up
        return {
            "accel_x": s.acceleration + self.accel_bias[0] + g(0, na),
            "accel_y": (s.velocity * s.yaw_rate) + self.accel_bias[1] + g(0, na),  # centripetal
            "accel_z": GRAVITY + self.accel_bias[2] + g(0, na),
            "gyro_x": self.gyro_bias[0] + g(0, ng),
            "gyro_y": self.gyro_bias[1] + g(0, ng),
            "gyro_z": s.yaw_rate + self.gyro_bias[2] + g(0, ng),
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

        sample = {
            "timestamp": round(self.time, 6),
            "scenario": scenario,  # extra label, handy for debugging
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

    hdr = "%6s %-10s | %6s %6s %6s | %7s %7s %7s %7s | %6s %6s %6s | %6s %6s"
    print(hdr % ("t", "scenario", "x", "y", "v", "fl", "fr", "rl", "rr",
                 "ax", "ay", "az", "gz", "encYaw"))
    for i in range(0, len(data), 50):  # one line every 0.5 s
        s = data[i]
        gt, e, m = s["ground_truth"], s["encoders"], s["imu"]
        print(hdr % (
            "%.2f" % s["timestamp"], s["scenario"],
            "%.2f" % gt["x"], "%.2f" % gt["y"], "%.2f" % gt["velocity"],
            "%.1f" % e["fl_rpm"], "%.1f" % e["fr_rpm"], "%.1f" % e["rl_rpm"], "%.1f" % e["rr_rpm"],
            "%.2f" % m["accel_x"], "%.2f" % m["accel_y"], "%.2f" % m["accel_z"],
            "%.2f" % m["gyro_z"], "%.2f" % expected_yaw_rate_from_encoders(e),
        ))
