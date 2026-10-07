"""Driving scenarios. Each returns (target_accel m/s^2, target_yaw_rate rad/s)."""

STOP = "STOP"
FORWARD = "FORWARD"
ACCELERATE = "ACCELERATE"
DECELERATE = "DECELERATE"
TURN_LEFT = "TURN_LEFT"
TURN_RIGHT = "TURN_RIGHT"

ACCEL_RATE = 0.5      # m/s^2
DECEL_RATE = -0.8     # m/s^2
TURN_RATE = 0.8       # rad/s (left = +, right = -)


def get_command(scenario, velocity):
    """Return (accel, yaw_rate) for the given scenario at the current speed."""
    if scenario == STOP:
        # brake to zero if still moving
        return (-1.5 if velocity > 0.0 else 0.0), 0.0
    if scenario == FORWARD:
        return 0.0, 0.0
    if scenario == ACCELERATE:
        return ACCEL_RATE, 0.0
    if scenario == DECELERATE:
        return DECEL_RATE, 0.0
    if scenario == TURN_LEFT:
        return 0.0, TURN_RATE
    if scenario == TURN_RIGHT:
        return 0.0, -TURN_RATE
    raise ValueError("Unknown scenario: " + str(scenario))


# Default demo timeline: (scenario, duration in seconds) -> 10 s total
DEFAULT_TIMELINE = [
    (STOP, 1.0),
    (ACCELERATE, 2.0),
    (FORWARD, 2.0),
    (TURN_LEFT, 1.5),
    (FORWARD, 1.0),
    (TURN_RIGHT, 1.0),
    (DECELERATE, 1.0),
    (STOP, 0.5),
]
