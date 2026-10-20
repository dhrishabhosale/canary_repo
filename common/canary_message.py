"""CANARY Message Model and Protocol Constants for Python simulation & dashboard."""
from dataclasses import dataclass
from typing import Optional

# Node IDs
NODE_ENCODER = 1
NODE_IMU = 2
NODE_MOTOR = 3
NODE_SECURITY = 4
NODE_ATTACKER = 5
NODE_GATEWAY = 6

# Message Types
MSG_WHEEL_SPEED = 1
MSG_IMU_DATA = 2
MSG_MOTION_CMD = 3
MSG_MOTOR_ACK = 4

# Wheel Subtypes (0-3)
WHEEL_FL = 0
WHEEL_FR = 1
WHEEL_RL = 2
WHEEL_RR = 3

# IMU Subtypes (0-5)
IMU_AX = 0
IMU_AY = 1
IMU_AZ = 2
IMU_GX = 3
IMU_GY = 4
IMU_GZ = 5


@dataclass(frozen=True)
class CANARYMessage:
    sender_id: int
    msg_type: int
    subtype: int
    epoch: int
    payload: int
    freshness: Optional[bytes] = None
    signature: Optional[bytes] = None
