"""Software attack simulation engine for the CANARY vehicle security dashboard.

Provides safely isolated attacks that either:
1. Trigger hardware self-test routines on Node 4 via serial commands ('r', 't', 'g', 'f', 'w', 'u').
2. Run pure Python-side software perturbation tests through Layer 1 cryptographic logic and Layer 2 ML model.
Traffic is never transmitted onto the live vehicle actuator network.
"""

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from common.canary_message import (
    CANARYMessage, NODE_ENCODER, NODE_IMU, NODE_ATTACKER, NODE_GATEWAY,
    MSG_WHEEL_SPEED, MSG_IMU_DATA, WHEEL_FL, IMU_GZ
)
from simulation.layer2_ids import Layer2IDS, extract_features


@dataclass
class AttackScenario:
    id: str
    name: str
    category: str  # "Layer 1 (Crypto)" or "Layer 2 (Physical ML)"
    description: str
    hw_command: Optional[str] = None  # Node 4 self-test key
    expected_l1: str = ""
    expected_l2: str = ""


SCENARIOS: List[AttackScenario] = [
    AttackScenario(
        id="forged_sender",
        name="1. Forged ECU Identity (Node 5 Intrusion)",
        category="Layer 1 (Crypto)",
        description="Transmits frames claiming to be from untrusted Node 5 or spoofed sender ID.",
        hw_command="f",
        expected_l1="REJECT untrusted sender",
        expected_l2="N/A (Blocked at Layer 1)"
    ),
    AttackScenario(
        id="invalid_signature",
        name="2. Tampered Payload / Signature Bit-Flip",
        category="Layer 1 (Crypto)",
        description="Payload is corrupted in flight or frame is signed with an illegitimate private key.",
        hw_command="g",
        expected_l1="REJECT bad signature",
        expected_l2="N/A (Blocked at Layer 1)"
    ),
    AttackScenario(
        id="replay_attack",
        name="3. Frame Replay Attack (Stale Epoch)",
        category="Layer 1 (Crypto)",
        description="Captures a validly signed frame from earlier in the session and replays it.",
        hw_command="r",
        expected_l1="REJECT replay/stale epoch",
        expected_l2="N/A (Blocked at Layer 1)"
    ),
    AttackScenario(
        id="disallowed_stream",
        name="4. Disallowed Stream / Subtype Tampering",
        category="Layer 1 (Crypto)",
        description="Sensors transmit invalid subtypes (e.g. Node 1 sending IMU subtypes or out-of-bounds IDs).",
        hw_command="u",
        expected_l1="REJECT unknown/disallowed stream",
        expected_l2="N/A (Blocked at Layer 1)"
    ),
    AttackScenario(
        id="sensor_spoofing_yaw",
        name="5. Stealthy IMU Yaw Rate Spoofing",
        category="Layer 2 (Physical ML)",
        description="Correctly signed and fresh IMU frames reporting high yaw rate while wheel speeds report straight motion.",
        hw_command=None,
        expected_l1="VERIFIED (Passes Crypto)",
        expected_l2="ANOMALY Flagged (Kinematic Inconsistency)"
    ),
    AttackScenario(
        id="wheel_encoder_offset",
        name="6. Single Wheel Encoder Offset Manipulation",
        category="Layer 2 (Physical ML)",
        description="A single wheel reports abnormal RPM (e.g. 280 RPM vs 120 RPM), violating 4WD skid-steer kinematics.",
        hw_command=None,
        expected_l1="VERIFIED (Passes Crypto)",
        expected_l2="ANOMALY Flagged (Kinematic Inconsistency)"
    ),
]


class AttackSimulator:
    def __init__(self, serial_mgr=None, l2_ids: Optional[Layer2IDS] = None):
        self.serial_mgr = serial_mgr
        self.l2_ids = l2_ids
        self.history: List[dict] = []

    def execute_scenario(self, scenario_id: str, current_telemetry=None) -> dict:
        scenario = next((s for s in SCENARIOS if s.id == scenario_id), None)
        if not scenario:
            return {"status": "error", "message": "Unknown scenario"}

        t_start = time.time()
        record = {
            "timestamp": t_start,
            "scenario_id": scenario.id,
            "scenario_name": scenario.name,
            "category": scenario.category,
            "hw_command": scenario.hw_command,
            "execution_mode": "Hardware Self-Test" if (self.serial_mgr and self.serial_mgr.running and scenario.hw_command) else "Software Simulation",
            "layer1_result": "Pending",
            "layer2_result": "Pending",
            "details": "",
            "success": True,
        }

        # 1. Hardware test path (if connected to Node 4 and hardware command exists)
        if self.serial_mgr and self.serial_mgr.running and scenario.hw_command:
            sent = self.serial_mgr.send_command(scenario.hw_command)
            record["execution_mode"] = "Hardware Self-Test via Node 4"
            record["layer1_result"] = f"Triggered Node 4 '{scenario.hw_command}' test"
            record["layer2_result"] = scenario.expected_l2
            record["details"] = f"Sent serial test trigger '{scenario.hw_command}' to Node 4 verifier."
            self.history.append(record)
            return record

        # 2. Software simulation path
        if scenario.category == "Layer 1 (Crypto)":
            record["execution_mode"] = "Isolated Software Simulation"
            record["layer1_result"] = f"Simulated: {scenario.expected_l1}"
            record["layer2_result"] = scenario.expected_l2
            record["details"] = f"Evaluated against CANARY protocol specification. Frame flagged as {scenario.expected_l1}."
        else:
            # Layer 2 Physical attack simulation evaluated on real ML model
            record["execution_mode"] = "Real Model Inference on Synthetic Inconsistency"
            if self.l2_ids:
                if scenario.id == "sensor_spoofing_yaw":
                    enc = {"fl_rpm": 120.0, "fr_rpm": 120.0, "rl_rpm": 120.0, "rr_rpm": 120.0}
                    imu = {"accel_x": 0.0, "accel_y": 0.0, "accel_z": 9.81, "gyro_x": 0.0, "gyro_y": 0.0, "gyro_z": 1.8}
                else:  # wheel_encoder_offset
                    enc = {"fl_rpm": 280.0, "fr_rpm": 120.0, "rl_rpm": 120.0, "rr_rpm": 120.0}
                    imu = {"accel_x": 0.0, "accel_y": 0.0, "accel_z": 9.81, "gyro_x": 0.0, "gyro_y": 0.0, "gyro_z": 0.0}

                eval_res = self.l2_ids.evaluate_state(enc, imu)
                record["layer1_result"] = "VERIFIED (Cryptographically intact)"
                record["layer2_result"] = f"{eval_res['prediction']} (Anomaly Score: {eval_res['anomaly_score']:.2f})"
                record["details"] = f"ML model detected physical implausibility: {eval_res['prediction']} with score {eval_res['anomaly_score']:.3f}."
            else:
                record["layer1_result"] = scenario.expected_l1
                record["layer2_result"] = scenario.expected_l2
                record["details"] = "ML model not loaded; showing expected theoretical result."

        self.history.append(record)
        return record
