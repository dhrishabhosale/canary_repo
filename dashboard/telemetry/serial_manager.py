"""Thread-safe background serial reader and parser for CANARY Node 4 (Security ECU).

Reads serial telemetry from Node 4, parses both summary lines and verification events,
and maintains thread-safe rolling queues for UI consumption.
"""

import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False


@dataclass
class Node4Telemetry:
    timestamp: float = 0.0
    # Packet counters
    rx_total: int = 0
    bad_len: int = 0
    q_drops: int = 0
    verified: int = 0
    # Rejection counters
    rej_untrusted: int = 0
    rej_stream: int = 0
    rej_sig: int = 0
    rej_fresh: int = 0
    rej_replay: int = 0
    # Verification performance
    verify_avg_us: int = 0
    verify_max_us: int = 0
    # Node 1 wheel counters and RPM
    wheel_verified: Tuple[int, int, int, int] = (0, 0, 0, 0)
    wheel_rpm: Tuple[float, float, float, float] = (0.0, 0.0, 0.0, 0.0)
    # Node 2 IMU
    imu_verified: int = 0
    accel: Tuple[float, float, float] = (0.0, 0.0, 9.81)
    gyro: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    yaw_rate: float = 0.0
    # Status tracking
    node1_online: bool = False
    node2_online: bool = False
    last_update_mono: float = 0.0


@dataclass
class SecurityEvent:
    timestamp: float
    sender_id: int
    msg_type: int
    subtype: int
    epoch: int
    payload: int
    verdict: str  # "VERIFIED" or "REJECT ..."
    is_test: bool = False
    details: str = ""


class SerialTelemetryManager:
    """Manages background serial port connection and parses Node 4 output."""

    # Regex patterns matching Node 4 logs
    RX_PAT = re.compile(r'\[N4\]\s+rx=(\d+)\s+badLen=(\d+)\s+qDrops=(\d+)')
    VER_PAT = re.compile(
        r'\[N4\]\s+verified=(\d+)\s+\|\s+rejected:\s+untrusted=(\d+)\s+stream=(\d+)\s+sig=(\d+)\s+fresh=(\d+)\s+replay=(\d+)\s+\|\s+verify avg=(\d+)us\s+max=(\d+)us'
    )
    WHEEL_CNT_PAT = re.compile(r'\[N4\]\s+Node1 VERIFIED frames:\s+FL=(\d+)\s+FR=(\d+)\s+RL=(\d+)\s+RR=(\d+)')
    WHEEL_RPM_PAT = re.compile(
        r'\[N4\]\s+Wheel RPM \(verified\):\s+FL=([+-]?\d+\.?\d*)\s+FR=([+-]?\d+\.?\d*)\s+RL=([+-]?\d+\.?\d*)\s+RR=([+-]?\d+\.?\d*)'
    )
    IMU_CNT_PAT = re.compile(r'\[N4\]\s+Node2 IMU (?:VERIFIED|verified|UNVERIFIED) frames:\s+(\d+)')
    ACCEL_PAT = re.compile(r'\[N4\]\s+Accel \[m/s\^2\]\s+\([^)]+\):\s+X=([+-]?\d+\.?\d*)\s+Y=([+-]?\d+\.?\d*)\s+Z=([+-]?\d+\.?\d*)')
    GYRO_PAT = re.compile(
        r'\[N4\]\s+Gyro\s+\[rad/s\]\s+\([^)]+\):\s+X=([+-]?\d+\.?\d*)\s+Y=([+-]?\d+\.?\d*)\s+Z=([+-]?\d+\.?\d*)(?:\s+\(Yaw:\s+([+-]?\d+\.?\d*)\))?'
    )
    EVENT_PAT = re.compile(
        r'\[N4\](\[TEST\])?\s+(VERIFIED|REJECT\s+[^|]+?)\s+\|\s+sender=(\d+)\s+type=(\d+)\s+sub=(\d+)\s+epoch=(\d+)\s+payload=([+-]?\d+)'
    )

    def __init__(self, history_len: int = 300):
        self.history_len = history_len
        self.lock = threading.Lock()
        self.serial_port: Optional[serial.Serial] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self.connected_port: Optional[str] = None
        self.baudrate: int = 115200

        self.latest = Node4Telemetry()
        self.history = deque(maxlen=history_len)
        self.events = deque(maxlen=200)
        self.raw_logs = deque(maxlen=100)

        self._last_rx_count = 0
        self._last_n1_cnt = 0
        self._last_n2_cnt = 0

    @staticmethod
    def list_ports() -> List[str]:
        if not SERIAL_AVAILABLE:
            return []
        return [p.device for p in serial.tools.list_ports.comports()]

    def connect(self, port: str, baudrate: int = 115200) -> Tuple[bool, str]:
        if not SERIAL_AVAILABLE:
            return False, "pyserial is not installed"
        with self.lock:
            if self.running:
                return True, "Already connected"
            try:
                self.serial_port = serial.Serial(port, baudrate, timeout=1.0)
                self.connected_port = port
                self.baudrate = baudrate
                self.running = True
                self.thread = threading.Thread(target=self._read_loop, daemon=True)
                self.thread.start()
                return True, f"Connected to {port} @ {baudrate}"
            except Exception as e:
                self.serial_port = None
                self.running = False
                return False, f"Failed to connect: {e}"

    def disconnect(self):
        with self.lock:
            self.running = False
            if self.serial_port:
                try:
                    self.serial_port.close()
                except Exception:
                    pass
                self.serial_port = None
            self.connected_port = None

    def send_command(self, cmd: str) -> bool:
        with self.lock:
            if not self.serial_port or not self.running:
                return False
            try:
                self.serial_port.write(cmd.encode("ascii"))
                self.serial_port.flush()
                return True
            except Exception:
                return False

    def get_snapshot(self) -> Tuple[Node4Telemetry, List[dict], List[SecurityEvent], List[str]]:
        with self.lock:
            snap = Node4Telemetry(**self.latest.__dict__)
            hist = list(self.history)
            evts = list(self.events)
            logs = list(self.raw_logs)
            # check stale
            if time.monotonic() - snap.last_update_mono > 3.0:
                snap.node1_online = False
                snap.node2_online = False
            return snap, hist, evts, logs

    def _read_loop(self):
        buf = ""
        while self.running:
            try:
                if not self.serial_port:
                    break
                raw = self.serial_port.read(self.serial_port.in_waiting or 1)
                if not raw:
                    continue
                buf += raw.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip("\r").strip()
                    if line:
                        self._parse_line(line)
            except Exception as e:
                time.sleep(0.1)
                if not self.running:
                    break

    def _parse_line(self, line: str):
        now = time.time()
        now_mono = time.monotonic()

        with self.lock:
            self.raw_logs.append(line)

            # Check individual event verdict
            m_evt = self.EVENT_PAT.search(line)
            if m_evt:
                is_test = bool(m_evt.group(1))
                verdict = m_evt.group(2).strip()
                s_id = int(m_evt.group(3))
                m_type = int(m_evt.group(4))
                sub = int(m_evt.group(5))
                epoch = int(m_evt.group(6))
                payload = int(m_evt.group(7))
                evt = SecurityEvent(
                    timestamp=now,
                    sender_id=s_id,
                    msg_type=m_type,
                    subtype=sub,
                    epoch=epoch,
                    payload=payload,
                    verdict=verdict,
                    is_test=is_test,
                    details=line,
                )
                self.events.append(evt)

            # Match summary blocks
            m_rx = self.RX_PAT.search(line)
            if m_rx:
                self.latest.rx_total = int(m_rx.group(1))
                self.latest.bad_len = int(m_rx.group(2))
                self.latest.q_drops = int(m_rx.group(3))
                self.latest.last_update_mono = now_mono

            m_ver = self.VER_PAT.search(line)
            if m_ver:
                self.latest.verified = int(m_ver.group(1))
                self.latest.rej_untrusted = int(m_ver.group(2))
                self.latest.rej_stream = int(m_ver.group(3))
                self.latest.rej_sig = int(m_ver.group(4))
                self.latest.rej_fresh = int(m_ver.group(5))
                self.latest.rej_replay = int(m_ver.group(6))
                self.latest.verify_avg_us = int(m_ver.group(7))
                self.latest.verify_max_us = int(m_ver.group(8))
                self.latest.last_update_mono = now_mono

            m_wcnt = self.WHEEL_CNT_PAT.search(line)
            if m_wcnt:
                w_cnt = (
                    int(m_wcnt.group(1)),
                    int(m_wcnt.group(2)),
                    int(m_wcnt.group(3)),
                    int(m_wcnt.group(4)),
                )
                self.latest.wheel_verified = w_cnt
                if sum(w_cnt) > self._last_n1_cnt:
                    self.latest.node1_online = True
                    self._last_n1_cnt = sum(w_cnt)
                self.latest.last_update_mono = now_mono

            m_wrpm = self.WHEEL_RPM_PAT.search(line)
            if m_wrpm:
                self.latest.wheel_rpm = (
                    float(m_wrpm.group(1)),
                    float(m_wrpm.group(2)),
                    float(m_wrpm.group(3)),
                    float(m_wrpm.group(4)),
                )
                self.latest.node1_online = True
                self.latest.last_update_mono = now_mono

            m_icnt = self.IMU_CNT_PAT.search(line)
            if m_icnt:
                cnt = int(m_icnt.group(1))
                self.latest.imu_verified = cnt
                if cnt > self._last_n2_cnt:
                    self.latest.node2_online = True
                    self._last_n2_cnt = cnt
                self.latest.last_update_mono = now_mono

            m_acc = self.ACCEL_PAT.search(line)
            if m_acc:
                self.latest.accel = (
                    float(m_acc.group(1)),
                    float(m_acc.group(2)),
                    float(m_acc.group(3)),
                )
                self.latest.node2_online = True
                self.latest.last_update_mono = now_mono

            m_gyr = self.GYRO_PAT.search(line)
            if m_gyr:
                gx = float(m_gyr.group(1))
                gy = float(m_gyr.group(2))
                gz = float(m_gyr.group(3))
                yaw = float(m_gyr.group(4)) if m_gyr.group(4) else gz
                self.latest.gyro = (gx, gy, gz)
                self.latest.yaw_rate = yaw
                self.latest.node2_online = True
                self.latest.last_update_mono = now_mono

                # Commit a point to rolling time-series history
                self.latest.timestamp = now
                hist_entry = {
                    "time": now,
                    "rx_total": self.latest.rx_total,
                    "verified": self.latest.verified,
                    "fl_rpm": self.latest.wheel_rpm[0],
                    "fr_rpm": self.latest.wheel_rpm[1],
                    "rl_rpm": self.latest.wheel_rpm[2],
                    "rr_rpm": self.latest.wheel_rpm[3],
                    "accel_x": self.latest.accel[0],
                    "accel_y": self.latest.accel[1],
                    "accel_z": self.latest.accel[2],
                    "gyro_x": self.latest.gyro[0],
                    "gyro_y": self.latest.gyro[1],
                    "gyro_z": self.latest.gyro[2],
                    "yaw_rate": self.latest.yaw_rate,
                }
                self.history.append(hist_entry)
