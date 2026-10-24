# CANARY Security Operations Center (SOC) Dashboard

Real-time Cybersecurity Monitoring and Intrusion Detection System Dashboard for the CANARY Autonomous Vehicle Architecture.

## System Overview
CANARY is a multi-tier intrusion detection architecture for simulated vehicular ECUs exchanging 91-byte CAN-like messages over **ESP-NOW**:
- **Node 1 (Encoder ECU):** 4-wheel velocity reporting (`FL`, `FR`, `RL`, `RR`).
- **Node 2 (IMU ECU):** 6-DOF inertial measurements (`AX`, `AY`, `AZ`, `GX`, `GY`, `GZ`).
- **Node 4 (Security ECU):** Layer 1 cryptographic verifier (Ed25519 signature + BLAKE3 hash-tree freshness tokens + monotonic replay checks).
- **Dashboard (Host SOC):** Live serial ingestion, Layer 1 verifier telemetry, real-time Layer 2 AI-Aided Kalman Filter & Random Forest inference, and safe attack simulation.

---

## Features
1. **Live Serial Ingestion & Parsing:**
   - Asynchronous background thread reading Node 4 serial telemetry at 115200 baud without blocking the UI.
   - Parses real-time wheel RPM, IMU accelerations, angular rates, packet queues, and verify latencies.
2. **Layer 1 Cryptographic Status:**
   - Tracks verified packet streams and breaks down rejection root causes:
     - `REJECT untrusted sender` (e.g. Node 5 or unauthorized node ID)
     - `REJECT unknown/disallowed stream`
     - `REJECT bad signature` (Ed25519 failure)
     - `REJECT bad freshness` (BLAKE3 hash-tree mismatch)
     - `REJECT replay/stale epoch`
3. **Layer 2 AI-Aided Physical IDS:**
   - Fuses live wheel RPMs and IMU dynamics through a discrete-time **Rover Kalman Filter** to estimate forward velocity, yaw rate, and innovation residuals.
   - Evaluates the 11-feature state on a **100-tree Random Forest Classifier** to detect stealthy cyber-physical spoofing.
4. **Isolated Cyber-Physical Attack Injection Lab:**
   - Triggers hardware self-test routines on Node 4 over serial (`r`, `t`, `g`, `f`, `w`, `u`).
   - Simulates stealthy sensor spoofing and single-wheel offset attacks against the real ML model.
   - Safe test boundary: No synthetic attacks are ever transmitted to live actuators or the motor ECU.

---

## Setup & Launch Instructions

### 1. Requirements Installation
Ensure Python 3.10+ is available:
```bash
pip install -r requirements.txt
```

### 2. Launching the Dashboard
Launch the dashboard with Streamlit:
```bash
streamlit run dashboard/app.py
```

### 3. Connecting to Hardware
1. Connect Node 4 (Security ECU) to your computer via USB.
2. Open the sidebar under **Operational Mode** and select **LIVE HARDWARE**.
3. Select your serial port (e.g., `COM5` on Windows or `/dev/ttyUSB0` on Linux) and baud rate (`115200`).
4. Click **Connect**. The dashboard will immediately stream live telemetry and verifier counters.

### 5. Running Without Hardware (Demo Mode)
If hardware is disconnected:
1. Select **SIMULATION / DEMO** in the sidebar.
2. The dashboard will populate with realistic baseline vehicle telemetry.
3. Use the **Attack Simulation** tab to evaluate synthetic attacks against the real Random Forest model.

---

## Testing & Verification
Unit tests are included to verify Layer 2 Kalman filter fusion and the Random Forest model:
```bash
python tests/test_layer2.py
```
*(All 9 tests pass covering straight driving, differential turns, and multi-tier attacks).*
