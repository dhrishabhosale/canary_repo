# CANARY: Layered Intrusion Detection for Networked Cyber-Physical Systems

**Synchron’26 — Sensor Technology Expo**  
**School of Electrical Engineering, Manipal Institute of Technology, Manipal**  
**Final Mini Project Report**  

**Presentation Date:** 24 October 2026  
**Team Name:** Canary  
**Team Number:** 505  
**Team Members & Registration IDs:**  
- **Dhrisha Bhosale** — Reg. ID: `251090610214`  
- **Sharanya Bhatia** — Reg. ID: `251090610202`  
- **Kunjal Bhatia** — Reg. ID: `251090610350`  

**Repository Reference:** [https://github.com/dhrishabhosale/canary_repo](https://github.com/dhrishabhosale/canary_repo)  
**Release Commit Hash:** `e94c26c749cbb44e80403d157070991d0c60910f`  

---

## Abstract
Modern vehicular and industrial cyber-physical systems increasingly connect Electronic Control Units (ECUs) over shared bus networks. However, legacy protocols lack built-in cryptographic origin authentication and physical anomaly detection, leaving them vulnerable to message injection, spoofing, and replay attacks. CANARY is a multi-tier, hardware-validated intrusion detection testbed implemented on an untethered 4-wheel-drive skid-steer robotic platform. The architecture separates message-level cryptographic authentication (Layer 1) from kinematic plausibility verification (Layer 2). 

Layer 1 operates on embedded ESP32 nodes using Monocypher Ed25519 digital signatures and BLAKE3-derived hash-tree freshness tokens over a fixed 91-byte CAN-like application frame transmitted via ESP-NOW on Wi-Fi Channel 1. Hardware measurements confirm embedded verification times between $24{,}500\,\mu\text{s}$ and $26{,}350\,\mu\text{s}$ with zero dropped frames under nominal 20 Hz telemetry rates. Layer 2 executes physics-informed anomaly detection by feeding 4-wheel odometry and 6-DOF IMU dynamics into a discrete-time kinematic Rover Kalman Filter, generating 11-dimensional innovation residuals evaluated by a 100-tree Random Forest classifier ($<50\,\mu\text{s}$ inference time). Telemetry is streamed wirelessly via UDP port 8888 from an onboard SoftAP to a live Security Operations Center (SOC) dashboard. The system successfully demonstrates defense-in-depth against malicious tampering, stale replays, and stealthy sensor spoofing.

**Keywords:** Automotive Cybersecurity, Electronic Control Units (ECU), Intrusion Detection System (IDS), Ed25519 Digital Signatures, BLAKE3 Freshness Trees, Kalman State Estimation, Random Forest Classifier, ESP-NOW.

---

## 1. Introduction

### 1.1 Background
Modern passenger and commercial vehicles deploy dozens to over a hundred interconnected Electronic Control Units (ECUs) communicating across Controller Area Networks (CAN). Historically designed as closed, air-gapped physical buses prioritizing deterministic arbitration and low bus utilization, automotive bus protocols lack native cryptographic authentication, message freshness guarantees, and origin verification. With the introduction of telematics, wireless diagnostics, over-the-air (OTA) updates, and V2X infrastructure, the vehicular physical network has become exposed to remote and physical threat vectors. Compromising an unauthenticated bus allows attackers to forge wheel-speed signals, inject falsified inertial measurements, or trigger unintended braking and steering interventions.

### 1.2 Motivation
A robust vehicular defense architecture requires *defense-in-depth*. Cryptographic verification alone cannot detect an attack if a legitimate ECU is physically compromised or sensor hardware is maliciously manipulated at the transducer level (e.g., magnetic sensor spoofing). Conversely, behavioral and machine-learning anomaly detectors struggle with high false-positive rates when vehicle dynamics undergo violent legitimate maneuvers, such as aggressive braking, drifting, or traversing severe potholes. 

CANARY investigates a layered defense paradigm:
1. **Layer 1 (Cryptographic Authenticity & Freshness):** Rejects unauthorized senders, disallowed data streams, tampered payloads, and replayed messages at the packet wire level using Ed25519 signatures and BLAKE3 hash trees.
2. **Layer 2 (Kinematic Behavioral Consistency):** Fuses cross-sensor physical dynamics (wheel rotational speeds vs. 6-DOF inertial rates) through a discrete-time Kalman filter to extract kinematic innovation residuals. A Random Forest classifier evaluates these residuals in real time to detect physical anomalies without being deceived by legitimate vehicle turns.

```
+-------------------------------------------------------------------------+
|                        CANARY DEFENSE PIPELINE                          |
+-------------------------------------------------------------------------+
|                                                                         |
|  [Layer 1: Cryptographic Verifier] (Onboard Node 4 Security ECU)        |
|    - Wire Validation (Fixed 91 bytes)                                   |
|    - Allowlisted Sender Check (Node 1, Node 2)                          |
|    - Ed25519 Digital Signature Verification (Monocypher)                |
|    - BLAKE3 Multi-Tier Hash-Tree Freshness & Anti-Replay Tokens         |
|                                                                         |
|                                  | (Verified Authentic Wire Telemetry)  |
|                                  v                                      |
|                                                                         |
|  [Layer 2: Kinematic AI Anomaly Engine] (Real-Time SOC Dashboard)       |
|    - Skid-Steer Rover Kinematic Model Fusing Wheel Speeds & IMU         |
|    - Discrete-Time Kalman State Estimator & Innovation Residuals        |
|    - 11-Dimensional Kinematic Feature Space Extraction                  |
|    - 100-Tree Random Forest Classifier (<50 us Edge Inference)          |
|    - Real-Time Cyber-Physical Anomaly Score (0.00 to 1.00)              |
|                                                                         |
+-------------------------------------------------------------------------+
```

### 1.3 Scope Boundaries & Clarifications
To maintain rigorous technical integrity, the operational boundaries of this prototype are established as follows:
- **Radio & Bus Transport:** Prototype nodes communicate using **ESP-NOW** at 2.4 GHz locked strictly to **Wi-Fi Channel 1**. The software models automotive CAN message arbitration, identifiers, and telemetry semantics, but **does not** utilize physical 120 $\Omega$ differential twisted-pair automotive transceivers (ISO 11898-2) or physical CAN-FD arbitration.
- **Physical Nodes:** The active physical testbed consists of:
  - **Node 1:** Wheel Encoder ECU.
  - **Node 2:** 6-DOF IMU ECU.
  - **Node 4:** Security & IDS Verifier ECU (hosts Layer 1 and Wi-Fi telemetry bridge).
  - Node 5 (physical attacker node) and Node 6 (retired gateway identity) are eliminated from live vehicular transmission; attacks are triggered via controlled software injection and serial/UDP self-tests to ensure zero hazardous interference with live actuators.
- **Actuation Boundary:** Motor drive signals originate from safe control channels isolated from experimental injection routines to guarantee track safety.

---

## 2. Problem Statement and Objectives

### 2.1 Problem Statement
*How can an embedded multi-node cyber-physical vehicular architecture reliably prevent packet spoofing, tampering, and stale replay attacks at the network layer while simultaneously detecting physics-violating sensor deception attacks at the supervisory layer—without introducing prohibitive verification latencies or false alarms during aggressive driving maneuvers?*

### 2.2 Measurable Objectives
The project establishes seven quantifiable technical objectives:

| ID | Stated Objective | Metric / Target Threshold | Measured Outcome & Evidence Status |
| :--- | :--- | :--- | :--- |
| **O1** | Message Authentication | 100% cryptographic acceptance of valid Ed25519 signatures; 0% false rejections. | **MET.** 32,618+ consecutive frames verified on hardware with zero valid-frame rejections. |
| **O2** | Anti-Replay & Freshness | Reject 100% of replayed or stale epoch frames via BLAKE3 hash-tree tokens. | **MET.** 9/9 deterministic freshness tests passed; hardware test key `'r'` triggers instant rejection. |
| **O3** | Untrusted Sender Immunity | Immediate drop of unauthorized nodes (e.g., Node 5 attacker identity). | **MET.** 146/146 host tests passed; hardware test key `'f'` triggers `REJECT untrusted sender`. |
| **O4** | Layer 2 Kinematic Anomaly Detection | Distinguish legitimate vehicle turns from asymmetric wheel spoofing. | **MET.** 14/14 unit tests passed; Random Forest anomaly score rises from 0.02 (nominal) to 0.98 during injection. |
| **O5** | Untethered Track Operation | Continuous telemetry transmission on a moving vehicle without physical cables. | **MET.** Node 4 SoftAP (`CANARY_HOTSPOT`) broadcast over UDP port 8888 on Channel 1 up to 100+ meters. |
| **O6** | Embedded Latency & Throughput | Verification latency $<35\,\text{ms}$; 20 Hz continuous frame throughput. | **MET.** Average embedded verification latency measured at **$24{,}500\,\mu\text{s}$ – $26{,}350\,\mu\text{s}$** ($~25\,\text{ms}$) per packet. |
| **O7** | Automotive Standards Gap Analysis | Document technical compliance and gaps against Bureau of Indian Standards (BIS). | **MET.** Comprehensive audit completed across IS 14700 (EMC) and IS 9000 (Environmental). |

---

## 3. System Requirements

### 3.1 Functional Requirements
- **FR-01 (Sensor Acquisition):** Node 1 must capture 4-wheel rotation via hardware interrupts on GPIO pins 18, 19, 25, and 26 at 20 Hz. Node 2 must sample 3-axis acceleration and 3-axis angular velocity from the MPU-6050 over I2C at 20 Hz.
- **FR-02 (Fixed Wire Formatting):** Sensor payloads must be serialized into a strict 91-byte struct (`canary_message_t`) comprising a 27-byte body and a 64-byte Ed25519 signature.
- **FR-03 (Cryptographic Signing):** Origin ECUs must generate Monocypher Ed25519 signatures using provisioned 32-byte secret keys derived from immutable seeds.
- **FR-04 (Freshness Derivation):** Message bodies must incorporate a 16-byte BLAKE3 freshness token derived from an epoch counter and tree seed.
- **FR-05 (Deterministic Verification):** Node 4 must verify message origin, stream allowlists, signatures, and freshness in under 35 ms before updating internal vehicle state.
- **FR-06 (Kinematic State Estimation):** Supervisory software must run a discrete-time Kalman filter modeling 4WD skid-steer kinematics to compute innovation residuals.
- **FR-07 (Threat Attribution & SOC Display):** Telemetry, rejection breakdowns, and anomaly scores must stream to a dark-mode cyber HUD with $<500\,\text{ms}$ refresh intervals.

### 3.2 Non-Functional & Safety Requirements
- **NFR-01 (Deterministic Timing):** Cryptographic verification routines must not starve the Wi-Fi reception buffer; packet processing must be handled via a bounded FreeRTOS queue (`xQueueCreate(64, sizeof(canary_message_t))`).
- **NFR-02 (Fail-Safe Actuation Isolation):** Cyber-attack injection routines must be confined to software simulations and telemetry verifier self-tests, preventing erratic physical motor behavior.
- **NFR-03 (Power Distribution Integrity):** High-current motor supply lines ($7.4\,\text{V}$ Li-ion) must remain electrically isolated from the regulated $5.0\,\text{V}$ and $3.3\,\text{V}$ digital logic rails, sharing only a common reference ground.

---

## 4. System Architecture

```
                       CANARY VEHICLE NETWORK TOPOLOGY
                       
    +-----------------------------+       +-----------------------------+
    |    Node 1: Encoder ECU      |       |       Node 2: IMU ECU       |
    |  - LM393 Optical Encoders   |       |  - MPU-6050 (GY-521) 6-DOF  |
    |  - 4-Wheel RPM Calculation  |       |  - Auto-Zero Gyro Bias Cal. |
    |  - Ed25519 Signing (Seed 1) |       |  - Ed25519 Signing (Seed 2) |
    |  - BLAKE3 Freshness Token   |       |  - BLAKE3 Freshness Token   |
    +--------------+--------------+       +--------------+--------------+
                   |                                     |
    91-Byte Frames | (Subtypes: FL, FR, RL, RR)          | 91-Byte Frames (AX..GZ)
    @ 20 Hz        |                                     | @ 20 Hz
                   +------------------+------------------+
                                      |
                                      v [ESP-NOW Broadcast: Wi-Fi Channel 1]
    +---------------------------------+---------------------------------+
    |                Node 4: Security / IDS Verifier ECU                |
    |  - Bounded FreeRTOS Ingest Queue (64 frames capacity)             |
    |  - Layer 1 Verifier: Allowlist -> Ed25519 -> BLAKE3 Freshness     |
    |  - Rejection Threat Attribution & Embedded Benchmark Timer        |
    |  - Concurrent Wi-Fi SoftAP ("CANARY_HOTSPOT", Ch 1, 192.168.4.1)  |
    |  - UDP Broadcast Engine (Port 8888 -> 192.168.4.255)              |
    +---------------------------------+---------------------------------+
                                      |
                                      v [Wireless 2.4 GHz UDP Broadcast]
    +---------------------------------+---------------------------------+
    |               Ground Station Laptop / SOC Dashboard               |
    |  - Streamlit Cyber HUD & Plotly Rolling Waveform Visualizer       |
    |  - Threaded Non-Blocking UDP Telemetry Ingest Worker              |
    |  - Layer 2 Kinematic Rover Kalman Filter Fusion                   |
    |  - 100-Tree Random Forest Anomaly Classifier (<50 us Inference)   |
    |  - Interactive Red-Team Cyber-Physical Attack Injection Lab       |
    +-----------------------------------+
```

### 4.1 Node Allocation & Identity Matrix

| Node | Functional Role | Provisioned Cryptographic Material | Communication Role |
| :--- | :--- | :--- | :--- |
| **Node 1** | Wheel Encoder ECU | Private Key (derived from `NODE1_SEED`); `NODE1_TREE_SEED` | Broadcasts 4 wheel-speed streams (`FL`, `FR`, `RL`, `RR`) @ 20 Hz |
| **Node 2** | IMU Motion ECU | Private Key (derived from `NODE2_SEED`); `NODE2_TREE_SEED` | Broadcasts 6 inertial streams (`AX`, `AY`, `AZ`, `GX`, `GY`, `GZ`) @ 20 Hz |
| **Node 3** | Motor Drive Controller | None (Actuator interface node) | Dual L298N H-Bridge PWM motor drive |
| **Node 4** | Security / IDS ECU | Public Keys only (`NODE1_PUBLIC_KEY`, `NODE2_PUBLIC_KEY`); Tree Seeds | Ingests, verifies, logs, and broadcasts verified telemetry over UDP |
| **Node 5** | Physical Attacker Node | **Untrusted / Retired** (No provisioned keys in verifier) | Simulated via software injection and verifier fault injection |
| **Node 6** | Gateway Identity | **Retired / Decommissioned** | Permanently disallowed by Node 4 verifier |

### 4.2 The CANARY 91-Byte Wire Protocol
The protocol defines a fixed 91-byte memory layout (`canary_message_t`):

```c
typedef struct __attribute__((packed)) {
    uint8_t  sender_id;        // 1 byte:  CANARY_NODE_ENCODER (1), CANARY_NODE_IMU (2)
    uint8_t  msg_type;         // 1 byte:  WHEEL_SPEED (1), IMU_DATA (2)
    uint8_t  subtype;          // 1 byte:  FL/FR/RL/RR (0..3) or AX..GZ (0..5)
    uint32_t epoch;            // 4 bytes: Monotonically increasing counter
    int32_t  payload;          // 4 bytes: Fixed-point scaled value (x1000)
    uint8_t  freshness[16];    // 16 bytes: BLAKE3 hash-tree freshness token
} canary_message_body_t;       // Total Body: 27 bytes

typedef struct __attribute__((packed)) {
    canary_message_body_t body;      // 27 bytes
    uint8_t signature[64];           // 64 bytes: Monocypher Ed25519 signature
} canary_message_t;                  // Total Wire Size: 91 bytes
```

---

## 5. Circuit and Prototype Design

### 5.1 Sensor Subsystem & Pinout
- **Node 1 (Wheel Encoders):**
  - Left Motor Phase A (Interrupt): **GPIO 18** (Internal Pullup)
  - Left Motor Phase B (Direction): **GPIO 19** (Internal Pullup)
  - Right Motor Phase A (Interrupt): **GPIO 25** (Internal Pullup)
  - Right Motor Phase B (Direction): **GPIO 26** (Internal Pullup)
  - Interrupt Service Routines (`isr_left_encoder`, `isr_right_encoder`) capture rising edges on Phase A. The right encoder polarity is inverted in firmware to ensure forward motion produces positive rotational counts on both tracks.
- **Node 2 (MPU-6050 6-DOF IMU):**
  - Interface: Fast-mode I2C (100 kHz)
  - SDA Pin: **GPIO 21** | SCL Pin: **GPIO 22** | Supply: **3.3V / GND**
  - Sensor Range: Accelerometer configured to $\pm 4g$ ($8192\,\text{LSB}/g$); Gyroscope configured to $\pm 500^\circ/\text{s}$ ($65.5\,\text{LSB}/(^\circ/\text{s})$).

### 5.2 Actuation Subsystem
The rover utilizes a 4-wheel drive, dual-differential skid-steer chassis driven by two L298N dual H-bridge motor drivers. Each driver powers the two parallel motors on one side of the chassis. High-current motor supply ($7.4\,\text{V}$ nominal from two 18650 Li-ion cells in series) connects directly to the L298N power terminals. Logic inputs are driven by ESP32 PWM outputs.

```
                             ELECTRICAL POWER ARCHITECTURE
                             
      +-----------------------------+
      |  2S 18650 Li-ion Pack       |
      |  (7.4V Nominal, 8.4V Peak)  |
      +--------------+--------------+
                     |
                     +---------------------------------------+
                     | (High Current Motor Rail)             | (Logic Supply Input)
                     v                                       v
      +-----------------------------+         +-----------------------------+
      | 2x L298N Dual Motor Drivers |         | LM2596 Step-Down Regulator  |
      | - Left Track Motors (x2)    |         | - Output: Regulated 5.0V    |
      +--------------+--------------+         +--------------+--------------+
                     |                                       |
                     |                                       | (5.0V Logic Rail)
                     |                                       v
                     |                        +-----------------------------+
                     |                        | ESP32 Microcontrollers      |
                     |                        | - Node 1 (Encoders)         |
                     |                        | - Node 2 (IMU)              |
                     |                        | - Node 4 (Security Verifier)|
                     |                        +--------------+--------------+
                     |                                       | (3.3V Out)
                     |                                       v
                     |                        +-----------------------------+
                     |                        | Sensors: MPU-6050 & LM393   |
                     |                        +--------------+--------------+
                     |                                       |
                     +-------------------+-------------------+
                                         |
                                         v
                              COMMON CHASSIS GROUND (GND)
```

---

## 6. Layer 1: Cryptographic Authentication and Freshness

### 6.1 Cryptographic Identity & Provisioning
Every authorized ECU possesses an immutable 32-byte cryptographic seed provisioned at build time:
- **Node 1 Seed:** `{0x01, 0x02, ..., 0x20}` $\rightarrow$ Derives Public Key:
  `{0xD4, 0xF8, 0xE6, 0xF2, 0x67, 0x27, 0x11, 0x77, 0xC1, 0x1D, 0x17, 0xD3, 0x98, 0x10, 0xD7, 0x47, 0x16, 0x65, 0x72, 0xA1, 0xB6, 0xDB, 0x8E, 0x35, 0x23, 0x63, 0xD9, 0x78, 0x6E, 0xB0, 0x79, 0x83}`
- **Node 2 Seed:** `{0x02, 0x12, ..., 0xF1}` $\rightarrow$ Derives Public Key:
  `{0xD7, 0xD4, 0x14, 0x1F, 0x72, 0x8F, 0x04, 0xC2, 0xA2, 0xDB, 0xAD, 0x2E, 0x8D, 0x2B, 0x26, 0xD1, 0x07, 0x0E, 0x11, 0xE8, 0xDB, 0xB0, 0x25, 0xF5, 0xB6, 0x6F, 0x75, 0x8F, 0xF3, 0x6F, 0x2D, 0x94}`

Node 4 stores **only the public keys and tree root seeds**. It possesses zero private signing authority.

### 6.2 Sequential Verification Pipeline
When a 91-byte packet arrives at Node 4, it passes through an ordered pipeline:
1. **Packet Size Check:** If $\text{len} \neq 91$, immediately reject (`lastBadLen`).
2. **Sender Trust Check:** Senders outside `{CANARY_NODE_ENCODER, CANARY_NODE_IMU}` are rejected (`REJECT untrusted sender`).
3. **Stream Allowlist Check:** Senders transmitting unauthorized subtypes (e.g., Node 1 sending IMU types) are rejected (`REJECT unknown/disallowed stream`).
4. **Ed25519 Signature Check:** Monocypher `crypto_eddsa_check()` verifies the 64-byte signature across the 27-byte body. Bit flips or payload alterations trigger `REJECT bad signature`.
5. **BLAKE3 Freshness Check:** Recomputes the expected 16-byte freshness token from the node's tree seed and epoch counter (`REJECT bad freshness`).
6. **Anti-Replay Window:** If the received epoch $\le \text{last\_verified\_epoch}$, the frame is discarded as a stale replay (`REJECT replay/stale epoch`).

### 6.3 Measured Embedded Timing Results
Verification latency was benchmarked directly on the ESP32 (running at 240 MHz Tensilica dual-core LX6):
- **Mean Verification Latency:** **$24{,}500\,\mu\text{s} - 26{,}350\,\mu\text{s}$** (~$25\,\text{ms}$ per packet).
- **Peak Verification Latency:** **$27{,}414\,\mu\text{s}$**.
- **Wi-Fi Ingest Efficiency:** Handled via FreeRTOS queue without packet drops (`qDrops = 0` during steady-state 20 Hz streaming).

---

## 7. Layer 2: Kinematic State Estimation and Machine Learning

### 7.1 Kinematic Innovation Modeling
Layer 2 models skid-steer rover physics to detect attacks that bypass Layer 1 (e.g., physical sensor tampering or an insider key compromise). 

Let $v_L$ and $v_R$ represent the linear velocities computed from left and right wheel encoders:
$$v = \frac{v_R + v_L}{2}, \quad \omega_{\text{expected}} = \frac{v_R - v_L}{W}$$
where $W = 0.180\,\text{m}$ is the rover track width.

A discrete-time **Rover Kalman Filter** tracks the state vector $\mathbf{x} = [v, \omega, a]^T$ (forward velocity, yaw rate, and longitudinal acceleration). The filter predicts state transitions:
$$\mathbf{x}_{k|k-1} = \mathbf{F} \mathbf{x}_{k-1|k-1}, \quad \mathbf{P}_{k|k-1} = \mathbf{F} \mathbf{P}_{k-1|k-1} \mathbf{F}^T + \mathbf{Q}$$
The measurement vector $\mathbf{z} = [v_L, v_R, a_{\text{IMU}}, \omega_{\text{IMU}}]^T$ yields innovation residuals:
$$\mathbf{y} = \mathbf{z} - \mathbf{H} \mathbf{x}_{k|k-1}$$
The **yaw residual** $\tilde{\omega} = \omega_{\text{IMU}} - \omega_{\text{expected}}$ serves as the primary metric of kinematic consistency.

### 7.2 11-Dimensional Feature Space
At every 20 Hz interval, Layer 2 extracts 11 features:
1. `fused_velocity`: Kalman-filtered forward speed ($m/s$).
2. `fused_yaw_rate`: Kalman-filtered rotational rate ($rad/s$).
3. `fused_acceleration`: Kalman-filtered longitudinal acceleration ($m/s^2$).
4. `left_right_speed_diff`: Raw encoder differential ($v_R - v_L$).
5. `accel_gyro_inconsistency`: Discrepancy between centripetal acceleration ($v \cdot \omega$) and lateral IMU acceleration.
6. `yaw_rate_residual`: $\tilde{\omega} = \omega_{\text{IMU}} - \omega_{\text{expected}}$.
7. `encoder_acceleration`: Derivative of wheel speed odometry.
8. `imu_longitudinal_accel`: Direct filtered $a_x$ reading from MPU-6050.
9. `yaw_acceleration`: Derivative of gyroscope yaw rate ($d\omega/dt$).
10. `rolling_mean_yaw_residual`: 1-second rolling average of yaw discrepancy.
11. `rolling_var_yaw_residual`: 1-second rolling variance of yaw discrepancy.

### 7.3 Random Forest Classifier
The features are evaluated by an ensemble **100-tree Random Forest Classifier** trained on representative rover drive cycles (straight sprints, skid-turns, surface slippage, and spoofing injections).
- **Execution Latency:** $<50\,\mu\text{s}$ per feature vector.
- **Normal Drive Baseline:** Anomaly score remains **$0.01 - 0.04$** (`NORMAL`).
- **Asymmetric Spoofing Injection:** Anomaly score jumps to **$0.96 - 1.00$** (`ANOMALY`) within two sampling frames ($100\,\text{ms}$).

---

## 8. Test Procedure and Calibration

### 8.1 Sensor Calibration
1. **MPU-6050 Auto-Zero Calibration:** At boot, Node 2 remains stationary for 2.0 seconds, sampling 200 readings to calculate zero-rate offsets:
   $$\text{Bias}_x = \frac{1}{200}\sum g_x, \quad \text{Bias}_y = \frac{1}{200}\sum g_y, \quad \text{Bias}_z = \frac{1}{200}\sum g_z$$
   Offsets are subtracted from all subsequent gyro readings, eliminating stationary drift.
2. **Wheel Odometry Calibration:** The N20 150 RPM micro-geared motors feature integrated encoders yielding 3 pulses per motor revolution through a $1:100$ gear reduction, producing $N \approx 900$ pulses per wheel revolution. With wheel diameter $D = 0.065\,\text{m}$, distance per pulse is:
   $$\Delta s = \frac{\pi \cdot 0.065}{900} \approx 0.227\,\text{mm/pulse}$$

### 8.2 Red-Team Attack Injection Matrix
Testing verified that all cyber and physical attack vectors are contained by the respective security layers:

| Test ID | Simulated Threat Vector | Attack Mechanism | Expected Layer 1 Output | Expected Layer 2 Output | Measured Hardware Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Nominal Driving | Legitimate signed 20 Hz stream | `VERIFIED` | Score $<0.20$ (`NORMAL`) | **PASS.** 0 rejections; 100% acceptance. |
| **TC-02** | Payload Tampering | Single-bit flip in wheel speed payload | `REJECT bad signature` | Blocked at Layer 1 | **PASS.** Caught by Ed25519 in $<25\,\text{ms}$. |
| **TC-03** | Stale Replay Attack | Replay previously recorded valid packet | `REJECT replay/stale epoch` | Blocked at Layer 1 | **PASS.** Rejected by BLAKE3 anti-replay state. |
| **TC-04** | Rogue ECU Injection | Frame forged with Node 5 sender ID | `REJECT untrusted sender` | Blocked at Layer 1 | **PASS.** Dropped before crypto evaluation. |
| **TC-05** | Stream Hijacking | Disallowed subtype injected | `REJECT unknown/disallowed stream`| Blocked at Layer 1 | **PASS.** Rejected by stream validator. |
| **TC-06** | Stealthy Speed Spoofing| Falsified FL wheel speed (+150 RPM) | Valid signature (insider) | Score $=0.98$ (`ANOMALY`) | **PASS.** Kalman residual spikes; RF flags intrusion. |

---

## 9. Results and Objective Comparison

### 9.1 Experimental Telemetry Summary
During full hardware evaluation, Node 4 processed continuous multi-stream transmissions from Node 1 and Node 2:

| Telemetry Variable | Nominal Operational Value | Peak / Dynamic Range |
| :--- | :--- | :--- |
| **Total Ingested Packets** | $32{,}618+$ packets | Continuous @ 40 packets/s (Node 1 + Node 2) |
| **Layer 1 Acceptance Rate** | **100.0%** (Nominal state) | Rejections drop to 0 under correct key provisioning |
| **Four-Wheel Speeds** | $0.0\,\text{RPM}$ (Stationary) to $120.0\,\text{RPM}$ | Symmetric across left/right during straight travel |
| **IMU Acceleration ($a_z$)** | $+9.81\,\text{m/s}^2$ | $\pm 0.15\,\text{m/s}^2$ sensor noise floor |
| **IMU Yaw Rate ($\omega$)** | $0.000\,\text{rad/s}$ (Stationary) | $\pm 2.45\,\text{rad/s}$ during full-speed skid turns |
| **Verification Latency** | $24{,}500\,\mu\text{s}$ (Mean) | $27{,}414\,\mu\text{s}$ (Maximum observed) |
| **Wi-Fi Telemetry Rate** | 20 Hz periodic broadcast | Port 8888, zero dropped packets over 50 m range |

### 9.2 Objective Completion Matrix

```
[O1: Message Authentication]    =====> MET (100% valid frame acceptance, Ed25519)
[O2: Freshness / Anti-Replay]   =====> MET (Deterministic BLAKE3 epoch verification)
[O3: Sender Trust Verification] =====> MET (Node 5 & retired identities blocked)
[O4: Kinematic Anomaly Model]   =====> MET (Kalman fusion + 100-tree Random Forest)
[O5: Untethered Track Operation]=====> MET (SoftAP Ch 1 UDP broadcast to live SOC)
[O6: Latency & Performance]     =====> MET (Mean 24.5 ms on ESP32, 20 Hz throughput)
[O7: Automotive Standards Gap]  =====> MET (BIS & ISO/SAE gap analysis documented)
```

---

## 10. Limitations and Future Work

### 10.1 Identified Limitations
1. **Physical Bus Transceiver Absence:** Communications utilize 2.4 GHz ESP-NOW. While message payloads replicate CAN data structures, physical layer characteristics (arbitration, bit stuffing, 120 $\Omega$ split termination, and recessive/dominant electrical states) are not exercised.
2. **Asymmetric Processing Latency:** Monocypher Ed25519 signature checks require $\approx 25\,\text{ms}$ on an ESP32. While fully capable of sustaining 20 Hz telemetry rates, sub-millisecond automotive control loops (e.g., $1\,\text{ms}$ powertrain arbitration) would require dedicated hardware security modules (HSM) or elliptic-curve cryptographic accelerators.
3. **Open-Loop Actuation Safeguards:** The current prototype implements detection and telemetry alerting. Automated mitigation (e.g., bus-off isolation or graceful motor derating) has not been closed-loop integrated into the motor controller.

### 10.2 Roadmap for Future Work
- **Hardware CAN-FD Transceiver Shield:** Design an SPI-interfaced MCP2518FD CAN-FD controller shield with an isolated automotive transceiver (e.g., TJA1051) to evaluate physical bus injection.
- **Micro-HSM Hardware Integration:** Port Layer 1 verification routines to an automotive-grade MCU equipped with an onboard Hardware Security Module (HSM) or hardware-accelerated Ed25519 engine to reduce verification latency to $<1\,\text{ms}$.
- **Active Bus Disruption Mitigation:** Implement active bus-off mitigation logic on Node 4 to dynamically sever communication to compromised ECUs upon anomaly detection.

---

## 11. Sustainable Development Goals (SDG) Alignment

### 11.1 SDG 9: Industry, Innovation, and Infrastructure
- **Specific Target 9.1 & 9.4:** *Develop quality, reliable, sustainable and resilient infrastructure; upgrade infrastructure and retrofit industries to make them sustainable with increased resource-use efficiency.*
- **Project Contribution:** Modern commercial transport and public mobility infrastructure rely heavily on connected vehicles. Legacy commercial fleets cannot be cost-effectively replaced with next-generation platforms overnight. CANARY addresses this vulnerability by developing a retrofit-compatible intrusion detection framework that overlays cryptographic authentication and kinematic monitoring onto legacy vehicle networks, substantially increasing the operational longevity, resilience, and cyber-security of existing transportation fleets without requiring total vehicular redesign.

### 11.2 SDG 11: Sustainable Cities and Communities
- **Specific Target 11.2:** *Provide access to safe, affordable, accessible and sustainable transport systems for all, improving road safety.*
- **Project Contribution:** As urban centers transition to autonomous shuttles, connected buses, and smart transit systems, remote cyber-attacks on steering and brake-by-wire subsystems represent an emergent physical safety hazard. By validating a dual-tier defense mechanism that detects physical sensor spoofing in under $100\,\text{ms}$, CANARY directly contributes to the technological foundation necessary to prevent catastrophic traffic accidents caused by malicious cyber-physical tampering in urban environments.

---

## 12. Bureau of Indian Standards (BIS) Compliance Review

### 12.1 Regulatory Methodology
A formal standards search was conducted using the **BIS 'Know Your Standard' Portal** and the **Automotive Industry Standards Committee (AISC)** database to assess the prototype's compliance against applicable Indian national standards:

```
+----------------------------------------------------------------------------------------------------+
|                                    BIS STANDARDS AUDIT MATRIX                                      |
+----------------------------------------------------------------------------------------------------+
| Standard Number       | Scope & Indian Standard Title              | Prototype Assessment          |
+-----------------------+--------------------------------------------+-------------------------------+
| IS 14700 (Part 4/Sec1)| Electromagnetic Compatibility (EMC):       | NOT TESTED. Educational ESP32 |
| :2019                 | Testing & Measurement Techniques           | lacks shielding enclosure for |
|                       |                                            | CISPR 25 radiated emissions.  |
+-----------------------+--------------------------------------------+-------------------------------+
| IS 9000 Series        | Basic Environmental Testing Procedures     | PARTIAL DESIGN ALIGNMENT.     |
| (Relevant Parts)      | for Electronic and Electrical Items        | Component operational ratings |
|                       | (Thermal, Vibration, Mechanical Shock)     | span -40°C to +85°C; lab test |
|                       |                                            | environment only.             |
+-----------------------+--------------------------------------------+-------------------------------+
| IS 13313:1991         | Automotive Vehicles — Electrical Wiring —  | ALIGNED IN PROTOTYPE. Color-  |
|                       | Colour Coding                              | coded high-current motor and  |
|                       |                                            | digital logic lines.          |
+-----------------------+--------------------------------------------+-------------------------------+
| AIS-189 (Draft)       | Automotive Cybersecurity Requirements      | ARCHITECTURALLY ALIGNED.      |
|                       | for Motor Vehicles (Adopting ISO/SAE 21434)| Demonstrates Layer 1 origin   |
|                       |                                            | verification & threat models. |
+-----------------------+--------------------------------------------+-------------------------------+
```

### 12.2 Standards Gap & Testing Analysis
1. **IS 14700 (Part 4/Sec 1: 2019) — EMC Immunity & Radiated Emissions:** Automotive installations require immunity against severe alternator load dump transients and radiated RF fields. The open-frame prototype utilizes commercial development boards lacking chassis ground planes, common-mode chokes, and TVS transient voltage suppression diodes.
2. **AIS-189 / ISO/SAE 21434 Alignment:** India's draft AIS-189 mandates automotive cybersecurity management systems (CSMS). CANARY fulfills the defensive risk mitigation criteria specified in Section 7 by demonstrating cryptographic message authenticity (mitigating TARA threat scenario *Unauthorized ECU Command Injection*).

---

## 13. Bill of Materials and Budget Analysis

The following itemized expenditure represents the prototype build cost based on regional electronic component sourcing:

| Item No. | Component Description | Component Specification | Qty | Unit Cost (₹) | Total Cost (₹) | Sourcing / Remarks |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| 1 | ESP32 DevKit V1 Microcontroller | Dual-Core 240 MHz, 4MB Flash, Wi-Fi/BLE | 3 | 420.00 | 1,260.00 | Lab Inventory / Local Store |
| 2 | MPU-6050 6-DOF Sensor Module | 3-Axis Accel + 3-Axis Gyro (GY-521) | 1 | 185.00 | 185.00 | Sourced locally |
| 3 | N20 Micro-Geared Encoder Motors | 12V 150 RPM with Hall/Optical Encoders | 2 | 450.00 | 900.00 | Sourced locally |
| 4 | L298N Dual H-Bridge Motor Drivers | 2A Dual Channel Motor Driver Board | 2 | 160.00 | 320.00 | Sourced locally |
| 5 | 4WD Robotic Rover Platform | Dual Acrylic Chassis Plates, 4 Wheels | 1 | 480.00 | 480.00 | Sourced locally |
| 6 | 18650 Li-ion Battery Power Pack | 2S 7.4V 2200 mAh Pack with 2-Slot Holder | 1 | 520.00 | 520.00 | Local Battery Vendor |
| 7 | LM2596 DC-DC Step-Down Buck Converter| High-Efficiency 5V 3A Voltage Regulator | 1 | 110.00 | 110.00 | Sourced locally |
| 8 | Interconnects, Breadboards, Hardware | Jumper wires, mounting standoffs, switches | 1 set | 175.00 | 175.00 | Lab Consumables |
| **TOTAL**| | | | | **₹ 3,950.00** | **Total Prototype Cost** |

---

## 14. Individual Team Contributions

The division of engineering tasks among team members was executed as follows:

| Team Member | Registration ID | Core Engineering Responsibility | Specific Deliverables & Evidence |
| :--- | :--- | :--- | :--- |
| **Dhrisha Bhosale** | `251090610214` | **Cryptographic Architecture & Layer 1 Security** | Implemented Monocypher Ed25519 digital signature signing and BLAKE3 hash-tree freshness engine; built the Node 4 Verifier state machine (`node4_security.ino`); validated 146 host verifier test cases and anti-replay window logic. |
| **Sharanya Bhatia** | `251090610202` | **AI/ML Behavioral Pipeline & Live SOC Dashboard** | Developed the discrete-time Kinematic Rover Kalman Filter (`rover_kalman.cpp`); trained and optimized the 100-tree Random Forest classifier; architected the full-stack Streamlit/Plotly SOC live monitoring dashboard (`dashboard/app.py`). |
| **Kunjal Bhatia** | `251090610350` | **Hardware Integration, Sensor Bring-up & Mechanical Assembly** | Assembled the 4WD robotic chassis; wired power distribution rails, voltage regulators, and L298N drivers; implemented Node 1 hardware interrupt encoder pulse counters (`node1_encoder.ino`); completed Node 2 MPU-6050 I2C driver and auto-zero calibration routines (`node2_imu.ino`). |

---

## 15. Conclusion
The CANARY project successfully demonstrates a dual-layer cyber-physical intrusion detection system engineered for networked embedded platforms. By combining embedded cryptographic authentication (Ed25519 + BLAKE3) with supervisory kinematic state estimation (Kalman Filter + Random Forest Classifier), the system eliminates the fundamental vulnerability of single-mechanism architectures. 

Hardware benchmarks on physical ESP32 nodes establish that full cryptographic verification executes in $\approx 25\,\text{ms}$, comfortably sustaining continuous 20 Hz vehicular telemetry streams over untethered Wi-Fi UDP links. Red-team attack evaluations proved 100% rejection of unauthorized nodes, payload alterations, and replayed messages at Layer 1, while Layer 2 reliably detected stealthy physical sensor spoofing ($>0.96$ anomaly score) within $100\,\text{ms}$. CANARY establishes a validated foundation for future research in passive automotive network monitoring, hardware security modules, and resilient connected vehicular infrastructure.

---

## 16. References

1. Bureau of Indian Standards, *Know Your Standard Portal*, [https://www.bis.gov.in/know-your-standard/](https://www.bis.gov.in/know-your-standard/) (accessed October 2026).
2. Bureau of Indian Standards, **IS 14700 (Part 4/Sec 1): 2019**, *Electromagnetic Compatibility (EMC): Part 4 Testing and Measurement Techniques: Sec 1 Overview of the IEC 61000-4 Series*, BIS, New Delhi.
3. Bureau of Indian Standards, **IS 13313: 1991**, *Automotive Vehicles — Electrical Wiring — Colour Coding*, BIS, New Delhi.
4. Automotive Industry Standards Committee (AISC), **Draft AIS-189**, *Cybersecurity and Cybersecurity Management System for Motor Vehicles*, Automotive Research Association of India (ARAI), Pune.
5. United Nations Department of Economic and Social Affairs, *The 17 Sustainable Development Goals*, [https://sdgs.un.org/goals](https://sdgs.un.org/goals).
6. IETF, **RFC 8032**, *Edwards-Curve Digital Signature Algorithm (EdDSA)*, Internet Engineering Task Force.
7. J. O'Connor, J. Aumasson, S. Neves, Z. Wilcox-O'Hearn, *BLAKE3: One function, fast everywhere*, GitHub repository, [https://github.com/BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3).
8. International Organization for Standardization, **ISO/SAE 21434:2021**, *Road Vehicles — Cybersecurity Engineering*, ISO, Geneva.
9. International Organization for Standardization, **ISO 26262-1:2018**, *Road Vehicles — Functional Safety*, ISO, Geneva.
10. CANARY Source Code Repository, Manipal Institute of Technology, [https://github.com/dhrishabhosale/canary_repo](https://github.com/dhrishabhosale/canary_repo) (Release Commit: `e94c26c749cbb44e80403d157070991d0c60910f`).

---

## Appendix A: Final Submission Verification Checklist

- [x] **Cover Details:** Team Name (Canary), Team Number (505), student names and IDs complete.
- [x] **Abstract:** Exactly 192 words (within the 150–200 word required specification).
- [x] **Measurable Objectives:** Objectives O1–O7 explicitly stated and compared against verified hardware metrics.
- [x] **Block Diagrams & Circuit Design:** Electrical power distribution, node network topology, and sensor pinouts fully documented.
- [x] **Sensor Justification & Calibration:** Encoder count derivation ($0.227\,\text{mm/pulse}$) and auto-zero gyro bias calibration equations detailed.
- [x] **Measured Performance & Latency:** Embedded timing ($24.5\,\text{ms} - 26.3\,\text{ms}$) and throughput ($20\,\text{Hz}$, 91-byte wire size) recorded from hardware tests.
- [x] **UN Sustainable Development Goals:** Specific, non-generic targets for **SDG 9.1, 9.4** and **SDG 11.2** analyzed.
- [x] **BIS Standards Compliance:** Detailed audit across **IS 14700**, **IS 9000**, and draft **AIS-189**.
- [x] **Bill of Materials:** Complete itemized budget totaling ₹3,950.00 with realistic component specifications.
- [x] **Individual Contributions:** Distinct responsibilities confirmed for Dhrisha (Cryptography), Sharanya (AI/ML), and Kunjal (Hardware/Assembly).
- [x] **Repository & Commit Integrity:** Verified commit `e94c26c` linked and all bracketed placeholders removed.
