# CANARY

Two-layer automotive intrusion detection system on a 4WD skid-steer rover.
Six ESP32 nodes exchange CAN-like messages over ESP-NOW. Layer 1 verifies
message authenticity and freshness (Ed25519 + BLAKE3 hash-tree). Layer 2
checks physical plausibility (Kalman-filter fusion of wheel-encoder and
IMU data).

Full architecture spec: [`docs/CANARY_Architecture_Summary.docx`](docs/CANARY_Architecture_Summary.docx)
— that document is the single source of truth for the protocol, message
format, and node roles. If anything in this README ever disagrees with
it, the docx wins; update this file to match.

## Repo layout

```
canary/
├── docs/                       Architecture spec, diagrams, reports
│
├── firmware/
│   ├── lib/
│   │   ├── canary_common/      Shared across every node — DO NOT fork per-node
│   │   │   ├── canary_protocol.h   90-byte message struct
│   │   │   ├── canary_crypto.h/.c  Ed25519 sign/verify wrapper
│   │   │   └── (blake3 hash-tree code lands here once built)
│   │   ├── monocypher/         Vendored crypto library (Ed25519/EdDSA)
│   │   └── blake3/             Vendored hash library (freshness tree) — pending
│   │
│   ├── node1_encoder/          Wheel-encoder ECU
│   ├── node2_imu/              IMU ECU
│   ├── node3_motor_control/    Motor-control ECU (2x L298, 4 motors)
│   ├── node4_security/         Security/IDS ECU — the verifier
│   ├── node5_attacker/         Attacker node — no valid key, on purpose
│   └── node6_gateway/          WiFi-to-ESP-NOW command gateway
│
├── provisioning/
│   └── provision.c             Generates keypairs for Nodes 1, 2, 6.
│                                Run ONCE, offline. Output (canary_secrets.h)
│                                is gitignored — never commit real keys.
│
├── tests/
│   └── test_harness.c          Host-testable Layer 1 tests (no ESP32 needed)
│
└── hardware/
    ├── bom.md                  Bill of materials
    └── wiring/                 Wiring diagrams, GPIO pin maps
```

Each `firmware/nodeN_*/` folder is its own PlatformIO project. They all
depend on `firmware/lib/canary_common` and `firmware/lib/monocypher` via
`lib_extra_dirs` in each node's `platformio.ini` — the crypto and message
format code is written **once** and shared, not copy-pasted per node.

## Getting started

**1. Provision keys (once, offline, on your laptop — not on any ESP32):**
```bash
cd provisioning
gcc -I../firmware/lib/canary_common -I../firmware/lib/monocypher -O2 \
    provision.c ../firmware/lib/canary_common/canary_crypto.c \
    ../firmware/lib/monocypher/monocypher.c -o provision
./provision
```
This writes `canary_secrets.h` — split it by hand: each node's firmware
gets *only its own* secret key; Node 4 gets *every* public key and no
secret keys.

**2. Run the Layer 1 test suite (no hardware needed):**
```bash
cd tests
gcc -I../firmware/lib/canary_common -I../firmware/lib/monocypher -O2 \
    test_harness.c ../firmware/lib/canary_common/canary_crypto.c \
    ../firmware/lib/monocypher/monocypher.c -o test_harness
./test_harness
```
All four tests (legitimate message, forgery, tampered payload, replayed
epoch) should print `PASS`.

**3. Flash a node** (once PlatformIO projects are filled in):
```bash
cd firmware/node1_encoder
pio run -t upload
```

## Status

- [x] Message format (`canary_protocol.h`) — defined, size-checked (90 bytes)
- [x] Ed25519 sign/verify (`canary_crypto.c`) — implemented, tested
- [x] Provisioning tool — generates real keypairs for Nodes 1, 2, 6
- [x] Layer 1 test harness — 4/4 passing on host
- [ ] BLAKE3 hash-tree freshness token — not started
- [ ] ESP-NOW transport integration — not started
- [ ] Node 1–6 firmware bodies — placeholders only
- [ ] Layer 2 Kalman filter — not started
- [ ] On-device (ESP32) testing — not started

## Security notes

- `canary_secrets.h` (provisioning output) must never be committed — see
  `.gitignore`. If it's ever accidentally pushed, treat every key in it
  as burned and re-provision.
- Node 5 (attacker) is intentionally provisioned with nothing. Don't
  "fix" this — it's the point.
