"""CANARY Vehicle Security Operations Center (SOC) Dashboard.

Provides:
- Live Serial Telemetry from Node 4 (Security ECU).
- Cryptographic Layer 1 Status & Rejection Breakdown.
- Real-time Physical Layer 2 AI-Aided Kalman Filter & Random Forest Inference.
- Isolated Software & Hardware Attack Simulation.
- Comprehensive Dark SOC UI with Rolling Real-Time Plots.
"""

import sys
import time
from collections import deque
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Ensure repository root is on Python path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dashboard.telemetry.serial_manager import (
    Node4Telemetry,
    SecurityEvent,
    SerialTelemetryManager,
)
from dashboard.telemetry.attack_sim import (
    SCENARIOS,
    AttackSimulator,
)
from simulation.layer2_ids import Layer2IDS

# Set page config
st.set_page_config(
    page_title="CANARY SOC | Vehicle IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom dark cybersecurity SOC styling
st.markdown(
    """
<style>
    .reportview-container, .main, .block-container {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .stMetric {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 10px;
        border-radius: 6px;
    }
    .soc-header {
        font-size: 24px;
        font-weight: 700;
        color: #58a6ff;
        border-bottom: 2px solid #30363d;
        padding-bottom: 8px;
        margin-bottom: 15px;
    }
    .status-badge {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 13px;
    }
    .badge-ok { background-color: #238636; color: #ffffff; }
    .badge-warn { background-color: #d29922; color: #ffffff; }
    .badge-danger { background-color: #da3633; color: #ffffff; }
    .badge-info { background-color: #1f6feb; color: #ffffff; }
    .soc-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 14px;
        margin-bottom: 12px;
    }
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_resource
def get_serial_manager() -> SerialTelemetryManager:
    return SerialTelemetryManager()


@st.cache_resource
def get_l2_model() -> Layer2IDS:
    try:
        return Layer2IDS.load()
    except Exception as e:
        st.sidebar.error(f"Failed to load Layer 2 model: {e}")
        return None


serial_mgr = get_serial_manager()
l2_ids = get_l2_model()
attack_sim = AttackSimulator(serial_mgr, l2_ids)

# ---------------------------------------------------------------------
# Sidebar Configuration
# ---------------------------------------------------------------------
st.sidebar.title("🛡️ CANARY SOC CONTROLS")

op_mode = st.sidebar.radio(
    "Operational Mode",
    ["LIVE HARDWARE", "SIMULATION / DEMO"],
    index=0 if serial_mgr.running else 1,
)

if op_mode == "LIVE HARDWARE":
    st.sidebar.subheader("Serial Connection")
    available_ports = serial_mgr.list_ports()
    selected_port = st.sidebar.selectbox("Port", available_ports if available_ports else ["None found"])
    baud = st.sidebar.selectbox("Baud Rate", [115200, 921600, 57600], index=0)

    col_conn1, col_conn2 = st.sidebar.columns(2)
    with col_conn1:
        if st.button("Connect", disabled=serial_mgr.running or not available_ports):
            ok, msg = serial_mgr.connect(selected_port, baud)
            if ok:
                st.sidebar.success(msg)
                st.rerun()
            else:
                st.sidebar.error(msg)

    with col_conn2:
        if st.button("Disconnect", disabled=not serial_mgr.running):
            serial_mgr.disconnect()
            st.sidebar.info("Disconnected")
            st.rerun()

    conn_status = "🟢 CONNECTED" if serial_mgr.running else "🔴 DISCONNECTED"
    st.sidebar.markdown(f"**Status:** {conn_status} ({serial_mgr.connected_port or 'N/A'})")

else:
    st.sidebar.info("Running in software demonstration mode. Telemetry can be driven by synthetic attack suite.")

# Refresh controls
auto_refresh = st.sidebar.checkbox("Auto-refresh Telemetry", value=True)
refresh_rate = st.sidebar.slider("Refresh rate (s)", 0.2, 2.0, 0.5, 0.1)

# ---------------------------------------------------------------------
# Data Acquisition & State Estimation
# ---------------------------------------------------------------------
telem, history, events, raw_logs = serial_mgr.get_snapshot()

# Generate demo synthetic data if disconnected and in demo mode
if not serial_mgr.running and op_mode == "SIMULATION / DEMO":
    now = time.time()
    telem = Node4Telemetry(
        timestamp=now,
        rx_total=1240,
        bad_len=0,
        q_drops=0,
        verified=1240,
        rej_untrusted=0,
        rej_stream=0,
        rej_sig=0,
        rej_fresh=0,
        rej_replay=0,
        verify_avg_us=24500,
        verify_max_us=25600,
        wheel_verified=(310, 310, 310, 310),
        wheel_rpm=(45.2, 45.2, 45.2, 45.2),
        imu_verified=620,
        accel=(0.02, -0.01, 9.81),
        gyro=(0.001, -0.002, 0.003),
        yaw_rate=0.003,
        node1_online=True,
        node2_online=True,
        last_update_mono=time.monotonic(),
    )

# Evaluate Layer 2 ML Model on current telemetry
enc_dict = {
    "fl_rpm": telem.wheel_rpm[0],
    "fr_rpm": telem.wheel_rpm[1],
    "rl_rpm": telem.wheel_rpm[2],
    "rr_rpm": telem.wheel_rpm[3],
}
imu_dict = {
    "accel_x": telem.accel[0],
    "accel_y": telem.accel[1],
    "accel_z": telem.accel[2],
    "gyro_x": telem.gyro[0],
    "gyro_y": telem.gyro[1],
    "gyro_z": telem.gyro[2],
}

if l2_ids:
    ml_res = l2_ids.evaluate_state(enc_dict, imu_dict)
else:
    ml_res = {"prediction": "UNAVAILABLE", "anomaly_score": 0.0, "features": {}, "kalman_state": {}}

# ---------------------------------------------------------------------
# Main Dashboard Header
# ---------------------------------------------------------------------
st.markdown('<div class="soc-header">🛡️ CANARY VEHICLE SECURITY OPERATIONS CENTER</div>', unsafe_allow_html=True)

# Top KPI Row
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
with kpi1:
    mode_badge = f'<span class="status-badge badge-info">{op_mode}</span>'
    st.markdown(f"**Mode:** {mode_badge}", unsafe_allow_html=True)
    st.metric("Total Received", f"{telem.rx_total} pkts")

with kpi2:
    st.metric("Verified (Layer 1)", f"{telem.verified} pkts")
    rej_total = telem.rej_untrusted + telem.rej_stream + telem.rej_sig + telem.rej_fresh + telem.rej_replay
    st.metric("Total Rejected", f"{rej_total} pkts", delta=-rej_total if rej_total > 0 else 0)

with kpi3:
    n1_status = '<span class="status-badge badge-ok">ONLINE</span>' if telem.node1_online else '<span class="status-badge badge-warn">OFFLINE</span>'
    st.markdown(f"**Node 1 (Encoders):** {n1_status}", unsafe_allow_html=True)
    st.metric("Wheel Speed (Avg)", f"{(sum(telem.wheel_rpm)/4.0):.1f} RPM")

with kpi4:
    n2_status = '<span class="status-badge badge-ok">ONLINE</span>' if telem.node2_online else '<span class="status-badge badge-warn">OFFLINE</span>'
    st.markdown(f"**Node 2 (IMU):** {n2_status}", unsafe_allow_html=True)
    st.metric("Observed Yaw Rate", f"{telem.yaw_rate:.3f} rad/s")

with kpi5:
    ml_badge = '<span class="status-badge badge-ok">NORMAL</span>' if ml_res["prediction"] == "NORMAL" else '<span class="status-badge badge-danger">ANOMALY</span>'
    st.markdown(f"**Layer 2 ML IDS:** {ml_badge}", unsafe_allow_html=True)
    st.metric("Anomaly Score", f"{ml_res['anomaly_score']:.2f}")

st.write("---")

# ---------------------------------------------------------------------
# Dashboard Tabs
# ---------------------------------------------------------------------
tab_telemetry, tab_security, tab_ml, tab_attacks, tab_logs = st.tabs(
    ["📡 Live Telemetry", "🔒 Security & Verifier", "🧠 Layer 2 ML Model", "⚔️ Attack Simulation", "📜 Serial Logs"]
)

# ---------------------------------------------------------------------
# TAB 1: Live Telemetry
# ---------------------------------------------------------------------
with tab_telemetry:
    col_t1, col_t2 = st.columns(2)

    with col_t1:
        st.subheader("4-Wheel Rotational Velocities (RPM)")
        w_df = pd.DataFrame({
            "Wheel": ["Front-Left (FL)", "Front-Right (FR)", "Rear-Left (RL)", "Rear-Right (RR)"],
            "RPM": list(telem.wheel_rpm),
            "Verified Packets": list(telem.wheel_verified),
        })
        st.dataframe(w_df, use_container_width=True)

        fig_wheels = go.Figure()
        fig_wheels.add_trace(go.Bar(
            x=["FL", "FR", "RL", "RR"],
            y=list(telem.wheel_rpm),
            marker_color=["#58a6ff", "#58a6ff", "#3fb950", "#3fb950"],
        ))
        fig_wheels.update_layout(
            template="plotly_dark",
            title="Real-Time Wheel RPM",
            yaxis_title="RPM",
            margin=dict(l=20, r=20, t=30, b=20),
            height=280,
        )
        st.plotly_chart(fig_wheels, use_container_width=True)

    with col_t2:
        st.subheader("MPU-6050 Motion Dynamics")
        m_df = pd.DataFrame({
            "Axis": ["X-Axis", "Y-Axis", "Z-Axis"],
            "Acceleration (m/s²)": list(telem.accel),
            "Angular Rate (rad/s)": list(telem.gyro),
        })
        st.dataframe(m_df, use_container_width=True)

        fig_imu = go.Figure()
        fig_imu.add_trace(go.Bar(x=["Accel X", "Accel Y", "Accel Z"], y=list(telem.accel), name="m/s²", marker_color="#f0883e"))
        fig_imu.add_trace(go.Bar(x=["Gyro X", "Gyro Y", "Gyro Z"], y=list(telem.gyro), name="rad/s", marker_color="#a371f7"))
        fig_imu.update_layout(
            template="plotly_dark",
            title="IMU 6-DOF Physical Measurements",
            margin=dict(l=20, r=20, t=30, b=20),
            height=280,
            barmode="group",
        )
        st.plotly_chart(fig_imu, use_container_width=True)

    if history:
        st.subheader("Rolling Telemetry Trends")
        h_df = pd.DataFrame(history)
        h_df["rel_time"] = h_df["time"] - h_df["time"].iloc[0]

        fig_trend = go.Figure()
        fig_trend.add_trace(go.Scatter(x=h_df["rel_time"], y=h_df["fl_rpm"], name="FL RPM", line=dict(color="#58a6ff")))
        fig_trend.add_trace(go.Scatter(x=h_df["rel_time"], y=h_df["fr_rpm"], name="FR RPM", line=dict(color="#3fb950")))
        fig_trend.add_trace(go.Scatter(x=h_df["rel_time"], y=h_df["yaw_rate"], name="Yaw Rate (rad/s)", yaxis="y2", line=dict(color="#f0883e", dash="dash")))

        fig_trend.update_layout(
            template="plotly_dark",
            title="Wheel Speeds vs Observed Yaw Rate Over Time",
            xaxis_title="Elapsed Time (s)",
            yaxis_title="RPM",
            yaxis2=dict(title="Yaw Rate (rad/s)", overlaying="y", side="right"),
            height=320,
            margin=dict(l=20, r=20, t=30, b=20),
        )
        st.plotly_chart(fig_trend, use_container_width=True)

# ---------------------------------------------------------------------
# TAB 2: Security & Layer 1 Verifier
# ---------------------------------------------------------------------
with tab_security:
    st.subheader("Layer 1 Cryptographic Authentication & Freshness Status")

    sec_col1, sec_col2, sec_col3 = st.columns(3)
    with sec_col1:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown("**Node 1 (Encoder ECU)**")
        st.write(f"• Role: 4-Wheel Speed ECU")
        st.write(f"• Public Key: `39543B892EFC...` (Configured)")
        st.write(f"• Verified Streams: `FL`, `FR`, `RL`, `RR`")
        st.write(f"• Cumulative Verified: **{sum(telem.wheel_verified)} pkts**")
        st.markdown("</div>", unsafe_allow_html=True)

    with sec_col2:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown("**Node 2 (IMU ECU)**")
        st.write(f"• Role: 6-Axis Inertial Measurement")
        st.write(f"• Public Key: `9D73E9705A7E...` (Configured)")
        st.write(f"• Verified Streams: `AX`, `AY`, `AZ`, `GX`, `GY`, `GZ`")
        st.write(f"• Cumulative Verified: **{telem.imu_verified} pkts**")
        st.markdown("</div>", unsafe_allow_html=True)

    with sec_col3:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown("**Node 4 Verifier Metrics**")
        st.write(f"• Wire Size: 91 bytes / packet")
        st.write(f"• Queue Drops: **{telem.q_drops}**")
        st.write(f"• Average Verify Latency: **{telem.verify_avg_us} µs**")
        st.write(f"• Max Verify Latency: **{telem.verify_max_us} µs**")
        st.markdown("</div>", unsafe_allow_html=True)

    st.subheader("Rejection Root Cause Breakdown")
    col_r1, col_r2 = st.columns([1, 2])
    with col_r1:
        st.metric("Untrusted Sender (e.g. Node 5)", telem.rej_untrusted)
        st.metric("Unknown/Disallowed Stream", telem.rej_stream)
        st.metric("Bad Signature (Ed25519)", telem.rej_sig)
        st.metric("Bad Freshness (BLAKE3)", telem.rej_fresh)
        st.metric("Replay / Stale Epoch", telem.rej_replay)

    with col_r2:
        fig_rej = go.Figure(data=[go.Pie(
            labels=["Bad Signature", "Stale Replay", "Bad Freshness", "Disallowed Stream", "Untrusted Sender"],
            values=[telem.rej_sig, telem.rej_replay, telem.rej_fresh, telem.rej_stream, telem.rej_untrusted],
            hole=0.4,
            marker_colors=["#da3633", "#f0883e", "#a371f7", "#8b949e", "#ff7b72"],
        )])
        fig_rej.update_layout(
            template="plotly_dark",
            title="Layer 1 Rejection Distribution",
            margin=dict(l=20, r=20, t=30, b=20),
            height=280,
        )
        st.plotly_chart(fig_rej, use_container_width=True)

    st.subheader("Security Event Log (Latest 20 Events)")
    if events:
        evt_records = [
            {
                "Time": time.strftime("%H:%M:%S", time.localtime(e.timestamp)),
                "Type": "TEST" if e.is_test else "REAL",
                "Sender": f"Node {e.sender_id}",
                "Stream": f"Subtype {e.subtype}",
                "Epoch": e.epoch,
                "Payload": e.payload,
                "Verdict": e.verdict,
            }
            for e in reversed(list(events)[-20:])
        ]
        st.dataframe(pd.DataFrame(evt_records), use_container_width=True)
    else:
        st.info("No security rejection events recorded yet.")

# ---------------------------------------------------------------------
# TAB 3: Layer 2 ML Model
# ---------------------------------------------------------------------
with tab_ml:
    st.subheader("AI-Aided Physical Intrusion Detection System")
    st.markdown(
        """
    Layer 2 checks kinematic consistency between wheel speeds and IMU readings.
    A discrete-time **Rover Kalman Filter** fuses measurements into an innovation residual,
    which is evaluated by a **100-tree Random Forest Classifier** to distinguish legitimate turns from stealthy spoofing.
    """
    )

    ml_col1, ml_col2 = st.columns(2)
    with ml_col1:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown("**Model Specifications**")
        st.write("• Architecture: Supervised Random Forest (100 Decision Trees)")
        st.write("• Feature Dimension: 11 Kinematic Features")
        st.write("• Input Dimensions: 4 Wheel RPMs + 6-Axis IMU")
        st.write("• Decision Classes: `0 = NORMAL`, `1 = ANOMALY`")
        st.write(f"• Current Verdict: **{ml_res['prediction']}**")
        st.write(f"• Anomaly Probability: **{ml_res['anomaly_score']:.4f}**")
        st.markdown("</div>", unsafe_allow_html=True)

    with ml_col2:
        st.markdown('<div class="soc-card">', unsafe_allow_html=True)
        st.markdown("**Kalman Kinematic Fusion State**")
        k_state = ml_res.get("kalman_state", {})
        st.write(f"• Fused Forward Velocity: **{k_state.get('fused_velocity', 0.0):.3f} m/s**")
        st.write(f"• Fused Yaw Rate: **{k_state.get('fused_yaw_rate', 0.0):.3f} rad/s**")
        st.write(f"• Fused Longitudinal Accel: **{k_state.get('fused_acceleration', 0.0):.3f} m/s²**")
        st.markdown("</div>", unsafe_allow_html=True)

    if ml_res.get("features"):
        st.subheader("Extracted Features Ingested by Random Forest")
        feat_df = pd.DataFrame([{"Feature": k, "Value": round(v, 4)} for k, v in ml_res["features"].items()])
        st.dataframe(feat_df.T, use_container_width=True)

# ---------------------------------------------------------------------
# TAB 4: Attack Simulation
# ---------------------------------------------------------------------
with tab_attacks:
    st.subheader("⚔️ Cyber-Physical Attack Injection Lab")
    st.markdown(
        """
    Execute controlled attack scenarios to test the multi-tier defense architecture.
    - **Layer 1 Scenarios:** Send hardware self-test triggers to Node 4 over serial.
    - **Layer 2 Scenarios:** Evaluate synthetic sensor spoofing against the real ML model.
    *All attack vectors remain isolated from live actuator controls.*
    """
    )

    sel_scenario = st.selectbox(
        "Select Attack Scenario",
        [f"{s.id}: {s.name}" for s in SCENARIOS],
    )
    scen_id = sel_scenario.split(":")[0]
    scen_obj = next(s for s in SCENARIOS if s.id == scen_id)

    st.markdown(f"**Category:** `{scen_obj.category}`")
    st.markdown(f"**Description:** {scen_obj.description}")
    st.markdown(f"**Expected Layer 1 Outcome:** `{scen_obj.expected_l1}`")
    st.markdown(f"**Expected Layer 2 Outcome:** `{scen_obj.expected_l2}`")

    if st.button("🚀 Execute Attack Scenario"):
        result = attack_sim.execute_scenario(scen_id, telem)
        st.success(f"Executed: {result['scenario_name']}")
        st.json(result)

    if attack_sim.history:
        st.subheader("Attack Simulation Execution History")
        st.dataframe(pd.DataFrame(attack_sim.history), use_container_width=True)

# ---------------------------------------------------------------------
# TAB 5: Serial Logs
# ---------------------------------------------------------------------
with tab_logs:
    st.subheader("Raw Node 4 Serial Console Output")
    st.text_area("Live Terminal Buffer", value="\n".join(raw_logs), height=400)

# ---------------------------------------------------------------------
# Auto-refresh loop
# ---------------------------------------------------------------------
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
