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
    page_title="CANARY | Vehicle Defense SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom dark cybersecurity SOC styling with modern glassmorphism & HUD aesthetics
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre, .mono-font {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .main, .block-container {
        background-color: #0b0f19;
        color: #e2e8f0;
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    /* Top Navigation / Brand Banner */
    .top-banner {
        background: linear-gradient(135deg, rgba(13, 20, 36, 0.9) 0%, rgba(18, 28, 51, 0.85) 100%);
        border: 1px solid rgba(88, 166, 255, 0.18);
        border-radius: 12px;
        padding: 18px 24px;
        margin-bottom: 24px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        backdrop-filter: blur(8px);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .top-title {
        font-size: 24px;
        font-weight: 700;
        letter-spacing: 0.8px;
        background: linear-gradient(90deg, #58a6ff 0%, #38ef7d 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }
    .top-subtitle {
        font-size: 13px;
        color: #8b949e;
        margin-top: 4px;
    }

    /* Glassmorphism SOC Card */
    .soc-card {
        background: linear-gradient(145deg, rgba(22, 27, 34, 0.75) 0%, rgba(13, 17, 23, 0.9) 100%);
        border: 1px solid rgba(48, 54, 61, 0.8);
        border-radius: 12px;
        padding: 18px 20px;
        margin-bottom: 16px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .soc-card:hover {
        border-color: rgba(88, 166, 255, 0.4);
    }
    .soc-card-title {
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #8b949e;
        font-weight: 600;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    /* Modern KPI Cards */
    .kpi-box {
        background: linear-gradient(135deg, rgba(22, 31, 48, 0.65) 0%, rgba(15, 23, 42, 0.85) 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 12px;
        padding: 16px 18px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .kpi-title {
        font-size: 12px;
        color: #94a3b8;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }
    .kpi-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 26px;
        font-weight: 700;
        color: #f8fafc;
        margin: 6px 0;
    }
    .kpi-sub {
        font-size: 12px;
        color: #64748b;
    }

    /* Status Badges */
    .status-badge {
        display: inline-flex;
        align-items: center;
        padding: 4px 10px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 12px;
        letter-spacing: 0.5px;
    }
    .badge-ok {
        background: rgba(46, 160, 67, 0.15);
        color: #3fb950;
        border: 1px solid rgba(46, 160, 67, 0.4);
    }
    .badge-warn {
        background: rgba(210, 153, 34, 0.15);
        color: #d29922;
        border: 1px solid rgba(210, 153, 34, 0.4);
    }
    .badge-danger {
        background: rgba(248, 81, 73, 0.15);
        color: #f85149;
        border: 1px solid rgba(248, 81, 73, 0.4);
    }
    .badge-info {
        background: rgba(88, 166, 255, 0.15);
        color: #58a6ff;
        border: 1px solid rgba(88, 166, 255, 0.4);
    }

    /* Streamlit tabs customization */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
        border-bottom: 1px solid #30363d;
        padding-bottom: 4px;
        margin-bottom: 20px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: rgba(22, 27, 34, 0.6);
        border: 1px solid #30363d;
        border-radius: 8px 8px 0 0;
        color: #8b949e;
        padding: 10px 18px;
        font-weight: 600;
        font-size: 14px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1f2937 !important;
        border-color: #58a6ff #30363d transparent #30363d !important;
        color: #58a6ff !important;
    }

    /* Terminal console appearance */
    .terminal-box {
        background-color: #05080f;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #38ef7d;
        line-height: 1.5;
        max-height: 380px;
        overflow-y: auto;
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
    link_type = st.sidebar.radio(
        "Hardware Link",
        ["📶 Wireless Wi-Fi (UDP)", "🔌 USB Serial (COM)"],
        index=0 if serial_mgr.conn_type == "UDP" else 1,
    )

    if link_type == "📶 Wireless Wi-Fi (UDP)":
        st.sidebar.markdown(
            """
        <div style="font-size: 12px; color: #94a3b8; background: rgba(15,23,42,0.6); padding: 8px; border-radius: 6px; margin-bottom: 8px;">
            1. Connect laptop Wi-Fi to: <b>CANARY_HOTSPOT</b><br/>
            2. Password: <code>canary1234</code><br/>
            3. Port: <code>8888</code> (Channel 1)
        </div>
        """,
            unsafe_allow_html=True,
        )
        udp_port = st.sidebar.number_input("UDP Port", min_value=1024, max_value=65535, value=8888)

        col_conn1, col_conn2 = st.sidebar.columns(2)
        with col_conn1:
            if st.button("Listen UDP", disabled=serial_mgr.running):
                ok, msg = serial_mgr.connect_udp(port=udp_port)
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

    else:
        st.sidebar.subheader("Serial Connection")
        available_ports = serial_mgr.list_ports()
        selected_port = st.sidebar.selectbox("Port", available_ports if available_ports else ["None found"])
        baud = st.sidebar.selectbox("Baud Rate", [115200, 921600, 57600], index=0)

        col_conn1, col_conn2 = st.sidebar.columns(2)
        with col_conn1:
            if st.button("Connect COM", disabled=serial_mgr.running or not available_ports):
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

    conn_status = f"🟢 CONNECTED ({serial_mgr.conn_type})" if serial_mgr.running else "🔴 DISCONNECTED"
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
# Top Brand & Status Banner
# ---------------------------------------------------------------------
rej_total = telem.rej_untrusted + telem.rej_stream + telem.rej_sig + telem.rej_fresh + telem.rej_replay
status_color = "#3fb950" if rej_total == 0 else ("#f85149" if telem.rej_sig > 0 or telem.rej_replay > 0 else "#d29922")

st.markdown(
    f"""
<div class="top-banner">
    <div>
        <h1 class="top-title">🛡️ CANARY DEFENSE OPERATIONS CENTER</h1>
        <div class="top-subtitle">Multi-Layer In-Vehicle Intrusion Detection & Cryptographic Telemetry System</div>
    </div>
    <div style="text-align: right; display: flex; gap: 12px; align-items: center;">
        <span class="status-badge badge-info">{op_mode}</span>
        <span class="status-badge" style="background: rgba(30, 41, 59, 0.8); border: 1px solid #334155; color: #94a3b8; font-family: monospace;">
            CH 1 &nbsp;|&nbsp; 91B ESP-NOW
        </span>
        <span class="status-badge" style="background: rgba(22, 27, 34, 0.9); border: 1px solid {status_color}; color: {status_color};">
            ● L1 SEC: {'SECURE' if rej_total == 0 else f'{rej_total} REJECTED'}
        </span>
    </div>
</div>
""",
    unsafe_allow_html=True,
)

# Top KPI Row using sleek stylized cards
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
with kpi1:
    st.markdown(
        f"""
    <div class="kpi-box">
        <div class="kpi-title">Layer 1 Total Rx</div>
        <div class="kpi-value">{telem.rx_total:,} <span style="font-size: 14px; color: #64748b;">pkts</span></div>
        <div class="kpi-sub">Loss/Drops: <span style="color: {'#3fb950' if telem.q_drops == 0 else '#f85149'};">{telem.q_drops}</span></div>
    </div>
    """,
        unsafe_allow_html=True,
    )

with kpi2:
    verified_pct = (telem.verified / telem.rx_total * 100) if telem.rx_total > 0 else 100.0
    st.markdown(
        f"""
    <div class="kpi-box">
        <div class="kpi-title">Verified (Layer 1)</div>
        <div class="kpi-value" style="color: #38ef7d;">{telem.verified:,} <span style="font-size: 14px; color: #64748b;">pkts</span></div>
        <div class="kpi-sub">Acceptance: <span style="color: #38ef7d;">{verified_pct:.1f}%</span></div>
    </div>
    """,
        unsafe_allow_html=True,
    )

with kpi3:
    n1_badge = '<span class="status-badge badge-ok">ONLINE</span>' if telem.node1_online else '<span class="status-badge badge-warn">OFFLINE</span>'
    avg_rpm = sum(telem.wheel_rpm) / 4.0
    st.markdown(
        f"""
    <div class="kpi-box">
        <div class="kpi-title">Node 1 (Wheel Encoders) &nbsp;{n1_badge}</div>
        <div class="kpi-value">{avg_rpm:.1f} <span style="font-size: 14px; color: #64748b;">RPM</span></div>
        <div class="kpi-sub">FL: {telem.wheel_rpm[0]:.0f} | FR: {telem.wheel_rpm[1]:.0f} | RL: {telem.wheel_rpm[2]:.0f} | RR: {telem.wheel_rpm[3]:.0f}</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

with kpi4:
    n2_badge = '<span class="status-badge badge-ok">ONLINE</span>' if telem.node2_online else '<span class="status-badge badge-warn">OFFLINE</span>'
    st.markdown(
        f"""
    <div class="kpi-box">
        <div class="kpi-title">Node 2 (MPU-6050 IMU) &nbsp;{n2_badge}</div>
        <div class="kpi-value">{telem.yaw_rate:+.3f} <span style="font-size: 14px; color: #64748b;">rad/s</span></div>
        <div class="kpi-sub">Z-Accel: {telem.accel[2]:+.2f} m/s² | Verified: {telem.imu_verified}</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

with kpi5:
    is_normal = ml_res["prediction"] == "NORMAL"
    ml_badge = '<span class="status-badge badge-ok">NORMAL</span>' if is_normal else '<span class="status-badge badge-danger">ANOMALY</span>'
    anomaly_val = ml_res["anomaly_score"]
    anom_color = "#3fb950" if anomaly_val < 0.3 else ("#d29922" if anomaly_val < 0.6 else "#f85149")
    st.markdown(
        f"""
    <div class="kpi-box">
        <div class="kpi-title">Layer 2 ML IDS &nbsp;{ml_badge}</div>
        <div class="kpi-value" style="color: {anom_color};">{anomaly_val:.2f} <span style="font-size: 14px; color: #64748b;">score</span></div>
        <div class="kpi-sub">Kalman & Random Forest Classifier</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

st.write("")

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
        st.markdown(
            """
        <div class="soc-card">
            <div class="soc-card-title">🛞 4-Wheel Rotational Speed & Status</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        fig_wheels = go.Figure()
        fig_wheels.add_trace(go.Bar(
            x=["FL (Front-Left)", "FR (Front-Right)", "RL (Rear-Left)", "RR (Rear-Right)"],
            y=list(telem.wheel_rpm),
            marker=dict(
                color=["#38bdf8", "#38bdf8", "#34d399", "#34d399"],
                line=dict(color="rgba(255,255,255,0.2)", width=1.5),
            ),
            text=[f"{v:.1f} RPM" for v in telem.wheel_rpm],
            textposition="auto",
        ))
        fig_wheels.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(15,23,42,0.6)",
            plot_bgcolor="rgba(15,23,42,0.4)",
            yaxis_title="Rotational Velocity (RPM)",
            margin=dict(l=20, r=20, t=30, b=20),
            height=260,
        )
        st.plotly_chart(fig_wheels, use_container_width=True)

        w_df = pd.DataFrame({
            "Position": ["Front-Left (FL)", "Front-Right (FR)", "Rear-Left (RL)", "Rear-Right (RR)"],
            "RPM": [f"{r:.1f}" for r in telem.wheel_rpm],
            "Verified Wire Packets": list(telem.wheel_verified),
            "Status": ["ACTIVE" if telem.node1_online else "STANDBY"] * 4,
        })
        st.dataframe(w_df, use_container_width=True, hide_index=True)

    with col_t2:
        st.markdown(
            """
        <div class="soc-card">
            <div class="soc-card-title">🧭 MPU-6050 6-DOF Inertial Dynamics</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        fig_imu = go.Figure()
        fig_imu.add_trace(go.Bar(
            x=["Accel X", "Accel Y", "Accel Z"],
            y=list(telem.accel),
            name="Acceleration (m/s²)",
            marker_color="#fb923c",
            text=[f"{v:+.2f}" for v in telem.accel],
            textposition="auto",
        ))
        fig_imu.add_trace(go.Bar(
            x=["Gyro X", "Gyro Y", "Gyro Z"],
            y=list(telem.gyro),
            name="Angular Rate (rad/s)",
            marker_color="#a855f7",
            text=[f"{v:+.3f}" for v in telem.gyro],
            textposition="auto",
        ))
        fig_imu.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(15,23,42,0.6)",
            plot_bgcolor="rgba(15,23,42,0.4)",
            margin=dict(l=20, r=20, t=30, b=20),
            height=260,
            barmode="group",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig_imu, use_container_width=True)

        m_df = pd.DataFrame({
            "Dimension": ["X-Axis (Longitudinal / Roll)", "Y-Axis (Lateral / Pitch)", "Z-Axis (Vertical / Yaw)"],
            "Acceleration (m/s²)": [f"{a:+.3f}" for a in telem.accel],
            "Angular Rate (rad/s)": [f"{g:+.3f}" for g in telem.gyro],
        })
        st.dataframe(m_df, use_container_width=True, hide_index=True)

    if history:
        st.markdown(
            """
        <div class="soc-card" style="margin-top: 14px;">
            <div class="soc-card-title">📈 Rolling Kinematic Waveforms (Speeds vs Observed Yaw)</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        h_df = pd.DataFrame(history)
        h_df["rel_time"] = h_df["time"] - h_df["time"].iloc[0]

        fig_trend = go.Figure()
        fig_trend.add_trace(go.Scatter(
            x=h_df["rel_time"], y=h_df["fl_rpm"], name="FL Wheel RPM",
            line=dict(color="#38bdf8", width=2),
        ))
        fig_trend.add_trace(go.Scatter(
            x=h_df["rel_time"], y=h_df["fr_rpm"], name="FR Wheel RPM",
            line=dict(color="#34d399", width=2),
        ))
        fig_trend.add_trace(go.Scatter(
            x=h_df["rel_time"], y=h_df["yaw_rate"], name="Yaw Rate (rad/s)",
            yaxis="y2", line=dict(color="#fb923c", width=2, dash="dot"),
        ))

        fig_trend.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(15,23,42,0.6)",
            plot_bgcolor="rgba(15,23,42,0.4)",
            xaxis=dict(title="Elapsed Time (s)", showgrid=True, gridcolor="rgba(255,255,255,0.06)"),
            yaxis=dict(title="Wheel Speed (RPM)", showgrid=True, gridcolor="rgba(255,255,255,0.06)"),
            yaxis2=dict(title="Yaw Rate (rad/s)", overlaying="y", side="right", showgrid=False),
            height=300,
            margin=dict(l=20, r=20, t=30, b=20),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        )
        st.plotly_chart(fig_trend, use_container_width=True)

# ---------------------------------------------------------------------
# TAB 2: Security & Layer 1 Verifier
# ---------------------------------------------------------------------
with tab_security:
    st.markdown(
        """
    <div style="margin-bottom: 16px;">
        <h3 style="margin: 0; color: #58a6ff;">Layer 1 Cryptographic Authentication & Freshness Status</h3>
        <p style="color: #8b949e; font-size: 13px; margin: 4px 0 0 0;">
            Node 4 validates every 91-byte ESP-NOW frame: Identity verification (Monocypher Ed25519) + Anti-replay hash tree (BLAKE3).
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    sec_col1, sec_col2, sec_col3 = st.columns(3)
    with sec_col1:
        st.markdown(
            f"""
        <div class="soc-card">
            <div class="soc-card-title">🔐 Node 1: Encoder ECU</div>
            <div style="font-size: 13px; line-height: 1.8;">
                <div><span style="color: #8b949e;">Role:</span> 4-Wheel Speed ECU</div>
                <div><span style="color: #8b949e;">Pubkey:</span> <code class="mono-font" style="color: #38bdf8;">39543B892EFC...</code></div>
                <div><span style="color: #8b949e;">Allowlisted:</span> <code>FL</code>, <code>FR</code>, <code>RL</code>, <code>RR</code></div>
                <div><span style="color: #8b949e;">Verified Frames:</span> <strong style="color: #38ef7d;">{sum(telem.wheel_verified):,}</strong></div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with sec_col2:
        st.markdown(
            f"""
        <div class="soc-card">
            <div class="soc-card-title">🔐 Node 2: IMU ECU</div>
            <div style="font-size: 13px; line-height: 1.8;">
                <div><span style="color: #8b949e;">Role:</span> 6-Axis Inertial Dynamics</div>
                <div><span style="color: #8b949e;">Pubkey:</span> <code class="mono-font" style="color: #38bdf8;">D7D4141F728F...</code></div>
                <div><span style="color: #8b949e;">Allowlisted:</span> <code>AX</code>, <code>AY</code>, <code>AZ</code>, <code>GX</code>, <code>GY</code>, <code>GZ</code></div>
                <div><span style="color: #8b949e;">Verified Frames:</span> <strong style="color: #38ef7d;">{telem.imu_verified:,}</strong></div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with sec_col3:
        avg_lat_ms = telem.verify_avg_us / 1000.0
        max_lat_ms = telem.verify_max_us / 1000.0
        st.markdown(
            f"""
        <div class="soc-card">
            <div class="soc-card-title">⚡ Node 4 Verifier Metrics</div>
            <div style="font-size: 13px; line-height: 1.8;">
                <div><span style="color: #8b949e;">Frame Spec:</span> 91 bytes wire protocol</div>
                <div><span style="color: #8b949e;">Wi-Fi Queue Drops:</span> <strong style="color: {'#3fb950' if telem.q_drops == 0 else '#f85149'};">{telem.q_drops}</strong></div>
                <div><span style="color: #8b949e;">Mean Verify Latency:</span> <strong>{telem.verify_avg_us} µs</strong> ({avg_lat_ms:.2f} ms)</div>
                <div><span style="color: #8b949e;">Peak Verify Latency:</span> <strong>{telem.verify_max_us} µs</strong> ({max_lat_ms:.2f} ms)</div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    col_r1, col_r2 = st.columns([1, 2])
    with col_r1:
        st.markdown(
            """
        <div class="soc-card">
            <div class="soc-card-title">🛑 Rejection Root Cause Counters</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        st.metric("Untrusted Sender (Node 5/6)", telem.rej_untrusted)
        st.metric("Unknown / Disallowed Stream", telem.rej_stream)
        st.metric("Invalid Cryptographic Signature", telem.rej_sig)
        st.metric("Freshness Token Mismatch", telem.rej_fresh)
        st.metric("Replay / Stale Counter", telem.rej_replay)

    with col_r2:
        rej_sum = telem.rej_sig + telem.rej_replay + telem.rej_fresh + telem.rej_stream + telem.rej_untrusted
        if rej_sum > 0:
            fig_rej = go.Figure(data=[go.Pie(
                labels=["Bad Signature", "Stale Replay", "Bad Freshness", "Disallowed Stream", "Untrusted Sender"],
                values=[telem.rej_sig, telem.rej_replay, telem.rej_fresh, telem.rej_stream, telem.rej_untrusted],
                hole=0.45,
                marker_colors=["#f85149", "#fb923c", "#c084fc", "#64748b", "#f43f5e"],
            )])
            fig_rej.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(15,23,42,0.6)",
                plot_bgcolor="rgba(15,23,42,0.4)",
                title="Layer 1 Threat Attribution",
                margin=dict(l=20, r=20, t=30, b=20),
                height=290,
            )
            st.plotly_chart(fig_rej, use_container_width=True)
        else:
            st.markdown(
                """
            <div class="soc-card" style="height: 290px; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;">
                <div style="font-size: 40px; margin-bottom: 10px;">🛡️</div>
                <div style="color: #38ef7d; font-weight: 700; font-size: 16px;">Zero Rejections Recorded</div>
                <div style="color: #64748b; font-size: 13px; max-width: 320px; margin-top: 6px;">
                    All received frames pass Ed25519 authentication and BLAKE3 freshness verification.
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

    st.markdown(
        """
    <div class="soc-card" style="margin-top: 14px;">
        <div class="soc-card-title">📜 Layer 1 Security Events Audit Log</div>
    </div>
    """,
        unsafe_allow_html=True,
    )
    if events:
        evt_records = [
            {
                "Timestamp": time.strftime("%H:%M:%S", time.localtime(e.timestamp)),
                "Source": "LOCAL_TEST" if e.is_test else "WIRE_RX",
                "Sender": f"Node {e.sender_id}",
                "Stream": f"Sub {e.subtype}",
                "Epoch": e.epoch,
                "Wire Payload": e.payload,
                "Security Verdict": e.verdict,
            }
            for e in reversed(list(events)[-20:])
        ]
        st.dataframe(pd.DataFrame(evt_records), use_container_width=True, hide_index=True)
    else:
        st.info("No security rejection events recorded yet.")

# ---------------------------------------------------------------------
# TAB 3: Layer 2 ML Model
# ---------------------------------------------------------------------
with tab_ml:
    st.markdown(
        """
    <div style="margin-bottom: 16px;">
        <h3 style="margin: 0; color: #58a6ff;">🧠 AI-Aided Physical Intrusion Detection System</h3>
        <p style="color: #8b949e; font-size: 13px; margin: 4px 0 0 0;">
            Layer 2 performs physics-based kinematic consistency checks. A discrete-time <strong>Rover Kalman Filter</strong>
            fuses wheel velocities and IMU dynamics into innovation residuals, evaluated by a <strong>100-tree Random Forest</strong>
            to detect stealthy sensor spoofing that bypasses Layer 1.
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    ml_col1, ml_col2 = st.columns(2)
    with ml_col1:
        st.markdown(
            f"""
        <div class="soc-card">
            <div class="soc-card-title">🤖 Random Forest Classifier Engine</div>
            <div style="font-size: 13px; line-height: 1.8;">
                <div><span style="color: #8b949e;">Architecture:</span> Supervised Ensemble (100 Decision Trees)</div>
                <div><span style="color: #8b949e;">Feature Vector:</span> 11 Dynamic Kinematic Signals</div>
                <div><span style="color: #8b949e;">Current Prediction:</span> <strong style="color: {'#38ef7d' if ml_res['prediction'] == 'NORMAL' else '#f85149'};">{ml_res['prediction']}</strong></div>
                <div><span style="color: #8b949e;">Anomaly Probability:</span> <strong>{ml_res['anomaly_score']:.4f}</strong></div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=ml_res["anomaly_score"],
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Anomaly Risk Index", 'font': {'size': 14, 'color': '#94a3b8'}},
            gauge={
                'axis': {'range': [0, 1], 'tickwidth': 1, 'tickcolor': "#334155"},
                'bar': {'color': "#38bdf8"},
                'bgcolor': "rgba(15,23,42,0.6)",
                'borderwidth': 1,
                'bordercolor': "#334155",
                'steps': [
                    {'range': [0, 0.35], 'color': 'rgba(56, 239, 125, 0.2)'},
                    {'range': [0.35, 0.70], 'color': 'rgba(251, 146, 60, 0.2)'},
                    {'range': [0.70, 1.0], 'color': 'rgba(248, 81, 73, 0.25)'},
                ],
                'threshold': {
                    'line': {'color': "#f85149", 'width': 3},
                    'thickness': 0.8,
                    'value': 0.65,
                },
            },
        ))
        fig_gauge.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(15,23,42,0.6)",
            height=200,
            margin=dict(l=20, r=20, t=30, b=20),
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

    with ml_col2:
        k_state = ml_res.get("kalman_state", {})
        f_vel = k_state.get('fused_velocity', 0.0)
        f_yaw = k_state.get('fused_yaw_rate', 0.0)
        f_acc = k_state.get('fused_acceleration', 0.0)

        st.markdown(
            f"""
        <div class="soc-card">
            <div class="soc-card-title">🧮 Kalman Fusion & State Innovation</div>
            <div style="font-size: 13px; line-height: 1.8;">
                <div><span style="color: #8b949e;">Fused Forward Velocity:</span> <strong>{f_vel:.3f} m/s</strong></div>
                <div><span style="color: #8b949e;">Fused Yaw Rate:</span> <strong>{f_yaw:.3f} rad/s</strong></div>
                <div><span style="color: #8b949e;">Fused Longitudinal Accel:</span> <strong>{f_acc:.3f} m/s²</strong></div>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        k_df = pd.DataFrame({
            "State Variable": ["Forward Velocity (v)", "Yaw Rate (ω)", "Longitudinal Accel (a)"],
            "Fused Estimate": [f"{f_vel:.3f} m/s", f"{f_yaw:.3f} rad/s", f"{f_acc:.3f} m/s²"],
            "Direct Sensor Ref": [f"{(sum(telem.wheel_rpm)/4.0 * 0.033 * 0.10472):.3f} m/s", f"{telem.yaw_rate:.3f} rad/s", f"{telem.accel[0]:.3f} m/s²"],
        })
        st.dataframe(k_df, use_container_width=True, hide_index=True)

    if ml_res.get("features"):
        st.markdown(
            """
        <div class="soc-card" style="margin-top: 14px;">
            <div class="soc-card-title">📊 Kinematic Feature Vector Fed to Classifier</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        f_cols = st.columns(len(ml_res["features"]))
        for col, (fname, fval) in zip(f_cols, ml_res["features"].items()):
            with col:
                st.metric(fname, f"{fval:.3f}")

# ---------------------------------------------------------------------
# TAB 4: Attack Simulation
# ---------------------------------------------------------------------
with tab_attacks:
    st.markdown(
        """
    <div style="margin-bottom: 16px;">
        <h3 style="margin: 0; color: #58a6ff;">⚔️ Cyber-Physical Attack Simulation & Red-Teaming</h3>
        <p style="color: #8b949e; font-size: 13px; margin: 4px 0 0 0;">
            Execute isolated attack injections against the CANARY architecture. Verify that Layer 1 catches cryptographic violations
            and Layer 2 catches physical inconsistency.
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    sel_scenario = st.selectbox(
        "Select Attack Vector",
        [f"{s.id}: {s.name}" for s in SCENARIOS],
    )
    scen_id = sel_scenario.split(":")[0]
    scen_obj = next(s for s in SCENARIOS if s.id == scen_id)

    st.markdown(
        f"""
    <div class="soc-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
            <strong style="color: #58a6ff; font-size: 16px;">{scen_obj.name}</strong>
            <span class="status-badge badge-warn">{scen_obj.category}</span>
        </div>
        <div style="font-size: 13px; color: #cbd5e1; margin-bottom: 12px;">{scen_obj.description}</div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 12px;">
            <div style="background: rgba(15, 23, 42, 0.6); padding: 8px 12px; border-radius: 6px;">
                <span style="color: #8b949e;">Expected Layer 1 Response:</span><br/>
                <code style="color: #38bdf8;">{scen_obj.expected_l1}</code>
            </div>
            <div style="background: rgba(15, 23, 42, 0.6); padding: 8px 12px; border-radius: 6px;">
                <span style="color: #8b949e;">Expected Layer 2 Response:</span><br/>
                <code style="color: #fb923c;">{scen_obj.expected_l2}</code>
            </div>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    if st.button("🚀 Trigger Attack Scenario", type="primary"):
        result = attack_sim.execute_scenario(scen_id, telem)
        st.success(f"Executed: {result['scenario_name']}")
        st.json(result)

    if attack_sim.history:
        st.markdown(
            """
        <div class="soc-card" style="margin-top: 14px;">
            <div class="soc-card-title">📜 Attack Execution History</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
        st.dataframe(pd.DataFrame(attack_sim.history), use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------
# TAB 5: Serial Logs
# ---------------------------------------------------------------------
with tab_logs:
    st.markdown(
        """
    <div style="margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center;">
        <div>
            <h3 style="margin: 0; color: #58a6ff;">📜 Live Node 4 Serial Telemetry Stream</h3>
            <div style="color: #8b949e; font-size: 12px;">Direct ASCII telemetry and rejection events from verifier hardware</div>
        </div>
        <div>
            <span class="status-badge badge-info">{len(raw_logs)} lines buffered</span>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    log_content = "\n".join(raw_logs) if raw_logs else "No serial stream data received yet. Connect to Node 4 or switch to DEMO mode."
    st.markdown(f'<div class="terminal-box"><pre style="margin:0; background:transparent; border:none; color:inherit;">{log_content}</pre></div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------
# Auto-refresh loop
# ---------------------------------------------------------------------
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
