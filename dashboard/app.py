"""CANARY dashboard - Phase 3A (foundation) + 3B (system status) + 3C (6-node network)
+ 3D (live 4WD rover visualization) + 3E (detailed live telemetry)
+ 3F (Security Layer 1 panel - dashboard visualization only, see the 3F section below)
+ 3G (Security Layer 2: live Random Forest inference on the simulator's sensor values)
+ 3H (unified detection breakdown: Layer 1 + Layer 2 verdict, counters, reasons, timeline)
+ 3I (Attack Lab: controlled demo attacks through the existing Layer1Monitor.inject() and the
      simulator's existing PhysicalAttack hook; simulation / demonstration only).

Drives the EXISTING simulation (simulation/sensor_simulator.py -> VehicleModel).
No simulation logic lives here. This is a laptop simulation: messaging is
simulated CAN-like messaging over ESP-NOW, not real CAN / CAN-FD hardware.

Run from the repo root:  streamlit run dashboard/app.py
"""
import json
import math
import os
import sys
import time
from collections import deque
from dataclasses import replace
from html import escape as _esc
from pathlib import Path

import pandas as pd
import streamlit as st

# Make the repo root importable (simulation/, common/) regardless of launch dir.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from simulation import scenarios  # noqa: E402
from simulation.sensor_simulator import (  # noqa: E402
    SensorSimulator, PhysicalAttack, expected_yaw_rate_from_encoders,
    ATTACK_IMU_YAW_OFFSET, ATTACK_WHEEL_OFFSET, ATTACK_SIDE_OFFSET,
)
from simulation.vehicle_model import TRACK_WIDTH, rpm_to_velocity  # noqa: E402
from common.canary_message import (  # noqa: E402
    CANARYMessage,
    NODE_ENCODER, NODE_IMU, NODE_MOTOR, NODE_SECURITY, NODE_ATTACKER, NODE_GATEWAY,
    MSG_WHEEL_SPEED, MSG_IMU_DATA, MSG_MOTION_CMD, MSG_MOTOR_ACK,
    WHEEL_FL, WHEEL_FR, WHEEL_RL, WHEEL_RR,
    IMU_AX, IMU_AY, IMU_AZ, IMU_GX, IMU_GY, IMU_GZ,
)
try:  # 3G: the existing Layer 2 implementation (needs numpy + scikit-learn, as layer2_ids.py itself does)
    from simulation.layer2_ids import (  # noqa: E402
        Layer2IDS, extract_features, FEATURES_PATH as L2_FEATURES_PATH,
    )
    L2_IMPORT_ERROR = None
except ImportError as _exc:
    Layer2IDS, extract_features, L2_FEATURES_PATH = None, None, None
    L2_IMPORT_ERROR = str(_exc)

SEED = 42
DT = 0.01                 # simulator timestep (s), same default the simulator uses
REFRESH_S = 0.15          # dashboard refresh interval while RUNNING
MAX_STEPS_PER_TICK = 100  # cap catch-up after a stalled browser tab (1 s of sim time)
# The built-in timeline is 10 s and then holds STOP forever. Repeat it so the
# vehicle keeps driving while the dashboard runs (1 hour of sim time).
TIMELINE = scenarios.DEFAULT_TIMELINE * 360

# 3D rover view (drawing constants only - no physics). The camera follows the rover,
# the ground grid scrolls from VehicleModel x/y, and the rover rotates by VehicleModel yaw.
VIEW_W, VIEW_H = 640, 420
PX_PER_M = 200.0          # ground scale: 1 m of VehicleModel travel = 200 px
GRID_M = 0.25             # minor grid spacing (m)
TRAIL_MAX = 240           # breadcrumb points kept (one per simulator advance)

# 3E live-signal history: bounded, filled only from simulator samples.
HISTORY_MAX = 150         # points kept
HISTORY_STRIDE = 10       # keep every 10th sample (10 Hz at dt=0.01) -> ~15 s window
RPM_FULL = 260.0          # wheel RPM that maps to full glow (1 m/s is ~239 RPM)
YAW_FULL = 1.5            # yaw rate (rad/s) at which the steering arc reaches 70 deg

# Layer 2 artifacts: only checked for existence in 3B (nothing is loaded or run).
LAYER2_FILES = [REPO_ROOT / "models" / "layer2_random_forest.pkl",
                REPO_ROOT / "models" / "layer2_features.json"]

st.set_page_config(page_title="CANARY", page_icon="🐤", layout="wide",
                   initial_sidebar_state="collapsed")

st.markdown(
    """
    <style>
    :root { --bg:#0a0e14; --panel:#0f1620; --border:#1c2a3a; --text:#c9d6e2;
            --muted:#6b7f94; --green:#00e5a0; --cyan:#00b8ff; --amber:#ffb020; --red:#ff4d6d; }
    .stApp { background: var(--bg); color: var(--text); }
    header[data-testid="stHeader"] { background: transparent; }
    .block-container { padding-top: 2rem; max-width: 1300px; }
    html, body, [class*="css"] { font-family: "JetBrains Mono","Fira Code",Consolas,monospace; }

    .title { font-size:2.6rem; font-weight:800; letter-spacing:.35em; color:var(--green);
             margin:0; text-shadow:0 0 18px rgba(0,229,160,.35); }
    .tagline { font-size:1rem; margin:.2rem 0 0 0; letter-spacing:.08em; }
    .whim { font-size:.75rem; color:var(--muted); margin:.2rem 0 0 0; font-style:italic; }
    .rule { border:none; border-top:1px solid var(--border); margin:1.2rem 0; }
    .label { font-size:.72rem; letter-spacing:.25em; text-transform:uppercase;
             color:var(--muted); margin:0 0 .6rem 0; }
    .sublabel { font-size:.68rem; letter-spacing:.08em; color:var(--muted); margin:-.3rem 0 .7rem 0; }

    .mode { background:var(--panel); border:1px solid var(--cyan); border-radius:6px;
            padding:.7rem 1rem; text-align:right; box-shadow:0 0 14px rgba(0,184,255,.15); }
    .mode-k { font-size:.7rem; letter-spacing:.25em; color:var(--cyan); }
    .mode-v { font-size:.9rem; white-space:nowrap; font-weight:700; letter-spacing:.12em; color:var(--text); }

    .status { font-size:1.1rem; font-weight:700; letter-spacing:.2em; padding-top:.45rem; }
    .running { color:var(--green); text-shadow:0 0 10px rgba(0,229,160,.5); }
    .paused  { color:var(--amber); }

    .stButton > button { width:100%; background:var(--panel); color:var(--text);
        border:1px solid var(--border); letter-spacing:.2em; font-weight:700; }
    .stButton > button:hover:not(:disabled) { border-color:var(--green); color:var(--green); }
    .stButton > button:disabled { opacity:1; color:#3d4f63; border-color:#17222f; }

    [data-testid="stMetric"] { background:var(--panel); border:1px solid var(--border);
        border-left:3px solid var(--green); border-radius:6px; padding:.8rem 1rem; }
    [data-testid="stMetricLabel"] { color:var(--muted); letter-spacing:.15em; text-transform:uppercase; }
    [data-testid="stMetricValue"] { color:var(--text); font-size:1.05rem; }
    [data-testid="stMetricValue"] > div { overflow:visible; text-overflow:clip; }

    /* ---- 3B: system status tiles ---- */
    .sgrid { display:grid; grid-template-columns:repeat(4,1fr); gap:.7rem; }
    @media (max-width:800px) { .sgrid { grid-template-columns:repeat(2,1fr); } }
    .stile { background:var(--panel); border:1px solid var(--border); border-radius:6px;
             padding:.65rem .9rem; }
    .stile-k { font-size:.62rem; letter-spacing:.22em; color:var(--muted); text-transform:uppercase; }
    .stile-v { font-size:1.05rem; font-weight:700; letter-spacing:.12em; margin-top:.25rem; }
    .stile-v::before { content:"●"; font-size:.7rem; margin-right:.5rem; vertical-align:middle; }
    .stile.ok { border-left:3px solid var(--green); }   .stile.ok .stile-v { color:var(--green); }
    .stile.info { border-left:3px solid var(--cyan); }  .stile.info .stile-v { color:var(--cyan); }
    .stile.warn { border-left:3px solid var(--amber); } .stile.warn .stile-v { color:var(--amber); }
    .stile.bad { border-left:3px solid var(--red); }    .stile.bad .stile-v { color:var(--red); }
    .stile.num { border-left:3px solid var(--border); } .stile.num .stile-v { color:var(--text); }
    .stile.num .stile-v::before { content:""; margin:0; }

    /* ---- 3C: network stage ---- */
    .stage-wrap { overflow-x:auto; border:1px solid var(--border); border-radius:10px;
        background:
          radial-gradient(ellipse at 50% 50%, rgba(0,229,160,.10), transparent 50%),
          linear-gradient(rgba(28,42,58,.45) 1px, transparent 1px),
          linear-gradient(90deg, rgba(28,42,58,.45) 1px, transparent 1px),
          #080c12;
        background-size:auto, 40px 40px, 40px 40px, auto; }
    .stage { position:relative; width:1000px; height:480px; margin:0 auto; }
    .stage-tag { position:absolute; left:14px; top:10px; font-size:.6rem; letter-spacing:.2em;
                 color:var(--muted); }
    .stage-tag.r { left:auto; right:14px; color:var(--cyan); }

    .node { position:absolute; transform:translate(-50%,-50%); box-sizing:border-box;
            width:210px; height:84px; padding:.5rem .7rem; overflow:hidden; z-index:2;
            background:var(--panel); border:1px solid var(--border); border-radius:8px; }
    .n-top { display:flex; justify-content:space-between; align-items:center; }
    .n-id { font-size:.58rem; letter-spacing:.22em; color:var(--muted); }
    .chip { font-size:.55rem; letter-spacing:.14em; padding:1px 7px; border-radius:9px;
            border:1px solid; }
    .chip.ok { color:var(--green); border-color:rgba(0,229,160,.5); }
    .chip.idle { color:var(--amber); border-color:rgba(255,176,32,.5); }
    .n-name { font-size:.92rem; font-weight:700; margin:.2rem 0 .1rem 0; white-space:nowrap; }
    .n-sub { font-size:.58rem; letter-spacing:.06em; color:var(--muted); white-space:nowrap; }
    .node.sensor { border-left:3px solid var(--cyan); }
    .node.gateway { border-left:3px solid var(--amber); }
    .node.motor { border-left:3px solid var(--green); }
    .node.attacker { border:1px dashed rgba(255,77,109,.7); border-left:3px solid var(--red);
                     background:linear-gradient(135deg, #1a0d14, #0f1620); }
    .node.attacker .n-sub { color:var(--red); font-weight:700; letter-spacing:.14em; }
    .node.ids { width:250px; height:130px; padding:.7rem .9rem;
                border:2px solid var(--green); background:linear-gradient(160deg, #0b1f1c, #0f1620);
                box-shadow:0 0 28px rgba(0,229,160,.30);
                animation:idsring 2.4s ease-in-out infinite; }
    .node.ids .n-name { font-size:1.15rem; margin:.45rem 0 .25rem 0; color:var(--green); }
    .node.ids .n-sub { font-size:.62rem; line-height:1.5; white-space:normal; }
    .node.ids .n-id { color:var(--green); }
    @keyframes idsring { 0%,100% { box-shadow:0 0 18px rgba(0,229,160,.25); }
                         50% { box-shadow:0 0 38px rgba(0,229,160,.55); } }

    .lnk { position:absolute; height:2px; transform-origin:0 50%; z-index:1;
           background:rgba(0,184,255,.22); }
    .lnk.cmd { background:rgba(255,176,32,.22); }
    .lnk.live { background:rgba(0,184,255,.55); box-shadow:0 0 8px rgba(0,184,255,.35); }
    .lnk.cmd.live { background:rgba(255,176,32,.55); box-shadow:0 0 8px rgba(255,176,32,.35); }
    .lnk.bad { height:0; background:none; border-top:2px dashed rgba(255,77,109,.55); }
    .lnk::after { content:""; position:absolute; right:-2px; top:-4px; border-left:9px solid rgba(0,184,255,.8);
                  border-top:5px solid transparent; border-bottom:5px solid transparent; }
    .lnk.cmd::after { border-left-color:rgba(255,176,32,.8); }
    .lnk.bad::after { border-left-color:rgba(255,77,109,.6); top:-6px; }
    .pill { position:absolute; transform:translate(-50%,-50%); z-index:3; font-size:.58rem;
            letter-spacing:.14em; color:var(--muted); background:var(--bg);
            border:1px solid var(--border); border-radius:10px; padding:1px 8px; white-space:nowrap; }
    .pill.bad { color:var(--red); border-color:rgba(255,77,109,.5); }

    .pk { position:absolute; top:-3px; left:0; width:8px; height:8px; border-radius:50%; opacity:0;
          background:var(--cyan); box-shadow:0 0 9px var(--cyan);
          animation-duration:.1s; animation-timing-function:linear; animation-iteration-count:1; }
    .lnk.cmd .pk { background:var(--amber); box-shadow:0 0 9px var(--amber); }
    .pk.a { animation-name:travelA; }
    .pk.b { animation-name:travelB; }   /* same motion; toggling the name restarts the animation */
    @keyframes travelA { 0% { left:0; opacity:1; } 100% { left:calc(100% - 8px); opacity:1; } }
    @keyframes travelB { 0% { left:0; opacity:1; } 100% { left:calc(100% - 8px); opacity:1; } }
    /* ---- 3D: live 4WD vehicle ---- */
    .lv-stage { border:1px solid var(--border); border-radius:10px; overflow:hidden; background:#080c12; }
    .lv-stage svg { display:block; width:100%; height:auto; }
    .lv-stage text { font-family:"JetBrains Mono","Fira Code",Consolas,monospace; }
    .lv-lbl { fill:#c9d6e2; font-size:11px; font-weight:700; letter-spacing:.1em; }
    .lv-rpm { fill:#6b7f94; font-size:8px; }
    .lv-side { fill:#6b7f94; font-size:8px; letter-spacing:.22em; }
    .lv-front { fill:#00b8ff; font-size:8px; letter-spacing:.2em; }
    .lv-hud { fill:#6b7f94; font-size:9px; letter-spacing:.14em; }
    .lv-hud.c { fill:#00b8ff; }
    .lv-panel { background:var(--panel); border:1px solid var(--border); border-radius:10px;
                padding:.9rem 1rem; height:100%; box-sizing:border-box; }
    .lv-badges { display:flex; flex-wrap:wrap; gap:.4rem; margin-bottom:.8rem; }
    .lv-badge { font-size:.6rem; letter-spacing:.18em; padding:2px 9px; border-radius:9px;
                border:1px solid; white-space:nowrap; }
    .lv-badge.g { color:var(--green); border-color:rgba(0,229,160,.5); }
    .lv-badge.c { color:var(--cyan); border-color:rgba(0,184,255,.5); }
    .lv-badge.a { color:var(--amber); border-color:rgba(255,176,32,.5); }
    .lv-k { font-size:.58rem; letter-spacing:.22em; color:var(--muted); text-transform:uppercase;
            margin:.7rem 0 .35rem 0; }
    .lv-row { display:flex; justify-content:space-between; align-items:baseline;
              padding:.28rem 0; border-bottom:1px solid var(--border); font-size:.8rem; }
    .lv-row span:first-child { color:var(--muted); letter-spacing:.1em; font-size:.68rem; }
    .lv-row span:last-child { font-weight:700; }
    .lv-wgrid { display:grid; grid-template-columns:1fr 1fr; gap:.5rem; }
    .lv-w { background:#0a121b; border:1px solid var(--border); border-left:3px solid var(--muted);
            border-radius:6px; padding:.4rem .6rem; }
    .lv-w.fwd { border-left-color:var(--green); } .lv-w.rev { border-left-color:var(--amber); }
    .lv-w-k { font-size:.6rem; letter-spacing:.2em; color:var(--muted); }
    .lv-w-v { font-size:.85rem; font-weight:700; margin-top:.1rem; }
    .lv-side-note { font-size:.55rem; letter-spacing:.12em; color:var(--muted); margin-top:.5rem; }
    .tsub { font-size:.68rem; letter-spacing:.22em; text-transform:uppercase; color:var(--cyan);
            margin:1.2rem 0 .35rem 0; padding-left:.6rem; border-left:2px solid var(--cyan); }
    /* ---- 3F: Security Layer 1 (cyan = cryptographic, green = accept, red = reject, amber = replay) ---- */
    .l1-title { font-size:1.35rem; font-weight:800; letter-spacing:.3em; color:var(--cyan);
                margin:.1rem 0 .6rem 0; padding-bottom:.45rem; border-bottom:2px solid var(--cyan);
                text-shadow:0 0 14px rgba(0,184,255,.30); }
    .l1-q { font-size:.82rem; letter-spacing:.06em; margin:0 0 .8rem 0; }
    .l1-q b { color:var(--cyan); letter-spacing:.14em; }
    .l1-q span { display:block; font-size:.66rem; color:var(--muted); margin-top:.2rem; }
    .l1-split { display:grid; grid-template-columns:1fr 1fr; gap:.7rem; margin-bottom:.9rem; }
    @media (max-width:800px) { .l1-split { grid-template-columns:1fr; } }
    .l1-box { background:var(--panel); border:1px solid var(--border); border-radius:6px;
              padding:.6rem .9rem; }
    .l1-box.impl { border-left:3px solid var(--cyan); }
    .l1-box.viz { border:1px dashed rgba(255,176,32,.6); border-left:3px solid var(--amber); }
    .l1-box-k { font-size:.6rem; letter-spacing:.22em; color:var(--muted); text-transform:uppercase; }
    .l1-box-v { font-size:.8rem; font-weight:700; margin:.3rem 0 .2rem 0; }
    .l1-box.impl .l1-box-v { color:var(--cyan); }
    .l1-box.viz .l1-box-v { color:var(--amber); letter-spacing:.12em; }
    .l1-box-n { font-size:.64rem; color:var(--muted); line-height:1.45; }
    .stile.num.g { border-left-color:var(--green); } .stile.num.g .stile-v { color:var(--green); }
    .stile.num.r { border-left-color:var(--red); }   .stile.num.r .stile-v { color:var(--red); }
    .l1-feed { overflow-x:auto; background:#080c12; border:1px solid var(--border); border-radius:8px; }
    .l1-r { display:grid; grid-template-columns:5.4rem 4.4rem minmax(9rem,1.3fr) 4rem minmax(12rem,2fr);
            gap:.5rem; align-items:baseline; min-width:34rem; padding:.38rem .7rem; font-size:.76rem;
            border-bottom:1px solid var(--border); border-left:3px solid var(--border); }
    .l1-r:last-child { border-bottom:none; }
    .l1-r.hd { font-size:.58rem; letter-spacing:.22em; color:var(--muted); background:var(--panel);
               border-left-color:transparent; }
    .l1-r.ok { border-left-color:var(--green); } .l1-r.ok .l1-res { color:var(--green); }
    .l1-r.bad { border-left-color:var(--red); }  .l1-r.bad .l1-res { color:var(--red); }
    .l1-r.warn { border-left-color:var(--amber); } .l1-r.warn .l1-res { color:var(--amber); }
    .l1-r.sel { background:#0c1824; }
    .l1-res { font-weight:700; letter-spacing:.08em; }
    .l1-why { font-weight:400; letter-spacing:.06em; margin-left:.5rem; opacity:.85; }
    .l1-empty { padding:1rem; font-size:.74rem; color:var(--muted); }
    .lv-badge.r { color:var(--red); border-color:rgba(255,77,109,.5); }
    .l1-hex { font-weight:400; font-size:.66rem; word-break:break-all; text-align:right; color:var(--cyan);
              max-width:68%; }
    .l1-hex.dim { color:var(--muted); }
    .l1-val.ok { color:var(--green); } .l1-val.bad { color:var(--red); } .l1-val.warn { color:var(--amber); }
    /* ---- 3G: Security Layer 2 (violet = this layer's identity; green/amber/red = verdict) ---- */
    :root { --violet:#a78bfa; }
    .sgrid.s5 { grid-template-columns:repeat(5,1fr); }
    @media (max-width:800px) { .sgrid.s5 { grid-template-columns:repeat(2,1fr); } }
    .l2-title { font-size:1.35rem; font-weight:800; letter-spacing:.3em; color:var(--violet);
                margin:.1rem 0 .6rem 0; padding-bottom:.45rem; border-bottom:2px solid var(--violet);
                text-shadow:0 0 14px rgba(167,139,250,.30); }
    .l2-q { font-size:.82rem; letter-spacing:.06em; margin:0 0 .5rem 0; }
    .l2-q b { color:var(--violet); letter-spacing:.14em; }
    .l2-q span { display:block; font-size:.66rem; color:var(--muted); margin-top:.2rem; }
    .l2-cmp { display:grid; grid-template-columns:1fr auto 1fr; gap:.7rem; align-items:stretch; margin:.5rem 0 .3rem 0; }
    @media (max-width:800px) { .l2-cmp { grid-template-columns:1fr; } .l2-plus { display:none; } }
    .l2-c { background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:.6rem .9rem; }
    .l2-c.c1 { border-left:3px solid var(--cyan); } .l2-c.c2 { border-left:3px solid var(--violet); }
    .l2-ck { font-size:.6rem; letter-spacing:.22em; }
    .l2-c.c1 .l2-ck { color:var(--cyan); } .l2-c.c2 .l2-ck { color:var(--violet); }
    .l2-cv { font-size:.8rem; font-weight:700; margin:.25rem 0; }
    .l2-cq { font-size:.7rem; letter-spacing:.1em; color:var(--muted); line-height:1.5; }
    .l2-plus { align-self:center; font-size:1.6rem; color:var(--muted); }
    .l2-card { display:grid; grid-template-columns:minmax(13rem,1fr) 2.4fr; gap:1.4rem; margin:.9rem 0 .4rem 0;
               background:var(--panel); border:1px solid var(--border); border-left:5px solid var(--border);
               border-radius:8px; padding:1rem 1.2rem; }
    @media (max-width:800px) { .l2-card { grid-template-columns:1fr; } }
    .l2-card.ok { border-left-color:var(--green); } .l2-card.warn { border-left-color:var(--amber); }
    .l2-card.bad { border-left-color:var(--red); background:linear-gradient(135deg,#1a0d14,#0f1620); }
    .l2-card.info { border-left-color:var(--cyan); }
    .l2-vk { font-size:.58rem; letter-spacing:.22em; color:var(--muted); text-transform:uppercase; margin-top:.5rem; }
    .l2-vk:first-child { margin-top:0; }
    .l2-vv { font-size:1.25rem; font-weight:800; letter-spacing:.14em; margin-top:.2rem; }
    .l2-score { font-size:2.4rem; font-weight:800; line-height:1.1; letter-spacing:.04em; }
    .l2-card.ok .l2-vv, .l2-card.ok .l2-score { color:var(--green); }
    .l2-card.warn .l2-vv, .l2-card.warn .l2-score { color:var(--amber); }
    .l2-card.bad .l2-vv, .l2-card.bad .l2-score { color:var(--red); }
    .l2-card.info .l2-vv { color:var(--cyan); } .l2-card.info .l2-score { color:var(--muted); }
    .l2-gauge { position:relative; height:22px; background:#0a121b; border:1px solid var(--border);
                border-radius:11px; overflow:visible; margin-top:.3rem; }
    .l2-fill { height:100%; border-radius:11px; }
    .l2-card.ok .l2-fill { background:linear-gradient(90deg, rgba(0,229,160,.25), var(--green)); }
    .l2-card.warn .l2-fill { background:linear-gradient(90deg, rgba(255,176,32,.25), var(--amber)); }
    .l2-card.bad .l2-fill { background:linear-gradient(90deg, rgba(255,77,109,.30), var(--red));
                            box-shadow:0 0 14px rgba(255,77,109,.55); }
    .l2-thr { position:absolute; top:-5px; bottom:-5px; width:2px; background:var(--amber);
              box-shadow:0 0 6px var(--amber); }
    .l2-ticks { display:flex; justify-content:space-between; font-size:.58rem; letter-spacing:.12em;
                color:var(--muted); margin-top:.45rem; }
    .l2-explain { font-size:.78rem; line-height:1.5; margin-top:.8rem; }
    .l2-card.ok .l2-explain b { color:var(--green); } .l2-card.warn .l2-explain b { color:var(--amber); }
    .l2-card.bad .l2-explain b { color:var(--red); letter-spacing:.08em; }
    .l2-diag { display:grid; grid-template-columns:repeat(4,1fr); gap:.5rem; margin-top:.8rem; }
    @media (max-width:800px) { .l2-diag { grid-template-columns:repeat(2,1fr); } }
    .l2-diag > div { background:#0a121b; border:1px solid var(--border); border-radius:6px; padding:.4rem .6rem; }
    .l2-dk { font-size:.55rem; letter-spacing:.16em; color:var(--muted); text-transform:uppercase; }
    .l2-dv { font-size:.74rem; font-weight:700; margin-top:.15rem; }
    .l2-note { font-size:.58rem; letter-spacing:.06em; color:var(--muted); margin-top:.7rem; }
    .l2-feat { background:#080c12; border:1px solid var(--border); border-radius:8px; overflow-x:auto; }
    .l2-fr { display:grid; grid-template-columns:1.4rem minmax(8.5rem,1.2fr) minmax(7.5rem,1fr) minmax(4rem,1fr);
             gap:.5rem; align-items:center; min-width:21rem; padding:.3rem .6rem; font-size:.7rem;
             border-bottom:1px solid var(--border); }
    .l2-fr:last-child { border-bottom:none; }
    .l2-fr.hd { font-size:.56rem; letter-spacing:.2em; color:var(--muted); background:var(--panel); }
    .l2-fr span:first-child { color:var(--muted); }
    .l2-fr span:nth-child(3) { font-weight:700; white-space:nowrap; }
    .l2-bar { position:relative; height:8px; background:#0f1620; border-radius:4px; }
    .l2-bar::after { content:""; position:absolute; left:50%; top:-2px; bottom:-2px; width:1px; background:var(--border); }
    .l2-bar i { position:absolute; top:0; height:100%; border-radius:4px; }
    .l2-bar i.pos { background:var(--cyan); } .l2-bar i.neg { background:var(--amber); }
    /* ---- 3H: unified detection breakdown (cyan = Layer 1, violet = Layer 2, green/amber/red = verdict) ---- */
    .dt-title { font-size:1.35rem; font-weight:800; letter-spacing:.3em; color:var(--green);
                margin:.1rem 0 .6rem 0; padding-bottom:.45rem; border-bottom:2px solid var(--green);
                text-shadow:0 0 14px rgba(0,229,160,.30); }
    .dt-q { font-size:.78rem; letter-spacing:.05em; margin:0 0 .3rem 0; }
    .dt-q b.d1 { color:var(--cyan); letter-spacing:.14em; } .dt-q b.d2 { color:var(--violet); letter-spacing:.14em; }
    .dt-q .dt-plus { color:var(--muted); margin:0 .5rem; }
    .dt-disc { font-size:.62rem; letter-spacing:.06em; color:var(--muted); margin:0 0 .6rem 0; line-height:1.5; }
    .dt-verdict { display:grid; grid-template-columns:minmax(15rem,1fr) 2fr; gap:1.4rem; align-items:center;
                  background:var(--panel); border:1px solid var(--border); border-left:6px solid var(--border);
                  border-radius:10px; padding:1rem 1.4rem; margin:.5rem 0 .8rem 0; }
    @media (max-width:800px) { .dt-verdict { grid-template-columns:1fr; } }
    .dt-verdict.ok { border-left-color:var(--green); box-shadow:0 0 22px rgba(0,229,160,.14); }
    .dt-verdict.bad { border-left-color:var(--red); background:linear-gradient(135deg,#1a0d14,#0f1620);
                      box-shadow:0 0 26px rgba(255,77,109,.22); }
    .dt-verdict.mon { border-left-color:var(--cyan); }
    .dt-vk { font-size:.6rem; letter-spacing:.25em; color:var(--muted); text-transform:uppercase; }
    .dt-vv { font-size:1.9rem; font-weight:800; letter-spacing:.14em; line-height:1.15; margin-top:.3rem; }
    .dt-verdict.ok .dt-vv { color:var(--green); text-shadow:0 0 16px rgba(0,229,160,.40); }
    .dt-verdict.bad .dt-vv { color:var(--red); text-shadow:0 0 16px rgba(255,77,109,.45); }
    .dt-verdict.mon .dt-vv { color:var(--amber); }
    .dt-why { font-size:.8rem; line-height:1.5; }
    .dt-meta { display:flex; flex-wrap:wrap; gap:.5rem; margin-top:.6rem; }
    .dt-meta span { font-size:.6rem; letter-spacing:.16em; padding:2px 9px; border-radius:9px; border:1px solid;
                    white-space:nowrap; }
    .dt-meta .d1 { color:var(--cyan); border-color:rgba(0,184,255,.5); }
    .dt-meta .d2 { color:var(--violet); border-color:rgba(167,139,250,.5); }
    .dt-pipe { display:grid; grid-template-columns:1fr auto 1.5fr auto 1fr; gap:.5rem; align-items:center;
               margin:.2rem 0 .3rem 0; }
    @media (max-width:800px) { .dt-pipe { grid-template-columns:1fr; } .dt-arrow { transform:rotate(90deg); } }
    .dt-lanes { display:grid; gap:.45rem; }
    .dt-arrow { color:var(--muted); font-size:1.3rem; text-align:center; }
    .dt-stage { background:var(--panel); border:1px solid var(--border); border-left:3px solid var(--border);
                border-radius:8px; padding:.45rem .8rem; }
    .dt-sk { font-size:.56rem; letter-spacing:.2em; color:var(--muted); text-transform:uppercase; }
    .dt-sk.d1 { color:var(--cyan); } .dt-sk.d2 { color:var(--violet); }
    .dt-sv { font-size:.9rem; font-weight:700; letter-spacing:.12em; margin-top:.15rem; color:var(--muted); }
    .dt-stage.ok { border-color:rgba(0,229,160,.55); border-left-color:var(--green); box-shadow:0 0 12px rgba(0,229,160,.18); }
    .dt-stage.ok .dt-sv { color:var(--green); }
    .dt-stage.bad { border-color:rgba(255,77,109,.55); border-left-color:var(--red); box-shadow:0 0 12px rgba(255,77,109,.25); }
    .dt-stage.bad .dt-sv { color:var(--red); }
    .dt-stage.mon { border-left-color:var(--amber); } .dt-stage.mon .dt-sv { color:var(--amber); }
    .dt-stage.info { border-left-color:var(--cyan); } .dt-stage.info .dt-sv { color:var(--text); }
    .dt-p.d1 { border-top:3px solid var(--cyan); } .dt-p.d2 { border-top:3px solid var(--violet); }
    .dt-ph { font-size:.62rem; letter-spacing:.25em; } .dt-ph.d1 { color:var(--cyan); } .dt-ph.d2 { color:var(--violet); }
    .dt-pt { font-size:.95rem; font-weight:800; letter-spacing:.16em; margin:.15rem 0 .5rem 0; }
    .dt-pn { font-size:.58rem; letter-spacing:.1em; color:var(--muted); margin-top:.5rem; line-height:1.4; }
    .sgrid.s2 { grid-template-columns:repeat(2,1fr); } .sgrid.s3 { grid-template-columns:repeat(3,1fr); }
    .stile.num.z .stile-v { color:var(--muted); }
    .dt-ck { font-size:.6rem; letter-spacing:.22em; margin:0 0 .5rem 0; } .dt-ck.d1 { color:var(--cyan); } .dt-ck.d2 { color:var(--violet); }
    .dt-wb { background:var(--panel); border:1px solid var(--border); border-left:3px solid var(--border);
             border-radius:8px; padding:.6rem .9rem; margin-bottom:.6rem; }
    .dt-wb.d1 { border-left-color:var(--cyan); } .dt-wb.d2 { border-left-color:var(--violet); }
    .dt-wk { font-size:.62rem; letter-spacing:.2em; text-transform:uppercase; margin-bottom:.4rem; font-weight:700; }
    .dt-wb.d1 .dt-wk { color:var(--cyan); } .dt-wb.d2 .dt-wk { color:var(--violet); }
    .dt-wstmt { font-size:.82rem; font-weight:700; color:var(--red); margin-bottom:.4rem; letter-spacing:.04em; }
    .dt-none { font-size:.78rem; color:var(--muted); padding:.8rem 1rem; background:var(--panel);
               border:1px solid var(--border); border-left:3px solid var(--green); border-radius:8px; line-height:1.5; }
    .dt-feed { overflow-x:auto; background:#080c12; border:1px solid var(--border); border-radius:8px; }
    .dt-r { display:grid; grid-template-columns:5.4rem 2.6rem 6.8rem minmax(10rem,1fr); gap:.5rem; align-items:baseline;
            min-width:27rem; padding:.38rem .7rem; font-size:.74rem; border-bottom:1px solid var(--border);
            border-left:3px solid var(--border); }
    .dt-r:last-child { border-bottom:none; }
    .dt-r.hd { font-size:.58rem; letter-spacing:.22em; color:var(--muted); background:var(--panel); border-left-color:transparent; }
    .dt-r.ok { border-left-color:var(--green); } .dt-r.ok .dt-res { color:var(--green); }
    .dt-r.bad { border-left-color:var(--red); } .dt-r.bad .dt-res { color:var(--red); }
    .dt-r.warn { border-left-color:var(--amber); } .dt-r.warn .dt-res { color:var(--amber); }
    .dt-res { font-weight:700; letter-spacing:.08em; }
    .dt-ly { font-weight:700; letter-spacing:.1em; } .dt-ly.d1 { color:var(--cyan); } .dt-ly.d2 { color:var(--violet); }

    /* ---- 3I: Attack Lab ---- */
    .al-title { font-size:1.5rem; font-weight:800; letter-spacing:.3em; color:var(--red); margin:0;
                text-shadow:0 0 16px rgba(255,77,109,.35); }
    .al-sub { font-size:.8rem; color:var(--muted); margin:.15rem 0 .5rem 0; }
    .al-badge { display:inline-block; font-size:.62rem; letter-spacing:.2em; font-weight:700; color:var(--amber);
                border:1px solid rgba(255,176,32,.6); border-radius:4px; padding:2px 10px; margin-bottom:.5rem; }
    .al-disc { font-size:.64rem; color:var(--muted); letter-spacing:.04em; margin:0 0 .8rem 0; line-height:1.5; }
    .al-grp { font-size:.7rem; letter-spacing:.22em; font-weight:700; margin:.6rem 0 .5rem 0; }
    .al-grp.d1 { color:var(--cyan); } .al-grp.d2 { color:var(--violet,#b07cff); }
    .al-desc { font-size:.64rem; color:var(--muted); line-height:1.4; margin:.3rem 0 .4rem 0; min-height:2.1rem; }
    [class*="st-key-atk_l1_"] button { min-height:3.4rem; font-size:.95rem; border-color:rgba(0,184,255,.55); }
    [class*="st-key-atk_l2_"] button { min-height:3.4rem; font-size:.95rem; border-color:rgba(176,124,255,.55); }
    [class*="st-key-atk_l1_"] button:hover:not(:disabled) { border-color:var(--red); color:var(--red); }
    [class*="st-key-atk_l2_"] button:hover:not(:disabled) { border-color:var(--red); color:var(--red); }
    .al-note { font-size:.7rem; color:var(--amber); border:1px solid rgba(255,176,32,.5); border-radius:6px;
               padding:.45rem .8rem; margin:.5rem 0; }
    .al-act { display:grid; grid-template-columns:minmax(11rem,auto) 1fr 1fr 1fr; gap:1rem; align-items:center;
              background:linear-gradient(135deg,#1a0d14,#0f1620); border:1px solid rgba(255,77,109,.7);
              border-left:4px solid var(--red); border-radius:8px; padding:.8rem 1.1rem; margin:.8rem 0;
              box-shadow:0 0 22px rgba(255,77,109,.25); animation:alpulse 1.6s ease-in-out infinite; }
    .al-act.idle { background:var(--panel); border-color:var(--border); border-left-color:var(--green);
                   box-shadow:none; animation:none; }
    @media (max-width:800px) { .al-act { grid-template-columns:1fr; } }
    @keyframes alpulse { 0%,100% { box-shadow:0 0 12px rgba(255,77,109,.20); }
                         50% { box-shadow:0 0 30px rgba(255,77,109,.50); } }
    .al-act-h { font-size:1.1rem; font-weight:800; letter-spacing:.14em; color:var(--red); }
    .al-act.idle .al-act-h { color:var(--green); font-size:.92rem; }
    .al-act-k { font-size:.58rem; letter-spacing:.22em; color:var(--muted); text-transform:uppercase; }
    .al-act-v { font-size:.95rem; font-weight:700; letter-spacing:.08em; margin-top:.15rem; }
    .al-flow { display:flex; flex-wrap:wrap; align-items:stretch; gap:.5rem; margin:.6rem 0 .3rem 0; }
    .al-flow .dt-stage { flex:1 1 9rem; }
    .al-flow .dt-arrow { align-self:center; }
    .al-r { display:grid; grid-template-columns:4.6rem 1fr 4.8rem 7.2rem; gap:.5rem; padding:.38rem .7rem;
            font-size:.72rem; border-left:3px solid transparent; border-bottom:1px solid var(--border);
            background:var(--panel); }
    .al-r.hd { font-size:.58rem; letter-spacing:.22em; color:var(--muted); }
    .al-r.ok { border-left-color:var(--green); } .al-r.ok .al-st { color:var(--green); }
    .al-r.bad { border-left-color:var(--red); } .al-r.bad .al-st { color:var(--red); }
    .al-r.warn { border-left-color:var(--amber); } .al-r.warn .al-st { color:var(--amber); }
    .al-st { font-weight:700; letter-spacing:.08em; }
    .al-feed { border:1px solid var(--border); border-radius:6px; overflow:hidden; }
    .node.attacker.hot { border:2px solid var(--red); box-shadow:0 0 26px rgba(255,77,109,.60);
                         animation:alhot 1s ease-in-out infinite; }
    @keyframes alhot { 0%,100% { box-shadow:0 0 14px rgba(255,77,109,.35); }
                       50% { box-shadow:0 0 34px rgba(255,77,109,.80); } }
    .chip.hot { color:var(--red); border-color:rgba(255,77,109,.8); }
    .lnk.bad.hot { border-top:3px solid var(--red); box-shadow:0 0 10px rgba(255,77,109,.60); }
    .lnk.bad.hot::after { border-left-color:var(--red); }
    .pill.bad.hot { background:#2a0f18; font-weight:700; }
    .pk.hot { background:var(--red); box-shadow:0 0 10px var(--red); animation-name:travelA;
              animation-duration:.9s; animation-iteration-count:infinite; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ----------------------------------------------------------------------------
# 3F: SECURITY LAYER 1 - cryptographic authentication panel
# ----------------------------------------------------------------------------
# WHAT IS REAL AND WHAT IS NOT
#   The real Layer 1 is the C code (canary_verify.c): sender allowlist -> Monocypher Ed25519
#   -> BLAKE3 hash-tree freshness -> strict epoch/replay check -> replay state committed only
#   on accept, default deny. THIS DASHBOARD DOES NOT CALL IT and does no Ed25519/BLAKE3 work.
#   Everything on screen is labelled SIMULATED / DEMONSTRATION. What the dashboard does:
#     MIRROR   - the policy half of the pipeline (sender allowlist + strictly increasing epoch)
#                is re-evaluated in plain Python, so those results are genuinely computed;
#     NOT COMPUTED - signature and freshness: simulator messages carry placeholder bytes and
#                there is no crypto here, so nothing pretends to have checked them;
#     DECLARED - for a scenario the dashboard cannot compute (a tampered packet) the scenario
#                declares the outcome, and the panel says so.
#   No key material is read, stored or displayed anywhere in this file.
L1_EVENT_MAX = 40        # bounded history: the oldest event falls off the tail
L1_FEED_ROWS = 10        # rows drawn in the live feed (recursion depth never exceeds this)

# Same trust set as is_trusted_sender() in canary_verify.c. Node 5 (attacker) is never trusted.
TRUSTED_SENDERS = (NODE_ENCODER, NODE_IMU, NODE_GATEWAY)
FL_STREAM = (NODE_ENCODER, MSG_WHEEL_SPEED, WHEEL_FL)
GZ_STREAM = (NODE_IMU, MSG_IMU_DATA, IMU_GZ)
GATEWAY_STREAM = (NODE_GATEWAY, MSG_MOTION_CMD, 0)
# Allowlist: Node 1 wheel streams, Node 2 IMU streams, plus ONE demo stream for the
# configuration-driven Node 6 (the C verifier needs Node 6 streams configured explicitly).
CONFIGURED_STREAMS = (
    {(NODE_ENCODER, MSG_WHEEL_SPEED, s) for s in (WHEEL_FL, WHEEL_FR, WHEEL_RL, WHEEL_RR)}
    | {(NODE_IMU, MSG_IMU_DATA, s) for s in (IMU_AX, IMU_AY, IMU_AZ, IMU_GX, IMU_GY, IMU_GZ)}
    | {GATEWAY_STREAM}
)

L1_NODE_NAMES = {NODE_ENCODER: "ENCODER", NODE_IMU: "IMU", NODE_MOTOR: "MOTOR",
                 NODE_SECURITY: "SECURITY", NODE_ATTACKER: "UNTRUSTED / ATTACKER",
                 NODE_GATEWAY: "GATEWAY"}
L1_MSG_NAMES = {MSG_WHEEL_SPEED: "WHEEL_SPEED", MSG_IMU_DATA: "IMU_DATA",
                MSG_MOTION_CMD: "MOTION_CMD", MSG_MOTOR_ACK: "MOTOR_ACK"}
L1_SUBTYPE_NAMES = {
    MSG_WHEEL_SPEED: {WHEEL_FL: "FL", WHEEL_FR: "FR", WHEEL_RL: "RL", WHEEL_RR: "RR"},
    MSG_IMU_DATA: {IMU_AX: "AX", IMU_AY: "AY", IMU_AZ: "AZ", IMU_GX: "GX", IMU_GY: "GY", IMU_GZ: "GZ"},
}
# Result codes follow the CANARY_VERIFY_REJECT_* names in canary_verify.h.
L1_REASONS = {
    "UNTRUSTED_SENDER": "UNTRUSTED SENDER",
    "UNKNOWN_STREAM": "UNKNOWN STREAM",
    "BAD_SIGNATURE": "SIGNATURE INVALID",
    "BAD_FRESHNESS": "FRESHNESS INVALID",
    "REPLAY": "REPLAY / STALE EPOCH",
}


def _sub_name(msg_type, subtype):
    return L1_SUBTYPE_NAMES.get(msg_type, {}).get(subtype, str(subtype))


def _hex_html(data, what):
    """Short, safe view of signature/freshness bytes. Placeholder (all-zero) bytes are called out."""
    if not any(data):
        return '<span class="l1-hex dim">%d B all-zero %s placeholder</span>' % (len(data), what)
    h = bytes(data).hex()
    return '<span class="l1-hex">%s…%s · %d B</span>' % (h[:16], h[-8:], len(data))


# --- INHERITANCE: one small base class, specialised per outcome -------------
class SecurityEvent:
    """One Layer 1 verification event. Subclasses fix the verdict, icon and colour tone;
    everything else (rendering, labels) is shared here."""
    verdict = "?"
    icon = "?"
    tone = "info"

    def __init__(self, seq, clock, msg, code, source, basis):
        self.seq = seq          # monotonically increasing event id
        self.clock = clock      # wall-clock HH:MM:SS when the event was logged
        self.msg = msg          # the CANARYMessage that was checked (never modified)
        self.code = code        # result code, e.g. "ACCEPT" or "UNTRUSTED_SENDER"
        self.source = source    # SIMULATOR / DASHBOARD DEMO / INJECTED
        self.basis = basis      # MIRROR (computed policy check) or DECLARED (scenario says so)

    def note(self):
        return ""

    def node_label(self):
        return "NODE %d" % self.msg.sender_id

    def msg_label(self):
        return "%s %s" % (L1_MSG_NAMES.get(self.msg.msg_type, str(self.msg.msg_type)),
                          _sub_name(self.msg.msg_type, self.msg.subtype))

    def result_text(self):
        return "%s %s" % (self.icon, self.verdict)

    def row_html(self, selected=False):
        note = self.note()
        note_html = '<span class="l1-why">%s</span>' % note if note else ""
        return ('<div class="l1-r %s%s"><span>%s</span><span>%s</span><span>%s</span><span>%d</span>'
                '<span class="l1-res">%s%s</span></div>'
                % (self.tone, " sel" if selected else "", self.clock, self.node_label(),
                   self.msg_label(), self.msg.epoch, self.result_text(), note_html))


class AcceptedEvent(SecurityEvent):
    verdict, icon, tone = "ACCEPT", "✓", "ok"

    def note(self):
        return "simulated"


class RejectedEvent(SecurityEvent):
    verdict, icon, tone = "REJECT", "✗", "bad"

    def note(self):
        return L1_REASONS.get(self.code, self.code)


class ReplayRejectedEvent(RejectedEvent):
    tone = "warn"           # replay / freshness failures are amber, not red


def make_event(seq, clock, msg, code, source, basis):
    if code == "ACCEPT":
        cls = AcceptedEvent
    elif code in ("REPLAY", "BAD_FRESHNESS"):
        cls = ReplayRejectedEvent
    else:
        cls = RejectedEvent
    return cls(seq, clock, msg, code, source, basis)


# --- LINKED LIST: bounded verification history, newest event at the head ----
class _EventNode:
    __slots__ = ("event", "next")

    def __init__(self, event, nxt):
        self.event = event
        self.next = nxt


class EventLog:
    def __init__(self, max_len=L1_EVENT_MAX):
        self.head = None
        self.size = 0
        self.max_len = max_len

    def push(self, event):
        self.head = _EventNode(event, self.head)
        self.size += 1
        if self.size > self.max_len:         # cut the tail so the list can never grow without bound
            node = self.head
            for _ in range(self.max_len - 1):
                node = node.next
            node.next = None
            self.size = self.max_len

    def recent(self, limit):
        node = self.head
        while node is not None and limit > 0:
            yield node.event
            node, limit = node.next, limit - 1


# --- RECURSION: walk the list toward the tail; depth <= the limit passed in ---
def feed_rows_html(node, limit, selected_seq):
    """Render up to `limit` feed rows from `node` onward (depth <= L1_FEED_ROWS)."""
    if node is None or limit <= 0:
        return ""
    return node.event.row_html(node.event.seq == selected_seq) + \
        feed_rows_html(node.next, limit - 1, selected_seq)


def find_event(node, seq):
    """Look an event up by id (depth <= L1_EVENT_MAX because the list is bounded)."""
    if node is None:
        return None
    if node.event.seq == seq:
        return node.event
    return find_event(node.next, seq)


class Layer1Monitor:
    """Holds the Layer 1 counters, the bounded event log and the policy MIRROR state.
    It performs NO cryptography; see the 3F header comment."""

    def __init__(self):
        self.log = EventLog()
        self.accepted = 0
        self.rejected = 0
        self.rejects_by_code = {}
        self.last_epoch = {}       # mirror replay state: stream -> highest accepted epoch
        self.last_accepted = {}    # stream -> last accepted message (used by inject())
        self._seen = {}            # newest (msg, code) per stream since the last log_tick()
        self._seq = 0

    # ---- policy mirror: same order as canary_verify_message(), crypto stages skipped ----
    def _mirror(self, msg):
        if msg.sender_id not in TRUSTED_SENDERS:
            return "UNTRUSTED_SENDER"
        key = (msg.sender_id, msg.msg_type, msg.subtype)
        if key not in CONFIGURED_STREAMS:
            return "UNKNOWN_STREAM"
        # Ed25519 signature and BLAKE3 freshness are checked by the C verifier here.
        # The dashboard does NOT compute them.
        last = self.last_epoch.get(key)
        if last is not None and msg.epoch <= last:
            return "REPLAY"
        self.last_epoch[key] = msg.epoch       # commit only after every check passed
        return "ACCEPT"

    def _verify(self, msg, declared=None):
        if declared is not None:
            code, basis = declared, "DECLARED"
        else:
            code, basis = self._mirror(msg), "MIRROR"
        if code == "ACCEPT":
            self.accepted += 1
            self.last_accepted[(msg.sender_id, msg.msg_type, msg.subtype)] = msg
        else:
            self.rejected += 1
            self.rejects_by_code[code] = self.rejects_by_code.get(code, 0) + 1
        return code, basis

    def _log(self, msg, code, source, basis):
        self._seq += 1
        event = make_event(self._seq, time.strftime("%H:%M:%S"), msg, code, source, basis)
        self.log.push(event)
        return event

    def observe_sample(self, sample):
        """Every simulator step: run all 10 real simulator messages through the mirror (counters)."""
        for msg in sample["messages"]:
            code, basis = self._verify(msg)
            self._seen[(msg.sender_id, msg.msg_type, msg.subtype)] = (msg, code, basis)

    def log_tick(self, sample):
        """Once per dashboard refresh: log one representative event per sender into the feed,
        so the feed stays readable. Counters above still cover every message."""
        gateway = CANARYMessage(NODE_GATEWAY, MSG_MOTION_CMD, 0, sample["messages"][0].epoch, 0)
        g_code, g_basis = self._verify(gateway)       # dashboard-generated demo command, payload 0
        # pushed in reverse so each refresh reads NODE 1, NODE 2, NODE 6 from the top
        self._log(gateway, g_code, "DASHBOARD DEMO", g_basis)
        for key in (GZ_STREAM, FL_STREAM):
            seen = self._seen.get(key)
            if seen:
                self._log(seen[0], seen[1], "SIMULATOR", seen[2])
        self._seen.clear()

    def inject(self, kind):
        """PHASE 3I ENTRY POINT - not wired to any button yet (no Attack Lab here).
        kind: FORGED_SENDER | TAMPERED | REPLAY. Needs one accepted Node 1 FL message first."""
        base = self.last_accepted.get(FL_STREAM)
        if base is None:
            return None
        declared = None
        if kind == "FORGED_SENDER":
            # Node 5 has no key, so the packet stays unsigned. The mirror rejects it by sender.
            msg = CANARYMessage(NODE_ATTACKER, MSG_WHEEL_SPEED, WHEEL_FL, base.epoch + 1, base.payload)
        elif kind == "TAMPERED":
            msg = replace(base, payload=base.payload + 1000)   # signed bytes changed
            declared = "BAD_SIGNATURE"        # DECLARED: no signature is computed in the dashboard
        elif kind == "REPLAY":
            msg = base                        # same epoch sent again; the mirror's epoch rule rejects it
        else:
            raise ValueError("unknown Layer 1 event kind: %r" % (kind,))
        code, basis = self._verify(msg, declared)
        return self._log(msg, code, "INJECTED", basis)


def l1_status_html(mon):
    rc = mon.rejects_by_code
    head = mon.log.head.event if mon.log.head else None
    if rc.get("BAD_SIGNATURE"):
        sig = _tile("Ed25519 signature", "INVALID (DECLARED)", "bad")
    else:
        sig = _tile("Ed25519 signature", "NOT COMPUTED", "info")
    if rc.get("BAD_FRESHNESS"):
        fresh = _tile("BLAKE3 freshness", "STALE (DECLARED)", "warn")
    else:
        fresh = _tile("BLAKE3 freshness", "NOT COMPUTED", "info")
    replay = (_tile("Replay / epoch", "REPLAY REJECTED", "warn") if rc.get("REPLAY")
              else _tile("Replay / epoch", "EPOCH RULE (SIM)", "ok"))
    sender = (_tile("Sender authorization", "NODE 5 REJECTED", "bad") if rc.get("UNTRUSTED_SENDER")
              else _tile("Sender authorization", "ALLOWLIST (SIM)", "ok"))
    last = (_tile("Last verdict", head.result_text(), head.tone) if head
            else _tile("Last verdict", "-", "num"))
    tiles = [
        _tile("Layer 1 status", "DEMO MODE", "warn"), sig, fresh, replay,
        sender, last,
        _tile("Accepted packets", format(mon.accepted, ","), "num g"),
        _tile("Rejected packets", format(mon.rejected, ","), "num r"),
    ]
    return '<div class="sgrid">' + "".join(tiles) + "</div>"


def l1_intro_html():
    return (
        '<p class="l1-q"><b>Layer 1 answers:</b> WHO SENT THIS MESSAGE, AND IS IT FRESH?'
        '<span>It does not judge sensor physics. Spotting readings that contradict each other is '
        "Layer 2's job.</span></p>"
        '<div class="l1-split">'
        '<div class="l1-box impl"><div class="l1-box-k">Layer 1 implementation</div>'
        '<div class="l1-box-v">C · Monocypher Ed25519 · BLAKE3 hash-tree freshness · strict epoch '
        'replay check · default deny</div>'
        '<div class="l1-box-n">Authoritative and tested on its own. NOT invoked by this dashboard.</div></div>'
        '<div class="l1-box viz"><div class="l1-box-k">Dashboard verification visualization</div>'
        '<div class="l1-box-v">SIMULATED / DEMONSTRATION</div>'
        '<div class="l1-box-n">Sender allowlist and epoch rule are mirrored in Python. '
        'Signature and freshness are NOT computed here.</div></div>'
        '</div>')


def l1_detail_html(ev):
    if ev is None:
        return ('<div class="lv-panel"><div class="lv-k">Selected packet</div>'
                '<p class="sublabel">No packets yet - press START.</p></div>')
    m = ev.msg
    tone = {"ok": "g", "bad": "r", "warn": "a"}.get(ev.tone, "c")
    rows = [
        ("Sender", "NODE %d · %s" % (m.sender_id, L1_NODE_NAMES.get(m.sender_id, "?"))),
        ("Message type", "%s (%d)" % (L1_MSG_NAMES.get(m.msg_type, "?"), m.msg_type)),
        ("Subtype", "%s (%d)" % (_sub_name(m.msg_type, m.subtype), m.subtype)),
        ("Epoch", str(m.epoch)),
        ("Payload", "%d (int32)" % m.payload),
        ("Signature", _hex_html(m.signature, "signature")),
        ("Freshness", _hex_html(m.freshness, "freshness")),
        ("Verification result", '<span class="l1-val %s">%s%s</span>' % (
            ev.tone, ev.result_text(), (" · " + ev.note()) if ev.note() else "")),
    ]
    body = "".join('<div class="lv-row"><span>%s</span><span>%s</span></div>' % r for r in rows)
    if ev.basis == "DECLARED":
        basis = "Outcome DECLARED by the demo scenario. No signature was computed or checked."
    else:
        basis = ("Computed by the dashboard policy mirror (sender allowlist + epoch rule). "
                 "Ed25519 and BLAKE3 were NOT computed; the C verifier was NOT invoked.")
    return ('<div class="lv-panel"><div class="lv-k">Selected packet</div>'
            '<div class="lv-badges"><span class="lv-badge %s">%s</span>'
            '<span class="lv-badge c">SIMULATED</span><span class="lv-badge a">%s</span></div>'
            '%s<div class="lv-side-note">%s</div></div>'
            % (tone, ev.result_text(), ev.source, body, basis))


def layer1_section(mon):
    st.markdown('<p class="label">SECURITY LAYER 1</p>', unsafe_allow_html=True)
    st.markdown('<p class="l1-title">CRYPTOGRAPHIC AUTHENTICATION</p>', unsafe_allow_html=True)
    st.markdown(l1_intro_html(), unsafe_allow_html=True)
    st.markdown(l1_status_html(mon), unsafe_allow_html=True)

    shown = list(mon.log.recent(L1_FEED_ROWS))
    options = [-1] + [e.seq for e in shown]            # -1 = follow the newest packet
    if st.session_state.get("l1_sel", -1) not in options:
        st.session_state["l1_sel"] = -1                # selected packet scrolled off the feed

    def _option_label(seq):
        if seq == -1:
            return "Newest packet (auto)"
        ev = find_event(mon.log.head, seq)
        return "#%d  %s  %s  %s" % (seq, ev.clock, ev.node_label(), ev.msg_label()) if ev else str(seq)

    feed_col, detail_col = st.columns([3, 2])
    with detail_col:
        st.markdown('<p class="tsub">Packet details</p>', unsafe_allow_html=True)
        sel = st.selectbox("Inspect packet", options, key="l1_sel", format_func=_option_label,
                           label_visibility="collapsed")
        chosen = mon.log.head.event if (sel == -1 and mon.log.head) else find_event(mon.log.head, sel)
        st.markdown(l1_detail_html(chosen), unsafe_allow_html=True)
    with feed_col:
        st.markdown('<p class="tsub">Live verification feed</p>', unsafe_allow_html=True)
        st.markdown('<p class="sublabel">Newest first · %d of %d kept · one sample event per sender '
                    'per refresh · counters cover every message · all results SIMULATED</p>'
                    % (len(shown), L1_EVENT_MAX), unsafe_allow_html=True)
        header = ('<div class="l1-r hd"><span>TIME</span><span>NODE</span><span>MESSAGE</span>'
                  '<span>EPOCH</span><span>RESULT</span></div>')
        if shown:
            rows = feed_rows_html(mon.log.head, L1_FEED_ROWS, chosen.seq if chosen else None)
        else:
            rows = '<div class="l1-empty">No packets yet - press START.</div>'
        st.markdown('<div class="l1-feed">%s%s</div>' % (header, rows), unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# 3G: SECURITY LAYER 2 - physical / behavioral anomaly detection (Random Forest)
# ----------------------------------------------------------------------------
# This is REAL inference. The persisted Random Forest (models/layer2_random_forest.pkl) is loaded
# once through the existing Layer2IDS (simulation/layer2_ids.py) and every score on screen is that
# model's own predict_proba. Inputs are SENSOR values only (encoders + simulated IMU) built by the
# existing extract_features(); simulator ground truth is never a model feature. Nothing is hardcoded
# or random. Layer 2 is a machine-learning model, NOT cryptography.
L2_STRIDE = 10            # run inference on every 10th simulator sample (10 Hz at dt=0.01)
L2_HISTORY_MAX = 150      # bounded score history: 150 points ~ 15 s
L2_WATCH_SCORE = 0.25     # display only: amber band between this and the model's own threshold


def _l2_unit(name):
    if name == "acceleration":
        return "m/s²"
    if "yaw" in name:
        return "rad/s"
    return "m/s"


def _l2_scale(name):
    """Full-scale value for the little input bars. Display only, not used by the model."""
    if name == "acceleration":
        return 1.5
    if "yaw" in name:
        return YAW_FULL
    return 1.0


@st.cache_resource(show_spinner=False)
def _load_layer2_cached():
    """Reads the pickle ONCE per server process (cache_resource), never per refresh or timestep.
    Raising here means nothing is cached, so a missing model is retried on the next refresh."""
    if Layer2IDS is None:
        raise RuntimeError("layer2_ids could not be imported: %s" % L2_IMPORT_ERROR)
    ids = Layer2IDS.load()      # existing loader: also checks the JSON feature order matches the code
    with open(L2_FEATURES_PATH) as fh:
        spec = json.load(fh)    # feature ORDER comes from models/layer2_features.json
    model = ids.model
    return {
        "ids": ids, "error": None,
        "features": list(spec["features"]),
        "n_trees": len(model.estimators_),
        "n_features": int(model.n_features_in_),
        "model_name": ("Random Forest" if type(model).__name__ == "RandomForestClassifier"
                       else type(model).__name__),
        "threshold": float(ids.threshold),
    }


def get_layer2():
    try:
        return _load_layer2_cached()
    except Exception as exc:    # model missing / sklearn missing / feature mismatch: show it, no fake data
        return {"ids": None, "error": "%s: %s" % (type(exc).__name__, exc), "features": [],
                "n_trees": 0, "n_features": 0, "model_name": "-", "threshold": 0.5}


def run_layer2_inference(info, sample):
    """One real model call on the sample's SENSOR values (encoders + IMU), never ground truth."""
    enc, imu = sample["encoders"], sample["imu"]
    res = info["ids"].evaluate_state(enc, imu)      # existing Layer2IDS: RandomForest P(ANOMALY)
    return {
        "epoch": sample["messages"][0].epoch,
        "t": sample["timestamp"],
        "prediction": res["prediction"],
        "score": res["anomaly_score"],
        "feats": extract_features(enc, imu),        # the same 11 features the model just received
        "attack": sample.get("attack"),             # simulator's own injection label, display only
    }


def l2_zone(score, threshold):
    if score >= threshold:
        return "bad"
    if score >= L2_WATCH_SCORE:
        return "warn"
    return "ok"


def l2_intro_html():
    return (
        '<p class="l2-q"><b>Layer 2 asks:</b> DO THESE SENSOR VALUES MAKE PHYSICAL SENSE TOGETHER?'
        '<span>It compares wheel encoders with the IMU. It does not look at senders or signatures, '
        'and it is a machine-learning model, not a cryptographic system.</span></p>'
        '<p class="sublabel">Detects physical inconsistencies such as IMU yaw spoofing, wheel-speed '
        'manipulation and left/right side inconsistencies.</p>'
        '<div class="l2-cmp">'
        '<div class="l2-c c1"><div class="l2-ck">LAYER 1</div>'
        '<div class="l2-cv">Cryptographic / message trust</div>'
        '<div class="l2-cq">WHO SENT IT?<br>IS IT FRESH?</div></div>'
        '<div class="l2-plus">+</div>'
        '<div class="l2-c c2"><div class="l2-ck">LAYER 2</div>'
        '<div class="l2-cv">Physical / behavioral trust</div>'
        '<div class="l2-cq">DOES IT MAKE SENSE?</div></div></div>'
        '<p class="sublabel">Complementary layers: an authentic message can still carry impossible '
        'physics, and a plausible-looking reading can still come from the wrong sender.</p>')


def l2_model_tiles_html(info, running):
    if info["ids"] is None:
        tiles = [_tile("Model", "UNAVAILABLE", "bad"), _tile("Trees", "-", "num"),
                 _tile("Features", "-", "num"), _tile("Inference", "OFFLINE", "bad")]
    else:
        tiles = [_tile("Model", info["model_name"].upper(), "info"),
                 _tile("Trees", str(info["n_trees"]), "num"),
                 _tile("Features", str(info["n_features"]), "num"),
                 _tile("Inference", "LIVE" if running else "PAUSED", "ok" if running else "warn")]
    return '<div class="sgrid">' + "".join(tiles) + "</div>"


def l2_diag_html(f):
    gap_l = f["fl_speed"] - f["rl_speed"]
    gap_r = f["fr_speed"] - f["rr_speed"]
    items = [
        ("Yaw residual", "%+.4f rad/s" % f["yaw_residual"]),
        ("Expected → observed yaw", "%+.3f → %+.3f rad/s" % (f["expected_yaw_rate"], f["observed_yaw_rate"])),
        ("Left − right speed", "%+.3f m/s" % (f["left_speed"] - f["right_speed"])),
        ("Wheel disagreement", "FL−RL %+.3f · FR−RR %+.3f m/s" % (gap_l, gap_r)),
    ]
    return '<div class="l2-diag">' + "".join(
        '<div><div class="l2-dk">%s</div><div class="l2-dv">%s</div></div>' % it for it in items) + "</div>"


def l2_verdict_html(info, cur):
    thr = info["threshold"]
    if cur is None:
        return ('<div class="l2-card info"><div><div class="l2-vk">Status</div>'
                '<div class="l2-vv">AWAITING DATA</div><div class="l2-vk">Anomaly score</div>'
                '<div class="l2-score">-</div></div>'
                '<div><div class="l2-gauge"><div class="l2-fill" style="width:0%%"></div>'
                '<div class="l2-thr" style="left:%.1f%%"></div></div>'
                '<div class="l2-explain">No inference yet - press START.</div></div></div>' % (thr * 100))
    score, zone = cur["score"], l2_zone(cur["score"], thr)
    anomaly = cur["prediction"] == "ANOMALY"
    status = cur["prediction"] + (" · WATCH" if zone == "warn" else "")
    if anomaly:
        head = "⚠ PHYSICAL ANOMALY DETECTED"
        body = ("The model finds these sensor values inconsistent with the learned normal region. "
                "It reports inconsistency only; it does not name an attack type.")
    else:
        head = "✓ PHYSICAL CONSISTENCY"
        body = "Sensor relationships are within the learned normal region."
        if zone == "warn":
            body += " Score is elevated but below the threshold."
    inj = cur["attack"] if cur["attack"] else "none"
    return (
        '<div class="l2-card %s"><div>'
        '<div class="l2-vk">Status</div><div class="l2-vv">%s</div>'
        '<div class="l2-vk">Anomaly score</div><div class="l2-score">%.3f</div></div>'
        '<div><div class="l2-gauge"><div class="l2-fill" style="width:%.1f%%"></div>'
        '<div class="l2-thr" style="left:%.1f%%"></div></div>'
        '<div class="l2-ticks"><span>0.00</span><span>threshold %.2f</span><span>1.00</span></div>'
        '<div class="l2-explain"><b>%s</b><br>%s</div>%s'
        '<div class="l2-note">Simulator injection label (demo ground truth, not a model input): %s</div>'
        '</div></div>' % (zone, status, score, score * 100.0, thr * 100.0, thr, head, body,
                          l2_diag_html(cur["feats"]), inj))


def l2_telemetry_html(cur):
    f = cur["feats"] if cur else None
    anomaly = bool(cur) and cur["prediction"] == "ANOMALY"

    def t(label, key, unit, fmt, kind="num"):
        return _tile(label, (fmt % f[key] + " " + unit) if f else "-", kind)

    wheels = [t(n, k, "m/s", "%+.3f") for n, k in
              (("FL", "fl_speed"), ("FR", "fr_speed"), ("RL", "rl_speed"), ("RR", "rr_speed"))]
    motion = [t("Left speed", "left_speed", "m/s", "%+.3f"), t("Right speed", "right_speed", "m/s", "%+.3f"),
              t("Vehicle speed", "vehicle_speed", "m/s", "%+.3f"), t("Acceleration", "acceleration", "m/s²", "%+.3f")]
    yaw = [t("Expected yaw", "expected_yaw_rate", "rad/s", "%+.4f"),
           t("Observed yaw", "observed_yaw_rate", "rad/s", "%+.4f"),
           t("Yaw residual", "yaw_residual", "rad/s", "%+.4f", "num r" if anomaly else "num"),
           _tile("Simulation epoch", str(cur["epoch"]) if cur else "-", "num"),
           _tile("Simulation time", ("%.2f s" % cur["t"]) if cur else "-", "num")]
    return ('<div class="sgrid">%s</div><div class="sgrid" style="margin-top:.7rem">%s</div>'
            '<div class="sgrid s5" style="margin-top:.7rem">%s</div>'
            % ("".join(wheels), "".join(motion), "".join(yaw)))


def l2_features_html(info, cur):
    f = cur["feats"] if cur else None
    rows = ['<div class="l2-fr hd"><span>#</span><span>FEATURE</span><span>VALUE</span><span></span></div>']
    for i, name in enumerate(info["features"]):
        if f:
            v = f[name]
            pct = min(abs(v) / _l2_scale(name), 1.0) * 50.0
            bar = ('<i class="%s" style="%s:50%%;width:%.1f%%"></i>'
                   % ("pos" if v >= 0 else "neg", "left" if v >= 0 else "right", pct))
            val = "%+.4f %s" % (v, _l2_unit(name))
        else:
            bar, val = "", "-"
        rows.append('<div class="l2-fr"><span>%d</span><span>%s</span><span>%s</span>'
                    '<span class="l2-bar">%s</span></div>' % (i, name, val, bar))
    return '<div class="l2-feat">%s</div>' % "".join(rows)


def l2_chart(info, hist):
    if not hist:
        st.markdown('<p class="sublabel">No inferences yet - press START.</p>', unsafe_allow_html=True)
        return
    thr = info["threshold"]
    x = {"field": "t", "type": "quantitative", "title": "sim time (s)", "scale": {"zero": False}}
    y = {"field": "score", "type": "quantitative", "title": "anomaly score", "scale": {"domain": [0, 1]}}
    spec = {
        "width": "container", "height": 190, "background": "transparent",
        "config": {"view": {"stroke": None},
                   "axis": {"labelColor": "#6b7f94", "titleColor": "#6b7f94", "gridColor": "#1c2a3a",
                            "domainColor": "#1c2a3a", "tickColor": "#1c2a3a"}},
        "layer": [
            {"mark": {"type": "line", "color": "#00b8ff", "strokeWidth": 1.5},
             "encoding": {"x": x, "y": y}},
            {"mark": {"type": "point", "filled": True, "size": 26, "opacity": 1},
             "encoding": {"x": x, "y": y,
                          "color": {"value": "#00e5a0",
                                    "condition": [{"test": "datum.score >= %g" % thr, "value": "#ff4d6d"},
                                                  {"test": "datum.score >= %g" % L2_WATCH_SCORE,
                                                   "value": "#ffb020"}]}}},
            {"data": {"values": [{"thr": thr}]},
             "mark": {"type": "rule", "color": "#ffb020", "strokeDash": [6, 4], "strokeWidth": 1.5},
             "encoding": {"y": {"field": "thr", "type": "quantitative"}}},
        ],
    }
    st.vega_lite_chart(pd.DataFrame(hist), spec, theme=None)


def layer2_section(info, cur, hist, running):
    st.markdown('<p class="label">SECURITY LAYER 2</p>', unsafe_allow_html=True)
    st.markdown('<p class="l2-title">PHYSICAL / BEHAVIORAL ANOMALY DETECTION</p>', unsafe_allow_html=True)
    st.markdown(l2_intro_html(), unsafe_allow_html=True)
    st.markdown(l2_model_tiles_html(info, running), unsafe_allow_html=True)
    if info["ids"] is None:
        st.markdown('<div class="l2-card bad"><div><div class="l2-vk">Status</div>'
                    '<div class="l2-vv">MODEL UNAVAILABLE</div></div><div class="l2-explain">'
                    'Layer 2 inference is offline and no scores are shown. %s<br>'
                    'Expected files: models/layer2_random_forest.pkl, models/layer2_features.json.</div></div>'
                    % _esc(info["error"] or ""), unsafe_allow_html=True)
        return
    st.markdown(l2_verdict_html(info, cur), unsafe_allow_html=True)

    tel_col, feat_col = st.columns([3, 2])
    with tel_col:
        st.markdown('<p class="tsub">Live ML telemetry</p>', unsafe_allow_html=True)
        st.markdown('<p class="sublabel">Values the model is scoring right now · from the simulator\'s '
                    'sensors (encoders + IMU), not ground truth</p>', unsafe_allow_html=True)
        st.markdown(l2_telemetry_html(cur), unsafe_allow_html=True)
    with feat_col:
        st.markdown('<p class="tsub">Model input vector</p>', unsafe_allow_html=True)
        st.markdown('<p class="sublabel">%d features · order from models/layer2_features.json</p>'
                    % info["n_features"], unsafe_allow_html=True)
        st.markdown(l2_features_html(info, cur), unsafe_allow_html=True)

    st.markdown('<p class="tsub">Anomaly score history</p>', unsafe_allow_html=True)
    st.markdown('<p class="sublabel">Random Forest P(ANOMALY) · dashed amber line = threshold %.2f · '
                'last %d inferences kept, one per %d simulator samples · %d points now</p>'
                % (info["threshold"], L2_HISTORY_MAX, L2_STRIDE, len(hist)), unsafe_allow_html=True)
    l2_chart(info, hist)


# ----------------------------------------------------------------------------
# 3H: UNIFIED DETECTION BREAKDOWN - Layer 1 + Layer 2 on one screen
# ----------------------------------------------------------------------------
# This section computes NO security result of its own. It only reads:
#   Layer 1: the events and counters of Layer1Monitor (3F). Those are SIMULATED dashboard policy
#            checks (sender allowlist + epoch rule, or an outcome DECLARED by a demo scenario).
#            The C verifier (Ed25519 / BLAKE3) is NOT invoked here and nothing here says it was.
#   Layer 2: the real Random Forest results from run_layer2_inference() (3G).
# The two layers are evaluated INDEPENDENTLY on the same simulator sample: Layer 2 does not wait
# for Layer 1. The verdict only combines their current results.
DT_TIMELINE_MAX = 40        # bounded timeline: the oldest entry falls off (deque maxlen)
DT_TIMELINE_ROWS = 10       # rows drawn
DT_L1_HOLD_TICKS = 25       # a Layer 1 rejection stays on the verdict ~25 refreshes (~4 s) so it can be read
DT_L1_REJECT_ORDER = ("UNTRUSTED_SENDER", "REPLAY", "UNKNOWN_STREAM", "BAD_SIGNATURE", "BAD_FRESHNESS")


class DetectionTracker:
    """3H session state: Layer 2 counters, the bounded detection timeline and the Layer 1 state shown
    in the verdict. Fed only by real Layer 1 events (Layer1Monitor.log) and real Layer 2 inference
    results; it never invents a result. RESET replaces it with a fresh instance."""

    def __init__(self):
        self.l2_normal = 0
        self.l2_anomaly = 0
        self._l2_epoch = -1          # newest epoch already counted: every inference is counted once
        self._l2_state = None        # last Layer 2 prediction written to the timeline
        self._l1_seq = 0             # newest Layer 1 event id already processed
        self._l1_state = None        # last Layer 1 verdict written to the timeline
        self._l1_hold = 0            # refreshes left to keep showing a rejection
        self.l1_current = None       # Layer 1 event shown in the verdict (a rejection wins over accepts)
        self.l1_rejected = False
        self.timeline = deque(maxlen=DT_TIMELINE_MAX)

    def _add(self, clock, layer, tone, result, reason):
        self.timeline.append({"clock": clock, "layer": layer, "tone": tone,
                              "result": result, "reason": reason})

    def observe_l1(self, mon):
        """Once per dashboard refresh, after Layer1Monitor.log_tick(): pick up the new Layer 1 events."""
        fresh = []
        for ev in mon.log.recent(L1_EVENT_MAX):          # newest first
            if ev.seq <= self._l1_seq:
                break
            fresh.append(ev)
        if not fresh:
            return
        self._l1_seq = fresh[0].seq
        for ev in reversed(fresh):                        # oldest first so the timeline reads in order
            where = "%s / %s" % (ev.node_label(), ev.msg_label())
            if ev.verdict == "REJECT":                    # every rejection is logged
                self._add(ev.clock, "L1", ev.tone, "%s REJECT" % ev.icon,
                          "%s · %s" % (L1_REASONS.get(ev.code, ev.code), where))
                self._l1_state = "REJECT"
            elif self._l1_state != "ACCEPT":              # accepts: only when the state changes
                rep = fresh[0] if fresh[0].verdict != "REJECT" else ev   # name the newest sensor event
                self._add(ev.clock, "L1", "ok", "%s ACCEPT" % ev.icon,
                          "%s / %s" % (rep.node_label(), rep.msg_label()))
                self._l1_state = "ACCEPT"
        rejects = [e for e in fresh if e.verdict == "REJECT"]
        if rejects:
            self.l1_current, self.l1_rejected, self._l1_hold = rejects[0], True, DT_L1_HOLD_TICKS
        elif self._l1_hold > 0:
            self._l1_hold -= 1                            # keep the rejection visible a little longer
        else:
            self.l1_current, self.l1_rejected = fresh[0], False

    def record_l2(self, res, threshold):
        """Count one REAL inference result (from run_layer2_inference). Each epoch is counted once."""
        if res is None or res["epoch"] <= self._l2_epoch:
            return
        self._l2_epoch = res["epoch"]
        anomaly = res["prediction"] == "ANOMALY"
        if anomaly:
            self.l2_anomaly += 1
        else:
            self.l2_normal += 1
        if res["prediction"] != self._l2_state:           # timeline: state changes only
            self._l2_state = res["prediction"]
            if anomaly:
                self._add(time.strftime("%H:%M:%S"), "L2", "bad", "⚠ ANOMALY",
                          "score %.3f ≥ threshold %.2f" % (res["score"], threshold))
            else:
                self._add(time.strftime("%H:%M:%S"), "L2", "ok", "✓ NORMAL", "score %.3f" % res["score"])


def unified_verdict(det, info, cur):
    """(name, css, explanation). Four states only; nothing is inferred beyond the two layers' results."""
    l2_anom = cur is not None and cur["prediction"] == "ANOMALY"
    ev = det.l1_current
    if det.l1_rejected and ev is not None:
        extra = " Layer 2 also reports a physical anomaly." if l2_anom else ""
        return ("MESSAGE REJECTED", "bad",
                "Layer 1 rejected the message: %s (%s / %s). Shown for a few seconds after the event; "
                "the timeline keeps it.%s" % (L1_REASONS.get(ev.code, ev.code), ev.node_label(),
                                              ev.msg_label(), extra))
    if ev is None:
        return ("MONITORING", "mon", "Awaiting data - no Layer 1 events yet. Press START.")
    if info["ids"] is None:
        return ("MONITORING", "mon", "Layer 1 accepted, but the Layer 2 model is unavailable, so there is "
                                      "no physical-consistency result to combine.")
    if cur is None:
        return ("MONITORING", "mon", "Layer 1 accepted. Waiting for the first Layer 2 inference.")
    if l2_anom:
        return ("PHYSICAL ANOMALY", "bad",
                "Layer 1 accepted the message (simulated policy check), but Layer 2 reports that the sensor "
                "values do not make physical sense together (score %.3f ≥ threshold %.2f)."
                % (cur["score"], info["threshold"]))
    return ("SECURE", "ok",
            "Layer 1 accepted the message (simulated policy check) and Layer 2 finds the sensor values "
            "physically consistent (score %.3f < threshold %.2f)." % (cur["score"], info["threshold"]))


def _dt_rows(rows):
    return "".join('<div class="lv-row"><span>%s</span><span>%s</span></div>' % r for r in rows)


def _dt_l1_text(det):
    return "-" if det.l1_current is None else det.l1_current.verdict


def _dt_l2_text(info, cur):
    if info["ids"] is None:
        return "OFFLINE"
    return "-" if cur is None else "%s %.3f" % (cur["prediction"], cur["score"])


def dt_intro_html():
    return ('<p class="dt-q"><b class="d1">LAYER 1</b> who sent it · is it authentic · is it fresh'
            '<span class="dt-plus">+</span><b class="d2">LAYER 2</b> do the sensor values make physical '
            'sense together</p>'
            '<p class="dt-disc">Complementary and independent: Layer 1 protects message trust, Layer 2 protects '
            'physical-process consistency. Layer 1 results here are SIMULATED dashboard policy checks (the C '
            'Ed25519 / BLAKE3 verifier is not invoked). Layer 2 is live Random Forest inference.</p>')


def dt_verdict_html(v, det, info, cur):
    name, css, why = v
    return ('<div class="dt-verdict %s"><div><div class="dt-vk">Unified security verdict</div>'
            '<div class="dt-vv">%s</div></div><div><div class="dt-why">%s</div>'
            '<div class="dt-meta"><span class="d1">LAYER 1 · %s (SIMULATED)</span>'
            '<span class="d2">LAYER 2 · %s</span></div></div></div>'
            % (css, name, why, _dt_l1_text(det), _dt_l2_text(info, cur)))


def _dt_stage(who, title, value, css):
    return ('<div class="dt-stage %s"><div class="dt-sk %s">%s</div><div class="dt-sv">%s</div></div>'
            % (css, who, title, value))


def dt_pipeline_html(v, det, info, cur, epoch):
    ev = det.l1_current
    if ev is None:
        l1_css, l1_val = "idle", "-"
    elif det.l1_rejected:
        l1_css, l1_val = "bad", "✗ REJECT"
    else:
        l1_css, l1_val = "ok", "✓ ACCEPT"
    if info["ids"] is None:
        l2_css, l2_val = "idle", "OFFLINE"
    elif cur is None:
        l2_css, l2_val = "idle", "-"
    elif cur["prediction"] == "ANOMALY":
        l2_css, l2_val = "bad", "⚠ ANOMALY"
    else:
        l2_css, l2_val = "ok", "✓ NORMAL"
    msg = _dt_stage("", "Message / sensor sample", "-" if epoch is None else "EPOCH %d" % epoch,
                    "idle" if epoch is None else "info")
    lanes = (_dt_stage("d1", "Layer 1 · authentication / freshness", l1_val, l1_css)
             + _dt_stage("d2", "Layer 2 · physical consistency", l2_val, l2_css))
    end = _dt_stage("", "Unified security verdict", v[0], v[1])
    return ('<div class="dt-pipe">%s<div class="dt-arrow">→</div><div class="dt-lanes">%s</div>'
            '<div class="dt-arrow">→</div>%s</div>'
            '<p class="sublabel">Both layers inspect the same simulator sample independently and in parallel - '
            'Layer 2 does not wait for Layer 1. The verdict combines their current results.</p>'
            % (msg, lanes, end))


def dt_l1_html(det):
    ev = det.l1_current
    head = '<div class="lv-panel dt-p d1"><div class="dt-ph d1">LAYER 1</div><div class="dt-pt">CRYPTOGRAPHIC TRUST</div>'
    if ev is None:
        rows = [("Status", "AWAITING DATA"), ("Sender", "-"), ("Message", "-"), ("Epoch", "-"), ("Reason", "-")]
        note = "No Layer 1 events yet - press START."
    else:
        m = ev.msg
        if ev.verdict == "REJECT":
            reason = L1_REASONS.get(ev.code, ev.code)
        else:
            reason = "ALLOWLIST + EPOCH RULE PASSED"
        basis = "DECLARED BY DEMO SCENARIO" if ev.basis == "DECLARED" else "DASHBOARD POLICY MIRROR"
        rows = [
            ("Status", '<span class="l1-val %s">%s</span>' % (ev.tone, ev.result_text())),
            ("Sender", "NODE %d · %s" % (m.sender_id, L1_NODE_NAMES.get(m.sender_id, "?"))),
            ("Message", ev.msg_label()),
            ("Epoch", str(m.epoch)),
            ("Reason", reason),
            ("Basis", basis),
        ]
        note = ("SIMULATED: Ed25519 and BLAKE3 are not computed here; the C verifier is not invoked."
                if ev.basis != "DECLARED" else
                "SIMULATED: outcome declared by the demo scenario; no signature was computed or checked.")
    return head + _dt_rows(rows) + '<div class="dt-pn">%s</div></div>' % note


def dt_l2_html(info, cur):
    head = '<div class="lv-panel dt-p d2"><div class="dt-ph d2">LAYER 2</div><div class="dt-pt">PHYSICAL CONSISTENCY</div>'
    if info["ids"] is None:
        rows = [("Status", '<span class="l1-val bad">MODEL UNAVAILABLE</span>'), ("Score", "-"),
                ("Threshold", "-"), ("Residual", "-")]
        note = "No scores are shown because the model could not be loaded."
    elif cur is None:
        rows = [("Status", "AWAITING DATA"), ("Score", "-"), ("Threshold", "%.2f" % info["threshold"]),
                ("Residual", "-"), ("Model", "%s · %d TREES · %d FEATURES" % (
                    info["model_name"].upper(), info["n_trees"], info["n_features"]))]
        note = "No inference yet - press START."
    else:
        zone = l2_zone(cur["score"], info["threshold"])
        anomaly = cur["prediction"] == "ANOMALY"
        status = ("⚠ " if anomaly else "✓ ") + cur["prediction"] + (" · WATCH" if zone == "warn" else "")
        rows = [
            ("Status", '<span class="l1-val %s">%s</span>' % (zone, status)),
            ("Score", "%.3f" % cur["score"]),
            ("Threshold", "%.2f" % info["threshold"]),
            ("Residual", "%+.4f rad/s" % cur["feats"]["yaw_residual"]),
            ("Model", "%s · %d TREES · %d FEATURES" % (info["model_name"].upper(), info["n_trees"],
                                                        info["n_features"])),
        ]
        note = "Live predict_proba of the persisted model on sensor values (encoders + IMU)."
    return head + _dt_rows(rows) + '<div class="dt-pn">%s</div></div>' % note


def dt_counters_l1_html(mon):
    rc = mon.rejects_by_code
    top = [_tile("Accepted", format(mon.accepted, ","), "num g"),
           _tile("Rejected", format(mon.rejected, ","), "num r" if mon.rejected else "num z")]
    parts = []
    for code in DT_L1_REJECT_ORDER:
        n = rc.get(code, 0)
        kind = "num z" if n == 0 else ("warn" if code in ("REPLAY", "BAD_FRESHNESS") else "bad")
        parts.append(_tile(L1_REASONS[code], format(n, ","), kind))
    return ('<div class="dt-ck d1">LAYER 1 · MESSAGES</div><div class="sgrid s2">%s</div>'
            '<div class="sgrid s5" style="margin-top:.7rem">%s</div>' % ("".join(top), "".join(parts)))


def dt_counters_l2_html(det):
    total = det.l2_normal + det.l2_anomaly
    tiles = [_tile("Normal", format(det.l2_normal, ","), "num g"),
             _tile("Anomaly", format(det.l2_anomaly, ","), "num r" if det.l2_anomaly else "num z"),
             _tile("Evaluated", format(total, ","), "num")]
    return '<div class="dt-ck d2">LAYER 2 · INFERENCES</div><div class="sgrid s3">%s</div>' % "".join(tiles)


def dt_why_html(det, info, cur):
    """Reasons come only from the actual Layer 1 event and the actual Layer 2 inference."""
    blocks = []
    ev = det.l1_current
    if det.l1_rejected and ev is not None:
        m = ev.msg
        basis = ("Outcome DECLARED by the demo scenario; no signature was computed."
                 if ev.basis == "DECLARED" else
                 "Computed by the dashboard policy mirror; Ed25519 / BLAKE3 not computed.")
        blocks.append('<div class="dt-wb d1"><div class="dt-wk">Layer 1 rejected the message</div>%s'
                      '<div class="dt-pn">%s</div></div>' % (_dt_rows([
                          ("Reason", L1_REASONS.get(ev.code, ev.code)),
                          ("Sender", "NODE %d · %s" % (m.sender_id, L1_NODE_NAMES.get(m.sender_id, "?"))),
                          ("Message", ev.msg_label()), ("Epoch", str(m.epoch)), ("Source", ev.source)]), basis))
    if cur is not None and cur["prediction"] == "ANOMALY":
        f = cur["feats"]
        inj = _esc(str(cur["attack"])) if cur["attack"] else "none"
        rows = [
            ("Anomaly score", "%.3f" % cur["score"]),
            ("Threshold", "%.2f" % info["threshold"]),
            ("Expected yaw", "%+.4f rad/s" % f["expected_yaw_rate"]),
            ("Observed yaw", "%+.4f rad/s" % f["observed_yaw_rate"]),
            ("Yaw residual", "%+.4f rad/s" % f["yaw_residual"]),
            ("Left speed", "%+.3f m/s" % f["left_speed"]),
            ("Right speed", "%+.3f m/s" % f["right_speed"]),
            ("Wheel disagreement", "FL−RL %+.3f · FR−RR %+.3f m/s" % (
                f["fl_speed"] - f["rl_speed"], f["fr_speed"] - f["rr_speed"])),
        ]
        blocks.append('<div class="dt-wb d2"><div class="dt-wk">Layer 2 flagged this sample</div>'
                      '<div class="dt-wstmt">Physical inconsistency detected by the Random Forest.</div>%s'
                      '<div class="dt-pn">Simulator injection label (demo information, not a model input): %s'
                      '</div></div>' % (_dt_rows(rows), inj))
    if not blocks:
        if info["ids"] is None:
            msg = "No Layer 1 rejection. Layer 2 is offline, so no physical-consistency result is available."
        else:
            msg = ("Nothing flagged right now: no Layer 1 rejection and no Layer 2 anomaly in the current "
                   "state. Reasons appear here when either layer flags an event.")
        return '<div class="dt-none">%s</div>' % msg
    return "".join(blocks)


def dt_timeline_html(det):
    items = list(det.timeline)[::-1][:DT_TIMELINE_ROWS]
    header = ('<div class="dt-r hd"><span>TIME</span><span>LAYER</span><span>RESULT</span>'
              '<span>REASON</span></div>')
    if not items:
        return '<div class="dt-feed">%s<div class="l1-empty">No detection events yet - press START.</div></div>' % header
    rows = "".join(
        '<div class="dt-r %s"><span>%s</span><span class="dt-ly %s">%s</span><span class="dt-res">%s</span>'
        '<span>%s</span></div>' % (e["tone"], e["clock"], "d1" if e["layer"] == "L1" else "d2",
                                   e["layer"], e["result"], _esc(e["reason"])) for e in items)
    return '<div class="dt-feed">%s%s</div>' % (header, rows)


def detection_section(info, mon, det, cur, sample):
    st.markdown('<p class="label">DETECTION BREAKDOWN</p>', unsafe_allow_html=True)
    st.markdown('<p class="dt-title">UNIFIED DETECTION</p>', unsafe_allow_html=True)
    st.markdown(dt_intro_html(), unsafe_allow_html=True)
    v = unified_verdict(det, info, cur)
    st.markdown(dt_verdict_html(v, det, info, cur), unsafe_allow_html=True)
    epoch = sample["messages"][0].epoch if sample else None
    st.markdown(dt_pipeline_html(v, det, info, cur, epoch), unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(dt_l1_html(det), unsafe_allow_html=True)
    with col2:
        st.markdown(dt_l2_html(info, cur), unsafe_allow_html=True)

    st.markdown('<p class="tsub">Detection counters</p>', unsafe_allow_html=True)
    st.markdown('<p class="sublabel">Layer 1 counts every simulated message (10 per simulator step) · Layer 2 '
                'counts every real inference performed · both reset with RESET</p>', unsafe_allow_html=True)
    k1, k2 = st.columns([3, 2])
    with k1:
        st.markdown(dt_counters_l1_html(mon), unsafe_allow_html=True)
    with k2:
        st.markdown(dt_counters_l2_html(det), unsafe_allow_html=True)

    why_col, tl_col = st.columns([2, 3])
    with why_col:
        st.markdown('<p class="tsub">Why was this event flagged?</p>', unsafe_allow_html=True)
        st.markdown(dt_why_html(det, info, cur), unsafe_allow_html=True)
    with tl_col:
        st.markdown('<p class="tsub">Live detection timeline</p>', unsafe_allow_html=True)
        st.markdown('<p class="sublabel">Newest first · %d of %d kept · every rejection, plus Layer 1 / Layer 2 '
                    'state changes</p>' % (min(len(det.timeline), DT_TIMELINE_ROWS), DT_TIMELINE_MAX),
                    unsafe_allow_html=True)
        st.markdown(dt_timeline_html(det), unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# 3I: ATTACK LAB - controlled demo attacks (SIMULATION / DEMONSTRATION ONLY)
# ----------------------------------------------------------------------------
# No second injection system and no second detector live here:
#   Layer 1 buttons -> the existing Layer1Monitor.inject() (FORGED_SENDER / TAMPERED / REPLAY).
#     Its outcome is the dashboard policy mirror or a DECLARED result. Ed25519 / BLAKE3 are NOT computed
#     and the C verifier is NOT invoked, and nothing on screen says otherwise.
#   Layer 2 buttons -> the simulator's existing PhysicalAttack hook (SensorSimulator.set_attack) for a
#     limited stretch of SIMULATED time. The Random Forest then scores the attacked sensor values through
#     the normal Layer2IDS path; no score or verdict is ever set from here.
AL_HISTORY_MAX = 20           # bounded attack history (deque maxlen)
AL_DURATIONS = (3, 5, 10)     # selectable physical-attack lengths in simulated seconds
AL_L1_FLASH_S = 6.0           # wall-clock seconds the injected-packet banner / Node 5 highlight stay on

AL_L1 = {
    "FORGED_SENDER": {"name": "FORGED SENDER", "key": "atk_l1_forged",
                      "desc": "Inject a packet from the untrusted attacker node."},
    "TAMPERED": {"name": "TAMPERED PACKET", "key": "atk_l1_tampered",
                 "desc": "Modify a previously accepted packet after signing."},
    "REPLAY": {"name": "REPLAY ATTACK", "key": "atk_l1_replay",
               "desc": "Re-send an already accepted packet with an old epoch."},
}
# Offsets sit inside the ranges the existing Random Forest was trained on (layer2_ids._random_attack);
# they are plain attack parameters handed to PhysicalAttack, not predictions.
AL_PHYS = {
    "IMU_YAW": {"name": "IMU YAW SPOOF", "key": "atk_l2_imu", "kind": ATTACK_IMU_YAW_OFFSET,
                "value": 1.5, "target": None, "unit": "rad/s", "where": "IMU gyro Z",
                "desc": "Add a yaw-rate offset to the simulated IMU gyro Z reading."},
    "WHEEL": {"name": "WHEEL OFFSET", "key": "atk_l2_wheel", "kind": ATTACK_WHEEL_OFFSET,
              "value": 100.0, "target": "fl", "unit": "rpm", "where": "FL wheel encoder",
              "desc": "Add an RPM offset to one wheel's simulated encoder reading."},
    "SIDE": {"name": "SIDE OFFSET", "key": "atk_l2_side", "kind": ATTACK_SIDE_OFFSET,
             "value": 100.0, "target": "left", "unit": "rpm", "where": "both left-side wheel encoders",
             "desc": "Add an RPM offset to both left-side wheel encoders."},
}


class AttackLabState:
    """Session state of the Attack Lab. RESET replaces it with a fresh instance."""

    def __init__(self):
        self.history = deque(maxlen=AL_HISTORY_MAX)   # bounded; entries are small dicts
        self.active = None       # the running physical attack's record (also in history), else None
        self.last = None         # newest attack launched: drives ATTACK ANALYSIS and the flow strip
        self.l1_until = 0.0      # time.monotonic() deadline of the injected-packet indicator
        self.notice = ""

    # ---- Layer 1: one injected packet ------------------------------------------------------------
    def record_l1(self, kind, ev):
        blocked = ev.verdict == "REJECT"
        rec = {"layer": 1, "kind": kind, "name": AL_L1[kind]["name"], "clock": ev.clock, "event": ev,
               "status": "BLOCKED" if blocked else "ACCEPTED", "tone": "ok" if blocked else "bad"}
        self.history.append(rec)
        self.last = rec
        self.l1_until = time.monotonic() + AL_L1_FLASH_S
        self.notice = ""

    def l1_flash(self):
        """The Layer 1 record while its indicator is on screen, else None."""
        if self.last is not None and self.last["layer"] == 1 and time.monotonic() < self.l1_until:
            return self.last
        return None

    # ---- Layer 2: a physical attack armed on the existing simulator hook ---------------------------
    def start_physical(self, key, sim, duration):
        spec = AL_PHYS[key]
        if self.active is not None:
            self._finish(replaced=True)
        attack = PhysicalAttack(spec["kind"], spec["value"], target=spec["target"],
                                t_start=sim.time, t_end=sim.time + duration)
        sim.set_attack(attack)                            # the simulator's own attack mechanism
        rec = {"layer": 2, "kind": key, "name": spec["name"], "clock": time.strftime("%H:%M:%S"),
               "status": "ACTIVE", "tone": "warn", "attack": attack, "t_end": sim.time + duration,
               "duration": duration, "evals": 0, "anoms": 0, "peak": None, "_epoch": -1}
        self.history.append(rec)
        self.active = rec
        self.last = rec
        self.l1_until = 0.0                               # Node 5 returns to its normal look
        self.notice = ""

    def observe_l2(self, res):
        """Called with each REAL inference. Only inferences made while the attack was injected count."""
        rec = self.active
        if rec is None or res is None or res.get("attack") is None or res["epoch"] <= rec["_epoch"]:
            return
        rec["_epoch"] = res["epoch"]
        rec["evals"] += 1
        if res["prediction"] == "ANOMALY":
            rec["anoms"] += 1
            rec["status"], rec["tone"] = "DETECTED", "ok"
        if rec["peak"] is None or res["score"] > rec["peak"]["score"]:
            rec["peak"] = res

    def tick(self, sim):
        """After each advance: when the attack window is over, return the simulator to normal."""
        rec = self.active
        if rec is not None and sim.time >= rec["t_end"]:
            if sim.attack is rec["attack"]:
                sim.clear_attack()
            self._finish()

    def _finish(self, replaced=False):
        rec = self.active
        if rec is None:
            return
        if rec["status"] == "ACTIVE":                     # never flagged by the model during the window
            rec["status"], rec["tone"] = ("REPLACED", "warn") if replaced else ("NOT DETECTED", "bad")
        self.active = None


def _al_launch_l1(kind):
    lab, l1 = st.session_state.attack_lab, st.session_state.layer1
    ev = l1.inject(kind)                                  # existing Phase 3I entry point
    if ev is None:
        lab.notice = "Layer 1 injection needs one accepted Node 1 packet first - press START."
        return
    st.session_state.detect.observe_l1(l1)                # show the rejection in the verdict / timeline now
    lab.record_l1(kind, ev)


def _al_launch_physical(key):
    st.session_state.attack_lab.start_physical(
        key, st.session_state.sim, float(st.session_state.get("attack_duration", 5)))


def al_active_html(lab, sim, running):
    def cell(k, v):
        return '<div><div class="al-act-k">%s</div><div class="al-act-v">%s</div></div>' % (k, v)
    rec = lab.active
    if rec is not None:
        remaining = max(0.0, rec["t_end"] - sim.time)
        rem = "%.1f s%s" % (remaining, "" if running else " (simulation paused)")
        return ('<div class="al-act"><div class="al-act-h">⚠ ATTACK ACTIVE</div>%s%s%s</div>'
                % (cell("Attack", _esc(rec["name"])), cell("Layer", "LAYER 2"), cell("Remaining", rem)))
    fl = lab.l1_flash()
    if fl is not None:
        return ('<div class="al-act"><div class="al-act-h">⚠ INJECTED PACKET</div>%s%s%s</div>'
                % (cell("Attack", _esc(fl["name"])), cell("Layer", "LAYER 1"),
                   cell("Result", "✗ " + _esc(fl["status"]))))
    return ('<div class="al-act idle"><div class="al-act-h">● NO ATTACK ACTIVE</div>%s%s%s</div>'
            % (cell("Attack", "-"), cell("Layer", "-"), cell("Remaining", "-")))


def _al_arrow():
    return '<div class="dt-arrow">→</div>'


def al_flow_html(lab, mon, info, cur):
    rec = lab.last
    if rec is None:
        return ('<div class="dt-none">Click an attack to see how it travels through CANARY and which layer '
                'reacts: NORMAL → CLICK ATTACK → DETECTION → WHY? → SECURITY VERDICT.</div>')
    if rec["layer"] == 1:
        ev = rec["event"]
        blocked = ev.verdict == "REJECT"
        stages = [
            _dt_stage("", "Node 5 · attacker", "%s · claims NODE %d" % (_esc(rec["name"]), ev.msg.sender_id),
                      "bad"),
            _al_arrow(),
            _dt_stage("d1", "Node 4 · Security / IDS", "LAYER 1 CHECK (SIMULATED)", "info"),
            _al_arrow(),
            _dt_stage("", "Result", ("✗ BLOCKED · " if blocked else "✓ ACCEPTED · ")
                      + _esc(L1_REASONS.get(ev.code, ev.code)), "bad" if blocked else "ok"),
        ]
        tail = ("Stopped at Node 4. Nothing is forwarded to Node 3 (Motor-Control ECU)." if blocked
                else "Layer 1 accepted this packet.")
        return '<div class="al-flow">%s</div><p class="sublabel">%s</p>' % ("".join(stages), tail)
    # Layer 2: the point is that authenticated-looking sensor traffic passes Layer 1 and is still checked
    l1_ev = next((e for e in mon.log.recent(L1_EVENT_MAX) if e.source == "SIMULATOR"), None)
    l1_val = "-" if l1_ev is None else "%s (SIMULATED)" % l1_ev.result_text()
    l1_css = "idle" if l1_ev is None else ("ok" if l1_ev.verdict != "REJECT" else "bad")
    if info["ids"] is None:
        phys, rf, res, css = "-", "MODEL OFFLINE", "-", "idle"
    elif cur is None:
        phys, rf, res, css = "-", "-", "-", "idle"
    else:
        zone = l2_zone(cur["score"], info["threshold"])
        css = {"bad": "bad", "warn": "mon", "ok": "ok"}[zone]
        phys = "residual %+.3f rad/s" % cur["feats"]["yaw_residual"]
        rf = "score %.3f" % cur["score"]
        res = ("⚠ " if cur["prediction"] == "ANOMALY" else "✓ ") + cur["prediction"]
    stages = [
        _dt_stage("", "Sensor data", "ENCODERS + IMU · %s" % _esc(rec["name"]), "info"),
        _al_arrow(), _dt_stage("d1", "Layer 1 trust", l1_val, l1_css),
        _al_arrow(), _dt_stage("d2", "Physical consistency", phys, css),
        _al_arrow(), _dt_stage("d2", "Random Forest", rf, css),
        _al_arrow(), _dt_stage("", "Result", res, css),
    ]
    return ('<div class="al-flow">%s</div><p class="sublabel">The packets are authentic-looking and pass the '
            'Layer 1 policy check; only the physics is inconsistent. The result is the model\'s own.</p>'
            % "".join(stages))


def al_analysis_html(lab, info, cur):
    rec = lab.last
    head = '<div class="lv-panel dt-p"><div class="dt-pt">ATTACK ANALYSIS</div>'
    if rec is None:
        return head + '<p class="sublabel">No attack launched yet.</p></div>'
    if rec["layer"] == 1:
        ev = rec["event"]
        m = ev.msg
        basis = ("DECLARED by the demo scenario (no signature was computed)" if ev.basis == "DECLARED"
                 else "Dashboard policy mirror (sender allowlist + epoch rule)")
        rows = [
            ("Attack", _esc(rec["name"])),
            ("Packet", "NODE %d · %s · epoch %d" % (m.sender_id, ev.msg_label(), m.epoch)),
            ("Layer 1 result", '<span class="l1-val %s">%s · %s</span>' % (
                ev.tone, ev.result_text(), _esc(L1_REASONS.get(ev.code, ev.code)))
                if ev.verdict == "REJECT" else '<span class="l1-val ok">%s</span>' % ev.result_text()),
            ("Basis", basis),
        ]
        return (head + '<div class="dt-wstmt">Layer 1 protects message authenticity and freshness. '
                'The injected packet violates the trusted-message policy.</div>' + _dt_rows(rows)
                + '<div class="dt-pn">SIMULATED: Ed25519 and BLAKE3 are not computed here and the C verifier '
                  'is not invoked.</div></div>')
    spec = AL_PHYS[rec["kind"]]
    intro = ('<div class="dt-wstmt">Layer 2 evaluates whether independently observed sensor values remain '
             'physically consistent.</div>')
    param = ("Injected", "%+.2f %s on %s · %d s window" % (spec["value"], spec["unit"], spec["where"],
                                                         rec["duration"]))
    if info["ids"] is None:
        return head + intro + _dt_rows([param]) + '<div class="dt-pn">Layer 2 model unavailable: no evidence.</div></div>'
    if rec is lab.active:
        res, src = cur, "LIVE model result on the current sample"
    else:
        res, src = rec["peak"], "HIGHEST-SCORE inference made while the attack was injected"
    if res is None:
        return (head + intro + _dt_rows([param]) +
                '<div class="dt-pn">No Layer 2 inference has run during this attack yet.</div></div>')
    f = res["feats"]
    rows = [
        param,
        ("Model verdict", "%s%s" % ("⚠ " if res["prediction"] == "ANOMALY" else "✓ ", res["prediction"])),
        ("Anomaly score", "%.3f" % res["score"]),
        ("Threshold", "%.2f" % info["threshold"]),
        ("Expected yaw", "%+.4f rad/s" % f["expected_yaw_rate"]),
        ("Observed yaw", "%+.4f rad/s" % f["observed_yaw_rate"]),
        ("Yaw residual", "%+.4f rad/s" % f["yaw_residual"]),
        ("Wheel speeds", "FL %+.3f · FR %+.3f · RL %+.3f · RR %+.3f m/s" % (
            f["fl_speed"], f["fr_speed"], f["rl_speed"], f["rr_speed"])),
        ("Vehicle speed", "%.3f m/s" % f["vehicle_speed"]),
    ]
    return (head + intro + _dt_rows(rows) + '<div class="dt-pn">Evidence: %s (Random Forest predict_proba).'
            '</div></div>' % src)


def al_history_html(lab):
    header = ('<div class="al-r hd"><span>TIME</span><span>ATTACK</span><span>LAYER</span>'
              '<span>STATUS</span></div>')
    if not lab.history:
        return '<div class="al-feed">%s<div class="l1-empty">No attacks launched yet.</div></div>' % header
    rows = "".join('<div class="al-r %s"><span>%s</span><span>%s</span><span>LAYER %d</span>'
                   '<span class="al-st">%s</span></div>'
                   % (r["tone"], r["clock"], _esc(r["name"]), r["layer"], _esc(r["status"]))
                   for r in reversed(lab.history))
    return '<div class="al-feed">%s%s</div>' % (header, rows)


def attack_lab_section(info, lab, mon, cur, sim, running):
    st.markdown('<p class="label">ADVERSARY SIMULATION</p>', unsafe_allow_html=True)
    st.markdown('<p class="al-title">ATTACK LAB</p>', unsafe_allow_html=True)
    st.markdown('<p class="al-sub">Inject controlled attacks into the simulated CANARY network.</p>'
                '<span class="al-badge">SIMULATION / DEMONSTRATION ONLY</span>'
                '<p class="al-disc">Layer 1 outcomes are SIMULATED by the dashboard (policy mirror or declared '
                'result): Ed25519 and BLAKE3 are not computed and the C verifier is not invoked. Layer 2 '
                'results are live Random Forest inference on the sensor values.</p>', unsafe_allow_html=True)
    if lab.notice:
        st.markdown('<div class="al-note">%s</div>' % _esc(lab.notice), unsafe_allow_html=True)
    st.markdown(al_active_html(lab, sim, running), unsafe_allow_html=True)

    ready = mon.last_accepted.get(FL_STREAM) is not None
    st.markdown('<p class="al-grp d1">LAYER 1 ATTACKS</p>', unsafe_allow_html=True)
    for col, (kind, spec) in zip(st.columns(3), AL_L1.items()):
        with col:
            st.button(spec["name"], key=spec["key"], on_click=_al_launch_l1, args=(kind,),
                      disabled=not ready, use_container_width=True)
            st.markdown('<div class="al-desc">%s</div>' % spec["desc"], unsafe_allow_html=True)
    if not ready:
        st.markdown('<p class="sublabel">Press START: Layer 1 injection needs one accepted Node 1 packet '
                    'to build on.</p>', unsafe_allow_html=True)

    st.markdown('<p class="al-grp d2">LAYER 2 — PHYSICAL ATTACKS</p>', unsafe_allow_html=True)
    dcol, _ = st.columns([1, 3])
    with dcol:
        st.selectbox("ATTACK DURATION", AL_DURATIONS, index=AL_DURATIONS.index(5), key="attack_duration",
                     format_func=lambda sec: "%d s" % sec)
    for col, (key, spec) in zip(st.columns(3), AL_PHYS.items()):
        with col:
            st.button(spec["name"], key=spec["key"], on_click=_al_launch_physical, args=(key,),
                      use_container_width=True)
            st.markdown('<div class="al-desc">%s</div>' % spec["desc"], unsafe_allow_html=True)
    st.markdown('<p class="sublabel">Physical attacks run for the selected stretch of simulated time, then '
                'the simulator returns to normal on its own. They advance while the simulation is RUNNING.'
                '</p>', unsafe_allow_html=True)

    st.markdown(al_flow_html(lab, mon, info, cur), unsafe_allow_html=True)
    acol, hcol = st.columns([3, 2])
    with acol:
        st.markdown(al_analysis_html(lab, info, cur), unsafe_allow_html=True)
    with hcol:
        st.markdown('<p class="tsub">Attack history</p>', unsafe_allow_html=True)
        st.markdown('<p class="sublabel">Newest first · last %d kept · cleared by RESET</p>' % AL_HISTORY_MAX,
                    unsafe_allow_html=True)
        st.markdown(al_history_html(lab), unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# Session state
# ----------------------------------------------------------------------------
def _fresh_simulation():
    return SensorSimulator(dt=DT, timeline=TIMELINE, seed=SEED)


def _reset():
    st.session_state.sim = _fresh_simulation()
    st.session_state.running = False
    st.session_state.last_sample = None
    st.session_state.last_tick = None
    st.session_state.pulse = 0                       # +1 each time the simulator advanced
    st.session_state.msg_counts = {1: 0, 2: 0}       # CANARYMessages seen per sender node
    st.session_state.trail = []                      # 3D: recent (x, y) from VehicleModel, drawing only
    st.session_state.history = []                    # 3E: bounded live-signal history
    st.session_state.layer1 = Layer1Monitor()        # 3F: counters + bounded event log (no crypto)
    st.session_state.l2_history = []                 # 3G: bounded anomaly-score history
    st.session_state.l2_current = None               # 3G: latest Layer 2 result
    st.session_state.detect = DetectionTracker()     # 3H: unified verdict state, L2 counters, timeline
    st.session_state.attack_lab = AttackLabState()   # 3I: attack history / active attack (the new sim has none)


def _start():
    st.session_state.running = True
    st.session_state.last_tick = time.monotonic()  # no catch-up for paused time


def _pause():
    st.session_state.running = False


if "sim" not in st.session_state:
    _reset()
if "trail" not in st.session_state:
    st.session_state.trail = []
if "history" not in st.session_state:
    st.session_state.history = []
if "layer1" not in st.session_state:
    st.session_state.layer1 = Layer1Monitor()
if "l2_history" not in st.session_state:
    st.session_state.l2_history = []
if "l2_current" not in st.session_state:
    st.session_state.l2_current = None
if "detect" not in st.session_state:
    st.session_state.detect = DetectionTracker()
if "attack_lab" not in st.session_state:
    st.session_state.attack_lab = AttackLabState()


# ----------------------------------------------------------------------------
# 3E: telemetry derived from the simulator's own outputs (nothing is simulated here)
# ----------------------------------------------------------------------------
def _side_speeds(enc):
    """(left, right) side speed in m/s: mean of the side's two encoder RPMs, converted with the
    existing rpm_to_velocity(). Same averaging as expected_yaw_rate_from_encoders()."""
    left = rpm_to_velocity((enc["fl_rpm"] + enc["rl_rpm"]) / 2.0)
    right = rpm_to_velocity((enc["fr_rpm"] + enc["rr_rpm"]) / 2.0)
    return left, right


def _consistency(sample):
    """(expected, observed, residual) yaw rate in rad/s.
    expected = (right - left) / TRACK_WIDTH from the encoders (existing simulator helper),
    observed = simulated IMU gyro Z (NOT ground truth), residual = observed - expected."""
    expected = expected_yaw_rate_from_encoders(sample["encoders"])
    observed = sample["imu"]["gyro_z"]
    return expected, observed, observed - expected


def _history_point(sample):
    left, right = _side_speeds(sample["encoders"])
    expected, observed, residual = _consistency(sample)
    return {"t": sample["timestamp"], "left": left, "right": right,
            "expected": expected, "observed": observed, "residual": residual,
            "speed": sample["ground_truth"]["velocity"]}


def _advance():
    """Advance the existing simulator in step with wall-clock time."""
    sim = st.session_state.sim
    now = time.monotonic()
    elapsed = now - st.session_state.last_tick
    n = int(elapsed / sim.dt)
    if n <= 0:
        return
    if n > MAX_STEPS_PER_TICK:
        n = MAX_STEPS_PER_TICK
        st.session_state.last_tick = now
    else:
        st.session_state.last_tick += n * sim.dt
    counts = st.session_state.msg_counts
    hist = st.session_state.history
    l1 = st.session_state.layer1
    l2 = get_layer2()                                # 3G: cached model (not re-read from disk)
    l2_hist = st.session_state.l2_history
    det = st.session_state.detect                    # 3H: detection counters / timeline
    lab = st.session_state.attack_lab                # 3I: Attack Lab bookkeeping (no verdicts)
    l2_last = None
    for _ in range(n):
        sample = sim.step()
        l1.observe_sample(sample)                    # 3F: policy mirror over the real messages
        if l2["ids"] is not None and sample["messages"][0].epoch % L2_STRIDE == 0:
            l2_last = run_layer2_inference(l2, sample)           # 3G: real Random Forest score
            det.record_l2(l2_last, l2["threshold"])              # 3H: count this real inference
            lab.observe_l2(l2_last)                              # 3I: attribute it to the active attack
            l2_hist.append({"t": l2_last["t"], "score": l2_last["score"]})
        for msg in sample["messages"]:               # real messages built by the simulator
            counts[msg.sender_id] = counts.get(msg.sender_id, 0) + 1
        st.session_state.last_sample = sample
        if sample["messages"][0].epoch % HISTORY_STRIDE == 0:   # 3E: decimated, real samples only
            hist.append(_history_point(sample))
    del hist[:-HISTORY_MAX]                          # 3E: keep the history bounded
    l1.log_tick(st.session_state.last_sample)        # 3F: one representative event per sender
    det.observe_l1(l1)                               # 3H: read the Layer 1 events just logged
    if l2["ids"] is not None:                        # 3G: current result always matches the newest sample
        newest = st.session_state.last_sample
        if l2_last is None or l2_last["epoch"] != newest["messages"][0].epoch:
            l2_last = run_layer2_inference(l2, newest)
            det.record_l2(l2_last, l2["threshold"])          # 3H: count this real inference
            lab.observe_l2(l2_last)                          # 3I
        st.session_state.l2_current = l2_last
        del l2_hist[:-L2_HISTORY_MAX]                # 3G: keep the score history bounded
    lab.tick(sim)                                    # 3I: attack window over -> simulator back to normal
    gt = st.session_state.last_sample["ground_truth"]
    trail = st.session_state.trail                   # 3D: pose history for the breadcrumb trail only
    trail.append((gt["x"], gt["y"]))
    del trail[:-TRAIL_MAX]
    st.session_state.pulse += 1


# ----------------------------------------------------------------------------
# 3B: system status
# ----------------------------------------------------------------------------
def _tile(label, value, kind):
    return ('<div class="stile %s"><div class="stile-k">%s</div>'
            '<div class="stile-v">%s</div></div>' % (kind, label, value))


def system_status_html(sample):
    connected = isinstance(st.session_state.get("sim"), SensorSimulator)
    layer2_ready = all(p.is_file() for p in LAYER2_FILES)   # existence only; nothing is loaded
    epoch = str(sample["messages"][0].epoch) if sample else "-"
    sim_time = "%.2f s" % sample["timestamp"] if sample else "-"
    tiles = [
        _tile("CANARY", "ONLINE", "ok"),
        _tile("Simulation mode", "ACTIVE" if connected else "INACTIVE", "info" if connected else "bad"),
        _tile("Vehicle simulation", "CONNECTED" if connected else "DISCONNECTED",
              "ok" if connected else "bad"),
        _tile("Security / IDS", "STANDBY", "warn"),
        _tile("Layer 1", "READY", "ok"),
        _tile("Layer 2 ML", "READY" if layer2_ready else "MODEL MISSING",
              "ok" if layer2_ready else "bad"),
        _tile("Simulation epoch", epoch, "num"),
        _tile("Simulation time", sim_time, "num"),
    ]
    return '<div class="sgrid">' + "".join(tiles) + "</div>"


# ----------------------------------------------------------------------------
# 3C: six-node network
# ----------------------------------------------------------------------------
# node id: (center x, center y, half width, half height) on the 1000x480 stage
NODE_GEOM = {
    1: (130, 70, 105, 42),
    2: (130, 240, 105, 42),
    6: (130, 410, 105, 42),
    4: (500, 240, 125, 65),
    3: (870, 240, 105, 42),
    5: (500, 420, 105, 42),
}
# (source, destination, label, kind)  - the fixed CANARY architecture
LINKS = [
    (1, 4, "WHEEL ×4", "data"),
    (2, 4, "IMU ×6", "data"),
    (6, 4, "CMD", "cmd"),
    (4, 3, "CMD", "cmd"),
    (5, 4, "NO TRAFFIC", "bad"),
]
PACKET_DELAYS = ("0s", ".03s", ".06s")


def _edge_offset(hw, hh, ux, uy):
    """Distance from a box centre to its edge along unit direction (ux, uy)."""
    tx = hw / abs(ux) if abs(ux) > 1e-9 else float("inf")
    ty = hh / abs(uy) if abs(uy) > 1e-9 else float("inf")
    return min(tx, ty)


HOT_PACKET_DELAYS = ("0s", ".3s", ".6s")     # 3I: red packets on an injected Node 5 -> Node 4 link


def _link_html(src, dst, label, kind, phase, hot=False):
    x1, y1, hw1, hh1 = NODE_GEOM[src]
    x2, y2, hw2, hh2 = NODE_GEOM[dst]
    dx, dy = x2 - x1, y2 - y1
    dist = math.hypot(dx, dy)
    ux, uy = dx / dist, dy / dist
    s = _edge_offset(hw1, hh1, ux, uy) + 6
    e = _edge_offset(hw2, hh2, ux, uy) + 6
    length = dist - s - e
    sx, sy = x1 + ux * s, y1 + uy * s
    mx, my = sx + ux * length / 2, sy + uy * length / 2
    angle = math.degrees(math.atan2(dy, dx))

    cls = "lnk" + ("" if kind == "data" else " " + kind)
    packets = ""
    if kind != "bad" and phase:
        cls += " live"
        packets = "".join('<i class="pk %s" style="animation-delay:%s"></i>' % (phase, d)
                          for d in PACKET_DELAYS)
    if hot:        # 3I: only the attacker link; red packets run while a Layer 1 injection is shown
        cls += " hot"
        packets = "".join('<i class="pk hot" style="animation-delay:%s"></i>' % d for d in HOT_PACKET_DELAYS)
    pill_cls = ("pill bad" if kind == "bad" else "pill") + (" hot" if hot else "")
    return ('<div class="%s" style="left:%.1fpx;top:%.1fpx;width:%.1fpx;transform:rotate(%.2fdeg)">%s</div>'
            '<div class="%s" style="left:%.1fpx;top:%.1fpx">%s</div>'
            % (cls, sx, sy, length, angle, packets, pill_cls, mx, my, label))


def _node_html(nid, cls, icon, name, chip, chip_cls, sub):
    x, y, _, _ = NODE_GEOM[nid]
    return ('<div class="node %s" style="left:%dpx;top:%dpx">'
            '<div class="n-top"><span class="n-id">NODE %d</span><span class="chip %s">%s</span></div>'
            '<div class="n-name">%s %s</div><div class="n-sub">%s</div></div>'
            % (cls, x, y, nid, chip_cls, chip, icon, name, sub))


def network_html(running, pulse, counts, attack=None):
    """attack: the Layer 1 injection record from the Attack Lab while it is being shown, else None."""
    # Packets animate only while the existing simulator is actually advancing.
    # The animation name alternates a/b with each simulator advance, which restarts it.
    phase = ("a" if pulse % 2 else "b") if (running and pulse > 0) else ""
    connected = isinstance(st.session_state.get("sim"), SensorSimulator)
    state = "ONLINE" if connected else "OFFLINE"
    n1, n2 = counts.get(1, 0), counts.get(2, 0)
    parts = [
        '<div class="stage-wrap"><div class="stage">',
        '<div class="stage-tag">SIMULATED CAN-LIKE MESSAGING OVER ESP-NOW</div>',
        '<div class="stage-tag r">LAPTOP SIMULATION · NO REAL CAN HARDWARE</div>',
    ]
    hot = attack is not None
    for s, d, lbl, k in LINKS:
        if hot and (s, d) == (5, 4):
            parts.append(_link_html(s, d, "%s ✗ BLOCKED" % attack["name"], k, phase, hot=True))
        else:
            parts.append(_link_html(s, d, lbl, k, phase))
    parts += [
        _node_html(1, "sensor", "🛞", "Encoder ECU", state, "ok",
                   "TX wheel speed · %s msgs" % format(n1, ",")),
        _node_html(2, "sensor", "🧭", "IMU ECU", state, "ok",
                   "TX accel + gyro · %s msgs" % format(n2, ",")),
        _node_html(6, "gateway", "📡", "Gateway ECU", state, "ok", "Laptop / WiFi gateway side"),
        _node_html(3, "motor", "⚙️", "Motor-Control ECU", state, "ok", "Drive command sink"),
        _node_html(5, "attacker hot" if hot else "attacker", "😈", "Attacker ECU",
                   "INJECTING" if hot else "IDLE", "hot" if hot else "idle", "UNTRUSTED / ATTACKER"),
        _node_html(4, "ids", "🐤", "Security / IDS ECU", "STANDBY", "idle",
                   "RX from nodes 1+2 · %s msgs (sim)<br>Layer 1 DEMO active · Layer 2 ML next"
                   % format(n1 + n2, ",")),
        "</div></div>",
    ]
    return "".join(parts)


# ----------------------------------------------------------------------------
# 3D: live 4WD rover visualization
# ----------------------------------------------------------------------------
# Rover is drawn facing +x (screen right) in its own frame; left side = screen up.
# (label, encoder key, local x, local y)  FL/FR front, RL/RR rear; left = -y, right = +y
WHEEL_LAYOUT = [
    ("FL", "fl_rpm", 30, -35),
    ("FR", "fr_rpm", 30, 35),
    ("RL", "rl_rpm", -30, -35),
    ("RR", "rr_rpm", -30, 35),
]


def _wheel_look(rpm):
    """(colour, glow 0..1, css class) from a real encoder RPM value."""
    if rpm is None:
        return "#3d4f63", 0.0, ""
    glow = min(abs(rpm) / RPM_FULL, 1.0)
    if rpm > 1.0:
        return "#00e5a0", glow, "fwd"
    if rpm < -1.0:
        return "#ffb020", glow, "rev"
    return "#6b7f94", 0.0, ""


def _upright(x, y, text, cls, yaw_deg):
    """Text placed in the rover frame but counter-rotated so it stays readable."""
    return ('<text transform="translate(%.1f %.1f) rotate(%.2f)" class="%s" text-anchor="middle">%s</text>'
            % (x, y, yaw_deg, cls, text))


def rover_svg(gt, enc, trail):
    """Top-down 4WD skid-steer rover. gt = VehicleModel.state(); enc = encoder dict or None."""
    cx, cy = VIEW_W / 2.0, VIEW_H / 2.0
    x, y, yaw = gt["x"], gt["y"], gt["yaw"]
    yaw_deg = math.degrees(yaw)
    gx, gy = cx - x * PX_PER_M, cy + y * PX_PER_M       # screen position of the world origin
    cell = GRID_M * PX_PER_M

    p = ['<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg">' % (VIEW_W, VIEW_H)]
    p.append(
        '<defs>'
        '<pattern id="lvg1" width="%.1f" height="%.1f" patternUnits="userSpaceOnUse" '
        'patternTransform="translate(%.2f %.2f)"><path d="M%.1f 0H0V%.1f" fill="none" stroke="#1c2a3a" '
        'stroke-width="1" opacity=".7"/></pattern>'
        '<pattern id="lvg2" width="%.1f" height="%.1f" patternUnits="userSpaceOnUse" '
        'patternTransform="translate(%.2f %.2f)"><path d="M%.1f 0H0V%.1f" fill="none" stroke="#27405a" '
        'stroke-width="1.2" opacity=".9"/></pattern>'
        '<radialGradient id="lvfade" cx="50%%" cy="50%%" r="60%%"><stop offset="0%%" stop-color="#00e5a0" '
        'stop-opacity=".10"/><stop offset="100%%" stop-color="#00e5a0" stop-opacity="0"/></radialGradient>'
        '<linearGradient id="lvbody" x1="0" y1="0" x2="1" y2="1"><stop offset="0%%" stop-color="#16222f"/>'
        '<stop offset="100%%" stop-color="#0c141d"/></linearGradient>'
        '<filter id="lvglow" x="-50%%" y="-50%%" width="200%%" height="200%%">'
        '<feGaussianBlur stdDeviation="3"/></filter>'
        '</defs>' % (cell, cell, gx, gy, cell, cell, cell * 4, cell * 4, gx, gy, cell * 4, cell * 4))
    p.append('<rect width="%d" height="%d" fill="#080c12"/>' % (VIEW_W, VIEW_H))
    p.append('<rect width="%d" height="%d" fill="url(#lvg1)"/>' % (VIEW_W, VIEW_H))
    p.append('<rect width="%d" height="%d" fill="url(#lvg2)"/>' % (VIEW_W, VIEW_H))
    p.append('<rect width="%d" height="%d" fill="url(#lvfade)"/>' % (VIEW_W, VIEW_H))

    # world origin marker (scrolls with the ground; proves RESET returned to the start)
    p.append('<g opacity=".8"><circle cx="%.1f" cy="%.1f" r="5" fill="none" stroke="#6b7f94"/>'
             '<path d="M%.1f %.1fh10M%.1f %.1fh-10M%.1f %.1fv10M%.1f %.1fv-10" stroke="#6b7f94"/>'
             '<text x="%.1f" y="%.1f" class="lv-hud">START POINT</text></g>'
             % (gx, gy, gx + 5, gy, gx - 5, gy, gx, gy + 5, gx, gy - 5, gx + 10, gy - 10))

    # breadcrumb trail of where the VehicleModel has actually been
    if len(trail) > 1:
        pts = " ".join("%.1f,%.1f" % (cx + (tx - x) * PX_PER_M, cy - (ty - y) * PX_PER_M)
                       for tx, ty in trail)
        p.append('<polyline points="%s" fill="none" stroke="#00b8ff" stroke-width="2" opacity=".45" '
                 'stroke-linejoin="round" stroke-linecap="round"/>' % pts)

    # --- rover (rotated by VehicleModel yaw; CCW-positive yaw -> negative SVG rotation) ---
    p.append('<g transform="translate(%.1f %.1f) rotate(%.3f)">' % (cx, cy, -yaw_deg))

    # heading vector: length follows the VehicleModel speed
    speed = max(gt["velocity"], 0.0)
    length = 30.0 + 90.0 * min(speed, 1.0)
    p.append('<line x1="66" y1="0" x2="%.1f" y2="0" stroke="#00b8ff" stroke-width="2" '
             'stroke-dasharray="6 4" opacity=".85"/>'
             '<polygon points="%.1f,-5 %.1f,0 %.1f,5" fill="#00b8ff" opacity=".9"/>'
             % (66 + length, 62 + length, 72 + length, 62 + length))

    # steering arc: sweeps toward the side the VehicleModel is turning (left = up, CCW positive)
    phi = max(-1.0, min(1.0, gt["yaw_rate"] / YAW_FULL)) * 70.0
    if abs(phi) > 0.5:
        r, a = 120.0, math.radians(phi)
        p.append('<path d="M%.1f 0A%.1f %.1f 0 0 %d %.2f %.2f" fill="none" stroke="#ffb020" '
                 'stroke-width="3" stroke-linecap="round" opacity=".9"/>'
                 % (r, r, r, 0 if phi > 0 else 1, r * math.cos(a), -r * math.sin(a)))

    # wheels
    for label, key, wx, wy in WHEEL_LAYOUT:
        rpm = enc[key] if enc else None
        col, glow, _ = _wheel_look(rpm)
        p.append('<g transform="translate(%d %d)">' % (wx, wy))
        if glow > 0:
            p.append('<rect x="-15" y="-7" width="30" height="14" rx="3" fill="%s" opacity="%.2f" '
                     'filter="url(#lvglow)"/>' % (col, 0.15 + 0.7 * glow))
        p.append('<rect x="-15" y="-7" width="30" height="14" rx="3" fill="#0a121b" stroke="%s" '
                 'stroke-width="2"/>' % col)
        for tx in (-9, -3, 3, 9):                        # tread marks
            p.append('<line x1="%d" y1="-5" x2="%d" y2="5" stroke="%s" stroke-width="1.5" opacity=".55"/>'
                     % (tx, tx, col))
        p.append('</g>')
        side = -1 if wy < 0 else 1
        rpm_txt = "%+.0f" % rpm if rpm is not None else "-"
        p.append(_upright(wx, wy + side * 18 + (3 if side < 0 else 6), rpm_txt, "lv-rpm", yaw_deg))
        p.append(_upright(wx, wy + side * 29 + (3 if side < 0 else 6), label, "lv-lbl", yaw_deg))

    # axles + chassis
    p.append('<line x1="30" y1="-30" x2="30" y2="30" stroke="#1c2a3a" stroke-width="3"/>'
             '<line x1="-30" y1="-30" x2="-30" y2="30" stroke="#1c2a3a" stroke-width="3"/>')
    p.append('<polygon points="-44,-20 -38,-26 38,-26 48,-15 48,15 38,26 -38,26 -44,20" '
             'fill="none" stroke="#00e5a0" stroke-width="3" opacity=".35" filter="url(#lvglow)"/>'
             '<polygon points="-44,-20 -38,-26 38,-26 48,-15 48,15 38,26 -38,26 -44,20" '
             'fill="url(#lvbody)" stroke="#00e5a0" stroke-width="1.5"/>'
             '<rect x="-30" y="-15" width="58" height="30" rx="4" fill="#0c141d" stroke="#1c2a3a"/>'
             '<rect x="-22" y="-8" width="20" height="16" rx="2" fill="none" stroke="#27405a"/>'
             '<path d="M-2 0H8M8 0V-8H20M8 0V8H20" fill="none" stroke="#27405a"/>'
             '<circle cx="-12" cy="0" r="2.5" fill="#00e5a0"/>'
             '<circle cx="22" cy="0" r="3" fill="#00b8ff"/>')
    # front direction indicator
    p.append('<polygon points="48,-11 63,0 48,11" fill="#00b8ff" opacity=".35" filter="url(#lvglow)"/>'
             '<polygon points="48,-11 63,0 48,11" fill="#00b8ff"/>')
    p.append(_upright(80, -10, "FRONT", "lv-front", yaw_deg))
    p.append(_upright(0, -86, "LEFT SIDE", "lv-side", yaw_deg))
    p.append(_upright(0, 96, "RIGHT SIDE", "lv-side", yaw_deg))
    p.append('</g>')

    # HUD
    p.append('<text x="14" y="22" class="lv-hud">4WD SKID-STEER · TOP-DOWN</text>'
             '<text x="%d" y="22" class="lv-hud c" text-anchor="end">SIMULATION MODE</text>'
             '<text x="14" y="%d" class="lv-hud">GRID %.2f m · ROVER ICON NOT TO SCALE</text>'
             '<text x="%d" y="%d" class="lv-hud" text-anchor="end">X %+.2f m  Y %+.2f m  HDG %.1f°</text>'
             % (VIEW_W - 14, VIEW_H - 12, GRID_M, VIEW_W - 14, VIEW_H - 12, x, y, yaw_deg % 360.0))
    p.append('</svg>')
    return '<div class="lv-stage">' + "".join(p) + '</div>'


def vehicle_panel_html(gt, enc, sample, running):
    """Live telemetry beside the rover. Values come from VehicleModel state + encoder messages."""
    def row(k, v):
        return '<div class="lv-row"><span>%s</span><span>%s</span></div>' % (k, v)

    sim_time = "%.2f s" % sample["timestamp"] if sample else "-"
    epoch = str(sample["messages"][0].epoch) if sample else "-"
    state_badge = ('<span class="lv-badge g">● LIVE</span>' if running
                   else '<span class="lv-badge a">● PAUSED</span>')
    wheels = []
    for label, key, _, _ in WHEEL_LAYOUT:
        rpm = enc[key] if enc else None
        _, _, cls = _wheel_look(rpm)
        wheels.append('<div class="lv-w %s"><div class="lv-w-k">%s</div><div class="lv-w-v">%s</div></div>'
                      % (cls, label, ("%+.1f rpm" % rpm) if rpm is not None else "-"))
    return (
        '<div class="lv-panel">'
        '<div class="lv-badges"><span class="lv-badge c">4WD SKID-STEER</span>'
        '<span class="lv-badge c">SIMULATION MODE</span>%s</div>'
        '<div class="lv-k">Vehicle</div>%s%s%s%s%s'
        '<div class="lv-k">Wheel encoders</div><div class="lv-wgrid">%s</div>'
        '<div class="lv-side-note">FL/RL = LEFT SIDE · FR/RR = RIGHT SIDE · RPM FROM ENCODER MESSAGES</div>'
        '</div>'
        % (state_badge,
           row("SPEED", "%.3f m/s" % gt["velocity"]),
           row("ACCEL", "%.3f m/s²" % gt["acceleration"]),
           row("YAW RATE", "%.3f rad/s" % gt["yaw_rate"]),
           row("SIM TIME", sim_time),
           row("EPOCH", epoch),
           "".join(wheels))
    )


# ----------------------------------------------------------------------------
# 3E: detailed live telemetry
# ----------------------------------------------------------------------------
WHEEL_KEYS = [("FL", "fl_rpm"), ("FR", "fr_rpm"), ("RL", "rl_rpm"), ("RR", "rr_rpm")]

# (title, y-axis unit, {legend label: history key}, colours)
LIVE_CHARTS = [
    ("Left vs right side speed", "m/s", {"Left": "left", "Right": "right"}, ["#00b8ff", "#ffb020"]),
    ("Expected vs observed yaw rate", "rad/s", {"Expected (encoders)": "expected",
                                                "Observed (IMU gyro Z)": "observed"}, ["#00b8ff", "#00e5a0"]),
    ("Yaw residual (observed - expected)", "rad/s", {"Residual": "residual"}, ["#ff4d6d"]),
    ("Vehicle speed", "m/s", {"Speed": "speed"}, ["#00e5a0"]),
]


def _metric_row(items):
    """items: [(label, value), ...] rendered as one row of st.metric cards."""
    for col, (label, value) in zip(st.columns(len(items)), items):
        col.metric(label, value)


def live_telemetry_section(s, sim, running):
    """LIVE TELEMETRY. Reads the existing simulator only: the latest sample `s`, the
    VehicleModel state, and the bounded history that _advance() filled from real samples."""
    gt = sim.vehicle.state()
    dash = "-"

    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)
    st.markdown('<p class="label">LIVE TELEMETRY</p>', unsafe_allow_html=True)

    # --- wheel telemetry: encoder values from the sample / wheel CANARYMessages ---
    st.markdown('<p class="tsub">Wheel telemetry</p>', unsafe_allow_html=True)
    st.markdown('<p class="sublabel">Encoder ECU · left = mean(FL, RL) · right = mean(FR, RR) · '
                'converted with the existing rpm_to_velocity()</p>', unsafe_allow_html=True)
    if s:
        enc = s["encoders"]
        left, right = _side_speeds(enc)
        wheel_vals = ["%+.1f rpm" % enc[k] for _, k in WHEEL_KEYS]
        side_vals = ["%+.3f m/s" % left, "%+.3f m/s" % right]
    else:
        wheel_vals, side_vals = [dash] * 4, [dash] * 2
    _metric_row([("FL front-left", wheel_vals[0]), ("FR front-right", wheel_vals[1]),
                 ("RL rear-left", wheel_vals[2]), ("RR rear-right", wheel_vals[3]),
                 ("Left speed", side_vals[0]), ("Right speed", side_vals[1])])

    # --- vehicle state: VehicleModel ground truth ---
    st.markdown('<p class="tsub">Vehicle state</p>', unsafe_allow_html=True)
    st.markdown('<p class="sublabel">VehicleModel state (ground truth)</p>', unsafe_allow_html=True)
    _metric_row([("Speed", "%.3f m/s" % gt["velocity"]),
                 ("Acceleration", "%+.3f m/s²" % gt["acceleration"]),
                 ("Yaw rate", "%+.3f rad/s" % gt["yaw_rate"]),
                 ("X position", "%+.3f m" % gt["x"]),
                 ("Y position", "%+.3f m" % gt["y"]),
                 ("Heading / yaw", "%.1f° (%+.3f rad)" % (math.degrees(gt["yaw"]) % 360.0, gt["yaw"]))])

    # --- physical consistency: encoders vs IMU ---
    st.markdown('<p class="tsub">Physical consistency</p>', unsafe_allow_html=True)
    st.markdown('<p class="sublabel">expected = (right − left) / TRACK_WIDTH (%.3f m) from encoders · '
                'observed = simulated IMU gyro Z · residual = observed − expected · '
                'display only, no detection yet</p>' % TRACK_WIDTH, unsafe_allow_html=True)
    if s:
        expected, observed, residual = _consistency(s)
        cons_vals = ["%+.4f rad/s" % v for v in (expected, observed, residual)]
    else:
        cons_vals = [dash] * 3
    _metric_row([("Expected yaw rate", cons_vals[0]), ("Observed yaw rate (IMU)", cons_vals[1]),
                 ("Yaw residual", cons_vals[2])])

    # --- simulation information ---
    st.markdown('<p class="tsub">Simulation information</p>', unsafe_allow_html=True)
    _metric_row([("Epoch", str(s["messages"][0].epoch) if s else dash),
                 ("Simulation time", "%.2f s" % s["timestamp"] if s else dash),
                 ("Scenario", s["scenario"] if s else dash),
                 ("Timestep", "%g ms · %d Hz" % (sim.dt * 1000.0, round(1.0 / sim.dt))),
                 ("State", "RUNNING" if running else "PAUSED")])

    # --- live signals: bounded history of real samples ---
    hist = st.session_state.history
    st.markdown('<p class="tsub">Live signals</p>', unsafe_allow_html=True)
    st.markdown('<p class="sublabel">Last %d samples kept · every %dth simulator sample · '
                'updates only while the simulator runs · %d points now</p>'
                % (HISTORY_MAX, HISTORY_STRIDE, len(hist)), unsafe_allow_html=True)
    if not hist:
        st.markdown('<p class="sublabel">No samples yet - press START.</p>', unsafe_allow_html=True)
        return
    times = [h["t"] for h in hist]
    for pair in (LIVE_CHARTS[:2], LIVE_CHARTS[2:]):
        for col, (title, unit, series, colours) in zip(st.columns(2), pair):
            frame = pd.DataFrame({name: [h[key] for h in hist] for name, key in series.items()},
                                 index=pd.Index(times, name="sim time (s)"))
            with col:
                st.markdown('<p class="sublabel">%s</p>' % title, unsafe_allow_html=True)
                st.line_chart(frame, color=colours, height=170, x_label="sim time (s)", y_label=unit)


# ----------------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------------
left, right = st.columns([5, 2])
with left:
    st.markdown(
        """
        <p class="title">CANARY</p>
        <p class="tagline">Cyber-Physical Intrusion Detection System</p>
        <p class="whim">the canary in the CAN bus - chirps when the physics lies</p>
        """,
        unsafe_allow_html=True,
    )
with right:
    st.markdown(
        """
        <div class="mode"><div class="mode-k">SIMULATION MODE</div>
        <div class="mode-v">CANARY LAPTOP SIMULATION</div></div>
        """,
        unsafe_allow_html=True,
    )
st.markdown('<hr class="rule"/>', unsafe_allow_html=True)

# ----------------------------------------------------------------------------
# Controls + status
# ----------------------------------------------------------------------------
running = st.session_state.running
c1, c2, c3, c4 = st.columns([1, 1, 1, 2])
with c1:
    st.button("START", key="start", on_click=_start, disabled=running)
with c2:
    st.button("PAUSE", key="pause", on_click=_pause, disabled=not running)
with c3:
    st.button("RESET", key="reset", on_click=_reset)
with c4:
    if running:
        st.markdown('<div class="status running">● RUNNING</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status paused">● PAUSED</div>', unsafe_allow_html=True)

st.markdown('<hr class="rule"/>', unsafe_allow_html=True)


# ----------------------------------------------------------------------------
# Live panels (one auto-refreshing fragment while RUNNING)
# ----------------------------------------------------------------------------
@st.fragment(run_every=REFRESH_S if running else None)
def live_panels():
    if st.session_state.running:
        _advance()
    s = st.session_state.last_sample

    st.markdown('<p class="label">System status</p>', unsafe_allow_html=True)
    st.markdown(system_status_html(s), unsafe_allow_html=True)

    # 3D: live vehicle - everything below reads the existing simulator, nothing is simulated here
    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)
    st.markdown('<p class="label">LIVE VEHICLE</p>', unsafe_allow_html=True)
    vehicle_gt = st.session_state.sim.vehicle.state()    # VehicleModel x, y, yaw, velocity, accel, yaw_rate
    enc = s["encoders"] if s else None                   # same values packed into the wheel CANARYMessages
    vcol, tcol = st.columns([3, 2])
    with vcol:
        st.markdown(rover_svg(vehicle_gt, enc, st.session_state.trail), unsafe_allow_html=True)
    with tcol:
        st.markdown(vehicle_panel_html(vehicle_gt, enc, s, st.session_state.running),
                    unsafe_allow_html=True)

    # 3E: detailed live telemetry (reads the same simulator; no second simulation)
    live_telemetry_section(s, st.session_state.sim, st.session_state.running)

    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)
    st.markdown('<p class="label">CANARY network</p>', unsafe_allow_html=True)
    st.markdown(network_html(st.session_state.running, st.session_state.pulse,
                             st.session_state.msg_counts, st.session_state.attack_lab.l1_flash()),
                unsafe_allow_html=True)

    # 3F: Security Layer 1 (dashboard visualization only - the C verifier is not invoked)
    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)
    layer1_section(st.session_state.layer1)

    # 3G: Security Layer 2 (real Random Forest inference on the simulator's sensor values)
    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)
    layer2_section(get_layer2(), st.session_state.l2_current, st.session_state.l2_history,
                   st.session_state.running)

    # 3H: unified detection breakdown (combines the Layer 1 and Layer 2 states shown above)
    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)
    detection_section(get_layer2(), st.session_state.layer1, st.session_state.detect,
                      st.session_state.l2_current, s)

    # 3I: Attack Lab (Layer 1 injections via Layer1Monitor.inject(); Layer 2 via the simulator's PhysicalAttack)
    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)
    attack_lab_section(get_layer2(), st.session_state.attack_lab, st.session_state.layer1,
                       st.session_state.l2_current, st.session_state.sim, st.session_state.running)

    st.markdown('<hr class="rule"/>', unsafe_allow_html=True)
    st.markdown('<p class="label">Telemetry - existing simulator</p>', unsafe_allow_html=True)
    cols = st.columns(6)
    if s is None:
        values = ["-"] * 6
    else:
        gt = s["ground_truth"]
        values = [
            "%.2f s" % s["timestamp"],
            str(s["messages"][0].epoch),
            s["scenario"],
            "%.3f m/s" % gt["velocity"],
            "%.3f m/s²" % gt["acceleration"],
            "%.3f rad/s" % gt["yaw_rate"],
        ]
    labels = ["Sim time", "Epoch", "Scenario", "Vehicle speed", "Acceleration", "Yaw rate"]
    for col, label, value in zip(cols, labels, values):
        col.metric(label, value)


live_panels()
