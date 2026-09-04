# final_three_attacks.py
# Optimized for DDoS, Botnet C2 Beaconing, and Port Scanning

import pandas as pd
import numpy as np
import joblib
import time
import random
import string
import hashlib
from collections import deque, defaultdict
from datetime import datetime, timedelta
import os
import warnings
import threading

from flask import Flask, jsonify, render_template_string, request
from flask_cors import CORS

warnings.filterwarnings('ignore')


# ============================================================
# 1. FEATURE ENGINEERING HELPERS
# ============================================================

def entropy(series):
    """Compute Shannon entropy of a pandas Series."""
    counts = series.value_counts(normalize=True)

    if len(counts) == 0:
        return 0.0

    return -sum(counts * np.log2(counts))


def compute_window_features(window_df):
    """
    Given a DataFrame of flows in the current window,
    compute a feature vector suitable for the model.
    """
    if len(window_df) == 0:
        return None

    # --------------------------------------------------------
    # Basic aggregates
    # --------------------------------------------------------

    total_flows = len(window_df)

    total_bytes_out = window_df['bytes_out'].sum()
    total_bytes_in = window_df['bytes_in'].sum()

    total_packets_out = window_df['packets_out'].sum()
    total_packets_in = window_df['packets_in'].sum()

    # --------------------------------------------------------
    # Protocol and flag counts
    # --------------------------------------------------------

    syn_count = window_df['tcp_flags'].str.contains(
        'S',
        na=False
    ).sum()

    udp_count = (
        window_df['protocol'] == 'UDP'
    ).sum()

    # --------------------------------------------------------
    # Unique entities
    # --------------------------------------------------------

    unique_src_ips = window_df['src_ip'].nunique()
    unique_dst_ips = window_df['dst_ip'].nunique()
    unique_dst_ports = window_df['dst_port'].nunique()
    unique_src_ports = window_df['src_port'].nunique()

    # --------------------------------------------------------
    # Entropy
    # --------------------------------------------------------

    # DDoS with spoofed source IPs tends to have high entropy.
    src_ip_entropy = entropy(
        window_df['src_ip']
    )

    dst_port_entropy = entropy(
        window_df['dst_port'].astype(str)
    )

    # --------------------------------------------------------
    # Inter-arrival time statistics
    # --------------------------------------------------------

    if 'timestamp' in window_df.columns:

        window_df = window_df.sort_values(
            'timestamp'
        )

        iat_list = []

        for (src, dst), group in window_df.groupby(
            ['src_ip', 'dst_ip']
        ):
            if len(group) > 1:

                diffs = (
                    group['timestamp']
                    .diff()
                    .dt.total_seconds()
                    .dropna()
                )

                iat_list.extend(
                    diffs.tolist()
                )

        if iat_list:

            avg_iat = np.mean(iat_list)
            std_iat = np.std(iat_list)
            min_iat = np.min(iat_list)
            max_iat = np.max(iat_list)

            cv_iat = (
                std_iat /
                (avg_iat + 1e-9)
            )

        else:

            avg_iat = 0
            std_iat = 0
            min_iat = 0
            max_iat = 0
            cv_iat = 0

    else:

        avg_iat = 0
        std_iat = 0
        min_iat = 0
        max_iat = 0
        cv_iat = 0

    # --------------------------------------------------------
    # Rate features
    # --------------------------------------------------------

    window_duration = 60.0

    flows_per_sec = (
        total_flows /
        window_duration
    )

    bytes_per_sec_out = (
        total_bytes_out /
        window_duration
    )

    packets_per_sec_out = (
        total_packets_out /
        window_duration
    )

    # --------------------------------------------------------
    # Fan-out features
    # --------------------------------------------------------

    fan_out_ports = (
        unique_dst_ports /
        (unique_src_ips + 1e-9)
    )

    fan_out_hosts = (
        unique_dst_ips /
        (unique_src_ips + 1e-9)
    )

    # --------------------------------------------------------
    # Final feature vector
    # --------------------------------------------------------

    features = {
        'total_flows': total_flows,
        'total_bytes_out': total_bytes_out,
        'total_bytes_in': total_bytes_in,
        'total_packets_out': total_packets_out,
        'total_packets_in': total_packets_in,

        'syn_count': syn_count,
        'udp_count': udp_count,

        'unique_src_ips': unique_src_ips,
        'unique_dst_ips': unique_dst_ips,
        'unique_dst_ports': unique_dst_ports,
        'unique_src_ports': unique_src_ports,

        'src_ip_entropy': src_ip_entropy,
        'dst_port_entropy': dst_port_entropy,

        'avg_iat': avg_iat,
        'std_iat': std_iat,
        'min_iat': min_iat,
        'max_iat': max_iat,
        'cv_iat': cv_iat,

        'flows_per_sec': flows_per_sec,
        'bytes_per_sec_out': bytes_per_sec_out,
        'packets_per_sec_out': packets_per_sec_out,

        'fan_out_ports': fan_out_ports,
        'fan_out_hosts': fan_out_hosts,
    }

    return features


# ============================================================
# 2. SYNTHETIC DATA GENERATION
# ============================================================

def generate_benign_flows(n=1500, duration=120):
    """Generate normal background traffic."""

    flows = []

    start = datetime.now()

    for _ in range(n):

        ts = (
            start +
            timedelta(
                seconds=random.uniform(
                    0,
                    duration
                )
            )
        )

        src = (
            f"192.168.1.{random.randint(1, 50)}"
        )

        dst = (
            f"10.0.{random.randint(0, 3)}."
            f"{random.randint(1, 254)}"
        )

        proto = random.choices(
            ['TCP', 'UDP'],
            weights=[0.9, 0.1]
        )[0]

        src_port = random.randint(
            1024,
            65535
        )

        dst_port = random.choice(
            [
                80,
                443,
                53,
                8080,
                22,
                25
            ]
        )

        bytes_out = int(
            np.random.exponential(5000)
        )

        bytes_in = int(
            np.random.exponential(10000)
        )

        packets_out = max(
            1,
            bytes_out //
            random.randint(50, 500)
        )

        packets_in = max(
            1,
            bytes_in //
            random.randint(50, 500)
        )

        tcp_flags = (
            '...'
            if proto == 'TCP'
            else ''
        )

        flows.append([
            ts,
            src,
            dst,
            src_port,
            dst_port,
            proto,
            bytes_out,
            bytes_in,
            packets_out,
            packets_in,
            tcp_flags,
            '',
            ''
        ])

    return flows


def generate_ddos_flows(n=800, duration=30):
    """
    Simulate a volumetric DDoS:
    SYN flood with many spoofed source IPs
    and a UDP reflection component.
    """

    flows = []

    start = datetime.now()

    victim_ip = '10.0.0.100'

    # --------------------------------------------------------
    # SYN flood
    # --------------------------------------------------------

    for _ in range(n):

        ts = (
            start +
            timedelta(
                seconds=random.uniform(
                    0,
                    duration
                )
            )
        )

        src = (
            f"203.0.113.{random.randint(1, 254)}"
        )

        src_port = random.randint(
            1024,
            65535
        )

        dst_port = 80

        proto = 'TCP'

        bytes_out = 0
        bytes_in = 0

        packets_out = 1
        packets_in = 0

        tcp_flags = 'S'

        flows.append([
            ts,
            src,
            victim_ip,
            src_port,
            dst_port,
            proto,
            bytes_out,
            bytes_in,
            packets_out,
            packets_in,
            tcp_flags,
            '',
            ''
        ])

    # --------------------------------------------------------
    # UDP reflection component
    # --------------------------------------------------------

    for _ in range(int(n * 0.3)):

        ts = (
            start +
            timedelta(
                seconds=random.uniform(
                    0,
                    duration
                )
            )
        )

        src = (
            f"198.51.100.{random.randint(1, 254)}"
        )

        src_port = 53

        dst_port = random.randint(
            1024,
            65535
        )

        proto = 'UDP'

        bytes_out = random.randint(
            1000,
            5000
        )

        bytes_in = 100

        packets_out = random.randint(
            1,
            5
        )

        packets_in = 1

        flows.append([
            ts,
            src,
            victim_ip,
            src_port,
            dst_port,
            proto,
            bytes_out,
            bytes_in,
            packets_out,
            packets_in,
            '',
            '',
            ''
        ])

    return flows


def generate_beaconing_flows(
    n_bots=10,
    beacons_per_bot=20,
    interval=30,
    duration=600
):
    """
    Simulate botnet C2 beaconing:
    periodic small flows from a few internal hosts
    to a small set of external C2 servers.
    """

    flows = []

    start = datetime.now()

    c2_ips = [
        f"185.220.101.{i}"
        for i in range(1, 5)
    ]

    for bot_id in range(n_bots):

        src_ip = (
            f"192.168.1.{50 + bot_id}"
        )

        c2_ip = random.choice(
            c2_ips
        )

        for i in range(beacons_per_bot):

            ts = (
                start +
                timedelta(
                    seconds=(
                        i * interval +
                        random.uniform(-2, 2)
                    )
                )
            )

            src_port = random.randint(
                1024,
                65535
            )

            dst_port = 443

            proto = 'TCP'

            bytes_out = random.randint(
                50,
                200
            )

            bytes_in = random.randint(
                100,
                300
            )

            packets_out = 1
            packets_in = 1

            tls_fp = (
                'malicious_c2_fingerprint'
            )

            flows.append([
                ts,
                src_ip,
                c2_ip,
                src_port,
                dst_port,
                proto,
                bytes_out,
                bytes_in,
                packets_out,
                packets_in,
                '...',
                '',
                tls_fp
            ])

    return flows


def generate_port_scan_flows(
    n_scans=5,
    ports_per_scan=200,
    duration=60
):
    """
    Simulate reconnaissance:
    a single source scanning many ports on one
    or multiple hosts.
    """

    flows = []

    start = datetime.now()

    scanner_ip = '192.168.1.70'

    targets = [
        '10.0.0.5',
        '10.0.0.6',
        '10.0.1.10'
    ]

    for _ in range(n_scans):

        target = random.choice(
            targets
        )

        ports = random.sample(
            range(1, 65535),
            ports_per_scan
        )

        for port in ports:

            ts = (
                start +
                timedelta(
                    seconds=random.uniform(
                        0,
                        duration
                    )
                )
            )

            src_port = random.randint(
                1024,
                65535
            )

            proto = 'TCP'

            bytes_out = 0
            bytes_in = 0

            packets_out = 1
            packets_in = 0

            tcp_flags = 'S'

            flows.append([
                ts,
                scanner_ip,
                target,
                src_port,
                port,
                proto,
                bytes_out,
                bytes_in,
                packets_out,
                packets_in,
                tcp_flags,
                '',
                ''
            ])

    return flows


def generate_all_data():
    """
    Generate a mixed training dataset.

    Each traffic type is generated in its own disjoint
    time segment. This prevents long beaconing traffic
    from overlapping and dominating other classes.
    """

    print("Generating training data...")

    def shift(flows, offset_seconds):

        for f in flows:
            f[0] = (
                f[0] +
                timedelta(
                    seconds=offset_seconds
                )
            )

        return flows

    all_flows = []

    cursor = 0.0

    # --------------------------------------------------------
    # Benign segment 1
    # --------------------------------------------------------

    benign1 = generate_benign_flows(
        400,
        60
    )

    all_flows.extend(
        shift(
            benign1,
            cursor
        )
    )

    cursor += 60

    # --------------------------------------------------------
    # DDoS segment
    # --------------------------------------------------------

    ddos = generate_ddos_flows(
        800,
        30
    )

    all_flows.extend(
        shift(
            ddos,
            cursor
        )
    )

    cursor += 30 + 30

    # --------------------------------------------------------
    # Benign segment 2
    # --------------------------------------------------------

    benign2 = generate_benign_flows(
        400,
        60
    )

    all_flows.extend(
        shift(
            benign2,
            cursor
        )
    )

    cursor += 60

    # --------------------------------------------------------
    # Port scan segment
    # --------------------------------------------------------

    portscan = generate_port_scan_flows(
        5,
        200,
        60
    )

    all_flows.extend(
        shift(
            portscan,
            cursor
        )
    )

    cursor += 60 + 30

    # --------------------------------------------------------
    # Benign segment 3
    # --------------------------------------------------------

    benign3 = generate_benign_flows(
        700,
        120
    )

    all_flows.extend(
        shift(
            benign3,
            cursor
        )
    )

    cursor += 120

    # --------------------------------------------------------
    # Beaconing segment
    # --------------------------------------------------------

    beacon = generate_beaconing_flows(
        10,
        20,
        30,
        600
    )

    all_flows.extend(
        shift(
            beacon,
            cursor
        )
    )

    cursor += 600

    # --------------------------------------------------------
    # DataFrame
    # --------------------------------------------------------

    df = pd.DataFrame(
        all_flows,
        columns=[
            'timestamp',
            'src_ip',
            'dst_ip',
            'src_port',
            'dst_port',
            'protocol',
            'bytes_out',
            'bytes_in',
            'packets_out',
            'packets_in',
            'tcp_flags',
            'dns_query',
            'tls_fingerprint'
        ]
    )

    df = (
        df.sort_values('timestamp')
        .reset_index(drop=True)
    )

    df.to_csv(
        'training_data.csv',
        index=False
    )

    print(
        f"✅ Generated {len(df)} flows, "
        f"saved to training_data.csv"
    )

    return df


# ============================================================
# 3. MODEL TRAINING
# ============================================================

def _flow_dicts(flows):
    """
    Convert raw flow-list rows into the dicts
    ThreatDetector expects.
    """

    out = []

    for flow in flows:

        out.append({
            'timestamp': flow[0],
            'src_ip': flow[1],
            'dst_ip': flow[2],
            'src_port': flow[3],
            'dst_port': flow[4],
            'protocol': flow[5],
            'bytes_out': flow[6],
            'bytes_in': flow[7],
            'packets_out': flow[8],
            'packets_in': flow[9],
            'tcp_flags': flow[10],
            'dns_query': flow[11],
            'tls_fingerprint': flow[12]
        })

    return out


def _windows_for_class(
    flows,
    label,
    sample_every=5
):
    """
    Replay flows through the same growing/expiring
    60-second window logic used by the live detector.

    IMPORTANT:
    Flows are sorted chronologically before windowing.
    """

    window = deque(
        maxlen=10000
    )

    samples = []

    # --------------------------------------------------------
    # IMPORTANT:
    # Training uses chronological ordering.
    # --------------------------------------------------------

    flow_dicts = sorted(
        _flow_dicts(flows),
        key=lambda d: pd.to_datetime(
            d['timestamp']
        )
    )

    for i, fd in enumerate(
        flow_dicts
    ):

        ts = pd.to_datetime(
            fd['timestamp']
        )

        fd = dict(fd)

        fd['timestamp'] = ts

        window.append(fd)

        cutoff = (
            ts -
            timedelta(seconds=60)
        )

        while (
            window and
            window[0]['timestamp'] < cutoff
        ):
            window.popleft()

        if len(window) < 20:
            continue

        if i % sample_every != 0:
            continue

        window_df = pd.DataFrame(
            list(window)
        )

        feats = compute_window_features(
            window_df
        )

        if feats:
            samples.append(feats)

    return (
        samples,
        [label] * len(samples)
    )


def _build_training_windows():
    """
    Build a balanced training set.

    Multiple independent runs are generated for
    each class so the model sees varied traffic.
    """

    windows = []
    window_labels = []

    # --------------------------------------------------------
    # Benign
    # --------------------------------------------------------

    for _ in range(4):

        s, l = _windows_for_class(
            generate_benign_flows(
                400,
                60
            ),
            0
        )

        windows += s
        window_labels += l

    # --------------------------------------------------------
    # DDoS
    # --------------------------------------------------------

    for _ in range(10):

        s, l = _windows_for_class(
            generate_ddos_flows(
                random.randint(
                    250,
                    400
                ),
                random.randint(
                    12,
                    20
                )
            ),
            1
        )

        windows += s
        window_labels += l

    # --------------------------------------------------------
    # Beaconing
    # --------------------------------------------------------

    for _ in range(8):

        s, l = _windows_for_class(
            generate_beaconing_flows(
                random.randint(4, 8),
                random.randint(6, 10),
                10,
                90
            ),
            2
        )

        windows += s
        window_labels += l

    # --------------------------------------------------------
    # Port scanning
    # --------------------------------------------------------

    for _ in range(10):

        s, l = _windows_for_class(
            generate_port_scan_flows(
                random.randint(1, 3),
                random.randint(100, 180),
                20
            ),
            3
        )

        windows += s
        window_labels += l

    return (
        windows,
        window_labels
    )


def train_models(df):

    print("Training models...")

    os.makedirs(
        'models',
        exist_ok=True
    )

    windows, window_labels = (
        _build_training_windows()
    )

    label_counts = (
        pd.Series(window_labels)
        .value_counts()
        .to_dict()
    )

    print(
        f"Training window label counts: "
        f"{label_counts}"
    )

    X = (
        pd.DataFrame(windows)
        .fillna(0)
    )

    y = np.array(
        window_labels
    )

    # --------------------------------------------------------
    # Balance classes
    # --------------------------------------------------------

    rng = np.random.RandomState(
        42
    )

    counts = (
        pd.Series(y)
        .value_counts()
    )

    cap = int(
        counts.min() * 3
    )

    keep_idx = []

    for cls, cnt in counts.items():

        idx = np.where(
            y == cls
        )[0]

        if len(idx) > cap:

            idx = rng.choice(
                idx,
                size=cap,
                replace=False
            )

        keep_idx.extend(
            idx.tolist()
        )

    keep_idx = sorted(
        keep_idx
    )

    X = (
        X.iloc[keep_idx]
        .reset_index(drop=True)
    )

    y = y[
        keep_idx
    ]

    print(
        f"Training windows after balancing: "
        f"{len(X)} "
        f"(label counts: "
        f"{pd.Series(y).value_counts().to_dict()})"
    )

    # --------------------------------------------------------
    # Feature columns
    # --------------------------------------------------------

    feature_cols = list(
        X.columns
    )

    joblib.dump(
        feature_cols,
        'models/feature_cols.pkl'
    )

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    from sklearn.ensemble import (
        RandomForestClassifier
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced_subsample'
    )

    clf.fit(
        X,
        y
    )

    joblib.dump(
        clf,
        'models/three_class_rf.pkl'
    )

    print(
        "✅ Model saved "
        "(Random Forest, 200 trees)"
    )

    # --------------------------------------------------------
    # Feature importance
    # --------------------------------------------------------

    importances = (
        clf.feature_importances_
    )

    print(
        "\nTop 10 features:"
    )

    for name, score in sorted(
        zip(
            feature_cols,
            importances
        ),
        key=lambda x: x[1],
        reverse=True
    )[:10]:

        print(
            f"  {name}: {score:.3f}"
        )

    return (
        clf,
        feature_cols
    )


# ============================================================
# 4. REAL-TIME DETECTOR
# ============================================================

class ThreatDetector:

    def __init__(
        self,
        clf,
        feature_cols
    ):

        self.clf = clf

        self.feature_cols = (
            feature_cols
        )

        self.window = deque(
            maxlen=10000
        )

        self.alerts = []

        self.last_alert_time = {}

        self.cooldown = 10


    def reset(self):
        """
        Completely reset live detector state.

        Called whenever a new simulation begins.
        """

        self.window.clear()

        self.alerts.clear()

        self.last_alert_time.clear()


    def process_flow(
        self,
        flow_dict
    ):
        """
        Add a single chronological flow
        to the live detection window.
        """

        # ----------------------------------------------------
        # Convert timestamp
        # ----------------------------------------------------

        ts = pd.to_datetime(
            flow_dict['timestamp']
        )

        # Make a copy so the original object
        # isn't unexpectedly modified.
        flow_dict = dict(
            flow_dict
        )

        flow_dict['timestamp'] = ts

        # ----------------------------------------------------
        # Add flow
        # ----------------------------------------------------

        self.window.append(
            flow_dict
        )

        # ----------------------------------------------------
        # Evict flows older than 60 seconds
        #
        # This relies on process_flow receiving flows
        # in chronological order.
        # ----------------------------------------------------

        cutoff = (
            ts -
            timedelta(seconds=60)
        )

        while (
            self.window and
            self.window[0]['timestamp'] < cutoff
        ):
            self.window.popleft()

        # ----------------------------------------------------
        # Wait until enough traffic exists
        # ----------------------------------------------------

        if len(self.window) < 20:
            return []

        # ----------------------------------------------------
        # Feature extraction
        # ----------------------------------------------------

        window_df = pd.DataFrame(
            list(self.window)
        )

        features = (
            compute_window_features(
                window_df
            )
        )

        if features is None:
            return []

        # ----------------------------------------------------
        # Model prediction
        # ----------------------------------------------------

        X = pd.DataFrame(
            [features],
            columns=self.feature_cols
        ).fillna(0)

        proba = (
            self.clf
            .predict_proba(X)[0]
        )

        pred_index = np.argmax(
            proba
        )

        pred_class = (
            self.clf
            .classes_[pred_index]
        )

        confidence = (
            proba[pred_index]
        )

        # ----------------------------------------------------
        # Only alert on non-benign traffic
        # ----------------------------------------------------

        if (
            pred_class != 0
            and
            confidence > 0.7
        ):

            threat_name = {
                1: 'DDoS',
                2: 'Botnet C2 Beaconing',
                3: 'Port Scanning'
            }.get(
                pred_class,
                'Unknown'
            )

            # Since flows are chronological,
            # the last row is the newest flow.
            last = (
                window_df.iloc[-1]
            )

            key = (
                f"{threat_name}_"
                f"{last['src_ip']}_"
                f"{last['dst_ip']}"
            )

            now = ts.timestamp()

            # ------------------------------------------------
            # Alert cooldown
            # ------------------------------------------------

            if (
                key not in self.last_alert_time
                or
                (
                    now -
                    self.last_alert_time[key]
                ) > self.cooldown
            ):

                self.last_alert_time[key] = now

                alert = {
                    'timestamp': ts.isoformat(),

                    'flow_identifier': (
                        f"{last['src_ip']}:"
                        f"{last['src_port']}"
                        f"->"
                        f"{last['dst_ip']}:"
                        f"{last['dst_port']}"
                    ),

                    'threat_class': threat_name,

                    'confidence_score': round(
                        confidence,
                        3
                    ),

                    'supporting_evidence': {
                        'flows_in_window': len(
                            self.window
                        ),

                        'src_ip_entropy': round(
                            features[
                                'src_ip_entropy'
                            ],
                            2
                        ),

                        'fan_out_ports': round(
                            features[
                                'fan_out_ports'
                            ],
                            2
                        ),

                        'avg_iat': round(
                            features[
                                'avg_iat'
                            ],
                            2
                        )
                    }
                }

                self.alerts.append(
                    alert
                )

                print(
                    f"🔔 {threat_name} detected "
                    f"(confidence: "
                    f"{round(confidence * 100, 1)}%)"
                )

                return [
                    alert
                ]

        return []


# ============================================================
# 5. FLASK APP
# ============================================================

app = Flask(
    __name__
)

CORS(
    app
)

# Global detector instance
detector = None

# Global simulation state
simulation_active = False
stop_requested = False

processing_lock = threading.Lock()


# ============================================================
# 6. HTML / JAVASCRIPT
# ============================================================

HTML = '''
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        Cyber Threat Detection – AI-Powered
    </title>

    <style>

        :root {
            --bg: #0a0e17;
            --card-bg: rgba(255,255,255,0.03);
            --border: rgba(0,212,255,0.3);
            --primary: #00d4ff;
            --danger: #ff4d6d;
            --warning: #ffb86c;
            --success: #50fa7b;
            --text: #e0e0e0;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
            position: relative;
            overflow-x: hidden;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;

            background:
                linear-gradient(
                    rgba(0,212,255,0.05)
                    1px,
                    transparent 1px
                ),
                linear-gradient(
                    90deg,
                    rgba(0,212,255,0.05)
                    1px,
                    transparent 1px
                );

            background-size: 40px 40px;

            animation:
                gridMove 20s linear infinite;

            z-index: -1;
        }

        @keyframes gridMove {

            0% {
                background-position: 0 0;
            }

            100% {
                background-position: 40px 40px;
            }
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            position: relative;
            z-index: 1;
        }

        h1 {
            font-size: 28px;
            margin-bottom: 20px;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 12px;
            text-shadow:
                0 0 10px rgba(0,212,255,0.7);
        }

        h1 span {
            color: var(--danger);
            text-shadow:
                0 0 10px rgba(255,77,109,0.7);
        }

        .control-panel {
            background:
                rgba(10,14,23,0.8);

            border:
                1px solid var(--border);

            border-radius: 16px;

            padding: 20px;

            margin-bottom: 25px;

            backdrop-filter: blur(10px);

            display: flex;

            flex-wrap: wrap;

            gap: 15px;

            align-items: center;

            box-shadow:
                0 0 30px rgba(0,212,255,0.1);
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
            letter-spacing: 0.5px;
            color: white;
            position: relative;
            overflow: hidden;
            box-shadow:
                0 0 15px rgba(0,0,0,0.3);
        }

        .btn::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;

            background:
                linear-gradient(
                    45deg,
                    transparent,
                    rgba(255,255,255,0.1),
                    transparent
                );

            transform: rotate(45deg);

            transition: all 0.5s;
        }

        .btn:hover::after {
            left: 100%;
            top: 100%;
        }

        .btn:hover {
            transform: translateY(-2px);

            box-shadow:
                0 5px 25px rgba(0,0,0,0.5);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn-ddos {
            background:
                linear-gradient(
                    135deg,
                    #e63946,
                    #b71c1c
                );
        }

        .btn-beacon {
            background:
                linear-gradient(
                    135deg,
                    #f77f00,
                    #e65100
                );
        }

        .btn-portscan {
            background:
                linear-gradient(
                    135deg,
                    #6a4c93,
                    #4527a0
                );
        }

        .btn-all {
            background:
                linear-gradient(
                    135deg,
                    #2a9d8f,
                    #00695c
                );
        }

        .btn-stop {
            background:
                linear-gradient(
                    135deg,
                    #ff4d6d,
                    #c62828
                );
        }

        .btn-clear {
            background: #333;
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .stats {
            display: flex;
            gap: 30px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .stat-card {
            background:
                rgba(10,14,23,0.8);

            border:
                1px solid var(--border);

            border-radius: 12px;

            padding: 15px 25px;

            min-width: 200px;

            backdrop-filter: blur(10px);

            box-shadow:
                0 0 20px rgba(0,212,255,0.05);

            transition: all 0.3s;
        }

        .stat-card:hover {
            box-shadow:
                0 0 30px rgba(0,212,255,0.2);
        }

        .stat-card .label {
            font-size: 12px;
            text-transform: uppercase;
            color: #888;
            margin-bottom: 5px;
        }

        .stat-card .value {
            font-size: 28px;
            font-weight: 700;
        }

        .stat-card .value.danger {
            color: var(--danger);
            text-shadow:
                0 0 10px rgba(255,77,109,0.7);
        }

        .stat-card .value.warning {
            color: var(--warning);
            text-shadow:
                0 0 10px rgba(255,184,108,0.7);
        }

        .stat-card .value.success {
            color: var(--success);
        }

        table {
            width: 100%;
            border-collapse: collapse;

            background:
                rgba(10,14,23,0.8);

            border:
                1px solid var(--border);

            border-radius: 16px;

            overflow: hidden;

            backdrop-filter: blur(10px);

            box-shadow:
                0 0 30px rgba(0,212,255,0.05);
        }

        th {
            background:
                rgba(0,212,255,0.1);

            color: var(--primary);

            padding: 14px 16px;

            text-align: left;

            font-size: 13px;

            text-transform: uppercase;

            letter-spacing: 0.5px;
        }

        td {
            padding: 12px 16px;

            border-bottom:
                1px solid rgba(255,255,255,0.05);

            font-size: 14px;
        }

        tr:hover td {
            background:
                rgba(0,212,255,0.05);
        }

        .confidence-high {
            color: var(--danger);
            font-weight: bold;

            text-shadow:
                0 0 8px rgba(255,77,109,0.8);
        }

        .confidence-medium {
            color: var(--warning);
            font-weight: bold;

            text-shadow:
                0 0 8px rgba(255,184,108,0.8);
        }

        .confidence-low {
            color: var(--success);
        }

        .no-alerts {
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }

        .no-alerts .icon {
            font-size: 48px;
            display: block;
            margin-bottom: 15px;
        }

        .flow-id {
            font-family:
                'Courier New',
                monospace;

            font-size: 12px;
            color: #aaa;
        }

        .evidence {
            font-size: 12px;
            color: #888;
            max-width: 200px;
            word-wrap: break-word;
        }

        .live-indicator {
            display: inline-block;

            width: 10px;
            height: 10px;

            border-radius: 50%;

            background:
                var(--success);

            margin-right: 6px;

            animation:
                pulse 1.5s infinite;
        }

        @keyframes pulse {

            0% {
                box-shadow:
                    0 0 0 0
                    rgba(80,250,123,0.7);
            }

            70% {
                box-shadow:
                    0 0 0 10px
                    rgba(80,250,123,0);
            }

            100% {
                box-shadow:
                    0 0 0 0
                    rgba(80,250,123,0);
            }
        }

        .refresh-note {
            color: #555;
            font-size: 12px;
            margin-top: 15px;
            text-align: center;
        }

        @media (max-width: 768px) {

            .control-panel {
                flex-direction: column;
                align-items: stretch;
            }

            .btn {
                width: 100%;
            }

            .stats {
                gap: 10px;
            }

            .stat-card {
                min-width: 100%;
            }
        }

    </style>

</head>


<body>

    <div class="container">

        <h1>
            🛡️ AI-Based Cyber Threat Detection
            <span>| Unidirectional IP Traffic</span>
        </h1>


        <div class="control-panel">

            <span
                style="
                    font-weight:600;
                    margin-right:10px;
                "
            >
                🔬 Simulate Attack:
            </span>


            <button
                class="btn btn-ddos"
                onclick="simulate('ddos')"
            >
                DDoS
                (SYN Flood + UDP Amplification)
            </button>


            <button
                class="btn btn-beacon"
                onclick="simulate('beaconing')"
            >
                Botnet C2 Beaconing
            </button>


            <button
                class="btn btn-portscan"
                onclick="simulate('portscan')"
            >
                Port Scanning (Recon)
            </button>


            <button
                class="btn btn-all"
                onclick="simulate('all')"
            >
                Run All
            </button>


            <button
                class="btn btn-stop"
                onclick="stopSimulation()"
            >
                ⏹ Stop
            </button>


            <button
                class="btn btn-clear"
                onclick="clearAlerts()"
            >
                Clear Alerts
            </button>


            <span
                style="
                    margin-left:auto;
                    font-size:12px;
                    color:#888;
                "
            >

                <span
                    class="live-indicator"
                ></span>

                LIVE

            </span>

        </div>


        <div class="stats">

            <div class="stat-card">

                <div class="label">
                    Total Alerts
                </div>

                <div
                    class="value danger"
                    id="totalAlerts"
                >
                    0
                </div>

            </div>


            <div class="stat-card">

                <div class="label">
                    DDoS
                </div>

                <div
                    class="value danger"
                    id="ddosCount"
                >
                    0
                </div>

            </div>


            <div class="stat-card">

                <div class="label">
                    Beaconing
                </div>

                <div
                    class="value warning"
                    id="beaconCount"
                >
                    0
                </div>

            </div>


            <div class="stat-card">

                <div class="label">
                    Port Scan
                </div>

                <div
                    class="value warning"
                    id="portCount"
                >
                    0
                </div>

            </div>

        </div>


        <table>

            <thead>

                <tr>
                    <th>Timestamp</th>
                    <th>Threat Class</th>
                    <th>Confidence</th>
                    <th>Flow Identifier</th>
                    <th>Evidence</th>
                </tr>

            </thead>


            <tbody id="alertsBody">

                <tr>

                    <td
                        colspan="5"
                        class="no-alerts"
                    >

                        <span class="icon">
                            ⏳
                        </span>

                        Waiting for alerts...

                        <br>

                        <span
                            style="
                                font-size:13px;
                                color:#444;
                            "
                        >
                            Select an attack simulation above.
                        </span>

                    </td>

                </tr>

            </tbody>

        </table>


        <p class="refresh-note">
            🔄 Auto-refreshing every 2 seconds
        </p>

    </div>


    <script>

        let simulationRunning = false;


        // ====================================================
        // START SIMULATION
        // ====================================================

        function simulate(attack) {

            if (simulationRunning) {

                alert(
                    'A simulation is already running. Stop it first.'
                );

                return;
            }

            simulationRunning = true;

            document
                .querySelectorAll('.btn')
                .forEach(
                    b => b.disabled = true
                );


            fetch(
                '/api/simulate/' + attack,
                {
                    method: 'POST'
                }
            )

            .then(
                r => r.json()
            )

            .then(
                data => {

                    if (data.status === 'ok') {

                        pollSimulationStatus();

                    } else {

                        alert(
                            'Simulation failed: ' +
                            data.message
                        );

                        resetButtons();
                    }

                }
            )

            .catch(
                err => {

                    console.error(
                        'Error:',
                        err
                    );

                    resetButtons();
                }
            );
        }


        // ====================================================
        // STOP SIMULATION
        // ====================================================

        function stopSimulation() {

            fetch(
                '/api/stop',
                {
                    method: 'POST'
                }
            )

            .then(
                r => r.json()
            )

            .then(
                data => {

                    console.log(
                        'Stop requested:',
                        data.message
                    );

                }
            );
        }


        // ====================================================
        // POLL SIMULATION
        // ====================================================

        function pollSimulationStatus() {

            setTimeout(
                () => {

                    resetButtons();

                    fetchData();

                },
                5000
            );
        }


        // ====================================================
        // RESET BUTTONS
        // ====================================================

        function resetButtons() {

            document
                .querySelectorAll('.btn')
                .forEach(
                    b => b.disabled = false
                );

            simulationRunning = false;
        }


        // ====================================================
        // CLEAR ALERTS
        // ====================================================

        function clearAlerts() {

            fetch(
                '/api/clear',
                {
                    method: 'POST'
                }
            )

            .then(
                () => fetchData()
            );
        }


        // ====================================================
        // FETCH ALERT DATA
        // ====================================================

        function fetchData() {

            fetch(
                '/api/alerts'
            )

            .then(
                r => r.json()
            )

            .then(
                alerts => {

                    const tbody =
                        document.getElementById(
                            'alertsBody'
                        );


                    if (alerts.length === 0) {

                        tbody.innerHTML =
                            '<tr>' +
                            '<td colspan="5" ' +
                            'class="no-alerts">' +
                            '✅ No threats detected' +
                            '</td>' +
                            '</tr>';

                    } else {

                        tbody.innerHTML = '';


                        alerts
                            .slice()
                            .reverse()
                            .forEach(
                                a => {

                                    const cls =
                                        a.confidence_score > 0.85
                                            ? 'confidence-high'
                                            : a.confidence_score > 0.7
                                                ? 'confidence-medium'
                                                : 'confidence-low';


                                    tbody.innerHTML +=
                                        `<tr>
                                            <td>
                                                ${a.timestamp}
                                            </td>

                                            <td>
                                                <strong>
                                                    ${a.threat_class}
                                                </strong>
                                            </td>

                                            <td
                                                class="${cls}"
                                            >
                                                ${
                                                    (
                                                        a.confidence_score *
                                                        100
                                                    ).toFixed(1)
                                                }%
                                            </td>

                                            <td
                                                class="flow-id"
                                            >
                                                ${a.flow_identifier}
                                            </td>

                                            <td
                                                class="evidence"
                                            >
                                                ${
                                                    JSON.stringify(
                                                        a.supporting_evidence
                                                    )
                                                }
                                            </td>
                                        </tr>`;
                                }
                            );
                    }
                }
            );


            // ------------------------------------------------
            // Stats
            // ------------------------------------------------

            fetch(
                '/api/stats'
            )

            .then(
                r => r.json()
            )

            .then(
                stats => {

                    document
                        .getElementById(
                            'totalAlerts'
                        )
                        .textContent =
                            stats.total_alerts;


                    document
                        .getElementById(
                            'ddosCount'
                        )
                        .textContent =
                            stats.by_class['DDoS'] || 0;


                    document
                        .getElementById(
                            'beaconCount'
                        )
                        .textContent =
                            stats.by_class[
                                'Botnet C2 Beaconing'
                            ] || 0;


                    document
                        .getElementById(
                            'portCount'
                        )
                        .textContent =
                            stats.by_class[
                                'Port Scanning'
                            ] || 0;

                }
            );
        }


        // ====================================================
        // AUTO REFRESH
        // ====================================================

        setInterval(
            fetchData,
            2000
        );

        fetchData();

    </script>

</body>

</html>
'''


# ============================================================
# 7. FLASK ROUTES
# ============================================================

@app.route('/')
def index():

    return render_template_string(
        HTML
    )


@app.route('/api/alerts')
def get_alerts():

    if detector is None:
        return jsonify([])

    return jsonify(
        detector.alerts[-50:]
    )


@app.route('/api/stats')
def get_stats():

    if detector is None:

        return jsonify({
            'total_alerts': 0,
            'by_class': {}
        })

    by_class = defaultdict(
        int
    )

    for alert in detector.alerts:

        by_class[
            alert['threat_class']
        ] += 1

    return jsonify({

        'total_alerts':
            len(detector.alerts),

        'by_class':
            dict(by_class)

    })


@app.route(
    '/api/clear',
    methods=['POST']
)
def clear_alerts():

    if detector:

        # Clear displayed alerts.
        detector.alerts.clear()

        # Also clear cooldown state so a new simulation
        # can generate fresh alerts immediately.
        detector.last_alert_time.clear()

        # IMPORTANT:
        # Clearing alerts should also clear the traffic
        # window. Otherwise the next simulation could inherit
        # old traffic even though the UI looks empty.
        detector.window.clear()

    return jsonify({
        'status': 'ok'
    })


@app.route(
    '/api/simulate/<attack>',
    methods=['POST']
)
def simulate_attack(attack):
    """
    Generate a burst of flows for the selected attack
    and process them in a background thread.

    Every simulation is treated as an independent scenario.
    """

    global simulation_active
    global stop_requested


    # --------------------------------------------------------
    # Make sure detector exists
    # --------------------------------------------------------

    if detector is None:

        return jsonify({
            'status': 'error',
            'message': 'Model not loaded yet'
        }), 500


    # --------------------------------------------------------
    # Start fresh simulation
    # --------------------------------------------------------

    with processing_lock:

        if simulation_active:

            return jsonify({
                'status': 'error',
                'message':
                    'Simulation already running'
            }), 409


        simulation_active = True

        stop_requested = False

        # ====================================================
        # IMPORTANT FIX #1
        #
        # Every button click starts an independent scenario.
        # Do not inherit the previous attack's traffic.
        # ====================================================

        detector.window.clear()

        # Reset alert cooldown state too.
        detector.last_alert_time.clear()


    # --------------------------------------------------------
    # Generate selected attack
    # --------------------------------------------------------

    flows = []


    if attack == 'ddos':

        flows = generate_ddos_flows(
            n=300,
            duration=15
        )


    elif attack == 'beaconing':

        flows = generate_beaconing_flows(
            n_bots=5,
            beacons_per_bot=8,
            interval=10,
            duration=80
        )


    elif attack == 'portscan':

        flows = generate_port_scan_flows(
            n_scans=2,
            ports_per_scan=150,
            duration=20
        )


    elif attack == 'all':

        flows.extend(
            generate_ddos_flows(
                200,
                10
            )
        )

        flows.extend(
            generate_beaconing_flows(
                3,
                5,
                10,
                50
            )
        )

        flows.extend(
            generate_port_scan_flows(
                1,
                100,
                15
            )
        )


    else:

        with processing_lock:

            simulation_active = False

        return jsonify({
            'status': 'error',
            'message':
                'Unknown attack type'
        }), 400


    # --------------------------------------------------------
    # Background flow processing
    # --------------------------------------------------------

    def process_flows():

        global simulation_active


        # ====================================================
        # IMPORTANT FIX #2
        #
        # The attack generators use random timestamps.
        #
        # Training explicitly sorts its flows chronologically.
        #
        # Live detection MUST do the same thing.
        # ====================================================

        sorted_flows = sorted(
            flows,
            key=lambda f:
                pd.to_datetime(f[0])
        )


        try:

            for flow in sorted_flows:

                if stop_requested:

                    break


                # --------------------------------------------
                # Convert raw flow to detector dictionary
                # --------------------------------------------

                flow_dict = {

                    'timestamp':
                        flow[0],

                    'src_ip':
                        flow[1],

                    'dst_ip':
                        flow[2],

                    'src_port':
                        flow[3],

                    'dst_port':
                        flow[4],

                    'protocol':
                        flow[5],

                    'bytes_out':
                        flow[6],

                    'bytes_in':
                        flow[7],

                    'packets_out':
                        flow[8],

                    'packets_in':
                        flow[9],

                    'tcp_flags':
                        flow[10],

                    'dns_query':
                        flow[11],

                    'tls_fingerprint':
                        flow[12]
                }


                # --------------------------------------------
                # Run model
                # --------------------------------------------

                detector.process_flow(
                    flow_dict
                )


                # --------------------------------------------
                # Simulate live traffic
                # --------------------------------------------

                time.sleep(
                    0.02
                )


        finally:

            # Always release simulation state.
            with processing_lock:

                simulation_active = False


    # --------------------------------------------------------
    # Start background thread
    # --------------------------------------------------------

    thread = threading.Thread(
        target=process_flows,
        daemon=True
    )

    thread.start()


    return jsonify({

        'status':
            'ok',

        'flows_generated':
            len(flows)

    })


@app.route(
    '/api/stop',
    methods=['POST']
)
def stop_simulation():
    """
    Signal the current background simulation to stop.
    """

    global stop_requested

    with processing_lock:

        stop_requested = True

    return jsonify({

        'status':
            'ok',

        'message':
            'Stopping simulation...'

    })


# ============================================================
# 8. MAIN EXECUTION
# ============================================================

if __name__ == '__main__':

    print(
        "=" * 60
    )

    print(
        "AI-Based Cyber Threat Detection – "
        "3 Attack Types"
    )

    print(
        "=" * 60
    )


    # --------------------------------------------------------
    # Step 1: Generate training data
    # --------------------------------------------------------

    train_df = generate_all_data()


    # --------------------------------------------------------
    # Step 2: Train model
    # --------------------------------------------------------

    clf, feature_cols = train_models(
        train_df
    )


    # --------------------------------------------------------
    # Step 3: Initialize detector
    # --------------------------------------------------------

    detector = ThreatDetector(
        clf,
        feature_cols
    )

    print(
        "\n✅ Detector ready. "
        "Starting web server..."
    )


    # --------------------------------------------------------
    # Step 4: Launch Flask
    # --------------------------------------------------------

    print(
        "\n" + "=" * 60
    )

    print(
        "🚀 Server running at "
        "http://localhost:5000"
    )

    print(
        "   (Press Ctrl+C to stop)"
    )

    print(
        "=" * 60
    )


    app.run(
        debug=False,
        host='0.0.0.0',
        port=5000
    )
