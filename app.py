import base64
import os
import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="CipherLab | Cryptographic Performance Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent
CSV_FILE = PROJECT_DIR / "benchmark_results.csv"


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b1120;
        color: #e5edf8;
    }

    [data-testid="stSidebar"] {
        background-color: #101a2c;
        border-right: 1px solid #263750;
    }

    h1, h2, h3 {
        color: #f1f5f9 !important;
    }

    p, li, label {
        color: #cbd5e1;
    }

    /* Text area: white background and dark readable text */
    .stTextArea textarea,
    .stTextInput input,
    [data-baseweb="textarea"] textarea,
    [data-baseweb="input"] input {
        background-color: #ffffff !important;
        color: #111827 !important;
        -webkit-text-fill-color: #111827 !important;
        caret-color: #111827 !important;
        border: 1px solid #94a3b8 !important;
        border-radius: 9px !important;
    }

    .stTextArea textarea::placeholder,
    .stTextInput input::placeholder {
        color: #64748b !important;
        -webkit-text-fill-color: #64748b !important;
        opacity: 1 !important;
    }

    .hero {
        background: linear-gradient(135deg, #14243d, #102c3d);
        border: 1px solid #28455c;
        border-radius: 18px;
        padding: 28px;
        margin-bottom: 24px;
    }

    .hero-title {
        font-size: 34px;
        font-weight: 800;
        color: #f8fafc;
        margin-bottom: 8px;
    }

    .hero-subtitle {
        color: #a8c4d9;
        font-size: 16px;
        line-height: 1.7;
    }

    .section-card {
        background: #121d30;
        border: 1px solid #263750;
        border-radius: 14px;
        padding: 20px;
        margin-bottom: 16px;
    }

    .small-label {
        color: #9eb2c9;
        font-size: 13px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    .big-value {
        color: #38d9f5;
        font-size: 25px;
        font-weight: 800;
        margin-top: 8px;
        overflow-wrap: anywhere;
    }

    .muted {
        color: #9eb2c9;
        font-size: 13px;
        line-height: 1.6;
    }

    div.stButton > button {
        border-radius: 9px;
        border: 1px solid #31516d;
        background-color: #172b43;
        color: #eaf6ff;
        font-weight: 600;
        min-height: 42px;
    }

    div.stButton > button:hover {
        background-color: #1d425c;
        border-color: #38d9f5;
        color: white;
    }

    div[data-testid="stMetric"] {
        background: #121d30;
        border: 1px solid #263750;
        padding: 16px;
        border-radius: 12px;
    }

    hr {
        border-color: #263750;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# NAVIGATION
# ============================================================

PAGES = [
    "Overview",
    "Encryption Lab",
    "Security Tests",
    "Performance Analysis",
    "About Project",
]


def go_to_page(page_name):
    st.session_state["navigation_page"] = page_name


if "navigation_page" not in st.session_state:
    st.session_state["navigation_page"] = "Overview"


# ============================================================
# ENCRYPTION FUNCTIONS
# ============================================================

def generate_key(algorithm):
    if algorithm == "AES-256-GCM":
        return AESGCM.generate_key(bit_length=256)

    if algorithm == "ChaCha20-Poly1305":
        return ChaCha20Poly1305.generate_key()

    raise ValueError("Unsupported algorithm.")


def get_cipher(algorithm, key):
    if algorithm == "AES-256-GCM":
        return AESGCM(key)

    if algorithm == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key)

    raise ValueError("Unsupported algorithm.")


def encrypt_message(message, algorithm):
    key = generate_key(algorithm)
    nonce = os.urandom(12)
    cipher = get_cipher(algorithm, key)

    ciphertext = cipher.encrypt(
        nonce,
        message.encode("utf-8"),
        None,
    )

    return key, nonce, ciphertext


def decrypt_message(ciphertext, key, nonce, algorithm):
    cipher = get_cipher(algorithm, key)

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        None,
    )

    return plaintext.decode("utf-8")


def format_bytes(number):
    number = float(number)

    if number >= 1024 * 1024:
        return f"{number / (1024 * 1024):.2f} MiB"

    if number >= 1024:
        return f"{number / 1024:.2f} KiB"

    return f"{number:.0f} bytes"


def metric_card(label, value, description=""):
    st.markdown(
        f"""
        <div class="section-card">
            <div class="small-label">{label}</div>
            <div class="big-value">{value}</div>
            <div class="muted">{description}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# CSV READING AND NUMERIC CONVERSION
# ============================================================

def normalize_column_name(name):
    name = str(name).strip().lower()
    name = name.replace("_", " ")
    name = re.sub(r"\s+", " ", name)
    name = name.replace("(mi b/s)", "(mib/s)")

    aliases = {
        "algorithm name": "algorithm",
        "data size bytes": "data size",
        "data size (bytes)": "data size",
        "datasize": "data size",
        "average encryption time": "average encryption time (ms)",
        "avg encryption time": "average encryption time (ms)",
        "mean encryption time": "average encryption time (ms)",
        "average decryption time": "average decryption time (ms)",
        "avg decryption time": "average decryption time (ms)",
        "mean decryption time": "average decryption time (ms)",
        "encryption throughput": "encryption throughput (mib/s)",
        "decryption throughput": "decryption throughput (mib/s)",
    }

    return aliases.get(name, name)


def to_number(value):
    """
    Convert a single CSV value into a float.

    Handles numbers stored as strings, spaces, commas, scientific
    notation, and common unit suffixes.

    Returns None when the value cannot be converted.
    """

    if pd.isna(value):
        return None

    if isinstance(value, (int, float)):
        try:
            number = float(value)
            if pd.notna(number) and number not in (
                float("inf"),
                float("-inf"),
            ):
                return number
            return None
        except (ValueError, TypeError):
            return None

    text_value = str(value).strip()

    if not text_value:
        return None

    text_value = text_value.replace(",", "")

    # Extract a numeric value, including scientific notation.
    match = re.search(
        r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?",
        text_value,
    )

    if not match:
        return None

    try:
        number = float(match.group(0))

        if number in (float("inf"), float("-inf")):
            return None

        return number

    except (ValueError, TypeError):
        return None


def calculate_throughput(data_size_bytes, time_ms):
    """
    Calculate throughput in MiB/s.

    Formula:
    (data size in bytes / 1,048,576) / (time in milliseconds / 1000)
    """

    if data_size_bytes is None or time_ms is None:
        return None

    if data_size_bytes <= 0 or time_ms <= 0:
        return None

    size_mib = data_size_bytes / (1024 * 1024)
    time_seconds = time_ms / 1000

    return size_mib / time_seconds


def load_benchmark_data():
    """
    Load benchmark data while preserving valid rows.

    Only data size and encryption/decryption time are essential.
    If throughput is missing or invalid, it is recalculated.
    """

    if not CSV_FILE.exists():
        return None, (
            f"File not found: {CSV_FILE.name}. "
            "Make sure it is in the same folder as app.py."
        ), None

    try:
        raw = pd.read_csv(
            CSV_FILE,
            sep=None,
            engine="python",
            encoding="utf-8-sig",
            skipinitialspace=True,
        )

    except Exception as error:
        return None, f"Could not read the CSV file: {error}", None

    if raw.empty:
        return None, "The CSV file contains no data rows.", raw

    raw.columns = [
        normalize_column_name(column)
        for column in raw.columns
    ]

    required_columns = [
        "algorithm",
        "data size",
        "average encryption time (ms)",
        "average decryption time (ms)",
    ]

    missing = [
        column for column in required_columns
        if column not in raw.columns
    ]

    if missing:
        return (
            None,
            "Missing required CSV columns: "
            + ", ".join(missing)
            + ". Detected columns: "
            + ", ".join(raw.columns.astype(str)),
            raw,
        )

    rows = []

    for _, row in raw.iterrows():

        algorithm_raw = str(row["algorithm"]).strip()

        if not algorithm_raw or algorithm_raw.lower() == "nan":
            continue

        normalized_algorithm = (
            algorithm_raw.lower()
            .replace(" ", "")
            .replace("_", "-")
        )

        algorithm_aliases = {
            "aes": "AES-256-GCM",
            "aes256": "AES-256-GCM",
            "aes-256": "AES-256-GCM",
            "aes256gcm": "AES-256-GCM",
            "aes-256-gcm": "AES-256-GCM",
            "chacha20": "ChaCha20-Poly1305",
            "chacha20poly1305": "ChaCha20-Poly1305",
            "chacha20-poly1305": "ChaCha20-Poly1305",
        }

        algorithm = algorithm_aliases.get(
            normalized_algorithm,
            algorithm_raw,
        )

        size = to_number(row["data size"])
        encryption_time = to_number(
            row["average encryption time (ms)"]
        )
        decryption_time = to_number(
            row["average decryption time (ms)"]
        )

        # These three fields are necessary for time-based comparisons.
        if size is None or encryption_time is None or decryption_time is None:
            continue

        if size <= 0 or encryption_time <= 0 or decryption_time <= 0:
            continue

        encryption_throughput = None
        decryption_throughput = None

        if "encryption throughput (mib/s)" in raw.columns:
            encryption_throughput = to_number(
                row["encryption throughput (mib/s)"]
            )

        if "decryption throughput (mib/s)" in raw.columns:
            decryption_throughput = to_number(
                row["decryption throughput (mib/s)"]
            )

        # Calculate throughput if it is missing, zero, or invalid.
        if (
            encryption_throughput is None
            or encryption_throughput <= 0
        ):
            encryption_throughput = calculate_throughput(
                size,
                encryption_time,
            )

        if (
            decryption_throughput is None
            or decryption_throughput <= 0
        ):
            decryption_throughput = calculate_throughput(
                size,
                decryption_time,
            )

        if encryption_throughput is None or decryption_throughput is None:
            continue

        # Include the original measurements plus normalized values.
        rows.append(
            {
                "Algorithm": algorithm,
                "Data Size": size,
                "Average Encryption Time (ms)": encryption_time,
                "Average Decryption Time (ms)": decryption_time,
                "Encryption Throughput (MiB/s)": encryption_throughput,
                "Decryption Throughput (MiB/s)": decryption_throughput,
            }
        )

    if not rows:
        diagnostic_columns = list(raw.columns)

        preview = raw.head(5).to_dict(orient="records")

        return (
            None,
            "The CSV file was opened, but no rows had valid positive "
            "data sizes and encryption/decryption times. "
            f"Detected columns: {diagnostic_columns}. "
            "See the raw CSV preview below to inspect the actual values.",
            {
                "raw": raw,
                "preview": preview,
            },
        )

    clean_data = pd.DataFrame(rows)

    return clean_data, None, raw


# ============================================================
# PERFORMANCE HELPERS
# ============================================================

def overall_benchmark_summary(data):
    return data.groupby("Algorithm").agg(
        Mean_Encryption_Time=(
            "Average Encryption Time (ms)",
            "mean",
        ),
        Mean_Decryption_Time=(
            "Average Decryption Time (ms)",
            "mean",
        ),
        Mean_Encryption_Throughput=(
            "Encryption Throughput (MiB/s)",
            "mean",
        ),
        Mean_Decryption_Throughput=(
            "Decryption Throughput (MiB/s)",
            "mean",
        ),
    )


def create_bar_chart(data, metric, title, ylabel):
    plot_data = data.pivot_table(
        index="Data Size",
        columns="Algorithm",
        values=metric,
        aggfunc="mean",
    ).sort_index()

    fig, ax = plt.subplots(figsize=(10, 4.5))

    plot_data.plot(
        kind="bar",
        ax=ax,
        width=0.78,
    )

    ax.set_title(title, fontsize=13, pad=15)
    ax.set_xlabel("Data Size (bytes)")
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    ax.set_axisbelow(True)
    ax.legend(title="Algorithm")
    ax.tick_params(axis="x", rotation=30)

    fig.tight_layout()

    return fig


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        """
        <div style="padding: 8px 0 18px 0;">
            <div style="font-size: 27px; font-weight: 800;">
                🔐 CipherLab
            </div>
            <div style="color: #9eb2c9; font-size: 13px;">
                Cryptographic Performance Analyzer
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    selected_page = st.radio(
        "NAVIGATION",
        PAGES,
        key="navigation_page",
    )

    st.markdown("---")
    st.markdown("### Algorithms")
    st.caption("AES-256-GCM")
    st.caption("ChaCha20-Poly1305")
    st.markdown("---")
    st.caption("Academic prototype • Python + Streamlit")


# ============================================================
# LOAD CSV
# ============================================================

benchmark_data, benchmark_error, raw_csv_data = load_benchmark_data()


# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
    <div class="hero">
        <div class="hero-title">CipherLab</div>
        <div class="hero-subtitle">
            Explore authenticated encryption, test data integrity,
            and compare the measured performance of AES-256-GCM
            and ChaCha20-Poly1305.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# OVERVIEW
# ============================================================

if selected_page == "Overview":

    st.subheader("Cryptographic Performance Overview")

    st.write(
        "This dashboard demonstrates two authenticated encryption "
        "algorithms and displays your recorded benchmark measurements."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        metric_card(
            "Algorithms",
            "02",
            "AES-256-GCM and ChaCha20-Poly1305",
        )

    with col2:
        metric_card(
            "Encryption type",
            "AEAD",
            "Encryption with authentication",
        )

    with col3:
        metric_card(
            "Benchmark source",
            "CSV",
            "Your recorded benchmark results",
        )

    st.markdown("## What do the benchmark results tell us?")

    if benchmark_error:
        st.warning(benchmark_error)

    else:
        summary = overall_benchmark_summary(benchmark_data)

        if len(summary) >= 2:

            fastest = summary["Mean_Encryption_Time"].idxmin()
            highest = summary["Mean_Encryption_Throughput"].idxmax()

            col1, col2 = st.columns(2)

            with col1:
                metric_card(
                    "Lowest mean encryption time",
                    fastest,
                    f"{summary.loc[fastest, 'Mean_Encryption_Time']:.4f} ms",
                )

            with col2:
                metric_card(
                    "Highest mean encryption throughput",
                    highest,
                    f"{summary.loc[highest, 'Mean_Encryption_Throughput']:.2f} MiB/s",
                )

        else:
            st.info("At least two algorithms are required for comparison.")

    st.markdown("## Explore the dashboard")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### 🔒 Encryption Lab")
        st.write("Encrypt and decrypt a sample message.")

        st.button(
            "Open Encryption Lab",
            key="overview_encryption_button",
            on_click=go_to_page,
            args=("Encryption Lab",),
            use_container_width=True,
        )

    with col2:
        st.markdown("### 🛡️ Security Tests")
        st.write("Test ciphertext tampering and incorrect keys.")

        st.button(
            "Open Security Tests",
            key="overview_security_button",
            on_click=go_to_page,
            args=("Security Tests",),
            use_container_width=True,
        )

    with col3:
        st.markdown("### 📊 Performance Analysis")
        st.write("Review benchmark charts and measurements.")

        st.button(
            "Open Performance Analysis",
            key="overview_performance_button",
            on_click=go_to_page,
            args=("Performance Analysis",),
            use_container_width=True,
        )

    st.markdown("## Important interpretation")

    st.markdown(
        """
        - Lower encryption time means faster completion.
        - Higher throughput means more data processed per second.
        - Both algorithms provide authenticated encryption when used
          correctly.
        - This project does not directly measure electrical power
          or energy consumption.
        """
    )


# ============================================================
# ENCRYPTION LAB
# ============================================================

elif selected_page == "Encryption Lab":

    st.subheader("Encryption Lab")

    st.write(
        "Enter a message, choose an algorithm, encrypt it, and "
        "then decrypt it to verify the original message."
    )

    st.warning(
        "Educational demonstration only. Do not enter passwords "
        "or confidential information."
    )

    algorithm = st.selectbox(
        "Choose an encryption algorithm",
        ["AES-256-GCM", "ChaCha20-Poly1305"],
        key="encryption_algorithm",
    )

    message = st.text_area(
        "Enter your message",
        value="Hello! This is a CipherLab encryption demonstration.",
        height=140,
        key="encryption_message",
        placeholder="Type your message here...",
    )

    if st.button(
        "Encrypt Message",
        key="encrypt_message_button",
        type="primary",
    ):

        if not message:
            st.warning("Please enter a message first.")

        else:
            try:
                key, nonce, ciphertext = encrypt_message(
                    message,
                    algorithm,
                )

                st.session_state["lab_algorithm"] = algorithm
                st.session_state["lab_key"] = key
                st.session_state["lab_nonce"] = nonce
                st.session_state["lab_ciphertext"] = ciphertext
                st.session_state["lab_original_message"] = message

                st.session_state.pop(
                    "lab_decrypted_message",
                    None,
                )

                st.success("Message encrypted successfully.")

            except Exception as error:
                st.error(f"Encryption failed: {error}")

    if "lab_ciphertext" in st.session_state:

        st.markdown("---")
        st.subheader("Encryption output")

        saved_algorithm = st.session_state["lab_algorithm"]
        saved_key = st.session_state["lab_key"]
        saved_nonce = st.session_state["lab_nonce"]
        saved_ciphertext = st.session_state["lab_ciphertext"]

        st.write(f"**Algorithm:** {saved_algorithm}")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Generated key (Base64)**")
            st.code(
                base64.b64encode(saved_key).decode("utf-8"),
                language=None,
            )

            st.markdown("**Nonce (Base64)**")
            st.code(
                base64.b64encode(saved_nonce).decode("utf-8"),
                language=None,
            )

        with col2:
            st.markdown("**Ciphertext (Base64)**")
            st.code(
                base64.b64encode(saved_ciphertext).decode("utf-8"),
                language=None,
            )

            st.markdown("**Ciphertext size**")
            st.write(format_bytes(len(saved_ciphertext)))

        st.markdown("---")
        st.subheader("Decrypt the message")

        if st.button(
            "Decrypt Message",
            key="decrypt_message_button",
        ):

            try:
                decrypted = decrypt_message(
                    saved_ciphertext,
                    saved_key,
                    saved_nonce,
                    saved_algorithm,
                )

                st.session_state["lab_decrypted_message"] = decrypted

                st.success("Decryption and authentication succeeded.")

            except Exception:
                st.error(
                    "Decryption failed. The key, nonce or ciphertext "
                    "may be incorrect or corrupted."
                )

        if "lab_decrypted_message" in st.session_state:

            st.markdown("**Decrypted message**")

            st.code(
                st.session_state["lab_decrypted_message"],
                language=None,
            )

            if (
                st.session_state["lab_original_message"]
                == st.session_state["lab_decrypted_message"]
            ):
                st.success(
                    "Verification passed: the decrypted message "
                    "matches the original message."
                )
            else:
                st.error("Verification failed.")


# ============================================================
# SECURITY TESTS
# ============================================================

elif selected_page == "Security Tests":

    st.subheader("Security Tests")

    st.write(
        "Test how authenticated encryption reacts to modified "
        "ciphertext and an incorrect decryption key."
    )

    algorithm = st.selectbox(
        "Choose an algorithm",
        ["AES-256-GCM", "ChaCha20-Poly1305"],
        key="security_algorithm",
    )

    sample_message = b"This is a sample message for an integrity test."

    col1, col2 = st.columns(2)

    with col1:

        st.markdown("### Test 1: Ciphertext tampering")

        st.write(
            "Modify one byte of the encrypted message and attempt "
            "to decrypt it."
        )

        if st.button(
            "Run Tampering Test",
            key="tampering_test_button",
            use_container_width=True,
        ):

            test_key = generate_key(algorithm)
            test_nonce = os.urandom(12)
            cipher = get_cipher(algorithm, test_key)

            ciphertext = cipher.encrypt(
                test_nonce,
                sample_message,
                None,
            )

            changed = bytearray(ciphertext)
            changed[0] ^= 1

            try:
                cipher.decrypt(
                    test_nonce,
                    bytes(changed),
                    None,
                )

                st.error(
                    "Unexpected result: modified ciphertext was accepted."
                )

            except Exception:
                st.success(
                    "Test passed: modified ciphertext was rejected."
                )

    with col2:

        st.markdown("### Test 2: Incorrect key")

        st.write(
            "Attempt to decrypt a message with a different random key."
        )

        if st.button(
            "Run Wrong-Key Test",
            key="wrong_key_test_button",
            use_container_width=True,
        ):

            original_key = generate_key(algorithm)
            wrong_key = generate_key(algorithm)
            test_nonce = os.urandom(12)

            cipher = get_cipher(algorithm, original_key)

            ciphertext = cipher.encrypt(
                test_nonce,
                sample_message,
                None,
            )

            wrong_cipher = get_cipher(algorithm, wrong_key)

            try:
                wrong_cipher.decrypt(
                    test_nonce,
                    ciphertext,
                    None,
                )

                st.error(
                    "Unexpected result: decryption succeeded "
                    "with an incorrect key."
                )

            except Exception:
                st.success(
                    "Test passed: the incorrect key was rejected."
                )

    st.markdown("---")

    st.subheader("What do these tests demonstrate?")

    st.markdown(
        """
        **Confidentiality:** encrypted data does not directly reveal
        the original message.

        **Integrity:** modifications to authenticated ciphertext
        should be detected.

        **Authentication:** the ciphertext must validate with the
        supplied key and nonce.

        These examples demonstrate expected behaviour but are not
        a complete security audit.
        """
    )


# ============================================================
# PERFORMANCE ANALYSIS
# ============================================================

elif selected_page == "Performance Analysis":

    st.subheader("Performance Analysis")

    st.write(
        "Compare the benchmark measurements recorded for "
        "AES-256-GCM and ChaCha20-Poly1305."
    )

    if benchmark_error:

        st.error(benchmark_error)

        if isinstance(raw_csv_data, dict):

            st.markdown("### CSV diagnostic information")

            st.write(
                "The application could read the file, but it could "
                "not identify valid benchmark rows."
            )

            st.markdown("**First five CSV records**")

            st.json(raw_csv_data.get("preview", []))

        elif isinstance(raw_csv_data, pd.DataFrame):

            st.markdown("### CSV preview")

            st.dataframe(
                raw_csv_data.head(10),
                use_container_width=True,
                hide_index=True,
            )

        st.info(
            "If this error continues, the CSV preview above will help "
            "identify whether the stored values are missing, malformed, "
            "or use a different format."
        )

    else:

        data = benchmark_data.copy()

        st.success(
            f"Successfully loaded {len(data)} valid benchmark rows "
            f"from {data['Algorithm'].nunique()} algorithm(s)."
        )

        algorithms = sorted(
            data["Algorithm"].dropna().unique().tolist()
        )

        sizes = sorted(
            data["Data Size"].dropna().unique().tolist()
        )

        st.markdown("### Filters")

        col1, col2 = st.columns(2)

        with col1:
            selected_algorithms = st.multiselect(
                "Select algorithms",
                options=algorithms,
                default=algorithms,
                key="performance_algorithms",
            )

        with col2:
            selected_sizes = st.multiselect(
                "Select data sizes (bytes)",
                options=sizes,
                default=sizes,
                key="performance_sizes",
            )

        filtered_data = data[
            data["Algorithm"].isin(selected_algorithms)
            & data["Data Size"].isin(selected_sizes)
        ].copy()

        if filtered_data.empty:

            st.warning(
                "No rows match the selected filters. Select at least "
                "one algorithm and one data size."
            )

        else:

            st.markdown("### Performance charts")

            tabs = st.tabs(
                [
                    "Encryption Time",
                    "Decryption Time",
                    "Encryption Throughput",
                    "Decryption Throughput",
                ]
            )

            charts = [
                (
                    "Average Encryption Time (ms)",
                    "Average Encryption Time by Data Size",
                    "Time (ms)",
                ),
                (
                    "Average Decryption Time (ms)",
                    "Average Decryption Time by Data Size",
                    "Time (ms)",
                ),
                (
                    "Encryption Throughput (MiB/s)",
                    "Encryption Throughput by Data Size",
                    "Throughput (MiB/s)",
                ),
                (
                    "Decryption Throughput (MiB/s)",
                    "Decryption Throughput by Data Size",
                    "Throughput (MiB/s)",
                ),
            ]

            for tab, chart in zip(tabs, charts):

                with tab:

                    fig = create_bar_chart(
                        filtered_data,
                        chart[0],
                        chart[1],
                        chart[2],
                    )

                    st.pyplot(fig, use_container_width=True)
                    plt.close(fig)

            st.markdown("---")

            st.subheader("Benchmark data table")

            st.dataframe(
                filtered_data,
                use_container_width=True,
                hide_index=True,
            )

            csv_bytes = filtered_data.to_csv(
                index=False,
            ).encode("utf-8")

            st.download_button(
                "Download filtered benchmark results",
                data=csv_bytes,
                file_name="cipherlab_filtered_benchmark_results.csv",
                mime="text/csv",
            )

            st.markdown("---")

            st.subheader("Summary of recorded measurements")

            summary = overall_benchmark_summary(filtered_data)

            st.dataframe(
                summary.reset_index(),
                use_container_width=True,
                hide_index=True,
            )

            if len(summary) >= 2:

                fastest_enc = summary[
                    "Mean_Encryption_Time"
                ].idxmin()

                highest_enc = summary[
                    "Mean_Encryption_Throughput"
                ].idxmax()

                fastest_dec = summary[
                    "Mean_Decryption_Time"
                ].idxmin()

                highest_dec = summary[
                    "Mean_Decryption_Throughput"
                ].idxmax()

                col1, col2 = st.columns(2)

                with col1:

                    metric_card(
                        "Lowest mean encryption time",
                        fastest_enc,
                        "Calculated from the displayed records.",
                    )

                    metric_card(
                        "Lowest mean decryption time",
                        fastest_dec,
                        "Calculated from the displayed records.",
                    )

                with col2:

                    metric_card(
                        "Highest mean encryption throughput",
                        highest_enc,
                        "Calculated from the displayed records.",
                    )

                    metric_card(
                        "Highest mean decryption throughput",
                        highest_dec,
                        "Calculated from the displayed records.",
                    )

            st.info(
                "These findings describe recorded benchmark results. "
                "They do not establish universal performance or "
                "energy efficiency."
            )

    st.markdown("---")

    st.subheader("Experimental limitations")

    st.markdown(
        """
        - Results depend on hardware, software and data size.
        - This prototype does not directly measure electrical power.
        - Energy-efficiency claims require a suitable energy-measurement
          method and experiments on the target hardware.
        """
    )


# ============================================================
# ABOUT PROJECT
# ============================================================

elif selected_page == "About Project":

    st.subheader("About This Project")

    st.markdown(
        """
        ### Project title

        **Evaluation of ChaCha20-Poly1305 as an Alternative to AES
        on Low Power Platforms**

        ### Domain

        Classical Ciphers and Symmetric Key Cryptography

        ### Objectives

        1. Implement AES-256-GCM encryption and decryption.
        2. Implement ChaCha20-Poly1305 encryption and decryption.
        3. Demonstrate ciphertext integrity and authentication.
        4. Compare recorded encryption and decryption performance.
        5. Present measurements using charts and tables.
        6. Explain the limitations of the experiment.

        ### Technologies

        - Python
        - Cryptography
        - Streamlit
        - Pandas
        - Matplotlib
        - CSV

        ### AES-256-GCM

        AES is a symmetric encryption algorithm. GCM provides
        authenticated encryption, protecting confidentiality and
        helping detect modifications to encrypted data.

        ### ChaCha20-Poly1305

        ChaCha20 is a stream cipher, and Poly1305 provides
        authentication. Together, they form authenticated encryption.

        ### Experimental scope

        This project compares recorded benchmark measurements.
        It does not directly measure electrical power or energy
        consumption.

        ### Future improvements

        - Test on a Raspberry Pi or another low-power device.
        - Measure energy consumption using a suitable method.
        - Compare multiple hardware platforms.
        - Repeat measurements and report variability.
        """
    )

    environment_file = PROJECT_DIR / "benchmark_environment.txt"

    st.markdown("---")
    st.subheader("Benchmark environment")

    if environment_file.exists():

        try:
            st.code(
                environment_file.read_text(encoding="utf-8"),
                language=None,
            )

        except Exception as error:
            st.warning(
                f"Could not read environment information: {error}"
            )

    else:
        st.info(
            "benchmark_environment.txt was not found."
        )

    st.warning(
        "This is an educational prototype, not a production key "
        "management system."
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.markdown(
    """
    <div style="text-align: center; padding: 10px; color: #8196ad;">
        CipherLab • Cryptographic Performance Analyzer
        <br>
        Academic prototype for learning and experimentation
    </div>
    """,
    unsafe_allow_html=True,
)