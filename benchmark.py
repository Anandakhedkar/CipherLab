import os
import time
import statistics
import platform
import sys
from pathlib import Path

import pandas as pd

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)


# ==================================================
# 1. BENCHMARK CONFIGURATION
# ==================================================

ALGORITHMS = {
    "AES-256-GCM": AESGCM,
    "ChaCha20-Poly1305": ChaCha20Poly1305,
}

DATA_SIZES = {
    "1 KB": 1024,
    "10 KB": 10 * 1024,
    "100 KB": 100 * 1024,
    "1 MB": 1024 * 1024,
    "5 MB": 5 * 1024 * 1024,
}

WARMUP_RUNS = 3
REPEATS = 30

# Each measured sample times several operations.
# The result is divided by the number of operations.
BATCH_SIZE = 10

OUTPUT_FILE = Path(__file__).resolve().parent / "benchmark_results.csv"
ENVIRONMENT_FILE = Path(__file__).resolve().parent / "benchmark_environment.txt"


# ==================================================
# 2. KEY GENERATION
# ==================================================

def generate_key(algorithm_name):
    """Generate a valid 256-bit key."""

    if algorithm_name == "AES-256-GCM":
        return AESGCM.generate_key(bit_length=256)

    if algorithm_name == "ChaCha20-Poly1305":
        return ChaCha20Poly1305.generate_key()

    raise ValueError(f"Unsupported algorithm: {algorithm_name}")


# ==================================================
# 3. BENCHMARK ONE ALGORITHM AND DATA SIZE
# ==================================================

def benchmark_algorithm(algorithm_name, cipher_class, data_size):
    """
    Measure authenticated encryption and decryption.

    Each timed sample contains BATCH_SIZE operations.
    Reported operation times are averages per operation.
    """

    plaintext = os.urandom(data_size)

    key = generate_key(algorithm_name)
    cipher = cipher_class(key)

    encryption_times = []
    decryption_times = []

    # --------------------------------------------------
    # Prepare independent nonces for every operation.
    # --------------------------------------------------

    def create_nonce():
        return os.urandom(12)

    # --------------------------------------------------
    # Warm-up operations
    # --------------------------------------------------

    for _ in range(WARMUP_RUNS):
        nonce = create_nonce()

        ciphertext = cipher.encrypt(
            nonce,
            plaintext,
            None,
        )

        recovered = cipher.decrypt(
            nonce,
            ciphertext,
            None,
        )

        if recovered != plaintext:
            raise RuntimeError(
                f"Warm-up verification failed: {algorithm_name}"
            )

    # --------------------------------------------------
    # Repeated batched measurements
    # --------------------------------------------------

    for _ in range(REPEATS):

        # Prepare encryption nonces outside the timed section.
        nonces = [create_nonce() for _ in range(BATCH_SIZE)]

        # Measure a batch of encryption operations.
        start_time = time.perf_counter_ns()

        ciphertexts = [
            cipher.encrypt(nonce, plaintext, None)
            for nonce in nonces
        ]

        elapsed_ns = time.perf_counter_ns() - start_time

        encryption_times.append(
            elapsed_ns / BATCH_SIZE / 1_000_000
        )

        # Measure a batch of decryption operations.
        start_time = time.perf_counter_ns()

        recovered_messages = [
            cipher.decrypt(nonce, ciphertext, None)
            for nonce, ciphertext in zip(nonces, ciphertexts)
        ]

        elapsed_ns = time.perf_counter_ns() - start_time

        decryption_times.append(
            elapsed_ns / BATCH_SIZE / 1_000_000
        )

        # Verify outside the timed sections.
        if any(message != plaintext for message in recovered_messages):
            raise RuntimeError(
                f"Decryption verification failed: {algorithm_name}"
            )

    # --------------------------------------------------
    # Timing statistics
    # --------------------------------------------------

    average_encryption_ms = statistics.mean(encryption_times)
    median_encryption_ms = statistics.median(encryption_times)
    encryption_std_ms = statistics.stdev(encryption_times)

    average_decryption_ms = statistics.mean(decryption_times)
    median_decryption_ms = statistics.median(decryption_times)
    decryption_std_ms = statistics.stdev(decryption_times)

    # --------------------------------------------------
    # Throughput
    # --------------------------------------------------

    size_mib = data_size / (1024 * 1024)

    encryption_throughput = (
        size_mib / (average_encryption_ms / 1000)
        if average_encryption_ms > 0
        else 0
    )

    decryption_throughput = (
        size_mib / (average_decryption_ms / 1000)
        if average_decryption_ms > 0
        else 0
    )

    size_label = next(
        label
        for label, size in DATA_SIZES.items()
        if size == data_size
    )

    return {
        "Algorithm": algorithm_name,
        "Data Size": size_label,

        "Average Encryption Time (ms)": average_encryption_ms,
        "Median Encryption Time (ms)": median_encryption_ms,
        "Encryption Std Dev (ms)": encryption_std_ms,

        "Average Decryption Time (ms)": average_decryption_ms,
        "Median Decryption Time (ms)": median_decryption_ms,
        "Decryption Std Dev (ms)": decryption_std_ms,

        "Encryption Throughput (MiB/s)": encryption_throughput,
        "Decryption Throughput (MiB/s)": decryption_throughput,

        "Warm-up Runs": WARMUP_RUNS,
        "Measured Repetitions": REPEATS,
        "Batch Size": BATCH_SIZE,
        "Verification": "Passed",
    }


# ==================================================
# 4. SAVE ENVIRONMENT INFORMATION
# ==================================================

def save_environment_information():
    """Record the environment used for the benchmark."""

    information = [
        "Cipher Performance Benchmark Environment",
        "=" * 45,
        f"Operating system: {platform.platform()}",
        f"Machine architecture: {platform.machine()}",
        f"Processor description: {platform.processor()}",
        f"Python version: {sys.version}",
        f"Python implementation: {platform.python_implementation()}",
        f"Logical CPU count: {os.cpu_count()}",
        f"Warm-up runs: {WARMUP_RUNS}",
        f"Measured repetitions: {REPEATS}",
        f"Operations per measured batch: {BATCH_SIZE}",
        "",
        "Limitations:",
        "- Execution time is not a direct measurement of energy use.",
        "- This experiment does not measure electrical power.",
        "- Results depend on hardware, software, and system activity.",
    ]

    ENVIRONMENT_FILE.write_text(
        "\n".join(information),
        encoding="utf-8",
    )


# ==================================================
# 5. RUN THE FULL BENCHMARK
# ==================================================

def main():

    results = []

    total_tests = len(ALGORITHMS) * len(DATA_SIZES)

    print("=" * 70)
    print("ENCRYPTION PERFORMANCE BENCHMARK")
    print("=" * 70)

    print(f"Operating system: {platform.platform()}")
    print(f"Machine architecture: {platform.machine()}")
    print(f"Python version: {platform.python_version()}")
    print(f"Algorithms: {len(ALGORITHMS)}")
    print(f"Data sizes: {len(DATA_SIZES)}")
    print(f"Warm-up runs: {WARMUP_RUNS}")
    print(f"Measured repetitions: {REPEATS}")
    print(f"Operations per measured batch: {BATCH_SIZE}")
    print(f"Total algorithm/data-size combinations: {total_tests}")
    print()

    test_number = 0

    # Alternate the algorithm order for each data size.
    algorithm_items = list(ALGORITHMS.items())

    for size_index, (size_label, data_size) in enumerate(DATA_SIZES.items()):

        if size_index % 2 == 0:
            current_algorithms = algorithm_items
        else:
            current_algorithms = list(reversed(algorithm_items))

        for algorithm_name, cipher_class in current_algorithms:

            test_number += 1

            print(
                f"[{test_number}/{total_tests}] "
                f"Testing {algorithm_name} with {size_label}..."
            )

            result = benchmark_algorithm(
                algorithm_name,
                cipher_class,
                data_size,
            )

            results.append(result)

            print(
                f"  Average encryption: "
                f"{result['Average Encryption Time (ms)']:.6f} ms"
            )

            print(
                f"  Average decryption: "
                f"{result['Average Decryption Time (ms)']:.6f} ms"
            )

            print(
                f"  Encryption throughput: "
                f"{result['Encryption Throughput (MiB/s)']:.2f} MiB/s"
            )

            print(
                f"  Decryption throughput: "
                f"{result['Decryption Throughput (MiB/s)']:.2f} MiB/s"
            )

            print()

    # --------------------------------------------------
    # Save results
    # --------------------------------------------------

    df = pd.DataFrame(results)

    df.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    save_environment_information()

    # --------------------------------------------------
    # Completion summary
    # --------------------------------------------------

    print("=" * 70)
    print("BENCHMARK COMPLETED SUCCESSFULLY")
    print("=" * 70)

    print(f"Results saved to: {OUTPUT_FILE.name}")
    print(f"Environment saved to: {ENVIRONMENT_FILE.name}")
    print()

    print(df.to_string(index=False))
    print()

    if df["Verification"].eq("Passed").all():
        print("All decryption verification checks passed.")
    else:
        print("WARNING: At least one verification check did not pass.")

    print()
    print("IMPORTANT:")
    print("- These measurements describe this computer and software.")
    print("- Batched timing reduces the influence of timer overhead.")
    print("- Standard deviation describes variation between samples.")
    print("- Execution time does not directly measure energy consumption.")
    print("- Low-power hardware has not been tested by this experiment.")


# ==================================================
# 6. PROGRAM ENTRY POINT
# ==================================================

if __name__ == "__main__":
    main()