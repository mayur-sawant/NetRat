import pandas as pd
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent / "data"
FLOW_DIR = BASE_DIR / "flows"

flow_files = list(FLOW_DIR.glob("*_flows.parquet"))

print(f"[+] Flow files found: {len(flow_files)}")

if not flow_files:
    print("[!] No flow files found.")
    exit()


# ============================================================
# Read latest flow file
# ============================================================

flow_file = max(flow_files, key=lambda f: f.stat().st_mtime)

print(f"\n[+] Reading: {flow_file.name}")

df = pd.read_parquet(flow_file)


# ============================================================
# Basic information
# ============================================================

print("\n" + "=" * 60)
print("BASIC INFORMATION")
print("=" * 60)

print(f"Rows (flows): {len(df)}")
print(f"Columns: {len(df.columns)}")

print("\nColumns:")
print(df.columns.tolist())


# ============================================================
# Missing values
# ============================================================

print("\n" + "=" * 60)
print("MISSING VALUES")
print("=" * 60)

missing = df.isna().sum()

print(missing[missing > 0])


# ============================================================
# Duplicate flow keys
# ============================================================

print("\n" + "=" * 60)
print("DUPLICATE FLOW KEYS")
print("=" * 60)

duplicates = df["flow_key"].duplicated().sum()

print(f"Duplicate flow keys: {duplicates}")


# ============================================================
# Packet counts
# ============================================================

print("\n" + "=" * 60)
print("PACKET COUNT")
print("=" * 60)

print(df["packet_count"].describe())


# ============================================================
# Bytes
# ============================================================

print("\n" + "=" * 60)
print("TOTAL BYTES")
print("=" * 60)

print(df["total_bytes"].describe())


# ============================================================
# Duration
# ============================================================

print("\n" + "=" * 60)
print("FLOW DURATION")
print("=" * 60)

print(df["duration"].describe())


# ============================================================
# Forward / backward validation
# ============================================================

print("\n" + "=" * 60)
print("DIRECTION VALIDATION")
print("=" * 60)

df["calculated_packets"] = (
    df["forward_packet_count"] +
    df["backward_packet_count"]
)

df["calculated_bytes"] = (
    df["forward_bytes"] +
    df["backward_bytes"]
)


packet_errors = (
    df["calculated_packets"] != df["packet_count"]
).sum()

byte_errors = (
    df["calculated_bytes"] != df["total_bytes"]
).sum()


print(f"Packet count mismatches: {packet_errors}")
print(f"Byte count mismatches: {byte_errors}")


# ============================================================
# Duration validation
# ============================================================

print("\n" + "=" * 60)
print("TIMESTAMP VALIDATION")
print("=" * 60)

timestamp_errors = (
    df["end_time"] < df["start_time"]
).sum()

negative_duration = (
    df["duration"] < 0
).sum()

print(f"End before start: {timestamp_errors}")
print(f"Negative durations: {negative_duration}")


# ============================================================
# Rate validation
# ============================================================

print("\n" + "=" * 60)
print("RATE VALIDATION")
print("=" * 60)

invalid_packet_rates = (
    (df["duration"] > 0) &
    (df["packets_per_second"] <= 0)
).sum()

invalid_byte_rates = (
    (df["duration"] > 0) &
    (df["bytes_per_second"] <= 0)
).sum()

print(f"Invalid packet rates: {invalid_packet_rates}")
print(f"Invalid byte rates: {invalid_byte_rates}")


# ============================================================
# Protocol distribution
# ============================================================

print("\n" + "=" * 60)
print("PROTOCOL DISTRIBUTION")
print("=" * 60)

print(df["protocol"].value_counts())


# ============================================================
# Labels
# ============================================================

print("\n" + "=" * 60)
print("LABEL DISTRIBUTION")
print("=" * 60)

print(df["label"].value_counts())


# ============================================================
# Flow summary
# ============================================================

print("\n" + "=" * 60)
print("FLOW SUMMARY")
print("=" * 60)

summary_columns = [
    "flow_key",
    "protocol",
    "duration",
    "packet_count",
    "total_bytes",
    "forward_packet_count",
    "backward_packet_count",
    "forward_bytes",
    "backward_bytes",
    "packets_per_second",
    "bytes_per_second",
    "label"
]

print(
    df[summary_columns]
    .sort_values("packet_count", ascending=False)
    .to_string(index=False)
)


print("\n[+] Validation completed.")