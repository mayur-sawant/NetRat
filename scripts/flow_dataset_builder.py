import pandas as pd
from pathlib import Path

# config

BASE_DIR = Path(__file__).resolve().parent.parent / "data"

FLOW_DIR = BASE_DIR / "flows"
FEATURE_DIR = BASE_DIR / "features"

FEATURE_DIR.mkdir(parents=True, exist_ok=True)


# find flow files

flow_files = list(FLOW_DIR.glob("*.parquet"))

print(f"[+] Flow files found : {len(flow_files)}")

if not flow_files:
    print("[!] No flow paraquet files found")
    raise SystemExit

# read flow file

all_flow = []

for flow_file in flow_files:
    print("\n" + "="*60)
    print(f"[+] Reading: {flow_file}")
    print("="*60)

    df = pd.read_parquet(flow_file)

    print(f"[+] Flows loaded: {len(df)}")
    print("[+] label")
    print(df["label"].value_counts())

    all_flow.append(df)

# combine dataset

print("\n[+] Combining flow datasets...")

training_df = pd.concat(
    all_flow,
    ignore_index=True
)


# remove duplicates

before = len(training_df)

training_df = training_df.drop_duplicates(
    subset = ["flow_key","label"]
)

after = len(training_df)

print(f"[+] Duplicate flows removed: {before - after}")

# reset index

training_df.reset_index(drop=True, inplace=True)

# info display

print("\n" + "=" * 60)
print("TRAINING DATASET")
print("=" * 60)

print(f"Rows: {len(training_df)}")
print(f"Columns: {len(training_df.columns)}")

print("\nColumns:")
print(training_df.columns.tolist())

print("\nLabels:")
print(training_df["label"].value_counts())

print("\nDataset information:")
training_df.info()

# save dataset

output_file = FEATURE_DIR / "training_dataset.parquet"

training_df.to_parquet(
    output_file,
    index=False
)

print("\n" + "=" * 60)
print(f"[+] Training dataset saved:")
print(output_file)
print("=" * 60)