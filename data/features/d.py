import pandas as pd

data = pd.read_parquet("training_dataset.parquet")

df = pd.DataFrame(data)

'''print(df.head())

print(df.describe(include='all'))

print(df)

print(df.isna().sum())

print("Total NaN values:", df.isna().sum().sum())'''


"""print("Shape:", df.shape)

print("\nMissing values:")
print(df.isna().sum())

print("\nTotal missing values:", df.isna().sum().sum())

print("\nData types:")
print(df.dtypes)"""


import pandas as pd

df = pd.read_parquet("training_dataset.parquet")

print("Shape:", df.shape)

print("\n========== DATA TYPES ==========")
print(df.dtypes)

print("\n========== MISSING VALUES ==========")
print(df.isna().sum())

print("\n========== NUMERICAL SUMMARY ==========")
print(df.describe())

print("\n========== LABEL DISTRIBUTION ==========")
print(df["label"].value_counts())

print("\n========== ZERO VALUES ==========")
numeric_cols = df.select_dtypes(include="number").columns

for col in numeric_cols:
    zeros = (df[col] == 0).sum()
    print(f"{col}: {zeros}")

print("\n========== NEGATIVE VALUES ==========")
for col in numeric_cols:
    negatives = (df[col] < 0).sum()
    print(f"{col}: {negatives}")