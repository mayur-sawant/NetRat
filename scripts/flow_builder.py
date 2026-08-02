import pandas as pd 
import os
import glob


PACKET_DIR = "../data/packets"
FLOW_DIR = "../data/flows"

os.makedirs(FLOW_DIR, exist_ok = True)

packet_files = glob.glob(os.path.join(PACKET_DIR,"*.parquet"))

print(packet_files)




for file in packet_files :
    print("\nReading:",file)
    df = pd.read_parquet(file)
    print(df.head())
    break


print(df.dtypes)

print("\nUnique UDP source ports:")
print(df["udp_src_port"].unique()[:30])

print("\nUnique UDP destination ports:")
print(df["udp_dst_port"].unique()[:30])











print(df.columns)

df["src_port"] = (
    df["tcp_src_port"]
    .fillna(df["udp_src_port"])
    .fillna(0)
    .astype(int)
)

df["dst_port"] = (
    df["tcp_dst_port"]
    .fillna(df["udp_dst_port"])
    .fillna(0)
    .astype(int)
)

print(df[[
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port"
]].head(10))


def create_flow_key(row):
    endpoint1 = (row["src_ip"],row["src_port"])
    endpoint2 = (row["dst_ip"],row["dst_port"])

    if endpoint1 <= endpoint2 :
        first = endpoint1
        second = endpoint2
    else :
        first = endpoint2 
        second = endpoint1

    return (
        f"{first[0]}:{first[1]}_"
        f"{second[0]}:{second[1]}_"
        f"{row['protocol']}"
    )


df["flow_key"] = df.apply(create_flow_key, axis = 1)

print(df[[
    "src_ip",
    "dst_port",
    "src_port",
    "dst_port",
    "flow_key"
]].head(15))

groups = df.groupby("flow_key")
print("Total flows:",len(groups))

print(df[[
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "flow_key"
]].head(15))


for flow_key, flow in groups:

    print("\nFlow Key:")
    print(flow_key)

    print("\nPackets in flow:")
    print(len(flow))

    print(flow.head())

    break



flow_sizes = df.groupby("flow_key").size()

print(flow_sizes.describe())

print(flow_sizes.sort_values(ascending=False).head(10))


print(df[["udp_src_port", "udp_dst_port"]].head(20))

print(df[df["protocol"] == 17][
    ["udp_src_port", "udp_dst_port"]
].describe())