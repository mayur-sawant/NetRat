import subprocess
import pandas as pd
import os
import sys
from datetime import datetime



# Configuration


INTERFACE = "eth0"

CAPTURE_TIME = 300   #5 minutes

BASE_DIR = "../data"

RAW_DIR = f"{BASE_DIR}/raw"
PACKET_DIR = f"{BASE_DIR}/packets"


os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(PACKET_DIR, exist_ok=True)




# Activity label


if len(sys.argv) < 2:
    print("Usage: python capture_pipeline.py activity_name")
    exit()

activity = sys.argv[1]



timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

filename = f"{activity}_{timestamp}"

pcap_file = f"{RAW_DIR}/{filename}.pcapng"
csv_file = f"{PACKET_DIR}/{filename}.csv"
parquet_file = f"{PACKET_DIR}/{filename}.parquet"




# 1. Capture packets


print("[+] Starting packet capture...")
print(f"[+] Activity: {activity}")
print(f"[+] Duration: {CAPTURE_TIME} seconds")


capture_cmd = [
   # "sudo",
    "tshark",
    "-i",
    INTERFACE,
    "-a",
    f"duration:{CAPTURE_TIME}",
    "-w",
    pcap_file
]


#subprocess.run(capture_cmd)


result = subprocess.run(capture_cmd)

if result.returncode != 0 or not os.path.exists(pcap_file):
    print("[ERROR] Packet capture failed")
    exit()



print("[+] Capture completed")




# 2. Convert PCAP to CSV



print("[+] Extracting packets...")


fields = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "tcp.len",
    "tcp.flags",
    "ip.ttl",
    "tcp.window_size_value",
    "dns.qry.name",
    "tls.handshake.extensions_server_name"
]


tshark_cmd = [
    "tshark",
    "-r",
    pcap_file,
    "-T",
    "fields"
]


for f in fields:
    tshark_cmd.extend(["-e", f])


tshark_cmd.extend(
    [
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E", 
        "occurrence=f"
    ]
)



with open(csv_file,"w") as output:

    subprocess.run(
        tshark_cmd,
        stdout=output
    )


print("[+] CSV created")




# 3. Clean dataframe



print("[+] Cleaning data")


df = pd.read_csv(csv_file)
#df = pd.read_csv(
#    csv_file,
 #   on_bad_lines="skip"
#)



# Rename columns

df.columns = [
    "frame_no",
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "tcp_src_port",
    "tcp_dst_port",
    "udp_src_port",
    "udp_dst_port",
    "packet_size",
    "tcp_payload_size",
    "tcp_flags",
    "ttl",
    "window_size",
    "dns_query",
    "tls_sni"
]

df["label"] = activity

# Convert timestamp

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    unit="s"
)


# Replace missing values

df.fillna(
    {
        "src_ip":"unknown",
        "dst_ip":"unknown",
        "protocol":0,
        "dns_query":"",
        "tls_sni":""
    },
    inplace=True
)


# Convert numeric columns

numeric_cols = [
    "tcp_src_port",
    "tcp_dst_port",
    "udp_src_port",
    "udp_dst_port",
    "packet_size",
    "tcp_payload_size",
    "ttl",
    "window_size"
]

"""
for col in numeric_cols:
    df[col] = pd.to_numeric(
        df[col],
        errors="coerce"
    )
"""

for col in numeric_cols:
    df[col] = (
        pd.to_numeric(df[col], errors="coerce")
        .fillna(0)
    )

df["protocol"] = pd.to_numeric(
    df["protocol"],
    errors="coerce"
).fillna(-1).astype("int16")

# Remove empty rows

df.dropna(
    subset=["packet_size"],
    inplace=True
)



# Save parquet
"""
df.to_parquet(
    parquet_file,
    index=False
)

# Delete temporary CSV after successful conversion
if os.path.exists(csv_file):
    os.remove(csv_file)
    print("[+] Temporary CSV removed")
"""

try:
    df.to_parquet(parquet_file, index=False)

    if os.path.exists(csv_file):
        os.remove(csv_file)
        print("[+] Temporary CSV removed")

    print(f"[+] Saved: {parquet_file}")

except Exception as e:
    print(f"[ERROR] Failed to save Parquet: {e}")



print("[+] Finished")
print(df.info())
print(f"[+] Saved: {parquet_file}")