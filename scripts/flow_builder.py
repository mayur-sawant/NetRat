import pandas as pd
from pathlib import Path

#config

BASE_DIR = Path(__file__).resolve().parent.parent / "data"

PACKET_DIR = BASE_DIR / "packets"
FLOW_DIR = BASE_DIR / "flows"

FLOW_DIR.mkdir(parents=True, exist_ok=True)

# find pkt file

packet_files = list(PACKET_DIR.glob("*.parquet"))

print(f"[+] Packet files found: {len(packet_files)}")

if not packet_files:
    print("[!] No packet Parquet files found.")
    exit()


# process pkt file

for packet_file in packet_files:
    print("\n" + "=" * 60)
    print(f"[+] Reading: {packet_file.name}")
    print("="*60)

    df = pd.read_parquet(packet_file)
    print(f"[+] Packets loaded: {len(df)}")

    # Remove packets that cannot form a valid IP flow
    

    invalid_mask = (
        df["src_ip"].isna() |
        df["dst_ip"].isna() |
        (df["src_ip"] == "unknown") |
        (df["dst_ip"] == "unknown") |
        (df["protocol"] == 0)
    )

    invalid_packet_count = invalid_mask.sum()

    df = df[~invalid_mask].copy()

    print(f"[+] Invalid packets removed: {invalid_packet_count}")
    print(f"[+] Valid packets remaining: {len(df)}")

    # create source/ports

    df["src_port"]=(
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

    # bidirectional flow

    def create_flow_key(row):

        endpoint1 = (row["src_ip"], row["src_port"])
        endpoint2 = (row["dst_ip"], row["dst_port"])

        if endpoint1 <= endpoint2:
            first = endpoint1
            second = endpoint2
        else:
            first = endpoint2
            second = endpoint1

        return (
            f"{first[0]}:{first[1]}_"
            f"{second[0]}:{second[1]}_"
            f"{row['protocol']}"
        )


    df["flow_key"] = df.apply(create_flow_key, axis=1)


   
    # Build flow-level features
 

    print("[+] Building flow features...")


    flow_rows = []


    for flow_key, flow in df.groupby("flow_key", sort=False):

        flow = flow.sort_values("timestamp")


        # Basic information
       
        first_packet = flow.iloc[0]
        last_packet = flow.iloc[-1]

        packet_count = len(flow)


        
        # Duration
        

        duration = (
            last_packet["timestamp"] -
            first_packet["timestamp"]
        ).total_seconds()


        
        # Packet sizes
       

        total_bytes = flow["packet_size"].sum()

        mean_packet_size = flow["packet_size"].mean()

        max_packet_size = flow["packet_size"].max()

        min_packet_size = flow["packet_size"].min()

        std_packet_size = flow["packet_size"].std()

        if pd.isna(std_packet_size):
            std_packet_size = 0


       
        # TCP payload
       
        total_tcp_payload = flow["tcp_payload_size"].fillna(0).sum()

        mean_tcp_payload = flow["tcp_payload_size"].fillna(0).mean()


       
        # Forward / backward packets
        
        first_src_ip = first_packet["src_ip"]
        first_src_port = first_packet["src_port"]

        forward_mask = (
            (flow["src_ip"] == first_src_ip) &
            (flow["src_port"] == first_src_port)
        )

        forward_packets = flow[forward_mask]

        backward_packets = flow[~forward_mask]


        forward_packet_count = len(forward_packets)

        backward_packet_count = len(backward_packets)


        forward_bytes = forward_packets["packet_size"].sum()

        backward_bytes = backward_packets["packet_size"].sum()


        
        # Packet rate
        
        if duration > 0:

            packets_per_second = packet_count / duration

            bytes_per_second = total_bytes / duration

        else:

            packets_per_second = 0

            bytes_per_second = 0


        
        # Inter-arrival time
       

        if packet_count > 1:

            inter_arrival = (
                flow["timestamp"]
                .diff()
                .dt.total_seconds()
                .dropna()
            )

            mean_inter_arrival = inter_arrival.mean()

            std_inter_arrival = inter_arrival.std()

            if pd.isna(std_inter_arrival):
                std_inter_arrival = 0

        else:

            mean_inter_arrival = 0

            std_inter_arrival = 0


        
        # Create flow record
        
        flow_row = {

            "flow_key": flow_key,

            "src_ip": first_src_ip,

            "dst_ip": first_packet["dst_ip"],

            "src_port": first_src_port,

            "dst_port": first_packet["dst_port"],

            "protocol": first_packet["protocol"],


            "start_time": first_packet["timestamp"],

            "end_time": last_packet["timestamp"],

            "duration": duration,


            "packet_count": packet_count,

            "total_bytes": total_bytes,

            "mean_packet_size": mean_packet_size,

            "std_packet_size": std_packet_size,

            "min_packet_size": min_packet_size,

            "max_packet_size": max_packet_size,


            "total_tcp_payload": total_tcp_payload,

            "mean_tcp_payload": mean_tcp_payload,


            "forward_packet_count": forward_packet_count,

            "backward_packet_count": backward_packet_count,

            "forward_bytes": forward_bytes,

            "backward_bytes": backward_bytes,


            "packets_per_second": packets_per_second,

            "bytes_per_second": bytes_per_second,


            "mean_inter_arrival": mean_inter_arrival,

            "std_inter_arrival": std_inter_arrival,


            "label": first_packet["label"]

        }


        flow_rows.append(flow_row)


    
    # Create flow DataFrame
    

    flow_df = pd.DataFrame(flow_rows)


    print(f"[+] Total flows created: {len(flow_df)}")


    
    # Display flow dataset
    

    print("\nFlow dataset:")

    print(flow_df.head())


    print("\nFlow dataset information:")

    print(flow_df.info())


    
    # Save flow dataset
   

    output_name = packet_file.stem + "_flows.parquet"

    output_file = FLOW_DIR / output_name

    flow_df.to_parquet(
        output_file,
        index=False
    )


    print(f"\n[+] Saved flows: {output_file}")


print("\n[+] Flow building completed.")        