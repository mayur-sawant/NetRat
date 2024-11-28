import struct

# Layer 1 - Ethernet
class Ethernet:
    def __init__(self, raw_frame):
        self.dst, self.src, self.eth_type = struct.unpack("!6s6sH", raw_frame[:14])
        self.dst = self.format_mac(self.dst)
        self.src = self.format_mac(self.src)
        self.eth_type = hex(self.eth_type)
        self.encapsulated_protocol = self.get_encapsulated_protocol()

    @staticmethod
    def format_mac(mac):
        return ':'.join(f'{b:02x}' for b in mac)

    def get_encapsulated_protocol(self):
        if self.eth_type == '0x800':  # IPv4
            return 'IPv4'
        elif self.eth_type == '0x86dd':  # IPv6
            return 'IPv6'
        elif self.eth_type == '0x806':  # ARP
            return 'ARP'
        else:
            return 'Unknown'


# Layer 2 - IPv4
class IPv4:
    def __init__(self, raw_frame):
        # Unpack the first 20 bytes of the IPv4 header
        self.src, self.dst, self.protocol = struct.unpack("!4s4sB", raw_frame[:9])
        self.src = self.format_ip(self.src)
        self.dst = self.format_ip(self.dst)
        self.protocol = self.get_protocol(self.protocol)

    @staticmethod
    def format_ip(ip):
        return '.'.join(map(str, ip))

    @staticmethod
    def get_protocol(protocol_num):
        protocols = {17: 'UDP', 6: 'TCP'}
        return protocols.get(protocol_num, 'Unknown')


# Layer 3 - UDP
class UDP:
    def __init__(self, raw_frame):
        self.src_port, self.dst_port, self.length, self.checksum = struct.unpack("!HHHH", raw_frame[:8])

    def __str__(self):
        return f"UDP {self.src_port}->{self.dst_port}"


# Layer 3 - TCP
class TCP:
    def __init__(self, raw_frame):
        self.src_port, self.dst_port, self.seq, self.ack, self.offset_flags = struct.unpack("!HHLLH", raw_frame[:14])
        self.flags = self.parse_flags(self.offset_flags)

    def parse_flags(self, flags):
        flag_bits = {
            0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH', 0x10: 'ACK', 0x20: 'URG'
        }
        return [flag for mask, flag in flag_bits.items() if flags & mask]

    def __str__(self):
        return f"TCP {self.src_port}->{self.dst_port} Flags: {' '.join(self.flags)}"


# Main Decoder - Decoder will handle the packet structure and decoding
class Decoder:
    def __init__(self, interface: str):
        self.interface = interface
        self.protocol_queue = ["Ethernet"]
        self.packet_num = 0

    def decode(self, raw_frame):
        # Decode Ethernet Frame
        ethernet_frame = Ethernet(raw_frame)
        print(f"Ethernet Frame: dst={ethernet_frame.dst}, src={ethernet_frame.src}, type={ethernet_frame.eth_type}")
        
        # Get the encapsulated protocol (IPv4, IPv6, etc.)
        if ethernet_frame.encapsulated_protocol == 'IPv4':
            self.protocol_queue.append('IPv4')
            ipv4_frame = IPv4(raw_frame[14:])
            print(f"IPv4 Frame: src={ipv4_frame.src}, dst={ipv4_frame.dst}, protocol={ipv4_frame.protocol}")
            if ipv4_frame.protocol == 'UDP':
                udp_frame = UDP(raw_frame[14 + 20:])  # Skip IPv4 header
                print(f"Decoded UDP protocol: {udp_frame}")
            elif ipv4_frame.protocol == 'TCP':
                tcp_frame = TCP(raw_frame[14 + 20:])  # Skip IPv4 header
                print(f"Decoded TCP protocol: {tcp_frame}")
            else:
                print("[+] Unknown Protocol")

        else:
            print("[+] Unknown Encapsulated Protocol")


# Example usage
if __name__ == "__main__":
    raw_frame = b'\x52\x55\x0a\x00\x02\x03\x08\x00\x27\xad\x25\x87\x08\x00\x45\x00\x00\x3c\x1c\x46\x00\x00\x40\x06\xb1\xe6\xc0\xa8\x00\x68\xc0\xa8\x00\x01\x00\x35\x00\x35'
    decoder = Decoder('eth0')
    decoder.decode(raw_frame)
