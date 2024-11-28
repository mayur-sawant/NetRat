#!/user/bin/env python3
#https://github.com/mayur-sawant/Packet-Sniffer

__author__="mayur-sawant"

import itertools 
import time
from socket import PF_PACKET, SOCK_RAW, ntohs, socket
from typing import Iterator
from netprotocols import Ethernet, IPv4, UDP, TCP


class Decoder:
    def __init__(self, interface: str):
        self.interface = interface
        self.packet_num = 0
        self.frame_length = 0
        self.epoch_time = 0
        self.protocol_queue = ["Ethernet"]  # Start with Ethernet as the first protocol to decode
        self.data = None

    def _bind_interface(self, sock):
        if self.interface is not None:
            sock.bind((self.interface, 0))
    
    def _attach_protocols(self, frame: bytes):
        # Start with Ethernet frame and continue to the next protocols based on encapsulation
        start = 0
        for proto in self.protocol_queue:
            try:
                if proto == "Ethernet":
                    ethernet_frame = Ethernet(frame)
                    print(f"Ethernet Frame: dst={ethernet_frame.dst}, src={ethernet_frame.src}, type={ethernet_frame.eth_type}")
                    self.protocol_queue.append(ethernet_frame.encapsulated_protocol)

                    # If encapsulated protocol is IPv4, continue decoding it
                    if ethernet_frame.encapsulated_protocol == "IPv4":
                        start = 14  # Skip Ethernet header (14 bytes)
                        ipv4_frame = IPv4(frame[start:])
                        print(f"IPv4 Frame: src={ipv4_frame.src}, dst={ipv4_frame.dst}, protocol={ipv4_frame.protocol}")
                        self.protocol_queue.append(ipv4_frame.protocol)  # Append either UDP or TCP based on protocol

                elif proto == "IPv4":
                    ipv4_frame = IPv4(frame[start:])
                    if ipv4_frame.protocol == "UDP":
                        udp_frame = UDP(frame[start + 20:])  # Skip IPv4 header (20 bytes)
                        print(f"Decoded UDP protocol: {udp_frame}")
                    elif ipv4_frame.protocol == "TCP":
                        tcp_frame = TCP(frame[start + 20:])  # Skip IPv4 header (20 bytes)
                        print(f"Decoded TCP protocol: {tcp_frame}")
                    else:
                        print("[+] Unknown Protocol")

                else:
                    print("[+] Unknown Protocol Layer")
            except Exception as e:
                print(f"Error decoding protocol: {e}")
                break

    def execute(self):
        # Receive the frame and decode it
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0003)) as sock:
            self._bind_interface(sock)
            for self.packet_num in itertools.count(1):
                frame = sock.recv(9000)
                self.frame_length = len(frame)
                self.epoch_time = time.time_ns() / (10**9)
                self._attach_protocols(frame)  # Attach protocols to the frame
                yield self  # Yield the decoded packet/frame for further processing




class PacketSniffer:
    def __init__(self):
        self._observers= list()

    def register(self,observer)->None:
        self._observers.append(observer)
    
    def _notify_all(self,*args,**kwargs)->None:
        [observer.update(*args,**kwargs) for observer in self._observers]
    
    def listen(self, interface:str)-> Iterator:
        for frame in Decoder(interface).execute():
            self._notify_all(frame)
            yield frame

