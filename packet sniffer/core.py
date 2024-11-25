#!/user/bin/env python3
#https://github.com/mayur-sawant/packet-sniffer

__author__="mayur-sawant"

import itertools 
import time
from socket import PF_PACKET, SOCK_RAM, ntohs, socket
from typing import Iterator
import netprotocols

class Decoder:
    def __init__(self,interface: str):
        self.interface= interface
        self.data=None
        self.protocol_queue=["Ethernet"]
        self.packet_num: int=0
        self.frame_length: int=0
        self.epoch_time: float=0

    def _bind_interface(self, sock: socket):
        if self.interface is not None:
            sock.bind((self.interface,0))
    
    def _attach_protocols(self, frame: bytes):
        start = end = 0
        for proto in self,protocol_queue:
            try:
                proto_class= getattr(netprotocols, proto)
            except AttributeError:
                continue
                end: int = start + proto_class.header-len 
                protocol = proto_class.decode(frame[start:end])
                setattr(self,proto.lower(),protocol)
                if protocol.encapsulated_proto in (None,"unidentified"):
                    break
                self.protocol_queue.append.append(protocol.encapsulated_proto)
                start=end
            self.data=frame[end:]
    
    def execute(self) -> Iterator:
        with socket(PF_PACKET, SOCK_RAM, ntohs(0x0003)) as sock:
            self._bind_interface(sock)
            for self.packet_num in intertools.count(1):
                self.frame_length= len(frame:=sock.recv(9000))
                self.epoch_time=time.time_ns()/(10**9)
                self._attach_protocols(frame)
                yield self
                del self.protocol_queue[1:]

