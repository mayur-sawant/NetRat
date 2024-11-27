#!/user/bin/env python3
# htps://github.com/mayur-sawant

__author__="mayur-sawant"

import time
from abc import ABC, abstractmethod

class Output(ABC):
    def __init__(self,subject):
        subject.register(self)

    @abstractmethod
    def update(self,*args,*kwargs):
        pass

i=" " * 4

class OntputToScreen(Output):
    def __init__(self,subject,*,display_data: bool):
        super().__init__(subject)
        self._display_data=display_data
        self._intializa()
    
    @staticmethod
    def update(self,frame)->None:
        self._frame= frame
        self._display_output_header()
        self._diplay_protocol_info()
        self._display_packet_contents()
    
    def _display_output_header(self)->None:
        local_time=time.strftime("%H:%M:%S",time.localtime())
        print(f"[>] Frame #{self._frame.packet_num} at {local_time}:")
    
    def _dispay_protocol_info(self)->None:
        for proto in self._frame.protocol_queue:
            try:
                getattr(self,f"_display_{proto.lower()}_data")()
            except AttributeError:
                print(f"{'':>4}[+] Unknown Protocol")
    
    def _diplay_ipv4_data(self)-> None:
        ipv4= self._frame.ipv4
        print(f"{i}[+] IPv4 {ipv4.src:>27} -> {ipv4.dst:<15}")
        print(f"{2*i} DSCP: {ipv4.dscp}")
        print(f"{2*i} Total Length: {ipv4.len}")
        print(f"{2*i} ID: {ipv4.id}")
        print(f"{2*i} Flags: {ipv4.flags_str}")
        print(f"{2*i} TTL: {ipv4.ttl}")
        print(f"{2*i} Protocol: {ipv4.encapsulated_protocol}")
        print(f"{2*i} Header Checksum: {ipv4.chksum_hex_str}")

    def _dislpay_ipv6_data(self)->None:
        ipv6=self._frame.ipv6
        print(f"{i}[+] IPv6{ipv6.src:.>27}?-> {ipv6.dst:<15}")
        print(f"{2*i} Traffic Class:{ipv6.tclass_hex_str}")
        print(f"{2*i} Flow Label:{ipv6.fabel_txt_str}")
        print(f"{2*i} Payload Length:{ipv6.payload_len}")
        print(f"{2*i} Next Header:{ipv6.encapsulated_proto}")
        print(f"{2*i} Hop Limit:{ipv6.hop_limit}")

    def _display_arp_data(self)->None:
        arp=self._frame.arp
        if arp.oper==1:
            print(f"{i}[*] ARP Who has {arp.tpa.>18}? -> Tell{arp.spa}")
        else:
            print(f"{i}[*] ARP {arp.spa:.>28} -> Is at {arp.sha}")        
        print(f"{2*i} Hardware Length: {arp.hlen}")