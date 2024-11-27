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
    
    def _