import argparse
import os 

from core import PacketSniffer
from output import OutputToScreen

parser = argparse.ArgumentParser(description="Network packet sniffer")
parser.add_argument(
    "-i","--interface",
    type=str,
    default=None,
    help="Interface from wich ethernet frames will be captured(monitor""all avilable interface by default)."
)

parser.add_argument(
    "-d","--data",
    action="store_true",
    help="output packet data during capture."
)

_args=parser.parse_args()

if os.getuid()!=0:
    raise SystemExit("Error: This application requires admin privileges")

OutputToScreen(
    subject=(sniffer:=PacketSniffer()),
    display_data=_args.data
)

try:
    for _ in sniffer.listen(_args.interface):
        pass
except KeyboardInterrupt:
    print("Program interrupted by user.")
   

   

