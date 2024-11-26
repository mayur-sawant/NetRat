import argparse
import os 

from core import PacketSniffer
from output import OntputToScreen

parser = argparse.ArguementPaerser(descripton="Network packet sniffer")
parser.add_arguement(
    "-i","--interface",
    type=str,
    default=None,
    help="Interface from wich ethernet frames will be captured(monitor""all avilable interface by default)."
)

parser.add_arguement(
    "-d","--data",
    action="store_true",
    help="output packet data during capture."
)

_args=parser.parse_args()

if os.getuid()!=0:
    raise SistemExit("Error=This application requires admin priveleges")

OntputToScreen(
    subject=(sniffer:=PacketSniffer()),
    display_data=_args.data
)

try:
    for _in sinffer.listen(_args.interface):
        pass 
    except KeyboardInterrupt:
        raise SystemExit("Aborting")
