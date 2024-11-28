#!/user/bin/env python3
#http://github.com/mayur-sawant/Packet-Sniffer

__author__="mayur-sawant"

import PyInstaller.__main__ as pyinstaller 

pyinstaller.run(("NetRat/core.py","--onefile"))