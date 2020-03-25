#!/usr/bin/env python

# Original Code by https://github.com/ollypwn/SMBGhost
# Improvements and optimization by: 
# Omar Peña @p3nt3ster (omarp.work@gmail.com)
# José Alvarado (alvaradovex@gmail.com)

import sys
if (sys.version_info < (3, 0)):
    print('Python 2 detected')
    print('Run this script with Python 3.x !')
    sys.exit()
from time import time
import socket
import struct
from netaddr import IPNetwork

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'
   WHITE = '\033[0m'
   RESET = '\033[39m'

banner = color.WHITE+color.BOLD+"""
          .-.
         / ee\_
       __\  o/ )
      (___   \/
        /     \\
      _/       \\    CVE-2020-0796
 .·.¸(_____.~._/ """+color.CYAN+"""SMBGhost Scanner """+color.YELLOW+"""1.0"""+color.BOLD+color.WHITE+"""

    """

usage = color.RED+color.BOLD+" [+]"+color.WHITE+color.BOLD+" Usage: "+sys.argv[0]+" ip or ip/CIDR\n\n"
usage += "   "+color.UNDERLINE+"Example"+color.END+color.BOLD+":"+" "+color.GREEN+sys.argv[0]+color.WHITE+color.BOLD+" 192.168.0.1\n"
usage += "            "+color.GREEN+color.BOLD+sys.argv[0]+color.WHITE+color.BOLD+" 192.168.0.0/24\n"

# Checking of port
def check_port(iptocheck, lebinary):

  sock = socket.socket(socket.AF_INET)
  sock.settimeout(0.3)
  
  try:
      sock.connect(( str(iptocheck),  445 ))
  except:
      sock.close()
      #continue
      return ''
  
  sock.send(lebinary)

  nb, = struct.unpack(">I", sock.recv(4))
  resp = sock.recv(nb)

  return resp  

# Program
init_time = time()

if len(sys.argv)<=1:
    print(banner)
    print(usage)
    final_time=time()-init_time
    #print(color.WHITE+"Elapsed time in seconds "+str(final_time)+color.RESET)
    sys.exit(1)
else:
  print(banner)

pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

ips = IPNetwork(sys.argv[1])
totalIP = 0
totalVuln = 0

for ip in ips:
    totalIP+= 1
    res= check_port(ip, pkt)

    if res[68:70] == b"\x11\x03" or res[70:72] == b"\x02\x00":
        #lehost=socket.gethostname()+" > "
        print(" "+color.BOLD+color.WHITE+str(ip) +color.BOLD+color.RED+" Vulnerable"+color.END)
        totalVuln += 1
    #else:
    #    print(str(ip) + " Not vulnerable")

if totalIP > 1:
  print(color.BOLD+" [+] "+str(totalIP)+" ip checked and Founds: "+color.YELLOW+str(totalVuln)+" hosts vulnerables\n"+color.WHITE)
  print("-"*44)
  final_time=time()-init_time
  print(" Elapsed time in seconds "+str(final_time)+color.RESET)
print("")
