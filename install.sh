#!/bin/bash
echo""
if [ "$1" = "all" ]; then
    sudo cp -fv scan-ms17-010.py /usr/bin/
    sudo cp -fv nlocate /usr/bin/
    sudo cp -fv scan-SMBGhost.py /usr/bin/

elif [ "$1" = "scan-ms17-010.py" ]; then
    sudo cp -fv scan-ms17-010.py /usr/bin/

elif [ "$1" = "nlocate" ]; then
    sudo cp -fv nlocate /usr/bin/

elif [ "$1" = "scan-SMBGhost.py" ]; then
    sudo cp -fv scan-SMBGhost.py /usr/bin/

else
    echo "Usage:
    sh install.sh nlocate
    sh install.sh scan-ms17-010.py
    sh install.sh scan-SMBGhost.py
    sh install.sh all\n"
fi