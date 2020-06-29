#!/bin/bash
# Script para detectar puertos abiertos
# Desarrollado por Omar Peña https://github.com/Macle0d/rtt

trap ctrl_c INT

echo ""
echo " ┏━┓┏━┓┏━┓╺┳╸┏━┓┏━╸┏━┓┏┓╻   ╻ ╻"
echo " ┣━┛┃ ┃┣┳┛ ┃ ┗━┓┃  ┣━┫┃┗┫   ┏╋┛"
echo " ╹  ┗━┛╹┗╸ ╹ ┗━┛┗━╸╹ ╹╹ ╹   ╹ ╹"
echo ""

function ctrl_c(){
	echo -e "\n\n[*] Exiting...\n"
	tput cnorm; exit 0
}

tput civis; for port in $(seq 1 65535); do
	timeout 1 bash -c "echo '' > /dev/tcp/$1/$port" 2>/dev/null && echo " [*] Port: $port ➡ OPEN" &
done;wait

tput cnorm
#tput civis -> se usa para ocultar el cursor
#tput cnorm -> se usa para mostrar el cursor
#tput cuu1 && tput el -> se usa para borrar la linea anterior
