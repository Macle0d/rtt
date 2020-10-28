#!/bin/bash
# Script para detectar puertos abiertos
# Desarrollado por Omar Peña https://github.com/Macle0d/rtt

trap ctrl_c INT
stty -echoctl
echo -e """
 \e[38;5;195m┏━┓┏━┓┏━┓╺┳╸┏━┓┏━╸┏━┓┏┓╻  \e[38;5;202m╻ ╻
 \e[38;5;195m┣━┛┃ ┃┣┳┛ ┃ ┗━┓┃  ┣━┫┃┗┫  \e[38;5;202m┏╋┛
 \e[38;5;195m╹  ┗━┛╹┗╸ ╹ ┗━┛┗━╸╹ ╹╹ ╹  \e[38;5;202m╹ ╹
\e[39m"""

function ctrl_c(){
	#echo -e "\n\n [-] Exiting...\n"
	echo -e "\n\thappy hacking... ツ\n"
	tput cnorm; exit 0
}

for IP in "$@"
do
	echo -e " \e[38;5;87m\e[1m[+]\e[39m\e[0m Scanning\t\e[1m\e[38;5;202m➡\e[0m \e[1m\e[38;5;11m$IP\e[0m"
	tput civis; for port in $(seq 1 65535); do
		timeout 1 bash -c "echo '' > /dev/tcp/$IP/$port" 2>/dev/null && echo -e " \e[38;5;87m\e[1m[✔]\e[39m\e[0m Port: $port\t\e[1m\e[38;5;202m➡\e[0m OPEN" &
	done;wait
	echo ""
	sleep 2
done

echo -e "\n\thappy hacking... ツ\n"
tput cnorm
#tput civis -> se usa para ocultar el cursor
#tput cnorm -> se usa para mostrar el cursor
#tput cuu1 && tput el -> se usa para borrar la linea anterior

# Colores
# \e[38;5;87m	➡ Verde agua
# \e[38;5;202m	➡ Naranja
# \e[37m		➡ Gris
# \e[38;5;11m	➡ Amarillo
