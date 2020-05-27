#!/bin/bash
# Script para detectar SO en base al ttl de repuesta del ping
# Desarrollado por Omar Peña https://github.com/Macle0d/rtt

# función para detectar cuando el usuario teclea Ctrl+C
trap ctrl_c INT
function ctrl_c(){
	echo -e "\n\n [*] detected Ctrl+C exiting...\n"
    tput cnorm; exit 0
}
# función ejecuta un ping para determinar SO
is_alive_ping()
{
	var=$(ping -W 1 -b -c 1 $1 | grep ttl | awk '{print $6}' | awk -F "=" '{print $2}')
	if [ ! -z "$var" ]
	then
		if [ $var -ge 0 ] && [ $var -le 64 ] 
		then
			echo -e " $1\t=> Linux"
		elif [ $var -ge 65 ] && [ $var -le 128 ]
		then
			echo -e " $1\t=> Windows"
		elif [ $var -ge 129 ] && [ $var -le 254 ]
		then
			echo -e " $1\t=> Solaris/AIX"
		fi
	fi
}
echo -e "\e[1m"
echo -e " ┏━┓┏━┓   ╺┳┓┏━╸╺┳╸┏━╸┏━╸╺┳╸"
echo -e " ┃ ┃┗━┓╺━╸ ┃┃┣╸  ┃ ┣╸ ┃   ┃ "
echo -e " ┗━┛┗━┛   ╺┻┛┗━╸ ╹ ┗━╸┗━╸ ╹ \n\e[0m"
read -p " [?] Introduzca un segmento de IP del tipo 10.10.10: " ip
echo ""
tput civis; for i in $ip.{2..254}
do
	is_alive_ping $i & disown
done;wait
tput cnorm
#tput civis -> se usa para ocultar el cursor
#tput cnorm -> se usa para mostrar el cursor
#tput cuu1 && tput el -> se usa para borrar la linea anterior
sleep 2
echo ""
exit 0
