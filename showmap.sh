#!/bin/bash
fname="showmap.sh"
version="0.7"
modified="03/10/2019"

#----------------------------------------------------------------- START OF SCRIPT -----------------------------------------------------------------

# colours - https://misc.flogisoft.com/bash/tip_colors_and_formatting
RED='\e[91m'
RESETCOL='\e[39m'

# doesnt seem to work that well so used version sort seems to be the best
export sortip="sort -V"

#name of temp files
inputtemp="temp.gnmap"
csvtemp="temp.csv"

#output folder 
createoutdir="Y"	#change to Y - if you always want mkdir outdir
outdir="parse"
outhostsdir="hosts"

#output file names
outputcsvfile="parsed_nmap.csv"
outputsummaryfile="summary.txt"
outputclosedfile="closed-summary.txt"
outputipfile="parsed_ipport.txt"
outputupfile="hosts_up.txt"
outputdownfile="hosts_down.txt"
outputtcpfile="ports_tcp.txt"
outputudpfile="ports_udp.txt"
outputsmbfile="smb.txt"
outputwebfile="web-urls.txt"
outputsslfile="ssl.txt"
outputclosedsummaryfile="closed-summary.txt"

# Menu Switches
men_all="N"
men_csv="N"
men_summary="N"
men_uports="N"
men_tcpports="N"
men_udpports="N"
men_uphosts="N"
men_downhosts="N"
men_ipport="N"
men_smb="N"
men_ssl="N"
men_web="N"
#men_hostports="N"
men_closed="N"
men_htmlreport="N"

function header () {
# header function  - used to print out the title of the script 
echo -e "\e[1m
     )))
    (((
  +-----+
  | (@) |]
  \_____/  Relax, we're almost done.\n"
#echo -e "- - - - - - - - - - - - - - - - - - - - - - - - - - - -"
echo -e "\e[39m\e[1m\e[96mVersion: $version - $modified" 																				 
echo -e "\e[39m\e[1m\e[96mOriginal code by:\e[39m\e[1m\e[33m Shifty0g - https://github.com/shifty0g"
echo -e "\e[39m\e[1m\e[96mAdaptations by:\e[39m\e[1m\e[33m RTT - https://github.com/Macle0d/rtt\e[39m\n"
echo -e "\e[1m- - - - - - - - - - - - - - - - - - - - - - - - - - - -\n\e[0m"
}

function helpmenu () {
# prints out the header and help menu when --help switch is selected to show the options to use 
header
echo 
echo "[*] Usage: $fname [input] [options]"
echo
echo -e "\e[95m[input]:		Grepable nmap file(s) .gnmap - can have multiple\e[39m"
echo
echo -e "\e[93m[options]:"
echo 
echo "	--help		Show this help menu"
echo "	--all		Runs ALL options"
echo "	--csv		Create .csv file - $outputcsvfile"
echo "	--summary	Create host Summary report - $outputsummaryfile"
echo "	--closed	Create Summary of hosts with CLOSED ports - $outputclosedfile"
echo "	--up		Parse 'Up' hosts - $outputupfile"
echo "	--down		Parse 'Down' hosts - $outputdownfile"
echo "	--ippport	Parse targets IP:PORT - $outputipfile"
echo "	--smb		Generate smb paths smb://IP - $outputsmbfile"
echo "	--web		Generate web URLS http://IP:PORT https://IP:PORT  - $outputwebfile"
echo "	--ssl		Generate ssl/tls hosts list IP:PORT - $outputsslfile"
echo 
echo -e "\e[39m[*] Example:"
echo 
echo "$fname *.gnmap --all"
echo "$fname nmap_tcp_full.gnmp nmap_udp_def.gnmap --summary"
echo "$fname nmap_tcp_full.gnmp nmap_udp_def.gnmap --web"
echo
echo "--------------------------------------------------------------------------------------"
echo
}

function diagnostics () {
# diagnostics function used to help figure out whats wrong - will delete this when release the script 
echo
echo
echo "################################[ DIAGNOSTICS ]########################################"
echo "\$0 - "$0
echo "\$1 - "$1
echo "\$* - "$*
echo "inpputfile - "$file
echo "inputfilepath - "$inputfilepath
echo "tempfile - "$tempfile
echo "outpath - "$outpath
echo "filecheck - "$filecheck
echo "#######################################################################################"
}

function mastercleanup () {
# MASTER cleanup - lazy just to wipe the temp stuff before and after soo all fresh
rm "${outpath}tempinput" "${outpath}ipptemp" "${outpath}closedtemp" "${outpath}summtemp" "${outpath}tempfile" "${outpath}tempfile2" "${outpath}$varTempFile2" "${outpath}inputfile" "${outpath}$varTempFile" "${outpath}$tempfile" "${outpath}$varSummTempFile" "${outpath}webtemp" "${outpath}webtemp2" "${hostportspath}hostptemp" "${outpath}$inputtemp" "${outpath}$inputtemp "${outputpath}$csvtemp > /dev/null 2>&1
}

function makecsv () {
# this is the main function which processes the inputfile and creates a csv file 
#cho -e "\e[1m\e[93m[>]\e[0m Creating CSV File"
while read line; do
	checkport=$(echo $line | grep -e '/open/' -e '/closed')
	if [ "$checkport" != "" ]; then
		host=$(echo $line | awk '{print $2}')
		lineports=$(echo $line | awk '{$1=$2=$3=$4=""; print $0}')
		if [ -f "${outpath}"tempfile2"" ]; then rm "${outpath}"tempfile2""; fi
		echo "$lineports" | tr "," "\n" | sed 's/^ *//g' >> "${outpath}"tempfile2""
		# Read the per-host temp file to write each open port as a line to the CSV temp file
		while read templine; do
		# check for open port
		checkport2=$(echo $templine | grep -e '/open/' -e '/closed')
		if [ "$checkport2" != "" ]; then
			port=$(echo $templine | awk -F '/' '{print $1}')
			status=$(echo $templine | awk -F '/' '{print $2}')
			protocol=$(echo $templine | awk -F '/' '{print $3}')
			service=$(echo $templine | awk -F '/' '{print $5}')
			version=$(echo $templine | awk -F '/' '{print $7}')
			echo "$host,$port,$status,$protocol,$service,$version" >> "${outpath}$csvtemp"
		fi
		done < "${outpath}tempfile2"
	fi
done < "${outpath}$inputtemp" 

# finalise and move the file if temp.csv
if [ -f "${outpath}$csvtemp" ]; then
   echo "HOST,PORT,STATUS,PROTOCOL,SERVICE,VERSION" > "${outpath}$outputcsvfile" 
   # sort by ip address - 1st.2nd.3rd.4th
   cat "${outpath}"temp.csv"" | sort -t"," -n -k1 | $sortip >> "${outpath}$outputcsvfile" 
   echo -e "\e[1m\e[93m[>]\e[0m Creating CSV File - $outputcsvfile"
fi

#cleanup 
rm "${outpath}$csvtemp" "${outpath}"tempfile2"" > /dev/null 2>&1

#end
}

function checkcsv () {
# checks if the makecsv fu nction has already ran and then sets the tempfile varible - stops repition as most other functions use the csv file 
if [ "$men_csv" == "Y" ]
then
	cp "${outpath}$outputcsvfile" "${outpath}$csvtemp"
else
	makecsv > /dev/null 2>&1
	mv "${outpath}$outputcsvfile" "${outpath}$csvtemp"
fi

# remove the head from the csv file 
sed -i -e "1d" "${outpath}$csvtemp"

# remove lines that have closed ports 
sed -i '/,closed,/d' "${outpath}$csvtemp"

export tempfile="$(realpath "${outpath}$csvtemp")"

# end
}

function summary () {
# creates the summary file of from the input of open ports 
echo -e "\e[1m\e[93m[>]\e[0m Creating Summary - $outputsummaryfile"

#check for csv file to process 
checkcsv

#clear any old file - fresh
rm "${outpath}$outputsummaryfile" > /dev/null 2>&1

printf "%-18s %-16s %-52.52s %-2s \n" " HOST " "PORT / PROTOCOL" " SERVICE" >> "${outpath}$outputsummaryfile"
printf "%-18s %-16s %-52.52s %-2s \n" " ---- " "---------------" " -------" >> "${outpath}$outputsummaryfile"
lasthost=""
while read line; do
	host=$(echo $line | awk -F ',' '{print $1}')
	port=$(echo $line | awk -F ',' '{print $2}')
	protocol=$(echo $line | awk -F ',' '{print $4}')
	service=$(echo $line | awk -F ',' '{print $5}')
	version=$(echo $line | awk -F ',' '{print $6}')
	if [ "$version" = "" ]; then
		version=""
	else
		version="- $version"
	fi
	printf "%-18s %-16s %-52.52s %-2s \n" " $host " "$port/$protocol " " $service $version" >> "${outpath}$outputsummaryfile"
	lasthost="$host"
done < "$tempfile"
echo "" >> "${outpath}$outputsummaryfile"

#cleanup
rm  "$tempfile" > /dev/null 2>&1

#end
}

function ipport () {
# creates a file of open ports IP:PORT
echo -e "\e[1m\e[93m[>]\e[0m Creating IP Port file - $outputipfile"

# check is csv is run and get a tempfile 
checkcsv

#clear any old file - fresh
rm "${outpath}$outputipfile" > /dev/null 2>&1

# finalise the file and clean up 
cat "$tempfile"  | cut -d, -f1,2 | tr -d '"' | tr , : | $sortip > "${outpath}$outputipfile"

#cleanup
rm  "$tempfile" > /dev/null 2>&1

#echo "	- $outputipfile"

#end
}

function uphosts () {
# creates a file with IPs for hosts with Up Statues - needs further checks to be better 
#echo -e "\e[1m\e[93m[>]\e[0m Parsing up hosts"
cat "$inputfilepath" | grep -e 'Status: Up' -e '/open/' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u -V  > "$outpath$outputupfile" 

# check if there are actually any IP addresses in the file - if not delete it no point 
if [ -z "$(cat "${outpath}$outputupfile" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")" ]
then
	  echo -e "\e[1m\e[93m[>]\e[0m Parsing up hosts$RED	- no up hosts $RESETCOL"
	  rm "${outpath}$outputupfile" > /dev/null 2>&1
else
      echo -e "\e[1m\e[93m[>]\e[0m Parsing up hosts - $outputupfile"
fi

#end
}

function downhosts () {
# creates a file with IPs for hosts with Down status 
#echo -e "\e[1m\e[93m[>]\e[0m Parsing down hosts"
cat "$inputfilepath" | grep 'Status: Down' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u -V > "${outpath}$outputdownfile"

# check if there are actually any IP addresses in the file - if not delete it no point 
if [ -z "$(cat "${outpath}$outputdownfile" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")" ]
then
      echo -e "\e[1m\e[93m[>]\e[0m Parsing down hosts$RED - no down hosts $RESETCOL"
	  rm "${outpath}$outputdownfile" > /dev/null 2>&1
else
      echo -e "\e[1m\e[93m[>]\e[0m Parsing down hosts - $outputdownfile"
fi

}

function tcpports () {
# creates a file of unqiue open TCP ports - 22,23,80,443...
#echo -e "\e[1m\e[93m[>]\e[0m Parsing tcp ports"
cat "$inputfilepath" | grep '/tcp/' | grep -o -P '.{0,9}/open/' | awk '{ print $2}' | cut -d /  -f 1 | sort -u -V | paste -s -d, 2>&1 > "${outpath}$outputtcpfile";

# check for a number if the file has them then likely has ports in  
if [ -z "$(cat "${outpath}$outputtcpfile" |  grep '[0-9]')" ]
then
	  echo -e "\e[1m\e[93m[>]\e[0m Parsing tcp ports$RED - no TCP ports $RESETCOL"
	  rm "${outpath}$outputtcpfile" > /dev/null 2>&1
else
      echo -e "\e[1m\e[93m[>]\e[0m Parsing tcp ports - $outputtcpfile"
fi

# end  
}

function udpports () {
# creates a file of unqiue open UDP ports - 53,161...
#echo -e "\e[1m\e[93m[>]\e[0m Parsing udp ports"
cat "$inputfilepath" | grep '/udp/'  | grep -o -P '.{0,9}/open/' | awk '{ print $2}' | cut -d /  -f 1 | sort -u -V | paste -s -d, 2>&1 > "${outpath}$outputudpfile"

# check for a number if the file has them then likely has ports in  
if [ -z "$(cat "${outpath}$outputudpfile" | grep '[0-9]')" ]
then
	  echo -e "\e[1m\e[93m[>]\e[0m Parsing udp ports$RED - no UDP ports $RESETCOL"
	  rm "${outpath}$outputudpfile" > /dev/null 2>&1
else
      echo -e "\e[1m\e[93m[>]\e[0m Parsing udp ports - $outputudpfile"
fi

# end 
}

function smb () {
# createa file for URI smb://192.168.1.1 
# will only grab out OPEN 445 TCP 
#echo -e "\e[1m\e[93m[>]\e[0m Creating smb paths"
cat "$inputfilepath" | grep '445/open/tcp/' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sed -e 's/^/smb:\/\//' | sort -u | $sortip | sort -t'/' -k2 -V  > "${outpath}$outputsmbfile"

# check for a smb:// if the file has them then likely has ports in  
if [ -z "$(cat "${outpath}$outputsmbfile" | grep 'smb://')" ]
then
	echo -e "\e[1m\e[93m[>]\e[0m Creating smb paths$RED	- no SMB ports $RESETCOL"
	rm "${outpath}$outputsmbfile" > /dev/null 2>&1
else
	echo -e "\e[1m\e[93m[>]\e[0m Creating smb paths - $outputsmbfile"
fi

# end 
}

function web () {
# make a file of URLS to use with tools like nikto wafwoof est
#echo -e "\e[1m\e[93m[>]\e[0m Creating web URLS"

# start fresh
rm "${outpath}$webfinalname" "${outpath}webtemp2"  > /dev/null 2>&1

#check that the csv file has been created
checkcsv

for line in $(cat "$tempfile"); do
	host=$(echo $line | awk -F ',' '{print $1}')
	port=$(echo $line | awk -F ',' '{print $2}')
	service=$(echo $line | awk -F ',' '{print $5}')
	version=$(echo $line | awk -F ',' '{print $6}')
	
	# a little overboard with the checks just to make sure all web ports are collected
	if [ "$port" = "80" ]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
   	if [ "$port" = "443" ]; then echo "https://${host}:$port/" >> "${outpath}webtemp2"; fi
    	if [ "$port" = "8080" ]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
    	if [ "$port" = "8443" ]; then echo "https://${host}:$port/" >> "${outpath}webtemp2"; fi
	if [ "$service" = "http" ]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
	if [[ "$service" == *"ssl"* ]]; then echo "https://${host}:$port/" >> "${outpath}webtemp2"; fi
	if [[ "$version" == *"Web"* ]]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
	if [[ "$version" == *"web"* ]]; then echo "http://${host}:$port/" >> "${outpath}webtemp2"; fi
done

# if webtemp2 exists then sort it 
if [ -f "${outpath}webtemp2" ]; then
	sort -u "${outpath}webtemp2" | $sortip | sort -t'/' -k2 -V  > "${outpath}$outputwebfile" 2>&1
	echo -e "\e[1m\e[93m[>]\e[0m Creating web URLS - $outputwebfile"
else
	echo -e "\e[1m\e[93m[>]\e[0m Creating web URLS$RED - no ports found $RESETCOL"
	rm "${outpath}$outputwebfile" > /dev/null 2>&1
fi

#cleanup
rm "${outpath}webtemp2" "$tempfile"  > /dev/null 2>&1

#end
}

function ssl () {
#echo -e "\e[1m\e[93m[>]\e[0m Creating ssl/tls list"

# start fresh
rm "${outpath}$outputsslfile" "${outpath}ssltemp2" > /dev/null 2>&1

#check that the csv file has been created
checkcsv

for line in $(cat "$tempfile"); do
	host=$(echo $line | awk -F ',' '{print $1}')
	port=$(echo $line | awk -F ',' '{print $2}')
	service=$(echo $line | awk -F ',' '{print $5}')
	version=$(echo $line | awk -F ',' '{print $6}')
	
	# a little overboard again - just to get anything with ssl or tls in 
	if [[ "$port" -eq "443" ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi
	if [[ "$service" == *"ssl"* ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi
	if [[ "$version" == *"ssl"* ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi
	if [[ "$service" == *"tls"* ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi
	if [[ "$version" == *"tls"* ]]; then echo "${host}:$port" >> "${outpath}ssltemp2"; fi

done

# if webtemp2 exists then sort it 
if [ -f "${outpath}ssltemp2" ]; then
	sort -u "${outpath}ssltemp2" | $sortip > "${outpath}$outputsslfile" 2>&1
	echo -e "\e[1m\e[93m[>]\e[0m Creating ssl/tls list - $outputsslfile"
else
	echo -e "\e[1m\e[93m[>]\e[0m Creating ssl/tls list$RED - no ports found $RESETCOL"
	rm "${outpath}$outputsslfile" > /dev/null 2>&1
fi

#clean up function
rm "${outpath}ssltemp" "${outpath}ssltemp2" "$tempfile" > /dev/null 2>&1
#end
}

function closedsummary() {
# creates a little report of hosts with closed ports
echo -e "\e[1m\e[93m[>]\e[0m Generating  Closed Ports Summary - $outputclosedsummaryfile"

rm "${outpath}$outputclosedsummaryfile" > /dev/null 2>&1
for host in $(cat "$inputfilepath" | grep "Host:" | grep "\/closed\/" | awk '{ print $2}'| sort --unique); do # will go through each host
    echo "Closed Ports For Host: $host " >> "${outpath}$outputclosedsummaryfile"
	echo -n "	" >> "${outpath}$outputclosedsummaryfile"
    for port in $(cat "$inputfilepath" | grep -w $host | grep -o -P '.{0,10}/closed/' | awk '{ print $2}' | cut -d /  -f 1 | sort --unique); do # go through ports
		echo -n $port", " >> "${outpath}$outputclosedsummaryfile"
    done # end ports loop
	echo -e "\n " >> "${outpath}$outputclosedsummaryfile"
done # end hosts loop
#echo "	- "$outputclosedsummaryfile

}


function printresults() {
# will print out the files generated at the end
if [ -f "${outpath}$outputsummaryfile" ]; then
	echo -e "\n\e[1m\e[93m Summary\e[39m\e[0m\n---------\n"
	cat "${outpath}$outputsummaryfile"
fi

if [ -f "${outpath}$outputipfile" ]; then
	echo -e "\nIP Ports\n--------\n"
	cat "${outpath}$outputipfile"
fi

if [ -f "${outpath}$outputupfile" ]; then
	echo -e "\nHosts Up\n--------\n"
	cat "${outpath}$outputupfile"
fi

if [ -f "${outpath}$outputdownfile" ]; then
	echo -e "\nHosts Down\n----------\n"
	cat "${outpath}$outputdownfile"
fi

if [ -f "${outpath}$outputsmbfile" ]; then
	echo -e "\nSMB\n---\n"
	cat "${outpath}$outputsmbfile"
fi

if [ -f "${outpath}$outputwebfile" ]; then
	echo -e "\nWEB\n---\n"
	cat "${outpath}$outputwebfile"
fi

if [ -f "${outpath}$outputsslfile" ]; then
	echo -e "\nSSL\n---\n"
	cat "${outpath}$outputsslfile"
fi

if [ -f "${outpath}$outputclosedsummaryfile" ]; then
	echo -e "\nClose Ports\n-----------\n"
	cat "${outpath}$outputclosedsummaryfile"
fi
}

########################
# MAIN 
########################

#cleanup
mastercleanup

# look trough and check inputfile and switches
for word in $(echo $*); do
	#echo $word
	if [[ $word == *".gnmap"* ]]; then
		#file+="$word "
		cat "$(realpath $word)" | sort -V >> $inputtemp
	fi
	if [ $word == "--help" ]; then
		helpmenu
		switch+="$word"
		exit
	fi
	if [ $word == "--csv" ]; then
		men_csv="Y"
		switch+="$word"
	fi
	if [ $word == "--summary" ]; then
		men_summary="Y"
		switch+="$word"
	fi
	if [ $word == "--up" ]; then
		men_uphosts="Y"
		switch+="$word"
	fi
	if [ $word == "--down" ]; then
		men_downhosts="Y"
		switch+="$word"
	fi
	if [ $word == "--ipport" ]; then
		men_ipport="Y"
		switch+="$word"
	fi
	if [ $word == "--smb" ]; then
		men_smb="Y"
		switch+="$word"
	fi
	if [ $word == "--web" ]; then
		men_web="Y"
		switch+="$word"
	fi
	if [ $word == "--ssl" ]; then
		men_ssl="Y"
		switch+="$word"
	fi
	if [ $word == "--closed" ]; then
		men_closed="Y"
		switch+="$word"
	fi		
	if [ $word == "--all" ]; then
		#include 
		men_all="Y"
		men_csv="Y"
		men_summary="Y"
		men_uports="Y"
		men_tcpports="Y"
		men_udpports="Y"
		men_uphosts="Y"
		men_downhosts="Y"
		men_ipport="Y"
		men_smb="Y"
		men_ssl="Y"
		men_web="Y"
		men_closed="Y"

		#Create $outdir to put all outout in - stop spam
		createoutdir="Y"
		switch+="$word"
	fi	
done

# does some checks on the input file to make sure its .gnmap + inspects the file to see its finished and has the right output flags -oA or -oG	
if [ -z "$(file "$(realpath $inputtemp)" | grep -o -e ASCII && head "$(realpath $inputtemp)" | grep -o -e "\-oA" -e "\-oG" && cat "$(realpath $inputtemp)")" ]; then
	helpmenu
	echo
	echo -e "\e[1m\e[91m[X] No input files FOUND - \e[5m.gnmap \e[25mfilename required - Must be nmap grepable! [X]\e[0m"
  	echo 
	exit 
fi

# check valid switches
if [ -z "$switch" ] 
then
	  helpmenu
	  echo 
      echo -e "\e[1m\e[91m[X] No Valid Switches FOUND - --csv, --all, etc.. [X]\e[0m"
	  echo 
	  exit  
fi

header 
                                      
# if all is selected make the outdir folder - stop the spam
if [ "$createoutdir" == "Y" ]
then 
	export outpath="$(realpath $outdir)/"
	mkdir $outdir > /dev/null 2>&1
	#mv inputfile $outdir
	mv temp.gnmap $outdir
	export inputfilepath="$(realpath "$outdir/$inputtemp")"
else
	export outpath=$(pwd)"/"
	export inputfilepath="$(realpath $inputtemp)"
fi

#1 -- make csv file
if [ "$men_csv" == "Y" ]; then makecsv; fi
#2 - summary (uses makecsv)
if [ "$men_summary" == "Y" ]; then summary; fi
# rest
if [ "$men_ipport" == "Y" ]; then ipport; fi
if [ "$men_tcpports" == "Y" ]; then	tcpports; fi
if [ "$men_udpports" == "Y" ]; then	udpports; fi
if [ "$men_uphosts" == "Y" ]; then uphosts; fi
if [ "$men_downhosts" == "Y" ]; then downhosts; fi
if [ "$men_smb" == "Y" ]; then smb; fi
if [ "$men_web" == "Y" ]; then web; fi
if [ "$men_ssl" == "Y" ]; then ssl; fi
if [ "$men_closed" == "Y" ]; then closedsummary; fi

# if yet print the results 
printresults

# remove comment to enable diagnostics function
#diagnostics

#cleanup
mastercleanup

# exit 
exit 0

#----------------------------------------------------------------- END OF SCRIPT -----------------------------------------------------------------