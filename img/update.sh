#!/bin/bash

# © 2024 Tom Duhamel

logfile=/var/log/updates.log

if [ -f "/etc/mod_version" ]
then
	version=$(</etc/mod_version)
else
	version=0
fi

rm /tmp/updates1.txt
rm -R /tmp/updates

date >> $logfile

wget --directory-prefix=/tmp https://perished-shifts.000webhostapp.com/updates/updates1.txt || { echo "Can't download master!" && exit 1; }

while read F 
do
	[[ $F = \#* ]] && continue
	[[ $F =~ ^([0-9]+)=(.+)$ ]] && ver="${BASH_REMATCH[1]}" && url="${BASH_REMATCH[2]}" || continue
	(( $ver <= $version )) && continue

	echo "Downloading update $ver from $url" >> $logfile

	wget --directory-prefix=/tmp/updates $url || { echo "Download failed!" >> $logfile && exit 1; }
	
	echo "Unpacking update $ver" >> $logfile
	tar xfz /tmp/updates/*.tgz --directory=/tmp/updates/ || { echo "Unpacking failed!" >> $logfile && exit 1; }
	
	echo "Excuting update $ver" >> $logfile
	bash /tmp/updates/update.sh && echo "Update $ver success" >> $logfile || { echo "Update $ver failed!" && exit 1; }
	
	rm -R /tmp/updates
	
	version=$ver
	echo $version > /etc/mod_version
	
done < "/tmp/updates1.txt"

rm /tmp/updates1.txt


 
