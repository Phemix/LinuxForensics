#!/bin/bash

#define date and hostname
today=$(date +"%m_%d_%Y")
host=$(hostname)

#remove previous dump script
rm -r /tmp/Linux-IR* 2> /dev/null

#call Enumeration Script
./EnumerationScript.sh  -e /tmp/ | tee /tmp/std_out_dump.txt

mv /tmp/std_out_dump.txt /tmp/Linux-IR-$today-$host/


# compress output
cd /tmp/
zip -r Linux-IR-Output-$today-$host Linux-IR*


echo -e "######################## PROCESSING AND FILE COLLECTION COMPLETE \n###################"
echo "End time is `date` "



:'

# use SCP to copy file on to prod server and then to NAS Share
read -p "Enter username: " username

#copy file over to Prod Server
scp /tmp/Linux-IR-Output* $username@10.52.152.192:/tmp 

# ssh into prod server
ssh $username@10.52.152.192

# do some cleanups of previous mounts and folder 
rm -r /tmp/nfsmount 2> /dev/null
rm -r /tmp/Linux-IR* 2> /dev/null

# create NFS mount directory
mkdir /tmp/nfsmount

# mount directory from Prod Server to NFS share
mount 10.1.112.44:/dfir_ir /tmp/nfsmount

#move investigation details to NAS Share (will also be on PROD server until next run)
mv /tmp/Linux-IR-Output* /tmp/nfsmount
'
