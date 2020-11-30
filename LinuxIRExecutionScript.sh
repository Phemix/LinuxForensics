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

