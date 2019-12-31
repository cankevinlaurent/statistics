#!/bin/sh

clear

chmod +x ~

echo 'Cleaning old processes...'
str=`ps -Af | grep statistics_retriever.py | grep -v "grep"`
arr=($(echo $str))
pid=${arr[1]}
kill -9 $pid

str=`ps -Af | grep statistics_enabler.py | grep -v "grep"`
arr=($(echo $str))
pid=${arr[1]}
kill -9 $pid

echo 'Done!'
echo 'Starting ...'
/usr/local/bin/python statistics_retriever.py &
/usr/local/bin/python statistics_enabler.py &
echo 'Done!'

