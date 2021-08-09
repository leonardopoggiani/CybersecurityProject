#!/bin/sh

kill -9 $(ps -ef | grep "valgrind" | grep -v grep | awk '{print $2}')

make clean 
make 
clear

echo "Starting server.."

valgrind --track-origins=yes ./server  &

