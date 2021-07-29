#!/bin/sh

make clean 
make 
clear

echo "Starting server.."

valgrind --track-origins=yes ./server  &

