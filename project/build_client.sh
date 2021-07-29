#!/bin/sh

clear

echo "Starting client.."

valgrind --track-origins=yes ./client

