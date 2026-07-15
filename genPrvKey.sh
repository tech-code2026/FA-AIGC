#!/bin/bash
#start-ganache-and-save-keyssh

# Debugging information output
set -x

# Start the Ganache CLI and redirect the output to a temporary file
OS=$(uname -s)
 
case "$OS" in
  Linux*)
    echo "Linux"
    ganache-cli --mnemonic "aigc"  > ganache_output.txt &
    ;;
  Darwin*)
    echo "macOS"
    ganache-cli --mnemonic "aigc" > ganache_output.txt &
    ;;
  CYGWIN*|MINGW32*|MSYS*|MINGW*)
    echo "Windows"
    ;;
  *)
    echo "Unknown OS"
    ;;
esac

# Wait for the Ganache CLI to fully start
sleep 5
rm .env

# Extract available accounts and write them to the .env file
i=1
cat ganache_output.txt | grep -A 12 'Available Accounts' | grep '0x' | while read -r line; do
  address=$(echo $line | awk '{print $2}')
  echo "ACCOUNT_$i=$address" >> .env
  ((i++))
done
a=0
# Read the private key and write it to the.env file, removing the '0x' prefix
cat ganache_output.txt | grep 'Private Keys' -A 12 | grep -o '0x.*' | while read -r line; do
  echo "PRIVATE_KEY_$((++a))=${line:2}" >> .env
done
# This command has a bug in Ubuntu systems where it fails to kill the ganache process. In Ubuntu, the ganache process is started as a 'node' process, so manual killing of the process occupying the port is required after using this command.
rm ganache_output.txt
# ps -ef|grep 'ganache-cli'|xargs kill -9
ps -ef | grep ganache-cli | grep -v grep | awk '{print $2}' | xargs kill -9

# pgrep ganache | xargs kill -9
