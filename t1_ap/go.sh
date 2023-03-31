#!/bin/sh
#iw reg set US
DIR=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
cd $DIR

ip addr add dev wlan0 192.168.1.1/24
iw dev wlan0 interface add mon0 type monitor
ip link set dev wlan0 up
ip link set dev mon0 up

# Run AP
cd /turtleap

while true
do
  python3 go.py
done
