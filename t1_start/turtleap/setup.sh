#!/bin/bash
modprobe -r mac80211_hwsim
modprobe mac80211_hwsim radios=4

nmcli dev set wlan1 managed no
nmcli dev set wlan2 managed no
nmcli dev set wlan3 managed no
nmcli dev set wlan0 managed no
iw dev wlan2 interface add cli0 type monitor
iw dev wlan0 interface add mon0 type monitor

ip link set dev wlan0 up
ip link set dev wlan1 up
ip link set dev wlan2 up
ip link set dev wlan3 up
ip link set dev cli0 up
ip link set dev mon0 up
