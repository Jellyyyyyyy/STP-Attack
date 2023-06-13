#!/bin/bash

OPTION="$1"

iptables $OPTION FORWARD -m physdev --physdev-in eth0 --physdev-out eth1 -p udp --dport 53 -j DROP
iptables $OPTION FORWARD -m physdev --physdev-in eth0 --physdev-out eth1 -p tcp --dport 53 -j DROP
iptables $OPTION FORWARD -m physdev --physdev-in eth1 --physdev-out eth0 -p udp --dport 53 -j DROP
iptables $OPTION FORWARD -m physdev --physdev-in eth1 --physdev-out eth0 -p tcp --dport 53 -j DROP
