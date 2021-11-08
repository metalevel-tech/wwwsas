#!/bin/sh

#/usr/sbin/netfilter-persistent start

/sbin/iptables-restore < /etc/wwwsas/confs/iptables.default-state.conf
#/sbin/iptables-restore < /etc/iptables/rules.v4

/sbin/ip6tables-restore < /etc/wwwsas/confs/ip6tables.default-state.conf
#/sbin/ip6tables-restore < /etc/iptables/rules.v6

exit 0
