#!/bin/sh

/sbin/iptables-save > /etc/wwwsas/confs/iptables.default-state.conf
#/sbin/iptables-save > /etc/iptables/rules.v4

/sbin/ip6tables-save > /etc/wwwsas/confs/ip6tables.default-state.conf
#/sbin/ip6tables-save > /etc/iptables/rules.v6

#/usr/sbin/netfilter-persistent save

exit 0

