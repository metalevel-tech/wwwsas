#!/bin/sh

/sbin/iptables-save > /etc/www-security-assistant/iptables.current-state.conf
#/sbin/iptables-save > /etc/iptables/rules.v4

/sbin/ip6tables-save > /etc/www-security-assistant/ip6tables.current-state.conf
#/sbin/ip6tables-save > /etc/iptables/rules.v6

#/usr/sbin/netfilter-persistent save

exit 0

