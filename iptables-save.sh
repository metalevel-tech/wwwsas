#!/bin/sh
/sbin/iptables-save > /etc/www-security-assistant/iptables.current-state.conf
exit 0
