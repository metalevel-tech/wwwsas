#!/bin/sh
/sbin/iptables-restore < /etc/www-security-assistant/iptables.current-state.conf
exit 0
