#!/bin/sh
/sbin/iptables-restore < /var/www-security-assistant/iptables-CURRENT.conf
exit 0
