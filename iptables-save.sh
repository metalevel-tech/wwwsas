#!/bin/sh
/sbin/iptables-save > /var/www-security-assistant/iptables-CURRENT.conf
exit 0
