#!/bin/bash

function log_and_flush() {
    printf '\n\n%s\n> %s\n' "$(date)" "iptables -L WWWSAS -n --line-numbers"
    /usr/sbin/iptables -L WWWSAS -n --line-numbers

    printf '\n\n%s\n> %s\n' "$(date)" "iptables -S WWWSAS"
    /usr/sbin/iptables -S WWWSAS

    printf '\n\n%s\n> %s\n' "$(date)" "iptables -F WWWSAS"
    /usr/sbin/iptables -F WWWSAS
}

log_and_flush() >>"/etc/wwwsas/tmp/iptables-flush.log"

exit 0
