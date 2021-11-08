#!/bin/sh
/sbin/ipset restore < /etc/wwwsas/confs/ipset.current-state.conf
exit 0
